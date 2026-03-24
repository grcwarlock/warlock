"""STIX/TAXII 2.1 consumer for correlating external threat intelligence.

Provides a ``TAXIIClient`` that discovers TAXII API roots, lists collections,
polls STIX indicators, and correlates them with internal Warlock findings.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore[assignment]
    _HAS_HTTPX = False

log = logging.getLogger(__name__)

_MAX_RETRIES = 3
_TIMEOUT = 30.0

# TAXII 2.1 media types
_TAXII_ACCEPT = "application/taxii+json;version=2.1"
_STIX_ACCEPT = "application/stix+json;version=2.1"


class TAXIIClientError(Exception):
    """Raised when a TAXII API operation fails."""


class TAXIIClient:
    """STIX/TAXII 2.1 client for consuming threat intelligence feeds.

    Args:
        username: Optional basic auth username for the TAXII server.
        password: Optional basic auth password.
        api_key: Optional API key (sent as ``Authorization: Bearer``).
    """

    def __init__(
        self,
        *,
        username: str | None = None,
        password: str | None = None,
        api_key: str | None = None,
    ) -> None:
        if not _HAS_HTTPX:
            raise TAXIIClientError("httpx is required for STIX/TAXII integration")

        self._username = username
        self._password = password
        self._api_key = api_key

    # ------------------------------------------------------------------
    # Auth and headers
    # ------------------------------------------------------------------

    def _auth(self) -> tuple[str, str] | None:
        if self._username and self._password:
            return (self._username, self._password)
        return None

    def _headers(self, accept: str = _TAXII_ACCEPT) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": accept,
            "Content-Type": "application/json",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    # ------------------------------------------------------------------
    # HTTP helper with retry
    # ------------------------------------------------------------------

    def _request(
        self,
        url: str,
        *,
        accept: str = _TAXII_ACCEPT,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """GET request with retry and exponential backoff."""
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                resp = httpx.get(
                    url,
                    headers=self._headers(accept),
                    auth=self._auth(),
                    params=params,
                    timeout=_TIMEOUT,
                )
                resp.raise_for_status()
                return resp.json()
            except Exception as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    import time

                    wait = 2**attempt
                    log.warning(
                        "TAXII GET %s failed (attempt %d/%d): %s -- retrying in %ds",
                        url,
                        attempt + 1,
                        _MAX_RETRIES,
                        exc,
                        wait,
                    )
                    time.sleep(wait)

        raise TAXIIClientError(f"TAXII GET {url} failed after {_MAX_RETRIES} attempts: {last_exc}")

    # ------------------------------------------------------------------
    # TAXII discovery
    # ------------------------------------------------------------------

    def discover_api_root(self, server_url: str) -> list[str]:
        """Discover TAXII API roots from the server discovery endpoint.

        Args:
            server_url: Base URL of the TAXII server
                (e.g. ``https://taxii.example.com``).

        Returns:
            List of API root URLs.
        """
        server_url = server_url.rstrip("/")
        discovery_url = f"{server_url}/taxii2/"

        data = self._request(discovery_url)
        api_roots = data.get("api_roots", [])

        log.info("Discovered %d API root(s) from %s", len(api_roots), server_url)
        return api_roots

    def get_collections(self, api_root: str) -> list[dict[str, Any]]:
        """List available collections under an API root.

        Args:
            api_root: The API root URL (from ``discover_api_root()``).

        Returns:
            List of collection dicts with ``id``, ``title``,
            ``description``, and ``can_read``/``can_write``.
        """
        api_root = api_root.rstrip("/")
        url = f"{api_root}/collections/"

        data = self._request(url)
        collections = data.get("collections", [])

        log.info("Found %d collection(s) at %s", len(collections), api_root)
        return collections

    # ------------------------------------------------------------------
    # Indicator polling
    # ------------------------------------------------------------------

    def poll_indicators(
        self,
        collection_id: str,
        since: datetime | None = None,
        *,
        api_root: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Fetch STIX indicator objects from a TAXII collection.

        Args:
            collection_id: The TAXII collection UUID.
            since: Only fetch objects added after this datetime.
            api_root: The API root URL.
            limit: Maximum number of objects to retrieve per request.

        Returns:
            List of STIX indicator objects (dicts).
        """
        if not api_root:
            raise TAXIIClientError("api_root is required for polling")

        api_root = api_root.rstrip("/")
        url = f"{api_root}/collections/{collection_id}/objects/"

        params: dict[str, str] = {
            "match[type]": "indicator",
            "limit": str(limit),
        }
        if since:
            params["added_after"] = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        data = self._request(url, accept=_STIX_ACCEPT, params=params)
        objects = data.get("objects", [])

        # Filter to only indicator type (server may return others)
        indicators = [obj for obj in objects if obj.get("type") == "indicator"]

        log.info(
            "Polled %d indicator(s) from collection %s (since=%s)",
            len(indicators),
            collection_id,
            since.isoformat() if since else "all",
        )
        return indicators

    # ------------------------------------------------------------------
    # Threat correlation
    # ------------------------------------------------------------------

    @staticmethod
    def match_indicators(
        indicators: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Correlate external STIX indicators with internal findings.

        Matches are performed by comparing indicator patterns against
        finding fields (CVE IDs, IP addresses, hashes, domains).

        Args:
            indicators: List of STIX indicator objects.
            findings: List of Warlock finding dicts.  Expected fields:
                ``finding_id``, ``title``, ``cve_ids`` (list[str]),
                ``ip_addresses`` (list[str]), ``hashes`` (list[str]),
                ``domains`` (list[str]).

        Returns:
            List of match dicts with ``indicator_id``, ``indicator_name``,
            ``finding_id``, ``match_type``, and ``match_value``.
        """
        matches: list[dict[str, Any]] = []

        # Build lookup indexes from findings
        cve_index: dict[str, list[str]] = {}
        ip_index: dict[str, list[str]] = {}
        hash_index: dict[str, list[str]] = {}
        domain_index: dict[str, list[str]] = {}

        for finding in findings:
            fid = finding.get("finding_id") or finding.get("id", "")
            for cve in finding.get("cve_ids", []):
                cve_index.setdefault(cve.upper(), []).append(fid)
            for ip in finding.get("ip_addresses", []):
                ip_index.setdefault(ip, []).append(fid)
            for h in finding.get("hashes", []):
                hash_index.setdefault(h.lower(), []).append(fid)
            for d in finding.get("domains", []):
                domain_index.setdefault(d.lower(), []).append(fid)

        for indicator in indicators:
            ind_id = indicator.get("id", "")
            ind_name = indicator.get("name", "")
            pattern = indicator.get("pattern", "")

            # Extract observable values from STIX pattern string
            # Patterns look like: [file:hashes.'SHA-256' = 'abc123']
            # or [ipv4-addr:value = '1.2.3.4']
            matched_findings = _extract_and_match(
                pattern, cve_index, ip_index, hash_index, domain_index
            )

            for fid, match_type, match_value in matched_findings:
                matches.append(
                    {
                        "indicator_id": ind_id,
                        "indicator_name": ind_name,
                        "finding_id": fid,
                        "match_type": match_type,
                        "match_value": match_value,
                    }
                )

        log.info(
            "Matched %d indicator-finding correlation(s) across %d indicators and %d findings",
            len(matches),
            len(indicators),
            len(findings),
        )
        return matches

    # ------------------------------------------------------------------
    # Configuration check
    # ------------------------------------------------------------------

    @staticmethod
    def is_configured() -> bool:
        """Return True.

        TAXII client does not require global config -- connection
        parameters are passed per-call.  Always considered available.
        """
        return True


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _extract_and_match(
    pattern: str,
    cve_index: dict[str, list[str]],
    ip_index: dict[str, list[str]],
    hash_index: dict[str, list[str]],
    domain_index: dict[str, list[str]],
) -> list[tuple[str, str, str]]:
    """Extract observable values from a STIX pattern and match against indexes.

    Returns list of (finding_id, match_type, match_value) tuples.
    """
    results: list[tuple[str, str, str]] = []

    # Extract quoted string values from the pattern
    import re

    values = re.findall(r"'([^']+)'", pattern)

    for val in values:
        val_stripped = val.strip()

        # Check CVE pattern (CVE-YYYY-NNNNN)
        if val_stripped.upper().startswith("CVE-"):
            for fid in cve_index.get(val_stripped.upper(), []):
                results.append((fid, "cve", val_stripped))

        # Check IP addresses (simple heuristic)
        elif _looks_like_ip(val_stripped):
            for fid in ip_index.get(val_stripped, []):
                results.append((fid, "ip_address", val_stripped))

        # Check hashes (hex strings of typical lengths)
        elif _looks_like_hash(val_stripped):
            for fid in hash_index.get(val_stripped.lower(), []):
                results.append((fid, "hash", val_stripped))

        # Check domains
        elif "." in val_stripped and not val_stripped.startswith("/"):
            for fid in domain_index.get(val_stripped.lower(), []):
                results.append((fid, "domain", val_stripped))

    return results


def _looks_like_ip(value: str) -> bool:
    """Heuristic check for IPv4 address format."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _looks_like_hash(value: str) -> bool:
    """Heuristic check for common hash lengths (MD5, SHA-1, SHA-256, SHA-512)."""
    if not all(c in "0123456789abcdefABCDEF" for c in value):
        return False
    return len(value) in (32, 40, 64, 128)
