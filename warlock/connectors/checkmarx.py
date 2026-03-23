"""Checkmarx connector — Layer 1 implementation for SAST code security.

Collects projects, scan results (vulnerabilities by severity/category),
and scan status via Checkmarx One REST API.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


class CheckmarxConnector(BaseConnector):
    """Collects compliance telemetry from Checkmarx One REST API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[checkmarx]")
        if not self.get_secret("WLK_CHECKMARX_BASE_URL"):
            errors.append("WLK_CHECKMARX_BASE_URL not set")
        if not self.get_secret("WLK_CHECKMARX_CLIENT_ID"):
            errors.append("WLK_CHECKMARX_CLIENT_ID not set")
        if not self.get_secret("WLK_CHECKMARX_CLIENT_SECRET"):
            errors.append("WLK_CHECKMARX_CLIENT_SECRET not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            base_url = self.get_secret("WLK_CHECKMARX_BASE_URL").rstrip("/")
            resp = client.get(f"{base_url}/api/projects", params={"limit": 1})
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="checkmarx",
            source_type=SourceType.CODE,
            provider="checkmarx",
        )

        client = self._client()
        base_url = self.get_secret("WLK_CHECKMARX_BASE_URL").rstrip("/")

        self._collect_projects(client, base_url, result)
        self._collect_scan_results(client, base_url, result)
        self._collect_vulnerabilities(client, base_url, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _get_access_token(self) -> str:
        """Obtain OAuth2 access token from Checkmarx IAM."""
        base_url = self.get_secret("WLK_CHECKMARX_BASE_URL").rstrip("/")
        client_id = self.get_secret("WLK_CHECKMARX_CLIENT_ID")
        client_secret = self.get_secret("WLK_CHECKMARX_CLIENT_SECRET")

        token_url = f"{base_url}/auth/realms/Checkmarx/protocol/openid-connect/token"
        resp = httpx.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _client(self) -> httpx.Client:
        """Build an httpx client with OAuth2 bearer token."""
        token = self._get_access_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        return httpx.Client(headers=headers, timeout=self.config.timeout_seconds)

    # -- Pagination --

    def _paginate(
        self,
        client: httpx.Client,
        url: str,
        result_key: str | None = None,
    ) -> list:
        """Offset-based pagination for Checkmarx One API."""
        max_pages = self.config.settings.get("max_pages", 20)
        per_page = self.config.settings.get("per_page", 100)
        all_items: list = []
        offset = 0

        for _ in range(max_pages):
            resp = client.get(url, params={"limit": per_page, "offset": offset})
            resp.raise_for_status()
            body = resp.json()

            if result_key:
                items = body.get(result_key, [])
            elif isinstance(body, list):
                items = body
            else:
                # Try common keys
                for key in ("projects", "scans", "results", "items"):
                    if key in body:
                        items = body[key]
                        break
                else:
                    items = []

            if not items:
                break

            all_items.extend(items)
            offset += len(items)

            total = body.get("totalCount", body.get("total", 0))
            if total and offset >= total:
                break

        return all_items

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="checkmarx",
            source_type=SourceType.CODE,
            provider="checkmarx",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_projects(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect all Checkmarx projects."""
        try:
            url = f"{base_url}/api/projects"
            projects = self._paginate(client, url, result_key="projects")
            result.events.append(
                self._raw_event(
                    "checkmarx_projects",
                    {"projects": projects},
                )
            )
        except Exception as e:
            log.debug("Checkmarx projects collection failed: %s", e)
            result.errors.append(f"checkmarx_projects: {e}")

    def _collect_scan_results(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect recent scan results across all projects."""
        try:
            url = f"{base_url}/api/scans"
            scans = self._paginate(client, url, result_key="scans")
            result.events.append(
                self._raw_event(
                    "checkmarx_scan_results",
                    {"scans": scans},
                )
            )
        except Exception as e:
            log.debug("Checkmarx scan results collection failed: %s", e)
            result.errors.append(f"checkmarx_scan_results: {e}")

    def _collect_vulnerabilities(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect vulnerability results from completed scans."""
        try:
            url = f"{base_url}/api/results"
            vulns = self._paginate(client, url, result_key="results")
            result.events.append(
                self._raw_event(
                    "checkmarx_vulnerabilities",
                    {"vulnerabilities": vulns},
                )
            )
        except Exception as e:
            log.debug("Checkmarx vulnerabilities collection failed: %s", e)
            result.errors.append(f"checkmarx_vulnerabilities: {e}")


# Register
registry.register("checkmarx", CheckmarxConnector)
