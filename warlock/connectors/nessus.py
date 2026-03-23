"""Nessus connector — Layer 1 implementation for standalone vulnerability scanner.

Collects scan results, vulnerabilities by severity/plugin, and host details
via the Nessus REST API (standalone scanner, not Tenable.io).
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


class NessusConnector(BaseConnector):
    """Collects compliance telemetry from a standalone Nessus scanner."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[nessus]")
        if not self.get_secret("WLK_NESSUS_BASE_URL"):
            errors.append("WLK_NESSUS_BASE_URL not set (e.g. https://scanner:8834)")
        if not self.get_secret("WLK_NESSUS_ACCESS_KEY"):
            errors.append("WLK_NESSUS_ACCESS_KEY not set")
        if not self.get_secret("WLK_NESSUS_SECRET_KEY"):
            errors.append("WLK_NESSUS_SECRET_KEY not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self._base_url()}/server/status")
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="nessus",
            source_type=SourceType.SCANNER,
            provider="nessus",
        )

        client = self._client()

        self._collect_scans(client, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _base_url(self) -> str:
        return self.get_secret("WLK_NESSUS_BASE_URL").rstrip("/")

    def _client(self) -> httpx.Client:
        access_key = self.get_secret("WLK_NESSUS_ACCESS_KEY")
        secret_key = self.get_secret("WLK_NESSUS_SECRET_KEY")
        headers = {
            "Content-Type": "application/json",
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
        }
        return httpx.Client(
            headers=headers,
            timeout=self.config.timeout_seconds,
            verify=False,  # Nessus uses self-signed certs by default
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="nessus",
            source_type=SourceType.SCANNER,
            provider="nessus",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_scans(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect all scans and their results."""
        try:
            resp = client.get(f"{self._base_url()}/scans")
            resp.raise_for_status()
            body = resp.json()
            scans = body.get("scans", []) or []

            result.events.append(self._raw_event("nessus_scans", {"scans": scans}))

            # For each completed scan, collect vulnerabilities and host details
            for scan in scans:
                scan_id = scan.get("id")
                status = scan.get("status", "")
                if scan_id is not None and status == "completed":
                    self._collect_scan_vulnerabilities(client, scan_id, result)
                    self._collect_scan_hosts(client, scan_id, result)

        except Exception as e:
            log.debug("Nessus scans collection failed: %s", e)
            result.errors.append(f"nessus_scans: {e}")

    def _collect_scan_vulnerabilities(
        self, client: httpx.Client, scan_id: int, result: ConnectorResult
    ) -> None:
        """Collect vulnerability details for a specific scan."""
        try:
            resp = client.get(f"{self._base_url()}/scans/{scan_id}")
            resp.raise_for_status()
            body = resp.json()
            vulnerabilities = body.get("vulnerabilities", []) or []
            info = body.get("info", {})

            result.events.append(
                self._raw_event(
                    "nessus_vulnerabilities",
                    {
                        "scan_id": scan_id,
                        "scan_name": info.get("name", ""),
                        "scan_start": info.get("scanner_start", ""),
                        "scan_end": info.get("scanner_end", ""),
                        "policy": info.get("policy", ""),
                        "vulnerabilities": vulnerabilities,
                    },
                )
            )
        except Exception as e:
            log.debug("Nessus vulnerabilities collection failed for scan %s: %s", scan_id, e)
            result.errors.append(f"nessus_vulnerabilities[{scan_id}]: {e}")

    def _collect_scan_hosts(
        self, client: httpx.Client, scan_id: int, result: ConnectorResult
    ) -> None:
        """Collect host details for a specific scan."""
        try:
            resp = client.get(f"{self._base_url()}/scans/{scan_id}")
            resp.raise_for_status()
            body = resp.json()
            hosts = body.get("hosts", []) or []

            host_details = []
            for host in hosts:
                host_id = host.get("host_id")
                if host_id is not None:
                    try:
                        host_resp = client.get(
                            f"{self._base_url()}/scans/{scan_id}/hosts/{host_id}"
                        )
                        host_resp.raise_for_status()
                        host_data = host_resp.json()
                        host_details.append(host_data)
                    except Exception as e:
                        log.debug(
                            "Nessus host detail failed for scan %s host %s: %s",
                            scan_id,
                            host_id,
                            e,
                        )

            result.events.append(
                self._raw_event(
                    "nessus_host_details",
                    {
                        "scan_id": scan_id,
                        "hosts": host_details,
                    },
                )
            )
        except Exception as e:
            log.debug("Nessus host details collection failed for scan %s: %s", scan_id, e)
            result.errors.append(f"nessus_host_details[{scan_id}]: {e}")


# Register
registry.register("nessus", NessusConnector)
