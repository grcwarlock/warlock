"""Tenable.io connector — Layer 1 implementation for vulnerability scanning.

Collects vulnerability exports, assets, compliance audit results, and agent status.
Uses httpx to call the Tenable.io REST API.
"""

from __future__ import annotations

import logging
import time
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


class TenableConnector(BaseConnector):
    """Collects compliance telemetry from Tenable.io APIs."""

    BASE_URL = "https://cloud.tenable.com"

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[tenable]")
        if not self.get_secret("TENABLE_ACCESS_KEY"):
            errors.append("TENABLE_ACCESS_KEY env var not set")
        if not self.get_secret("TENABLE_SECRET_KEY"):
            errors.append("TENABLE_SECRET_KEY env var not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self.BASE_URL}/server/status")
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="tenable",
            source_type=SourceType.SCANNER,
            provider="tenable",
        )

        client = self._client()

        # Collect vulnerability exports (critical/high)
        self._collect_vuln_export(client, result)
        # Collect assets
        self._collect_assets(client, result)
        # Collect compliance audit results
        self._collect_compliance(client, result)
        # Collect agent status
        self._collect_agents(client, result)

        result.complete()
        return result

    def _client(self) -> httpx.Client:
        return httpx.Client(
            headers={
                "X-ApiKeys": f"accessKey={self.get_secret('TENABLE_ACCESS_KEY')};"
                f"secretKey={self.get_secret('TENABLE_SECRET_KEY')}",
                "Accept": "application/json",
            },
            timeout=self.config.timeout_seconds,
        )

    def _collect_vuln_export(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Export vulnerabilities with severity critical or high."""
        try:
            # Request a vuln export
            resp = client.post(
                f"{self.BASE_URL}/vulns/export",
                json={
                    "filters": {
                        "severity": ["critical", "high"],
                    },
                    "num_assets": self.config.settings.get("export_chunk_size", 500),
                },
            )
            resp.raise_for_status()
            export_uuid = resp.json().get("export_uuid", "")
            if not export_uuid:
                result.errors.append("vulns/export: no export_uuid returned")
                return

            # Poll for export completion
            data = self._poll_export(client, "vulns", export_uuid)

            result.events.append(
                RawEventData(
                    source="tenable",
                    source_type=SourceType.SCANNER,
                    provider="tenable",
                    event_type="vuln_export",
                    raw_data={"vulnerabilities": data, "export_uuid": export_uuid},
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("Tenable vuln export failed: %s", e)
            result.errors.append(f"vuln_export: {e}")

    def _collect_assets(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Export asset inventory."""
        try:
            resp = client.post(
                f"{self.BASE_URL}/assets/export",
                json={
                    "chunk_size": self.config.settings.get("export_chunk_size", 500),
                },
            )
            resp.raise_for_status()
            export_uuid = resp.json().get("export_uuid", "")
            if not export_uuid:
                result.errors.append("assets/export: no export_uuid returned")
                return

            data = self._poll_export(client, "assets", export_uuid)

            result.events.append(
                RawEventData(
                    source="tenable",
                    source_type=SourceType.SCANNER,
                    provider="tenable",
                    event_type="asset_export",
                    raw_data={"assets": data, "export_uuid": export_uuid},
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("Tenable asset export failed: %s", e)
            result.errors.append(f"asset_export: {e}")

    def _collect_compliance(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect compliance audit results."""
        try:
            resp = client.get(
                f"{self.BASE_URL}/compliance/export",
                params={
                    "num_findings": self.config.settings.get("export_chunk_size", 500),
                },
            )
            resp.raise_for_status()
            export_uuid = resp.json().get("export_uuid", "")
            if not export_uuid:
                # Fall back to listing audits
                resp = client.get(f"{self.BASE_URL}/audit-log/v1/events", params={"limit": 1000})
                resp.raise_for_status()
                result.events.append(
                    RawEventData(
                        source="tenable",
                        source_type=SourceType.SCANNER,
                        provider="tenable",
                        event_type="compliance_audits",
                        raw_data={"audits": resp.json().get("events", [])},
                        observed_at=datetime.now(timezone.utc),
                    )
                )
                return

            data = self._poll_export(client, "compliance", export_uuid)

            result.events.append(
                RawEventData(
                    source="tenable",
                    source_type=SourceType.SCANNER,
                    provider="tenable",
                    event_type="compliance_audits",
                    raw_data={"audits": data, "export_uuid": export_uuid},
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("Tenable compliance collection failed: %s", e)
            result.errors.append(f"compliance_audits: {e}")

    def _collect_agents(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect agent status."""
        try:
            resp = client.get(
                f"{self.BASE_URL}/scanners/1/agents",
                params={
                    "limit": self.config.settings.get("agent_limit", 5000),
                },
            )
            resp.raise_for_status()
            agents = resp.json().get("agents", [])

            result.events.append(
                RawEventData(
                    source="tenable",
                    source_type=SourceType.SCANNER,
                    provider="tenable",
                    event_type="agent_status",
                    raw_data={"agents": agents},
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("Tenable agent collection failed: %s", e)
            result.errors.append(f"agent_status: {e}")

    def _poll_export(self, client: httpx.Client, resource: str, export_uuid: str) -> list:
        """Poll an export until ready, then download all chunks.

        Note: This method uses blocking ``time.sleep()`` between poll attempts,
        which will block the calling thread for up to ``export_poll_max *
        export_poll_interval`` seconds (default: 60 * 5 = 300s).  For production
        deployments with many concurrent connectors, consider replacing this with
        an async implementation using ``asyncio.sleep()`` and ``httpx.AsyncClient``
        to avoid starving the thread pool.
        """
        max_attempts = self.config.settings.get("export_poll_max", 60)
        poll_interval = self.config.settings.get("export_poll_interval", 5)

        for _ in range(max_attempts):
            resp = client.get(f"{self.BASE_URL}/{resource}/export/{export_uuid}/status")
            resp.raise_for_status()
            status_data = resp.json()
            status = status_data.get("status", "")

            if status == "FINISHED":
                chunks = status_data.get("chunks_available", [])
                all_data: list = []
                for chunk_id in chunks:
                    chunk_resp = client.get(
                        f"{self.BASE_URL}/{resource}/export/{export_uuid}/chunks/{chunk_id}"
                    )
                    chunk_resp.raise_for_status()
                    all_data.extend(chunk_resp.json())
                return all_data
            elif status in ("CANCELLED", "ERROR"):
                raise RuntimeError(f"Export {export_uuid} {status}")

            time.sleep(poll_interval)

        raise TimeoutError(f"Export {export_uuid} did not complete in time")


# Register
registry.register("tenable", TenableConnector)
