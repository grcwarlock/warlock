"""Trivy connector — Layer 1 implementation for vulnerability scanning.

Collects container scan results, IaC misconfigurations, secret findings,
and SBOM data via the Trivy Server API or by parsing local JSON output.
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


class TrivyConnector(BaseConnector):
    """Collects compliance telemetry from Trivy Server API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[trivy]")
        if not self.get_secret("WLK_TRIVY_SERVER_URL"):
            errors.append("WLK_TRIVY_SERVER_URL not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get("/healthz")
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="trivy",
            source_type=SourceType.SCANNER,
            provider="trivy",
        )

        client = self._client()

        self._collect_container_vulns(client, result)
        self._collect_iac_misconfigs(client, result)
        self._collect_secrets(client, result)
        self._collect_sbom(client, result)

        result.complete()
        return result

    # -- Client helper --

    def _client(self) -> httpx.Client:
        server_url = self.get_secret("WLK_TRIVY_SERVER_URL").rstrip("/")
        token = self.get_secret("WLK_TRIVY_TOKEN")
        headers = {"Accept": "application/json"}
        if token:
            headers["Trivy-Token"] = token
        return httpx.Client(
            base_url=server_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

    # -- Event helper --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="trivy",
            source_type=SourceType.SCANNER,
            provider="trivy",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_container_vulns(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect container image vulnerability scan results."""
        try:
            resp = client.get("/api/v1/scan/results", params={"type": "os"})
            resp.raise_for_status()
            body = resp.json()
            results = body.get("Results", body.get("results", []))
            result.events.append(self._raw_event("trivy_container_vulns", {"results": results}))
        except Exception as e:
            log.debug("Trivy container vulns collection failed: %s", e)
            result.errors.append(f"trivy_container_vulns: {e}")

    def _collect_iac_misconfigs(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect IaC misconfiguration scan results."""
        try:
            resp = client.get("/api/v1/scan/results", params={"type": "config"})
            resp.raise_for_status()
            body = resp.json()
            results = body.get("Results", body.get("results", []))
            result.events.append(self._raw_event("trivy_iac_misconfigs", {"results": results}))
        except Exception as e:
            log.debug("Trivy IaC misconfigs collection failed: %s", e)
            result.errors.append(f"trivy_iac_misconfigs: {e}")

    def _collect_secrets(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect secret detection scan results."""
        try:
            resp = client.get("/api/v1/scan/results", params={"type": "secret"})
            resp.raise_for_status()
            body = resp.json()
            results = body.get("Results", body.get("results", []))
            result.events.append(self._raw_event("trivy_secrets", {"results": results}))
        except Exception as e:
            log.debug("Trivy secrets collection failed: %s", e)
            result.errors.append(f"trivy_secrets: {e}")

    def _collect_sbom(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect SBOM (Software Bill of Materials) data."""
        try:
            resp = client.get("/api/v1/sbom", params={"format": "cyclonedx"})
            resp.raise_for_status()
            body = resp.json()
            components = body.get("components", body.get("Components", []))
            result.events.append(self._raw_event("trivy_sbom", {"components": components}))
        except Exception as e:
            log.debug("Trivy SBOM collection failed: %s", e)
            result.errors.append(f"trivy_sbom: {e}")


# Register
registry.register("trivy", TrivyConnector)
