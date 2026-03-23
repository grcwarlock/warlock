"""Rubrik Security Cloud connector — Layer 1 implementation for DLP.

Collects data classification, anomaly detection, and sensitive file findings
from the Rubrik Security Cloud API.
Uses Rubrik REST API v1 via httpx with API token authentication.
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

RUBRIK_SECURITY_BASE_URL = "https://api.rubrik.com"

RUBRIK_SECURITY_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/data-classification", "rubrik_security_data_classification", {"limit": "100"}),
    ("/api/v1/anomalies", "rubrik_security_anomalies", {"limit": "100"}),
    ("/api/v1/sensitive-files", "rubrik_security_sensitive_files", {"limit": "100"}),
]


class RubrikSecurityConnector(BaseConnector):
    """Collects DLP telemetry from the Rubrik Security Cloud API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("RUBRIK_API_TOKEN"):
            errors.append("RUBRIK_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("RUBRIK_API_TOKEN")
            base_url = self.config.settings.get("base_url", RUBRIK_SECURITY_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1/anomalies",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="rubrik_security",
            source_type=SourceType.DLP,
            provider="rubrik_security",
        )

        token = self.get_secret("RUBRIK_API_TOKEN")
        base_url = self.config.settings.get("base_url", RUBRIK_SECURITY_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in RUBRIK_SECURITY_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="rubrik_security",
                            source_type=SourceType.DLP,
                            provider="rubrik_security",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Rubrik Security %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


# Register
registry.register("rubrik_security", RubrikSecurityConnector)
