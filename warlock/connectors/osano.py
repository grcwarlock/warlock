"""Osano connector — Layer 1 implementation for Privacy / Consent Management.

Collects consent records, data maps, and vendor assessments from the Osano API.
Uses Osano REST API v1 via httpx with API key authentication.
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

OSANO_BASE_URL = "https://api.osano.com"

OSANO_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/consent-records", "osano_consent_records", {"limit": "100", "offset": "0"}),
    ("/api/v1/data-maps", "osano_data_maps", {"limit": "100", "offset": "0"}),
    ("/api/v1/vendor-assessments", "osano_vendor_assessments", {"limit": "100", "offset": "0"}),
]


class OsanoConnector(BaseConnector):
    """Collects privacy compliance telemetry from the Osano API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("OSANO_API_KEY"):
            errors.append("OSANO_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("OSANO_API_KEY")
            base_url = self.config.settings.get("base_url", OSANO_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1/consent-records",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="osano",
            source_type=SourceType.CUSTOM,
            provider="osano",
        )

        token = self.get_secret("OSANO_API_KEY")
        base_url = self.config.settings.get("base_url", OSANO_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in OSANO_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="osano",
                            source_type=SourceType.CUSTOM,
                            provider="osano",
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
                    log.debug("Osano %s failed: %s", endpoint, e)
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
registry.register("osano", OsanoConnector)
