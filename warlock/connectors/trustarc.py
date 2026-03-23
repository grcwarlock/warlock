"""TrustArc connector — Layer 1 implementation for GRC / Privacy.

Collects assessment, data inventory, and cookie consent data from the TrustArc API.
Uses TrustArc REST API v1 via httpx with API key authentication.
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

TRUSTARC_BASE_URL = "https://api.trustarc.com"

TRUSTARC_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/assessments", "trustarc_assessments", {"limit": "100", "page": "1"}),
    ("/api/v1/data-inventory", "trustarc_data_inventory", {"limit": "100", "page": "1"}),
    ("/api/v1/cookie-consent", "trustarc_cookie_consent", {"limit": "100", "page": "1"}),
]


class TrustArcConnector(BaseConnector):
    """Collects privacy compliance telemetry from the TrustArc GRC API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("TRUSTARC_API_KEY"):
            errors.append("TRUSTARC_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("TRUSTARC_API_KEY")
            base_url = self.config.settings.get("base_url", TRUSTARC_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1/assessments",
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
            source="trustarc",
            source_type=SourceType.GRC,
            provider="trustarc",
        )

        token = self.get_secret("TRUSTARC_API_KEY")
        base_url = self.config.settings.get("base_url", TRUSTARC_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in TRUSTARC_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="trustarc",
                            source_type=SourceType.GRC,
                            provider="trustarc",
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
                    log.debug("TrustArc %s failed: %s", endpoint, e)
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
registry.register("trustarc", TrustArcConnector)
