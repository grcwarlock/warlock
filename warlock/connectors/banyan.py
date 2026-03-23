"""Banyan Security connector — Layer 1 implementation for Network / Zero Trust.

Collects services, policies, and device inventory from the Banyan Security API.
Uses Banyan REST API v1 via httpx with API key authentication.
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

BANYAN_BASE_URL = "https://net.banyanops.com"

BANYAN_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/services", "banyan_services", {"count": "100"}),
    ("/api/v1/policies", "banyan_policies", {"count": "100"}),
    ("/api/v1/devices", "banyan_devices", {"count": "100"}),
]


class BanyanConnector(BaseConnector):
    """Collects compliance telemetry from the Banyan Security Zero Trust API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("BANYAN_API_KEY"):
            errors.append("BANYAN_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("BANYAN_API_KEY")
            base_url = self.config.settings.get("base_url", BANYAN_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1/services",
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
            source="banyan",
            source_type=SourceType.NETWORK,
            provider="banyan",
        )

        token = self.get_secret("BANYAN_API_KEY")
        base_url = self.config.settings.get("base_url", BANYAN_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in BANYAN_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="banyan",
                            source_type=SourceType.NETWORK,
                            provider="banyan",
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
                    log.debug("Banyan %s failed: %s", endpoint, e)
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
registry.register("banyan", BanyanConnector)
