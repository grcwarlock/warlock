"""Twingate connector — Layer 1 implementation for Network / Zero Trust.

Collects resources, connectors, and user inventory from the Twingate API.
Uses Twingate REST API v5 via httpx with API key authentication.
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

TWINGATE_BASE_URL = "https://api.twingate.com"

TWINGATE_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v5/resources", "twingate_resources", {"page": "1", "per_page": "100"}),
    ("/api/v5/connectors", "twingate_connectors", {"page": "1", "per_page": "100"}),
    ("/api/v5/users", "twingate_users", {"page": "1", "per_page": "100"}),
]


class TwingateConnector(BaseConnector):
    """Collects compliance telemetry from the Twingate Zero Trust network API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("TWINGATE_API_KEY"):
            errors.append("TWINGATE_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("TWINGATE_API_KEY")
            base_url = self.config.settings.get("base_url", TWINGATE_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v5/resources",
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
            source="twingate",
            source_type=SourceType.NETWORK,
            provider="twingate",
        )

        token = self.get_secret("TWINGATE_API_KEY")
        base_url = self.config.settings.get("base_url", TWINGATE_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in TWINGATE_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="twingate",
                            source_type=SourceType.NETWORK,
                            provider="twingate",
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
                    log.debug("Twingate %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "X-API-KEY": token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


# Register
registry.register("twingate", TwingateConnector)
