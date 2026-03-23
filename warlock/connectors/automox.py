"""Automox connector — Layer 1 implementation for MDM / Patch Management.

Collects server inventory, policy status, and patch data from the Automox API.
Uses Automox REST API via httpx with API key authentication.
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

AUTOMOX_BASE_URL = "https://console.automox.com"

AUTOMOX_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/servers", "automox_servers", {"limit": "500", "page": "0"}),
    ("/api/policies", "automox_policies", {"limit": "500", "page": "0"}),
    ("/api/patches", "automox_patches", {"limit": "500", "page": "0"}),
]


class AutomoxConnector(BaseConnector):
    """Collects MDM/patch compliance telemetry from the Automox API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("AUTOMOX_API_KEY"):
            errors.append("AUTOMOX_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("AUTOMOX_API_KEY")
            base_url = self.config.settings.get("base_url", AUTOMOX_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/servers",
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
            source="automox",
            source_type=SourceType.MDM,
            provider="automox",
        )

        token = self.get_secret("AUTOMOX_API_KEY")
        base_url = self.config.settings.get("base_url", AUTOMOX_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in AUTOMOX_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="automox",
                            source_type=SourceType.MDM,
                            provider="automox",
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
                    log.debug("Automox %s failed: %s", endpoint, e)
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
registry.register("automox", AutomoxConnector)
