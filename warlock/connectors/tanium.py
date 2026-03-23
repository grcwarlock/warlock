"""Tanium connector — Layer 1 implementation for EDR / Endpoint Management.

Collects endpoint inventory, patch status, and alert data from the Tanium API.
Uses Tanium REST API v2 via httpx with API token authentication.
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

TANIUM_BASE_URL = "https://api.tanium.com"

TANIUM_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v2/endpoints", "tanium_endpoints", {"count": "100", "offset": "0"}),
    ("/api/v2/patches", "tanium_patches", {"count": "100", "offset": "0"}),
    ("/api/v2/alerts", "tanium_alerts", {"count": "100", "offset": "0"}),
]


class TaniumConnector(BaseConnector):
    """Collects EDR/endpoint compliance telemetry from the Tanium API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("TANIUM_API_TOKEN"):
            errors.append("TANIUM_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("TANIUM_API_TOKEN")
            base_url = self.config.settings.get("base_url", TANIUM_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v2/endpoints",
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
            source="tanium",
            source_type=SourceType.EDR,
            provider="tanium",
        )

        token = self.get_secret("TANIUM_API_TOKEN")
        base_url = self.config.settings.get("base_url", TANIUM_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in TANIUM_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="tanium",
                            source_type=SourceType.EDR,
                            provider="tanium",
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
                    log.debug("Tanium %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "session": token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


# Register
registry.register("tanium", TaniumConnector)
