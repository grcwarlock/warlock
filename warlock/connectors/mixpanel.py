"""Mixpanel connector — Layer 1 implementation for ANALYTICS.

Collects data from the Mixpanel API.
Uses Bearer token authentication via MIXPANEL_API_SECRET.
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

MIXPANEL_BASE_URL = "https://mixpanel.com/api/2.0"

MIXPANEL_ENDPOINTS: list[tuple[str, str]] = [
    ("/engage", "mixpanel_users"),
    ("/jql", "mixpanel_events"),
]


class MixpanelConnector(BaseConnector):
    """Collects compliance telemetry from the Mixpanel API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("MIXPANEL_API_SECRET"):
            errors.append("MIXPANEL_API_SECRET env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("MIXPANEL_API_SECRET")
            base_url = self.config.settings.get("base_url", MIXPANEL_BASE_URL)
            resp = httpx.get(
                base_url,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
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
            source="mixpanel",
            source_type=SourceType.ANALYTICS,
            provider="mixpanel",
        )

        token = self.get_secret("MIXPANEL_API_SECRET")
        base_url = self.config.settings.get("base_url", MIXPANEL_BASE_URL)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type in MIXPANEL_ENDPOINTS:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    data = resp.json()
                    items = (
                        data
                        if isinstance(data, list)
                        else data.get("data", data.get("results", data.get("items", [data])))
                    )
                    result.events.append(
                        RawEventData(
                            source="mixpanel",
                            source_type=SourceType.ANALYTICS,
                            provider="mixpanel",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "response": items,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Mixpanel %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result


# Register
registry.register("mixpanel", MixpanelConnector)
