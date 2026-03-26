"""Scaleway connector — Layer 1 implementation for CLOUD.

Collects data from the Scaleway API.
Uses Bearer token authentication via SCALEWAY_API_KEY.
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

SCALEWAY_BASE_URL = "https://api.scaleway.com"

SCALEWAY_ENDPOINTS: list[tuple[str, str]] = [
    ("/instance/v1/servers", "scaleway_instances"),
    ("/vpc/v2/vpcs", "scaleway_vpcs"),
    ("/iam/v1alpha1/api-keys", "scaleway_api_keys"),
]


class ScalewayConnector(BaseConnector):
    """Collects compliance telemetry from the Scaleway API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("SCALEWAY_API_KEY"):
            errors.append("SCALEWAY_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("SCALEWAY_API_KEY")
            base_url = self.config.settings.get("base_url", SCALEWAY_BASE_URL)
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
            source="scaleway",
            source_type=SourceType.CLOUD,
            provider="scaleway",
        )

        token = self.get_secret("SCALEWAY_API_KEY")
        base_url = self.config.settings.get("base_url", SCALEWAY_BASE_URL)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type in SCALEWAY_ENDPOINTS:
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
                            source="scaleway",
                            source_type=SourceType.CLOUD,
                            provider="scaleway",
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
                    log.debug("Scaleway %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result


# Register
registry.register("scaleway", ScalewayConnector)
