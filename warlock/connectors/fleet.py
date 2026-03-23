"""Fleet connector — Layer 1 implementation for MDM / Osquery Fleet Management.

Collects host inventory, query results, and policy compliance from the Fleet API.
Uses Fleet REST API v1 via httpx with API token authentication.
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

FLEET_BASE_URL = "https://api.fleetdm.com"

FLEET_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/fleet/hosts", "fleet_hosts", {"per_page": "100", "page": "0"}),
    ("/api/v1/fleet/queries", "fleet_queries", {"per_page": "100", "page": "0"}),
    ("/api/v1/fleet/policies", "fleet_policies", {"per_page": "100", "page": "0"}),
]


class FleetConnector(BaseConnector):
    """Collects MDM/endpoint compliance telemetry from the Fleet API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("FLEET_API_TOKEN"):
            errors.append("FLEET_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("FLEET_API_TOKEN")
            base_url = self.config.settings.get("base_url", FLEET_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1/fleet/hosts",
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
            source="fleet",
            source_type=SourceType.MDM,
            provider="fleet",
        )

        token = self.get_secret("FLEET_API_TOKEN")
        base_url = self.config.settings.get("base_url", FLEET_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in FLEET_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="fleet",
                            source_type=SourceType.MDM,
                            provider="fleet",
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
                    log.debug("Fleet %s failed: %s", endpoint, e)
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
registry.register("fleet", FleetConnector)
