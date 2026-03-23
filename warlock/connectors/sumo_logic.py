"""Sumo Logic connector — Layer 1 implementation for SIEM.

Collects collectors, search jobs, and dashboards from Sumo Logic REST APIs.
Uses access ID / access key basic authentication.
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

SUMO_BASE_URL = "https://api.sumologic.com"

SUMO_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/collectors", "sumo_collectors", {"limit": "100"}),
    ("/api/v1/dashboards", "sumo_dashboards", {"limit": "100"}),
]


class SumoLogicConnector(BaseConnector):
    """Collects compliance telemetry from Sumo Logic REST APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("SUMO_ACCESS_ID"):
            errors.append("SUMO_ACCESS_ID env var is not set")
        if not self.get_secret("SUMO_ACCESS_KEY"):
            errors.append("SUMO_ACCESS_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.config.settings.get("base_url", SUMO_BASE_URL)
            access_id = self.get_secret("SUMO_ACCESS_ID")
            access_key = self.get_secret("SUMO_ACCESS_KEY")
            resp = httpx.get(
                f"{base_url}/api/v1/collectors",
                auth=(access_id, access_key),
                params={"limit": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="sumo_logic",
            source_type=SourceType.SIEM,
            provider="sumo_logic",
        )

        base_url = self.config.settings.get("base_url", SUMO_BASE_URL)
        access_id = self.get_secret("SUMO_ACCESS_ID")
        access_key = self.get_secret("SUMO_ACCESS_KEY")

        client = httpx.Client(
            base_url=base_url,
            auth=(access_id, access_key),
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in SUMO_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="sumo_logic",
                            source_type=SourceType.SIEM,
                            provider="sumo_logic",
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
                    log.debug("Sumo Logic %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow Sumo Logic token-based pagination."""
        all_items: list = []
        current_params = dict(params)

        while True:
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            # Sumo Logic wraps data under 'collectors', 'dashboards', etc.
            items: list = []
            for key in ("collectors", "dashboards", "searchJobs", "data"):
                if key in body and isinstance(body[key], list):
                    items = body[key]
                    break
            all_items.extend(items)

            next_token = body.get("next")
            if not next_token or not items:
                break
            current_params["token"] = next_token

        return all_items


# Register
registry.register("sumo_logic", SumoLogicConnector)
