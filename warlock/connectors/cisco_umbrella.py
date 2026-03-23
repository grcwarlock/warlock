"""Cisco Umbrella connector — Layer 1 implementation for NETWORK.

Collects roaming computers, policies, and destination lists from Cisco Umbrella
Management APIs. Uses API key / API secret for authentication.
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

UMBRELLA_BASE_URL = "https://api.umbrella.com"

# (path_template, event_type, params)
UMBRELLA_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/v2/organizations/{org}/roamingcomputers", "umbrella_roaming_computers", {"limit": "100", "page": "1"}),
    ("/v2/organizations/{org}/policies", "umbrella_policies", {"limit": "100", "page": "1"}),
    ("/v2/organizations/{org}/destinationlists", "umbrella_destination_lists", {"limit": "100", "page": "1"}),
]


class CiscoUmbrellaConnector(BaseConnector):
    """Collects compliance telemetry from Cisco Umbrella Management APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("UMBRELLA_API_KEY"):
            errors.append("UMBRELLA_API_KEY env var is not set")
        if not self.get_secret("UMBRELLA_API_SECRET"):
            errors.append("UMBRELLA_API_SECRET env var is not set")
        if not self.config.settings.get("org_id"):
            errors.append("settings.org_id is required for Cisco Umbrella")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            api_key = self.get_secret("UMBRELLA_API_KEY")
            api_secret = self.get_secret("UMBRELLA_API_SECRET")
            org_id = self.config.settings.get("org_id", "")
            base_url = self.config.settings.get("base_url", UMBRELLA_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v2/organizations/{org_id}/policies",
                auth=(api_key, api_secret),
                params={"limit": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="cisco_umbrella",
            source_type=SourceType.NETWORK,
            provider="cisco_umbrella",
        )

        org_id = self.config.settings.get("org_id", "")
        base_url = self.config.settings.get("base_url", UMBRELLA_BASE_URL)
        api_key = self.get_secret("UMBRELLA_API_KEY")
        api_secret = self.get_secret("UMBRELLA_API_SECRET")

        client = httpx.Client(
            base_url=base_url,
            auth=(api_key, api_secret),
            timeout=self.config.timeout_seconds,
        )

        try:
            for path_template, event_type, params in UMBRELLA_ENDPOINTS:
                endpoint = path_template.format(org=org_id)
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="cisco_umbrella",
                            source_type=SourceType.NETWORK,
                            provider="cisco_umbrella",
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
                    log.debug("Cisco Umbrella %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow Umbrella page-based pagination."""
        all_items: list = []
        current_params = dict(params)
        page = int(current_params.get("page", 1))

        while True:
            current_params["page"] = str(page)
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            # Umbrella wraps results under 'data'
            items = body.get("data", [])
            if not isinstance(items, list):
                items = []
            all_items.extend(items)

            meta = body.get("meta", {})
            total = meta.get("total", len(all_items))
            if len(all_items) >= total or not items:
                break
            page += 1

        return all_items


# Register
registry.register("cisco_umbrella", CiscoUmbrellaConnector)
