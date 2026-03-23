"""ServiceNow GRC connector — collects GRC policies, controls, and risks via Table API."""

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

SERVICENOW_GRC_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/now/table/sn_grc_policy", "servicenow_grc_policies", {"sysparm_limit": "200"}),
    ("/api/now/table/sn_grc_control", "servicenow_grc_controls", {"sysparm_limit": "200"}),
    ("/api/now/table/sn_grc_risk", "servicenow_grc_risks", {"sysparm_limit": "200"}),
]


class ServiceNowGRCConnector(BaseConnector):
    """Collects GRC compliance telemetry from ServiceNow Table API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("SERVICENOW_USERNAME"):
            errors.append("SERVICENOW_USERNAME env var is not set")
        if not self.get_secret("SERVICENOW_PASSWORD"):
            errors.append("SERVICENOW_PASSWORD env var is not set")
        if not self.config.settings.get("instance_url"):
            errors.append("settings.instance_url is required (e.g. https://myinstance.service-now.com)")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            instance_url = self.config.settings.get("instance_url", "")
            username = self.get_secret("SERVICENOW_USERNAME")
            password = self.get_secret("SERVICENOW_PASSWORD")
            resp = httpx.get(
                f"{instance_url}/api/now/table/sys_user",
                auth=(username, password),
                params={"sysparm_limit": "1"},
                headers={"Accept": "application/json"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="servicenow_grc",
            source_type=SourceType.ITSM,
            provider="servicenow_grc",
        )

        instance_url = self.config.settings.get("instance_url", "")
        username = self.get_secret("SERVICENOW_USERNAME")
        password = self.get_secret("SERVICENOW_PASSWORD")
        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        client = httpx.Client(
            auth=(username, password),
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in SERVICENOW_GRC_ENDPOINTS:
                try:
                    data = self._paginate(client, f"{instance_url}{endpoint}", params)
                    result.events.append(
                        RawEventData(
                            source="servicenow_grc",
                            source_type=SourceType.ITSM,
                            provider="servicenow_grc",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "instance_url": instance_url,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("ServiceNow GRC %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _paginate(self, client: object, url: str, params: dict) -> list:
        """Paginate ServiceNow Table API using offset/limit."""
        import httpx

        all_items: list = []
        limit = int(params.get("sysparm_limit", 200))
        offset = 0
        current_params = dict(params)

        while True:
            current_params["sysparm_offset"] = str(offset)
            resp = client.get(url, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()
            items = body.get("result", [])
            all_items.extend(items)
            if len(items) < limit:
                break
            offset += limit

        return all_items


registry.register("servicenow_grc", ServiceNowGRCConnector)
