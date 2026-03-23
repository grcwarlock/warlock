"""ServiceNow CMDB connector — Layer 1 implementation for ITSM.

Collects configuration items, CI relationships, and CI classes from
ServiceNow CMDB via the Table API with Basic authentication.
"""

from __future__ import annotations

import base64
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

# Endpoint → (event_type, params) mapping
SERVICENOW_CMDB_ENDPOINTS: list[tuple[str, str, dict]] = [
    (
        "/api/now/table/cmdb_ci",
        "servicenow_cmdb_cis",
        {"sysparm_limit": "100", "sysparm_offset": "0", "sysparm_fields": "sys_id,name,sys_class_name,operational_status,install_status,ip_address,fqdn,manufacturer,model_id,serial_number"},
    ),
    (
        "/api/now/table/cmdb_rel_ci",
        "servicenow_cmdb_relationships",
        {"sysparm_limit": "100", "sysparm_offset": "0", "sysparm_fields": "sys_id,parent,child,type"},
    ),
    (
        "/api/now/table/cmdb_ci_class",
        "servicenow_cmdb_classes",
        {"sysparm_limit": "100", "sysparm_offset": "0", "sysparm_fields": "sys_id,name,label"},
    ),
]


class ServiceNowCMDBConnector(BaseConnector):
    """Collects CMDB data from ServiceNow Table API."""

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
        if not self.config.settings.get("base_url"):
            errors.append("'base_url' must be set in connector settings (e.g. 'https://myinstance.service-now.com')")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.config.settings.get("base_url", "")
            resp = httpx.get(
                f"{base_url}/api/now/table/sys_user",
                headers=self._headers(),
                params={"sysparm_limit": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="servicenow_cmdb",
            source_type=SourceType.ITSM,
            provider="servicenow_cmdb",
        )

        base_url = self.config.settings.get("base_url", "")
        headers = self._headers()

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in SERVICENOW_CMDB_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="servicenow_cmdb",
                            source_type=SourceType.ITSM,
                            provider="servicenow_cmdb",
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
                    log.debug("ServiceNow CMDB %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self) -> dict[str, str]:
        username = self.get_secret("SERVICENOW_USERNAME")
        password = self.get_secret("SERVICENOW_PASSWORD")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow ServiceNow offset-based pagination."""
        all_items: list = []
        limit = int(params.get("sysparm_limit", 100))
        offset = 0
        current_params = dict(params)

        while True:
            current_params["sysparm_offset"] = str(offset)
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            items = body.get("result", [])
            if isinstance(items, list):
                all_items.extend(items)
            elif isinstance(items, dict):
                all_items.append(items)

            if len(items) < limit:
                break
            offset += limit

        return all_items


# Register
registry.register("servicenow_cmdb", ServiceNowCMDBConnector)
