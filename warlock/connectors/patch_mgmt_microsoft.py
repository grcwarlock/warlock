"""Microsoft Patch Management connector — Layer 1 implementation for MDM.

Collects device compliance policies and managed device patch status via
Microsoft Graph API using Bearer token authentication.
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

PATCH_MGMT_MICROSOFT_BASE_URL = "https://graph.microsoft.com/v1.0"

ENDPOINTS: list[tuple[str, str, dict]] = [
    (
        "/deviceManagement/deviceCompliancePolicies",
        "microsoft_compliance_policies",
        {"$top": "100"},
    ),
    (
        "/deviceManagement/managedDevices",
        "microsoft_managed_devices",
        {
            "$top": "100",
            "$select": "id,deviceName,operatingSystem,osVersion,complianceState,lastSyncDateTime,managedDeviceOwnerType",
        },
    ),
]


class MicrosoftPatchMgmtConnector(BaseConnector):
    """Collects patch management telemetry from Microsoft Graph API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("MICROSOFT_GRAPH_TOKEN"):
            errors.append("MICROSOFT_GRAPH_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("MICROSOFT_GRAPH_TOKEN")
            base_url = self.config.settings.get("base_url", PATCH_MGMT_MICROSOFT_BASE_URL)
            resp = httpx.get(
                f"{base_url}/deviceManagement/deviceCompliancePolicies",
                headers=self._headers(token),
                params={"$top": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="patch_mgmt_microsoft",
            source_type=SourceType.MDM,
            provider="patch_mgmt_microsoft",
        )

        token = self.get_secret("MICROSOFT_GRAPH_TOKEN")
        base_url = self.config.settings.get("base_url", PATCH_MGMT_MICROSOFT_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="patch_mgmt_microsoft",
                            source_type=SourceType.MDM,
                            provider="patch_mgmt_microsoft",
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
                    log.debug("Microsoft Patch Mgmt %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow Microsoft Graph OData nextLink pagination."""

        all_items: list = []
        current_url: str | None = endpoint
        current_params: dict | None = params

        while current_url:
            if current_params is not None:
                resp = client.get(current_url, params=current_params)  # type: ignore[attr-defined]
            else:
                resp = client.get(current_url)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            items = body.get("value", [])
            all_items.extend(items)

            next_link = body.get("@odata.nextLink")
            if next_link:
                # nextLink is a full URL — switch to absolute mode
                current_url = next_link
                current_params = None
            else:
                break

        return all_items


# Register
registry.register("patch_mgmt_microsoft", MicrosoftPatchMgmtConnector)
