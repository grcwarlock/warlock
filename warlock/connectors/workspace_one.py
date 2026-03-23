"""VMware Workspace ONE connector — Layer 1 implementation for MDM.

Collects devices, profiles, and apps from VMware Workspace ONE UEM REST APIs.
Uses API key authentication.
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

WORKSPACE_ONE_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/mdm/devices/search", "workspace_one_devices", {"pagesize": "100", "page": "0"}),
    ("/api/mdm/profiles", "workspace_one_profiles", {"pagesize": "100", "page": "0"}),
    ("/api/mdm/apps", "workspace_one_apps", {"pagesize": "100", "page": "0"}),
]


class WorkspaceOneConnector(BaseConnector):
    """Collects compliance telemetry from VMware Workspace ONE UEM APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("WORKSPACE_ONE_API_KEY"):
            errors.append("WORKSPACE_ONE_API_KEY env var is not set")
        if not self.config.settings.get("base_url"):
            errors.append(
                "settings.base_url is required for Workspace ONE (e.g. https://as###.awmdm.com)"
            )
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.config.settings.get("base_url", "")
            api_key = self.get_secret("WORKSPACE_ONE_API_KEY")
            resp = httpx.get(
                f"{base_url}/api/mdm/devices/search",
                headers=self._headers(api_key),
                params={"pagesize": "1", "page": "0"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="workspace_one",
            source_type=SourceType.MDM,
            provider="workspace_one",
        )

        base_url = self.config.settings.get("base_url", "")
        api_key = self.get_secret("WORKSPACE_ONE_API_KEY")
        headers = self._headers(api_key)

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type, params in WORKSPACE_ONE_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="workspace_one",
                            source_type=SourceType.MDM,
                            provider="workspace_one",
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
                    log.debug("Workspace ONE %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, api_key: str) -> dict[str, str]:
        return {
            "aw-tenant-code": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow Workspace ONE page-based pagination."""
        all_items: list = []
        current_params = dict(params)
        page = int(current_params.get("page", 0))
        page_size = int(current_params.get("pagesize", 100))

        while True:
            current_params["page"] = str(page)
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            # Workspace ONE wraps results in various keys
            items = body.get(
                "Devices", body.get("profiles", body.get("apps", body.get("Result", [])))
            )
            if not isinstance(items, list):
                items = []
            all_items.extend(items)

            total = body.get("Total", body.get("TotalResults", 0))
            if len(all_items) >= total or len(items) < page_size:
                break
            page += 1

        return all_items


# Register
registry.register("workspace_one", WorkspaceOneConnector)
