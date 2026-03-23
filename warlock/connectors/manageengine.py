"""ManageEngine connector — Layer 1 implementation for ITSM.

Collects requests, assets, and changes from the ManageEngine ServiceDesk Plus API v3.
Uses API key authentication via MANAGEENGINE_API_KEY.
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

MANAGEENGINE_BASE_URL = "https://helpdesk.example.com"

MANAGEENGINE_ENDPOINTS: list[tuple[str, str]] = [
    ("/api/v3/requests", "manageengine_requests"),
    ("/api/v3/assets", "manageengine_assets"),
    ("/api/v3/changes", "manageengine_changes"),
]


class ManageEngineConnector(BaseConnector):
    """Collects compliance telemetry from the ManageEngine ServiceDesk Plus API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("MANAGEENGINE_API_KEY"):
            errors.append("MANAGEENGINE_API_KEY env var is not set")
        if not self.config.settings.get("base_url"):
            errors.append(
                "base_url must be set in connector settings (e.g. https://helpdesk.example.com)"
            )
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            api_key = self.get_secret("MANAGEENGINE_API_KEY")
            base_url = self.config.settings.get("base_url", MANAGEENGINE_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v3/requests",
                headers=self._headers(api_key),
                params={"list_info": '{"row_count":1}'},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="manageengine",
            source_type=SourceType.ITSM,
            provider="manageengine",
        )

        api_key = self.get_secret("MANAGEENGINE_API_KEY")
        base_url = self.config.settings.get("base_url", MANAGEENGINE_BASE_URL)
        headers = self._headers(api_key)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in MANAGEENGINE_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="manageengine",
                            source_type=SourceType.ITSM,
                            provider="manageengine",
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
                    log.debug("ManageEngine %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, api_key: str) -> dict[str, str]:
        return {
            "authtoken": api_key,
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow ManageEngine list_info pagination."""
        import json

        all_items: list = []
        start = 1
        row_count = 100
        resource_key = endpoint.lstrip("/").split("/")[-1]  # "requests", "assets", "changes"

        while True:
            list_info = json.dumps({"start_index": start, "row_count": row_count})
            resp = client.get(endpoint, params={"list_info": list_info})  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            items = body.get(resource_key, [])
            all_items.extend(items)

            response_info = body.get("list_info", {})
            has_more = response_info.get("has_more_rows", False)
            if not has_more or len(items) < row_count:
                break
            start += row_count

        return all_items


# Register
registry.register("manageengine", ManageEngineConnector)
