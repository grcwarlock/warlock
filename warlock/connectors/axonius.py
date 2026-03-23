"""Axonius connector — Layer 1 implementation for CUSTOM asset aggregation.

Collects device assets, user assets, and adapter information.
Uses Axonius REST API v2 via httpx with API key/secret authentication.
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

# Endpoint → (event_type, params) mapping
AXONIUS_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v2/devices", "axonius_devices", {"limit": "100", "skip": "0"}),
    ("/api/v2/users", "axonius_users", {"limit": "100", "skip": "0"}),
    ("/api/v2/adapters", "axonius_adapters", {}),
]


class AxoniusConnector(BaseConnector):
    """Collects device and user asset data from Axonius REST APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("AXONIUS_API_KEY"):
            errors.append("AXONIUS_API_KEY env var is not set")
        if not self.get_secret("AXONIUS_API_SECRET"):
            errors.append("AXONIUS_API_SECRET env var is not set")
        if not self.config.settings.get("base_url"):
            errors.append(
                "'base_url' must be set in connector settings (e.g. 'https://mycompany.axonius.com')"
            )
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.config.settings.get("base_url", "")
            headers = self._headers()
            resp = httpx.get(
                f"{base_url}/api/v2/system/info",
                headers=headers,
                timeout=self.config.timeout_seconds,
                verify=False,
            )
            return resp.status_code in (200, 204)
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="axonius",
            source_type=SourceType.CUSTOM,
            provider="axonius",
        )

        base_url = self.config.settings.get("base_url", "")
        headers = self._headers()

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
            verify=False,
        )

        try:
            for endpoint, event_type, params in AXONIUS_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params, event_type)
                    result.events.append(
                        RawEventData(
                            source="axonius",
                            source_type=SourceType.CUSTOM,
                            provider="axonius",
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
                    log.debug("Axonius %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self) -> dict[str, str]:
        api_key = self.get_secret("AXONIUS_API_KEY")
        api_secret = self.get_secret("AXONIUS_API_SECRET")
        return {
            "api-key": api_key,
            "api-secret": api_secret,
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str, params: dict, event_type: str) -> list:
        """Follow Axonius skip/limit pagination."""
        all_items: list = []

        if not params:
            # Non-paginated endpoint (e.g. adapters)
            resp = client.get(endpoint)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()
            data = body.get("data", body) if isinstance(body, dict) else body
            if isinstance(data, list):
                return data
            return [data]

        limit = int(params.get("limit", 100))
        skip = 0
        current_params = dict(params)

        while True:
            current_params["skip"] = str(skip)
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            items = body.get("data", body.get("assets", []))
            if isinstance(items, list):
                all_items.extend(items)
            elif isinstance(items, dict):
                all_items.append(items)

            if len(items) < limit:
                break
            skip += limit

        return all_items


# Register
registry.register("axonius", AxoniusConnector)
