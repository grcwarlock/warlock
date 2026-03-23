"""Vanta connector — Layer 1 implementation for GRC.

Collects resources and test results from Vanta REST APIs.
Uses API key authentication via Bearer token.
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

VANTA_BASE_URL = "https://api.vanta.com"

VANTA_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/v1/resources/list", "vanta_resources", {"pageSize": "100"}),
    ("/v1/results/list", "vanta_results", {"pageSize": "100"}),
]


class VantaConnector(BaseConnector):
    """Collects compliance telemetry from Vanta REST APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("VANTA_API_KEY"):
            errors.append("VANTA_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            api_key = self.get_secret("VANTA_API_KEY")
            base_url = self.config.settings.get("base_url", VANTA_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v1/resources/list",
                headers={"Authorization": f"Bearer {api_key}"},
                params={"pageSize": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="vanta",
            source_type=SourceType.GRC,
            provider="vanta",
        )

        base_url = self.config.settings.get("base_url", VANTA_BASE_URL)
        api_key = self.get_secret("VANTA_API_KEY")
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        client = httpx.Client(base_url=base_url, headers=headers, timeout=self.config.timeout_seconds)

        try:
            for endpoint, event_type, params in VANTA_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="vanta",
                            source_type=SourceType.GRC,
                            provider="vanta",
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
                    log.debug("Vanta %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow Vanta cursor-based pagination."""
        all_items: list = []
        current_params = dict(params)

        while True:
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            items = body.get("results", body.get("data", []))
            if not isinstance(items, list):
                items = []
            all_items.extend(items)

            next_cursor = body.get("pageInfo", {}).get("endCursor")
            has_next = body.get("pageInfo", {}).get("hasNextPage", False)
            if not has_next or not next_cursor:
                break
            current_params["pageCursor"] = next_cursor

        return all_items


# Register
registry.register("vanta", VantaConnector)
