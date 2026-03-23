"""Zoom connector — Layer 1 implementation for COLLABORATION.

Collects user accounts, meetings inventory, and daily usage reports via Zoom API v2.
Uses JWT Bearer token authentication.
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

ZOOM_BASE_URL = "https://api.zoom.us"

ZOOM_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/v2/users", "zoom_users", {"status": "active", "page_size": "300"}),
    ("/v2/meetings", "zoom_meetings", {"type": "scheduled", "page_size": "300"}),
    ("/v2/report/daily", "zoom_daily_report", {}),
]


class ZoomConnector(BaseConnector):
    """Collects compliance telemetry from Zoom REST APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("ZOOM_JWT_TOKEN"):
            errors.append("ZOOM_JWT_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("ZOOM_JWT_TOKEN")
            base_url = self.config.settings.get("base_url", ZOOM_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v2/users/me",
                headers=self._headers(token),
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
            source="zoom",
            source_type=SourceType.COLLABORATION,
            provider="zoom",
        )

        token = self.get_secret("ZOOM_JWT_TOKEN")
        base_url = self.config.settings.get("base_url", ZOOM_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in ZOOM_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="zoom",
                            source_type=SourceType.COLLABORATION,
                            provider="zoom",
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
                    log.debug("Zoom %s failed: %s", endpoint, e)
                    result.errors.append(f"{event_type}: {e}")
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

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow Zoom next_page_token-based pagination."""
        all_items: list = []
        current_params = dict(params)

        # Determine the response collection key from endpoint
        _key_map = {
            "/v2/users": "users",
            "/v2/meetings": "meetings",
            "/v2/report/daily": "dates",
        }
        response_key = next((v for k, v in _key_map.items() if endpoint.startswith(k)), "results")

        while True:
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()
            all_items.extend(body.get(response_key, []))

            next_token = body.get("next_page_token", "")
            if not next_token:
                break
            current_params["next_page_token"] = next_token

        return all_items


# Register
registry.register("zoom", ZoomConnector)
