"""Nightfall AI connector — collects DLP scan results, policies, and alerts."""

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

NIGHTFALL_BASE_URL = "https://api.nightfall.ai"

NIGHTFALL_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/v3/scans", "nightfall_scans", {"pageSize": "100"}),
    ("/v3/policies", "nightfall_policies", {"pageSize": "100"}),
    ("/v3/alerts", "nightfall_alerts", {"pageSize": "100"}),
]


class NightfallConnector(BaseConnector):
    """Collects DLP findings and policy metadata from Nightfall AI."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("NIGHTFALL_API_KEY"):
            errors.append("NIGHTFALL_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            api_key = self.get_secret("NIGHTFALL_API_KEY")
            base_url = self.config.settings.get("base_url", NIGHTFALL_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v3/policies",
                headers=self._headers(api_key),
                params={"pageSize": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 204)
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="nightfall",
            source_type=SourceType.DLP,
            provider="nightfall",
        )

        api_key = self.get_secret("NIGHTFALL_API_KEY")
        base_url = self.config.settings.get("base_url", NIGHTFALL_BASE_URL)
        headers = self._headers(api_key)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in NIGHTFALL_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="nightfall",
                            source_type=SourceType.DLP,
                            provider="nightfall",
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
                    log.debug("Nightfall %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, api_key: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Paginate Nightfall cursor-based pagination."""
        all_items: list = []
        current_params = dict(params)

        while True:
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            # Nightfall returns items under various keys depending on endpoint
            items = (
                body.get("data")
                or body.get("scans")
                or body.get("policies")
                or body.get("alerts")
                or []
            )
            all_items.extend(items)

            next_cursor = body.get("nextPageToken") or body.get("cursor")
            if not next_cursor or not items:
                break
            current_params["pageToken"] = next_cursor

        return all_items


registry.register("nightfall", NightfallConnector)
