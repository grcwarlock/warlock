"""PlexTrac connector — Layer 1 implementation for CUSTOM (pentest/GRC).

Collects clients, reports, and findings from the PlexTrac API v2.
Uses API key authentication via PLEXTRAC_API_KEY.
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

PLEXTRAC_BASE_URL = "https://app.plextrac.com"

PLEXTRAC_ENDPOINTS: list[tuple[str, str]] = [
    ("/api/v2/clients", "plextrac_clients"),
    ("/api/v2/reports", "plextrac_reports"),
    ("/api/v2/findings", "plextrac_findings"),
]


class PlexTracConnector(BaseConnector):
    """Collects compliance and pentest telemetry from the PlexTrac API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("PLEXTRAC_API_KEY"):
            errors.append("PLEXTRAC_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            api_key = self.get_secret("PLEXTRAC_API_KEY")
            base_url = self.config.settings.get("base_url", PLEXTRAC_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v2/clients",
                headers=self._headers(api_key),
                params={"limit": 1},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="plextrac",
            source_type=SourceType.CUSTOM,
            provider="plextrac",
        )

        api_key = self.get_secret("PLEXTRAC_API_KEY")
        base_url = self.config.settings.get("base_url", PLEXTRAC_BASE_URL)
        headers = self._headers(api_key)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in PLEXTRAC_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="plextrac",
                            source_type=SourceType.CUSTOM,
                            provider="plextrac",
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
                    log.debug("PlexTrac %s failed: %s", endpoint, e)
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

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow PlexTrac page-based pagination."""
        all_items: list = []
        page = 1
        limit = 100

        while True:
            resp = client.get(endpoint, params={"page": page, "limit": limit})  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            if isinstance(body, list):
                items = body
            else:
                items = body.get("data", body.get("items", []))

            all_items.extend(items)
            if len(items) < limit:
                break
            page += 1

        return all_items


# Register
registry.register("plextrac", PlexTracConnector)
