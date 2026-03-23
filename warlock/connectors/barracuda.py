"""Barracuda connector — Layer 1 implementation for NETWORK.

Collects firewalls, threats, and policies from the Barracuda API.
Uses API key authentication via BARRACUDA_API_KEY.
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

BARRACUDA_BASE_URL = "https://api.barracudanetworks.com"

BARRACUDA_ENDPOINTS: list[tuple[str, str]] = [
    ("/v1/firewalls", "barracuda_firewalls"),
    ("/v1/threats", "barracuda_threats"),
    ("/v1/policies", "barracuda_policies"),
]


class BarracudaConnector(BaseConnector):
    """Collects compliance telemetry from the Barracuda Networks API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("BARRACUDA_API_KEY"):
            errors.append("BARRACUDA_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            api_key = self.get_secret("BARRACUDA_API_KEY")
            base_url = self.config.settings.get("base_url", BARRACUDA_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v1/firewalls",
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
            source="barracuda",
            source_type=SourceType.NETWORK,
            provider="barracuda",
        )

        api_key = self.get_secret("BARRACUDA_API_KEY")
        base_url = self.config.settings.get("base_url", BARRACUDA_BASE_URL)
        headers = self._headers(api_key)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in BARRACUDA_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="barracuda",
                            source_type=SourceType.NETWORK,
                            provider="barracuda",
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
                    log.debug("Barracuda %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, api_key: str) -> dict[str, str]:
        return {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow Barracuda offset-based pagination."""
        all_items: list = []
        offset = 0
        limit = 100

        while True:
            resp = client.get(endpoint, params={"offset": offset, "limit": limit})  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            if isinstance(body, list):
                items = body
            else:
                items = body.get("data", body.get("items", []))

            all_items.extend(items)
            if len(items) < limit:
                break
            offset += limit

        return all_items


# Register
registry.register("barracuda", BarracudaConnector)
