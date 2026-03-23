"""Hetzner connector — Layer 1 implementation for CLOUD.

Collects servers, firewalls, and certificates from the Hetzner Cloud API v1.
Uses Bearer token authentication via HETZNER_API_TOKEN.
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

HETZNER_BASE_URL = "https://api.hetzner.cloud"

HETZNER_ENDPOINTS: list[tuple[str, str]] = [
    ("/v1/servers", "hetzner_servers"),
    ("/v1/firewalls", "hetzner_firewalls"),
    ("/v1/certificates", "hetzner_certificates"),
]


class HetznerConnector(BaseConnector):
    """Collects compliance telemetry from the Hetzner Cloud API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("HETZNER_API_TOKEN"):
            errors.append("HETZNER_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("HETZNER_API_TOKEN")
            base_url = self.config.settings.get("base_url", HETZNER_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v1/datacenters",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="hetzner",
            source_type=SourceType.CLOUD,
            provider="hetzner",
        )

        token = self.get_secret("HETZNER_API_TOKEN")
        base_url = self.config.settings.get("base_url", HETZNER_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in HETZNER_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="hetzner",
                            source_type=SourceType.CLOUD,
                            provider="hetzner",
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
                    log.debug("Hetzner %s failed: %s", endpoint, e)
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

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow Hetzner cursor-based pagination."""
        # Hetzner uses a 'next_cursor' in meta.pagination
        all_items: list = []
        params: dict = {"per_page": 50}

        # Derive the response key from the endpoint path segment
        resource_key = endpoint.lstrip("/").split("/")[-1]  # e.g. "servers"

        while True:
            resp = client.get(endpoint, params=params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()
            items = body.get(resource_key, [])
            all_items.extend(items)

            next_cursor = body.get("meta", {}).get("pagination", {}).get("next_cursor")
            if not next_cursor:
                break
            params["cursor"] = next_cursor

        return all_items


# Register
registry.register("hetzner", HetznerConnector)
