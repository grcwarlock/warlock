"""Linode/Akamai connector — Layer 1 implementation for CLOUD.

Collects instances, firewalls, and account events from the Linode API v4.
Uses Bearer token authentication via LINODE_API_TOKEN.
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

LINODE_BASE_URL = "https://api.linode.com"

LINODE_ENDPOINTS: list[tuple[str, str]] = [
    ("/v4/linode/instances", "linode_instances"),
    ("/v4/networking/firewalls", "linode_firewalls"),
    ("/v4/account/events", "linode_events"),
]


class LinodeConnector(BaseConnector):
    """Collects compliance telemetry from the Linode/Akamai Cloud API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("LINODE_API_TOKEN"):
            errors.append("LINODE_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("LINODE_API_TOKEN")
            base_url = self.config.settings.get("base_url", LINODE_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v4/profile",
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
            source="linode",
            source_type=SourceType.CLOUD,
            provider="linode",
        )

        token = self.get_secret("LINODE_API_TOKEN")
        base_url = self.config.settings.get("base_url", LINODE_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in LINODE_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="linode",
                            source_type=SourceType.CLOUD,
                            provider="linode",
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
                    log.debug("Linode %s failed: %s", endpoint, e)
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
        """Follow Linode cursor-based pagination."""
        import httpx

        all_items: list = []
        page = 1

        while True:
            resp = client.get(endpoint, params={"page": page, "page_size": 100})  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()
            items = body.get("data", [])
            all_items.extend(items)
            pages = body.get("pages", 1)
            if page >= pages:
                break
            page += 1

        return all_items


# Register
registry.register("linode", LinodeConnector)
