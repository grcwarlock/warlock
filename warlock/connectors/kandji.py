"""Kandji connector — Layer 1 implementation for MDM / endpoint management.

Collects devices (OS version, encryption, firewall), blueprints,
library items, and users via the Kandji API v1.
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

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


class KandjiConnector(BaseConnector):
    """Collects compliance telemetry from Kandji API v1."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[kandji]")
        if not self.get_secret("WLK_KANDJI_SUBDOMAIN"):
            errors.append("WLK_KANDJI_SUBDOMAIN not set")
        if not self.get_secret("WLK_KANDJI_TOKEN"):
            errors.append("WLK_KANDJI_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self._base_url()}/api/v1/devices", params={"limit": "1"})
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="kandji",
            source_type=SourceType.MDM,
            provider="kandji",
        )

        client = self._client()

        self._collect_devices(client, result)
        self._collect_blueprints(client, result)
        self._collect_library_items(client, result)
        self._collect_users(client, result)

        result.complete()
        return result

    # -- HTTP client --

    def _base_url(self) -> str:
        subdomain = self.get_secret("WLK_KANDJI_SUBDOMAIN")
        return f"https://{subdomain}.api.kandji.io"

    def _client(self) -> httpx.Client:
        token = self.get_secret("WLK_KANDJI_TOKEN")
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="kandji",
            source_type=SourceType.MDM,
            provider="kandji",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_devices(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect device inventory with OS, encryption, and firewall status."""
        try:
            resp = client.get(
                f"{self._base_url()}/api/v1/devices",
                params={"limit": "300"},
            )
            resp.raise_for_status()
            devices = (
                resp.json() if isinstance(resp.json(), list) else resp.json().get("results", [])
            )
            result.events.append(self._raw_event("kandji_devices", {"devices": devices}))
        except Exception as e:
            log.debug("Kandji devices collection failed: %s", e)
            result.errors.append(f"kandji_devices: {e}")

    def _collect_blueprints(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect blueprints (configuration profiles)."""
        try:
            resp = client.get(f"{self._base_url()}/api/v1/blueprints")
            resp.raise_for_status()
            blueprints = (
                resp.json() if isinstance(resp.json(), list) else resp.json().get("results", [])
            )
            result.events.append(self._raw_event("kandji_blueprints", {"blueprints": blueprints}))
        except Exception as e:
            log.debug("Kandji blueprints collection failed: %s", e)
            result.errors.append(f"kandji_blueprints: {e}")

    def _collect_library_items(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect library items (apps, profiles, scripts)."""
        try:
            resp = client.get(
                f"{self._base_url()}/api/v1/library/library-items",
                params={"limit": "300"},
            )
            resp.raise_for_status()
            items = resp.json() if isinstance(resp.json(), list) else resp.json().get("results", [])
            result.events.append(self._raw_event("kandji_library_items", {"library_items": items}))
        except Exception as e:
            log.debug("Kandji library items collection failed: %s", e)
            result.errors.append(f"kandji_library_items: {e}")

    def _collect_users(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect Kandji users."""
        try:
            resp = client.get(
                f"{self._base_url()}/api/v1/users",
                params={"limit": "300"},
            )
            resp.raise_for_status()
            users = resp.json() if isinstance(resp.json(), list) else resp.json().get("results", [])
            result.events.append(self._raw_event("kandji_users", {"users": users}))
        except Exception as e:
            log.debug("Kandji users collection failed: %s", e)
            result.errors.append(f"kandji_users: {e}")


# Register
registry.register("kandji", KandjiConnector)
