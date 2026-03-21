"""Rippling connector — Layer 1 implementation for HR / IT management.

Collects employees (status, department, devices), devices (MDM status),
apps (SSO assignments), and activity logs via the Rippling Platform API
with Bearer token auth.
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

API_BASE = "https://api.rippling.com"


class RipplingConnector(BaseConnector):
    """Collects compliance telemetry from Rippling Platform API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[rippling]")
        if not self.get_secret("WLK_RIPPLING_TOKEN"):
            errors.append("WLK_RIPPLING_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{API_BASE}/platform/api/company")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="rippling",
            source_type=SourceType.HRIS,
            provider="rippling",
        )

        self._collect_employees(result)
        self._collect_devices(result)
        self._collect_apps(result)
        self._collect_activity(result)

        result.complete()
        return result

    # -- Client --

    def _client(self) -> httpx.Client:
        token = self.get_secret("WLK_RIPPLING_TOKEN")
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="rippling",
            source_type=SourceType.HRIS,
            provider="rippling",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_employees(self, result: ConnectorResult) -> None:
        """Collect employees — status, department, assigned devices."""
        try:
            client = self._client()
            resp = client.get(f"{API_BASE}/platform/api/employees")
            resp.raise_for_status()
            employees = resp.json().get("results", resp.json() if isinstance(resp.json(), list) else [])
            result.events.append(self._raw_event("rippling_employees", {"employees": employees}))
        except Exception as e:
            log.debug("Rippling employees collection failed: %s", e)
            result.errors.append(f"rippling_employees: {e}")

    def _collect_devices(self, result: ConnectorResult) -> None:
        """Collect devices with MDM enrollment status."""
        try:
            client = self._client()
            resp = client.get(f"{API_BASE}/platform/api/devices")
            resp.raise_for_status()
            devices = resp.json().get("results", resp.json() if isinstance(resp.json(), list) else [])
            result.events.append(self._raw_event("rippling_devices", {"devices": devices}))
        except Exception as e:
            log.debug("Rippling devices collection failed: %s", e)
            result.errors.append(f"rippling_devices: {e}")

    def _collect_apps(self, result: ConnectorResult) -> None:
        """Collect app SSO assignments."""
        try:
            client = self._client()
            resp = client.get(f"{API_BASE}/platform/api/apps")
            resp.raise_for_status()
            apps = resp.json().get("results", resp.json() if isinstance(resp.json(), list) else [])
            result.events.append(self._raw_event("rippling_apps", {"apps": apps}))
        except Exception as e:
            log.debug("Rippling apps collection failed: %s", e)
            result.errors.append(f"rippling_apps: {e}")

    def _collect_activity(self, result: ConnectorResult) -> None:
        """Collect activity / audit logs."""
        try:
            client = self._client()
            resp = client.get(f"{API_BASE}/platform/api/activity_logs", params={"limit": "500"})
            resp.raise_for_status()
            logs = resp.json().get("results", resp.json() if isinstance(resp.json(), list) else [])
            result.events.append(self._raw_event("rippling_activity", {"logs": logs}))
        except Exception as e:
            log.debug("Rippling activity logs collection failed: %s", e)
            result.errors.append(f"rippling_activity: {e}")


# Register
registry.register("rippling", RipplingConnector)
