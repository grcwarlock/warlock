"""JumpCloud connector — Layer 1 implementation for IAM / directory.

Collects users (MFA status, suspended), devices (OS, encryption),
policies, and auth logs via the JumpCloud V2 REST API.
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

_BASE_URL = "https://console.jumpcloud.com/api/v2"
_V1_URL = "https://console.jumpcloud.com/api"


class JumpCloudConnector(BaseConnector):
    """Collects compliance telemetry from JumpCloud REST API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[jumpcloud]")
        if not self.get_secret("WLK_JUMPCLOUD_API_KEY"):
            errors.append("WLK_JUMPCLOUD_API_KEY not set")
        return errors

    def health_check(self) -> bool:
        try:
            resp = self._client().get(f"{_V1_URL}/systemusers", params={"limit": "1"})
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="jumpcloud",
            source_type=SourceType.IAM,
            provider="jumpcloud",
        )

        client = self._client()

        self._collect_users(client, result)
        self._collect_devices(client, result)
        self._collect_policies(client, result)
        self._collect_auth_logs(client, result)

        result.complete()
        return result

    # -- Client --

    def _client(self) -> httpx.Client:
        api_key = self.get_secret("WLK_JUMPCLOUD_API_KEY")
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={
                "x-api-key": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="jumpcloud",
            source_type=SourceType.IAM,
            provider="jumpcloud",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_users(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect JumpCloud system users with MFA and suspension status."""
        try:
            resp = client.get(f"{_V1_URL}/systemusers", params={"limit": "1000"})
            resp.raise_for_status()
            users = resp.json().get("results", [])
            result.events.append(self._raw_event("jumpcloud_users", {"users": users}))
        except Exception as e:
            log.debug("JumpCloud users collection failed: %s", e)
            result.errors.append(f"jumpcloud_users: {e}")

    def _collect_devices(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect managed systems/devices with OS and encryption info."""
        try:
            resp = client.get(f"{_V1_URL}/systems", params={"limit": "1000"})
            resp.raise_for_status()
            devices = resp.json().get("results", [])
            result.events.append(self._raw_event("jumpcloud_devices", {"devices": devices}))
        except Exception as e:
            log.debug("JumpCloud devices collection failed: %s", e)
            result.errors.append(f"jumpcloud_devices: {e}")

    def _collect_policies(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect JumpCloud policies."""
        try:
            resp = client.get(f"{_BASE_URL}/policies", params={"limit": "100"})
            resp.raise_for_status()
            policies = resp.json()
            if isinstance(policies, dict):
                policies = policies.get("results", policies.get("data", []))
            result.events.append(self._raw_event("jumpcloud_policies", {"policies": policies}))
        except Exception as e:
            log.debug("JumpCloud policies collection failed: %s", e)
            result.errors.append(f"jumpcloud_policies: {e}")

    def _collect_auth_logs(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect directory insights auth/login events (last 24h)."""
        try:
            start_time = (
                datetime.now(timezone.utc)
                .replace(
                    hour=0,
                    minute=0,
                    second=0,
                    microsecond=0,
                )
                .isoformat()
            )
            resp = client.post(
                f"{_BASE_URL}/events",
                json={
                    "service": ["directory"],
                    "start_time": start_time,
                    "limit": 1000,
                    "search_term": {
                        "and": [{"event_type": {"$in": ["user_login", "user_login_attempt"]}}],
                    },
                },
            )
            resp.raise_for_status()
            logs = resp.json()
            if isinstance(logs, dict):
                logs = logs.get("results", logs.get("data", []))
            result.events.append(self._raw_event("jumpcloud_auth_logs", {"logs": logs}))
        except Exception as e:
            log.debug("JumpCloud auth logs collection failed: %s", e)
            result.errors.append(f"jumpcloud_auth_logs: {e}")


# Register
registry.register("jumpcloud", JumpCloudConnector)
