"""1Password connector — Layer 1 implementation for IAM / password management.

Collects sign-in attempts, item usage events, and audit events
via the 1Password Events API.
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


class OnePasswordConnector(BaseConnector):
    """Collects compliance telemetry from 1Password Events API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[onepassword]")
        if not self.get_secret("WLK_ONEPASSWORD_TOKEN"):
            errors.append("WLK_ONEPASSWORD_TOKEN not set")
        if not self.get_secret("WLK_ONEPASSWORD_DOMAIN"):
            errors.append("WLK_ONEPASSWORD_DOMAIN not set (e.g. events.1password.com)")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            domain = self.get_secret("WLK_ONEPASSWORD_DOMAIN").rstrip("/")
            # Use introspection endpoint to verify token
            resp = client.post(
                f"https://{domain}/api/v1/signinattempts",
                json={"limit": 1},
            )
            return resp.status_code in (200, 201)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="onepassword",
            source_type=SourceType.IAM,
            provider="onepassword",
        )

        client = self._client()
        domain = self.get_secret("WLK_ONEPASSWORD_DOMAIN").rstrip("/")
        base_url = f"https://{domain}"

        self._collect_signin_attempts(client, base_url, result)
        self._collect_item_usage(client, base_url, result)
        self._collect_audit_events(client, base_url, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _client(self) -> httpx.Client:
        """Build an httpx client with Bearer token auth."""
        token = self.get_secret("WLK_ONEPASSWORD_TOKEN")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        return httpx.Client(headers=headers, timeout=self.config.timeout_seconds)

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="onepassword",
            source_type=SourceType.IAM,
            provider="onepassword",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_signin_attempts(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect sign-in attempt events."""
        try:
            resp = client.post(
                f"{base_url}/api/v1/signinattempts",
                json={"limit": 1000},
            )
            resp.raise_for_status()
            attempts = resp.json().get("items", resp.json().get("cursor", []))
            if isinstance(attempts, str):
                attempts = []
            result.events.append(
                self._raw_event("onepassword_signin_attempts", {"attempts": attempts})
            )
        except Exception as e:
            log.debug("1Password sign-in attempts collection failed: %s", e)
            result.errors.append(f"onepassword_signin_attempts: {e}")

    def _collect_item_usage(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect item usage events (vault item access)."""
        try:
            resp = client.post(
                f"{base_url}/api/v1/itemusages",
                json={"limit": 1000},
            )
            resp.raise_for_status()
            usages = resp.json().get("items", [])
            if isinstance(usages, str):
                usages = []
            result.events.append(self._raw_event("onepassword_item_usage", {"usages": usages}))
        except Exception as e:
            log.debug("1Password item usage collection failed: %s", e)
            result.errors.append(f"onepassword_item_usage: {e}")

    def _collect_audit_events(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect audit events (admin actions, policy changes)."""
        try:
            resp = client.post(
                f"{base_url}/api/v1/auditevents",
                json={"limit": 1000},
            )
            resp.raise_for_status()
            events = resp.json().get("items", [])
            if isinstance(events, str):
                events = []
            result.events.append(self._raw_event("onepassword_audit_events", {"events": events}))
        except Exception as e:
            log.debug("1Password audit events collection failed: %s", e)
            result.errors.append(f"onepassword_audit_events: {e}")


# Register
registry.register("onepassword", OnePasswordConnector)
