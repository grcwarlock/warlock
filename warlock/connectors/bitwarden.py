"""Bitwarden connector — Layer 1 implementation for IAM / password management.

Collects organization members, policies, and event logs
via the Bitwarden Public API (OAuth2 client credentials).
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


class BitwardenConnector(BaseConnector):
    """Collects compliance telemetry from Bitwarden Public API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[bitwarden]")
        if not self.get_secret("WLK_BITWARDEN_CLIENT_ID"):
            errors.append("WLK_BITWARDEN_CLIENT_ID not set")
        if not self.get_secret("WLK_BITWARDEN_CLIENT_SECRET"):
            errors.append("WLK_BITWARDEN_CLIENT_SECRET not set")
        if not self.get_secret("WLK_BITWARDEN_BASE_URL"):
            errors.append("WLK_BITWARDEN_BASE_URL not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            base_url = self.get_secret("WLK_BITWARDEN_BASE_URL").rstrip("/")
            resp = client.get(f"{base_url}/public/members", params={"limit": 1})
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="bitwarden",
            source_type=SourceType.IAM,
            provider="bitwarden",
        )

        client = self._client()
        base_url = self.get_secret("WLK_BITWARDEN_BASE_URL").rstrip("/")

        self._collect_members(client, base_url, result)
        self._collect_policies(client, base_url, result)
        self._collect_events(client, base_url, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _get_bearer_token(self) -> str:
        """OAuth2 client credentials flow to obtain a Bearer token."""
        client_id = self.get_secret("WLK_BITWARDEN_CLIENT_ID")
        client_secret = self.get_secret("WLK_BITWARDEN_CLIENT_SECRET")

        # Bitwarden identity endpoint
        identity_url = "https://identity.bitwarden.com/connect/token"
        base_url = self.get_secret("WLK_BITWARDEN_BASE_URL").rstrip("/")
        # Self-hosted instances use their own identity endpoint
        if "bitwarden.com" not in base_url:
            identity_url = f"{base_url}/identity/connect/token"

        resp = httpx.post(
            identity_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "api.organization",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _client(self) -> httpx.Client:
        """Build an httpx client with Bearer token auth."""
        token = self._get_bearer_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        return httpx.Client(headers=headers, timeout=self.config.timeout_seconds)

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="bitwarden",
            source_type=SourceType.IAM,
            provider="bitwarden",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_members(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect organization members with 2FA and status."""
        try:
            resp = client.get(f"{base_url}/public/members")
            resp.raise_for_status()
            members = resp.json().get("data", resp.json().get("members", []))
            result.events.append(self._raw_event("bitwarden_members", {"members": members}))
        except Exception as e:
            log.debug("Bitwarden members collection failed: %s", e)
            result.errors.append(f"bitwarden_members: {e}")

    def _collect_policies(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect organization policies (master password, 2FA enforcement, etc.)."""
        try:
            resp = client.get(f"{base_url}/public/policies")
            resp.raise_for_status()
            policies = resp.json().get("data", resp.json().get("policies", []))
            result.events.append(self._raw_event("bitwarden_policies", {"policies": policies}))
        except Exception as e:
            log.debug("Bitwarden policies collection failed: %s", e)
            result.errors.append(f"bitwarden_policies: {e}")

    def _collect_events(self, client: httpx.Client, base_url: str, result: ConnectorResult) -> None:
        """Collect organization event logs."""
        try:
            resp = client.get(f"{base_url}/public/events")
            resp.raise_for_status()
            events = resp.json().get("data", resp.json().get("events", []))
            result.events.append(self._raw_event("bitwarden_events", {"events": events}))
        except Exception as e:
            log.debug("Bitwarden events collection failed: %s", e)
            result.errors.append(f"bitwarden_events: {e}")


# Register
registry.register("bitwarden", BitwardenConnector)
