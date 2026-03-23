"""Ping Identity connector — Layer 1 implementation for IAM.

Collects users, groups, and sign-on policies from Ping Identity PingOne APIs.
Uses OAuth2 client credentials for authentication.
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

PING_BASE_URL = "https://api.pingone.com"

# (path_template, event_type, params)
PING_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/v1/environments/{env}/users", "ping_users", {"limit": "100"}),
    ("/v1/environments/{env}/groups", "ping_groups", {"limit": "100"}),
    ("/v1/environments/{env}/signOnPolicies", "ping_sign_on_policies", {"limit": "100"}),
]


class PingIdentityConnector(BaseConnector):
    """Collects compliance telemetry from Ping Identity PingOne APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("PING_CLIENT_ID"):
            errors.append("PING_CLIENT_ID env var is not set")
        if not self.get_secret("PING_CLIENT_SECRET"):
            errors.append("PING_CLIENT_SECRET env var is not set")
        if not self.config.settings.get("environment_id"):
            errors.append("settings.environment_id is required for Ping Identity")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self._get_token()
            if not token:
                return False
            env_id = self.config.settings.get("environment_id", "")
            base_url = self.config.settings.get("base_url", PING_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v1/environments/{env_id}/users",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="ping_identity",
            source_type=SourceType.IAM,
            provider="ping_identity",
        )

        env_id = self.config.settings.get("environment_id", "")
        base_url = self.config.settings.get("base_url", PING_BASE_URL)
        token = self._get_token()

        if not token:
            result.errors.append("Failed to obtain OAuth2 access token")
            result.complete("error")
            return result

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        client = httpx.Client(base_url=base_url, headers=headers, timeout=self.config.timeout_seconds)

        try:
            for path_template, event_type, params in PING_ENDPOINTS:
                endpoint = path_template.format(env=env_id)
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="ping_identity",
                            source_type=SourceType.IAM,
                            provider="ping_identity",
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
                    log.debug("Ping Identity %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _get_token(self) -> str:
        """Obtain OAuth2 client credentials token."""
        try:
            import httpx

            client_id = self.get_secret("PING_CLIENT_ID")
            client_secret = self.get_secret("PING_CLIENT_SECRET")
            env_id = self.config.settings.get("environment_id", "")
            auth_url = self.config.settings.get(
                "auth_url",
                f"https://auth.pingone.com/{env_id}/as/token",
            )
            resp = httpx.post(
                auth_url,
                data={"grant_type": "client_credentials"},
                auth=(client_id, client_secret),
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json().get("access_token", "")
        except Exception as e:
            log.debug("Ping Identity token acquisition failed: %s", e)
            return ""

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow PingOne cursor-based pagination."""
        all_items: list = []
        current_params = dict(params)

        while True:
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            embedded = body.get("_embedded", {})
            # PingOne wraps resources under a key matching the last path segment
            for key in embedded:
                items = embedded[key]
                if isinstance(items, list):
                    all_items.extend(items)
                    break

            # Cursor pagination
            next_link = body.get("_links", {}).get("next", {}).get("href")
            if not next_link:
                break
            # Use the full next URL directly on next iteration
            endpoint = next_link
            current_params = {}

        return all_items


# Register
registry.register("ping_identity", PingIdentityConnector)
