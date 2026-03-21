"""Auth0 connector — Layer 1 implementation for IAM / identity platform.

Collects users (MFA enrollment, blocked status), connections, rules/actions,
and logs (login anomalies) via the Auth0 Management API with OAuth2
client-credentials authentication.
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


class Auth0Connector(BaseConnector):
    """Collects compliance telemetry from Auth0 Management API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[auth0]")
        if not self.get_secret("WLK_AUTH0_DOMAIN"):
            errors.append("WLK_AUTH0_DOMAIN not set")
        if not self.get_secret("WLK_AUTH0_CLIENT_ID"):
            errors.append("WLK_AUTH0_CLIENT_ID not set")
        if not self.get_secret("WLK_AUTH0_CLIENT_SECRET"):
            errors.append("WLK_AUTH0_CLIENT_SECRET not set")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._get_access_token()
            domain = self.get_secret("WLK_AUTH0_DOMAIN")
            client = self._client(token)
            resp = client.get(f"https://{domain}/api/v2/stats/active-users")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="auth0",
            source_type=SourceType.IAM,
            provider="auth0",
        )

        try:
            token = self._get_access_token()
        except Exception as e:
            log.debug("Auth0 token acquisition failed: %s", e)
            result.errors.append(f"auth0_token: {e}")
            result.complete()
            return result

        domain = self.get_secret("WLK_AUTH0_DOMAIN")
        client = self._client(token)

        self._collect_users(client, domain, result)
        self._collect_connections(client, domain, result)
        self._collect_rules(client, domain, result)
        self._collect_logs(client, domain, result)

        result.complete()
        return result

    # -- Auth --

    def _get_access_token(self) -> str:
        """Obtain an access token via OAuth2 client credentials grant."""
        domain = self.get_secret("WLK_AUTH0_DOMAIN")
        client_id = self.get_secret("WLK_AUTH0_CLIENT_ID")
        client_secret = self.get_secret("WLK_AUTH0_CLIENT_SECRET")

        client = httpx.Client(timeout=self.config.timeout_seconds)
        resp = client.post(
            f"https://{domain}/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "audience": f"https://{domain}/api/v2/",
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _client(self, token: str) -> httpx.Client:
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="auth0",
            source_type=SourceType.IAM,
            provider="auth0",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_users(
        self, client: httpx.Client, domain: str, result: ConnectorResult,
    ) -> None:
        """Collect Auth0 users with MFA enrollment and blocked status."""
        try:
            resp = client.get(
                f"https://{domain}/api/v2/users",
                params={"per_page": "100", "include_totals": "true"},
            )
            resp.raise_for_status()
            body = resp.json()
            users = body.get("users", body) if isinstance(body, dict) else body
            result.events.append(self._raw_event("auth0_users", {"users": users}))
        except Exception as e:
            log.debug("Auth0 users collection failed: %s", e)
            result.errors.append(f"auth0_users: {e}")

    def _collect_connections(
        self, client: httpx.Client, domain: str, result: ConnectorResult,
    ) -> None:
        """Collect Auth0 connections (identity providers)."""
        try:
            resp = client.get(
                f"https://{domain}/api/v2/connections",
                params={"per_page": "100"},
            )
            resp.raise_for_status()
            connections = resp.json()
            if isinstance(connections, dict):
                connections = connections.get("connections", [])
            result.events.append(
                self._raw_event("auth0_connections", {"connections": connections}),
            )
        except Exception as e:
            log.debug("Auth0 connections collection failed: %s", e)
            result.errors.append(f"auth0_connections: {e}")

    def _collect_rules(
        self, client: httpx.Client, domain: str, result: ConnectorResult,
    ) -> None:
        """Collect Auth0 rules and actions."""
        try:
            # Collect legacy rules
            resp = client.get(f"https://{domain}/api/v2/rules")
            resp.raise_for_status()
            rules = resp.json()
            if isinstance(rules, dict):
                rules = rules.get("rules", [])

            # Collect actions
            actions = []
            try:
                actions_resp = client.get(
                    f"https://{domain}/api/v2/actions/actions",
                    params={"per_page": "100"},
                )
                actions_resp.raise_for_status()
                actions_body = actions_resp.json()
                actions = actions_body.get("actions", actions_body) if isinstance(
                    actions_body, dict,
                ) else actions_body
            except Exception as e:
                log.debug("Auth0 actions collection failed: %s", e)

            result.events.append(
                self._raw_event("auth0_rules", {"rules": rules, "actions": actions}),
            )
        except Exception as e:
            log.debug("Auth0 rules collection failed: %s", e)
            result.errors.append(f"auth0_rules: {e}")

    def _collect_logs(
        self, client: httpx.Client, domain: str, result: ConnectorResult,
    ) -> None:
        """Collect Auth0 log events (failed logins, anomalies)."""
        try:
            resp = client.get(
                f"https://{domain}/api/v2/logs",
                params={"per_page": "100", "sort": "date:-1"},
            )
            resp.raise_for_status()
            logs = resp.json()
            if isinstance(logs, dict):
                logs = logs.get("logs", logs.get("data", []))
            result.events.append(self._raw_event("auth0_logs", {"logs": logs}))
        except Exception as e:
            log.debug("Auth0 logs collection failed: %s", e)
            result.errors.append(f"auth0_logs: {e}")


# Register
registry.register("auth0", Auth0Connector)
