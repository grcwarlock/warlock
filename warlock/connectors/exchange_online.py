"""Exchange Online connector — Layer 1 implementation for email security.

Collects message traces, mail flow rules, mailbox settings, and
ATP (Advanced Threat Protection) policies via Microsoft Graph API
with OAuth2 client credentials auth.
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

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LOGIN_BASE = "https://login.microsoftonline.com"


class ExchangeOnlineConnector(BaseConnector):
    """Collects compliance telemetry from Microsoft Graph API (Exchange Online)."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[exchange]")
        if not self.get_secret("WLK_EXCHANGE_TENANT_ID"):
            errors.append("WLK_EXCHANGE_TENANT_ID not set")
        if not self.get_secret("WLK_EXCHANGE_CLIENT_ID"):
            errors.append("WLK_EXCHANGE_CLIENT_ID not set")
        if not self.get_secret("WLK_EXCHANGE_CLIENT_SECRET"):
            errors.append("WLK_EXCHANGE_CLIENT_SECRET not set")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._get_access_token()
            client = self._client(token)
            resp = client.get(f"{GRAPH_BASE}/organization")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="exchange_online",
            source_type=SourceType.EMAIL_SECURITY,
            provider="microsoft",
        )

        try:
            token = self._get_access_token()
        except Exception as e:
            log.debug("Exchange Online auth failed: %s", e)
            result.errors.append(f"auth: {e}")
            result.complete()
            return result

        self._collect_message_traces(token, result)
        self._collect_mail_flow_rules(token, result)
        self._collect_mailbox_settings(token, result)
        self._collect_atp_policies(token, result)

        result.complete()
        return result

    # -- Auth --

    def _get_access_token(self) -> str:
        """Obtain OAuth2 access token via client credentials flow."""
        tenant_id = self.get_secret("WLK_EXCHANGE_TENANT_ID")
        client_id = self.get_secret("WLK_EXCHANGE_CLIENT_ID")
        client_secret = self.get_secret("WLK_EXCHANGE_CLIENT_SECRET")

        client = httpx.Client(timeout=30)
        resp = client.post(
            f"{LOGIN_BASE}/{tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    # -- Client --

    def _client(self, token: str) -> httpx.Client:
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="exchange_online",
            source_type=SourceType.EMAIL_SECURITY,
            provider="microsoft",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_message_traces(self, token: str, result: ConnectorResult) -> None:
        """Collect message trace data."""
        try:
            client = self._client(token)
            # Use reports endpoint for message traces
            resp = client.get(
                f"{GRAPH_BASE}/reports/getEmailActivityUserDetail(period='D7')",
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            traces = resp.json().get("value", [])
            result.events.append(self._raw_event("exchange_message_traces", {"traces": traces}))
        except Exception as e:
            log.debug("Exchange message traces collection failed: %s", e)
            result.errors.append(f"exchange_message_traces: {e}")

    def _collect_mail_flow_rules(self, token: str, result: ConnectorResult) -> None:
        """Collect mail flow (transport) rules."""
        try:
            client = self._client(token)
            resp = client.get(f"{GRAPH_BASE}/admin/exchange/transportRules")
            resp.raise_for_status()
            rules = resp.json().get("value", [])
            result.events.append(self._raw_event("exchange_mail_flow_rules", {"rules": rules}))
        except Exception as e:
            log.debug("Exchange mail flow rules collection failed: %s", e)
            result.errors.append(f"exchange_mail_flow_rules: {e}")

    def _collect_mailbox_settings(self, token: str, result: ConnectorResult) -> None:
        """Collect mailbox settings (forwarding, audit, etc.)."""
        try:
            client = self._client(token)
            # Get all users' mailbox settings
            resp = client.get(
                f"{GRAPH_BASE}/users",
                params={"$select": "id,displayName,mail,userPrincipalName", "$top": "999"},
            )
            resp.raise_for_status()
            users = resp.json().get("value", [])

            mailbox_settings = []
            for user in users[:200]:  # Limit to avoid throttling
                user_id = user.get("id", "")
                try:
                    settings_resp = client.get(f"{GRAPH_BASE}/users/{user_id}/mailboxSettings")
                    if settings_resp.status_code == 200:
                        settings = settings_resp.json()
                        settings["user_id"] = user_id
                        settings["display_name"] = user.get("displayName", "")
                        settings["mail"] = user.get("mail", "")
                        mailbox_settings.append(settings)
                except Exception:
                    pass

            result.events.append(
                self._raw_event("exchange_mailbox_settings", {"mailbox_settings": mailbox_settings})
            )
        except Exception as e:
            log.debug("Exchange mailbox settings collection failed: %s", e)
            result.errors.append(f"exchange_mailbox_settings: {e}")

    def _collect_atp_policies(self, token: str, result: ConnectorResult) -> None:
        """Collect Advanced Threat Protection policies."""
        try:
            client = self._client(token)
            resp = client.get(f"{GRAPH_BASE}/security/threatAssessmentRequests")
            resp.raise_for_status()
            policies = resp.json().get("value", [])
            result.events.append(self._raw_event("exchange_atp_policies", {"policies": policies}))
        except Exception as e:
            log.debug("Exchange ATP policies collection failed: %s", e)
            result.errors.append(f"exchange_atp_policies: {e}")


# Register
registry.register("exchange_online", ExchangeOnlineConnector)
