"""Slack connector — Layer 1 implementation for collaboration security.

Collects workspace info, DLP events (file shares), audit logs (admin actions),
and user list (MFA/SSO status) via the Slack Web API and Audit Logs API.
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


class SlackConnector(BaseConnector):
    """Collects compliance telemetry from Slack Web API and Audit Logs API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[slack]")
        if not self.get_secret("WLK_SLACK_TOKEN"):
            errors.append("WLK_SLACK_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.post("https://slack.com/api/auth.test")
            return resp.status_code == 200 and resp.json().get("ok", False)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="slack",
            source_type=SourceType.COLLABORATION,
            provider="slack",
        )

        self._collect_workspace(result)
        self._collect_dlp_events(result)
        self._collect_audit_logs(result)
        self._collect_users(result)

        result.complete()
        return result

    # -- Helpers --

    def _client(self) -> httpx.Client:
        token = self.get_secret("WLK_SLACK_TOKEN")
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; charset=utf-8",
            },
        )

    def _audit_client(self) -> httpx.Client:
        """Client for Enterprise Grid Audit Logs API."""
        token = self.get_secret("WLK_SLACK_AUDIT_TOKEN")
        if not token:
            token = self.get_secret("WLK_SLACK_TOKEN")
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; charset=utf-8",
            },
        )

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="slack",
            source_type=SourceType.COLLABORATION,
            provider="slack",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_workspace(self, result: ConnectorResult) -> None:
        """Collect workspace/team info including 2FA requirement."""
        try:
            client = self._client()
            resp = client.post("https://slack.com/api/team.info")
            resp.raise_for_status()
            data = resp.json()
            if data.get("ok"):
                team = data.get("team", {})
                result.events.append(self._raw_event("slack_workspace", {"team": team}))
            else:
                result.errors.append(f"slack_workspace: Slack API error — {data.get('error', 'unknown')}")
        except Exception as e:
            log.debug("Slack workspace collection failed: %s", e)
            result.errors.append(f"slack_workspace: {e}")

    def _collect_dlp_events(self, result: ConnectorResult) -> None:
        """Collect DLP events — files shared externally."""
        try:
            client = self._client()
            resp = client.post(
                "https://slack.com/api/files.list",
                json={"count": 100, "types": "all"},
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("ok"):
                files = data.get("files", [])
                # Filter for externally shared files
                external_files = [f for f in files if f.get("is_external", False) or f.get("is_public", False)]
                result.events.append(self._raw_event("slack_dlp_events", {"files": external_files, "total_files": len(files)}))
            else:
                result.errors.append(f"slack_dlp_events: Slack API error — {data.get('error', 'unknown')}")
        except Exception as e:
            log.debug("Slack DLP events collection failed: %s", e)
            result.errors.append(f"slack_dlp_events: {e}")

    def _collect_audit_logs(self, result: ConnectorResult) -> None:
        """Collect audit logs from Enterprise Grid Audit Logs API."""
        try:
            client = self._audit_client()
            resp = client.get(
                "https://api.slack.com/audit/v1/logs",
                params={"limit": "100"},
            )
            resp.raise_for_status()
            data = resp.json()
            entries = data.get("entries", [])
            result.events.append(self._raw_event("slack_audit_logs", {"entries": entries}))
        except Exception as e:
            log.debug("Slack audit logs collection failed: %s", e)
            result.errors.append(f"slack_audit_logs: {e}")

    def _collect_users(self, result: ConnectorResult) -> None:
        """Collect user list with MFA/SSO status."""
        try:
            client = self._client()
            resp = client.post(
                "https://slack.com/api/users.list",
                json={"limit": 200},
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("ok"):
                members = data.get("members", [])
                result.events.append(self._raw_event("slack_users", {"users": members}))
            else:
                result.errors.append(f"slack_users: Slack API error — {data.get('error', 'unknown')}")
        except Exception as e:
            log.debug("Slack users collection failed: %s", e)
            result.errors.append(f"slack_users: {e}")


# Register
registry.register("slack", SlackConnector)
