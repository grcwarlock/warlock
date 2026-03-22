"""Jira connector — Layer 1 implementation for ITSM.

Collects security bug tickets, SLA compliance status, and change requests
via the Jira Cloud REST API v3 with Basic authentication.
"""

from __future__ import annotations

import base64
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


class JiraConnector(BaseConnector):
    """Collects compliance telemetry from Jira Cloud REST API v3."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[jira]")
        if not self.get_secret("WLK_JIRA_DOMAIN"):
            errors.append("WLK_JIRA_DOMAIN not set")
        if not self.get_secret("WLK_JIRA_EMAIL"):
            errors.append("WLK_JIRA_EMAIL not set")
        if not self.get_secret("WLK_JIRA_API_TOKEN"):
            errors.append("WLK_JIRA_API_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self._base_url()}/myself")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="jira",
            source_type=SourceType.ITSM,
            provider="jira",
        )

        self._collect_security_bugs(result)
        self._collect_sla_status(result)
        self._collect_change_requests(result)

        result.complete()
        return result

    # -- Helpers --

    def _base_url(self) -> str:
        domain = self.get_secret("WLK_JIRA_DOMAIN")
        return f"https://{domain}.atlassian.net/rest/api/3"

    def _client(self) -> httpx.Client:
        email = self.get_secret("WLK_JIRA_EMAIL")
        token = self.get_secret("WLK_JIRA_API_TOKEN")
        auth_str = base64.b64encode(f"{email}:{token}".encode()).decode()
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={
                "Authorization": f"Basic {auth_str}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="jira",
            source_type=SourceType.ITSM,
            provider="jira",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_security_bugs(self, result: ConnectorResult) -> None:
        """Collect security-labeled bug tickets via JQL."""
        try:
            client = self._client()
            jql = 'type = Bug AND labels in (security, "security-bug", vulnerability)'
            resp = client.get(
                f"{self._base_url()}/search",
                params={
                    "jql": jql,
                    "maxResults": "100",
                    "fields": "summary,status,priority,assignee,created,updated,duedate,labels,resolution",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            issues = data.get("issues", [])
            result.events.append(
                self._raw_event(
                    "jira_security_bugs", {"issues": issues, "total": data.get("total", 0)}
                )
            )
        except Exception as e:
            log.debug("Jira security bugs collection failed: %s", e)
            result.errors.append(f"jira_security_bugs: {e}")

    def _collect_sla_status(self, result: ConnectorResult) -> None:
        """Collect SLA compliance data for security tickets."""
        try:
            client = self._client()
            # Query overdue security bugs
            jql = 'type = Bug AND labels in (security, "security-bug") AND duedate < now() AND resolution = Unresolved'
            resp = client.get(
                f"{self._base_url()}/search",
                params={
                    "jql": jql,
                    "maxResults": "100",
                    "fields": "summary,status,priority,assignee,created,duedate,labels",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            issues = data.get("issues", [])
            result.events.append(
                self._raw_event(
                    "jira_sla_status",
                    {"overdue_issues": issues, "total_overdue": data.get("total", 0)},
                )
            )
        except Exception as e:
            log.debug("Jira SLA status collection failed: %s", e)
            result.errors.append(f"jira_sla_status: {e}")

    def _collect_change_requests(self, result: ConnectorResult) -> None:
        """Collect change request tickets."""
        try:
            client = self._client()
            jql = 'type in ("Change Request", "Change") OR labels in ("change-request", "change-management")'
            resp = client.get(
                f"{self._base_url()}/search",
                params={
                    "jql": jql,
                    "maxResults": "100",
                    "fields": "summary,status,priority,assignee,created,updated,labels,resolution,customfield_10010",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            issues = data.get("issues", [])
            result.events.append(
                self._raw_event(
                    "jira_change_requests", {"issues": issues, "total": data.get("total", 0)}
                )
            )
        except Exception as e:
            log.debug("Jira change requests collection failed: %s", e)
            result.errors.append(f"jira_change_requests: {e}")


# Register
registry.register("jira", JiraConnector)
