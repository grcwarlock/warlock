"""Bidirectional Jira sync for findings and POA&M items.

Provides a ``JiraClient`` that can push findings/POA&Ms as Jira issues,
pull status updates, and perform bidirectional status synchronization.
Uses Jira REST API v3 with basic auth (email + API token).
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime
from typing import Any

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore[assignment]
    _HAS_HTTPX = False

from warlock.config import get_settings

log = logging.getLogger(__name__)

_MAX_RETRIES = 3
_TIMEOUT = 15.0

# Warlock status -> Jira status name
WARLOCK_TO_JIRA: dict[str, str] = {
    "open": "Open",
    "in_progress": "In Progress",
    "remediated": "Done",
    "risk_accepted": "Done",
    "false_positive": "Done",
}

# Jira status name (lowered) -> Warlock status
JIRA_TO_WARLOCK: dict[str, str] = {
    "open": "open",
    "to do": "open",
    "backlog": "open",
    "in progress": "in_progress",
    "in review": "in_progress",
    "done": "remediated",
    "closed": "remediated",
    "resolved": "remediated",
}

# Warlock severity -> Jira priority name
_JIRA_PRIORITY_MAP: dict[str, str] = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}


class JiraClientError(Exception):
    """Raised when a Jira API operation fails."""


class JiraClient:
    """Bidirectional Jira sync client for Warlock GRC findings and POA&Ms.

    Reads configuration from ``get_settings()``:
        - ``jira_base_url``
        - ``jira_email``
        - ``jira_api_token``
        - ``jira_project_key``
        - ``jira_issue_type``
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        email: str | None = None,
        api_token: str | None = None,
        project_key: str | None = None,
        issue_type: str | None = None,
    ) -> None:
        if not _HAS_HTTPX:
            raise JiraClientError("httpx is required for Jira integration")

        settings = get_settings()
        self._base_url = (base_url or settings.jira_base_url).strip().rstrip("/")
        self._email = (email or settings.jira_email).strip()
        self._api_token = (api_token or settings.jira_api_token).strip()
        self._project_key = (project_key or settings.jira_project_key).strip()
        self._issue_type = (issue_type or settings.jira_issue_type).strip()

        if not self._base_url or not self._email or not self._api_token:
            raise JiraClientError("Jira integration requires base_url, email, and api_token")

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def _auth_header(self) -> str:
        creds = f"{self._email}:{self._api_token}"
        encoded = base64.b64encode(creds.encode()).decode()
        return f"Basic {encoded}"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self._auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # HTTP helpers with retry
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        url: str,
        *,
        json_data: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Execute an HTTP request with retry and exponential backoff."""
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                resp = httpx.request(
                    method,
                    url,
                    headers=self._headers(),
                    json=json_data,
                    params=params,
                    timeout=_TIMEOUT,
                )
                resp.raise_for_status()
                if resp.status_code == 204:
                    return {}
                return resp.json()
            except Exception as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    import time

                    wait = 2**attempt
                    log.warning(
                        "Jira %s %s failed (attempt %d/%d): %s -- retrying in %ds",
                        method,
                        url,
                        attempt + 1,
                        _MAX_RETRIES,
                        exc,
                        wait,
                    )
                    time.sleep(wait)

        raise JiraClientError(
            f"Jira {method} {url} failed after {_MAX_RETRIES} attempts: {last_exc}"
        )

    # ------------------------------------------------------------------
    # Push operations
    # ------------------------------------------------------------------

    def push_finding(self, finding_dict: dict[str, Any]) -> dict[str, Any]:
        """Create a Jira issue from a finding dict.

        Args:
            finding_dict: Must contain at minimum ``title``, ``severity``,
                and ``description``.  Optional: ``source``, ``resource_id``,
                ``finding_id``.

        Returns:
            Dict with ``key`` (e.g. "GRC-42") and ``id`` of the created issue.
        """
        title = finding_dict.get("title", "Untitled Finding")
        severity = (finding_dict.get("severity") or "medium").lower()
        source = finding_dict.get("source", "warlock")
        resource_id = finding_dict.get("resource_id", "N/A")
        finding_id = finding_dict.get("finding_id") or finding_dict.get("id", "N/A")

        summary = f"[Warlock] Finding: {title}"
        if len(summary) > 255:
            summary = summary[:252] + "..."

        description_text = (
            f"Source: {source}\n"
            f"Severity: {severity}\n"
            f"Resource: {resource_id}\n"
            f"Finding ID: {finding_id}\n\n"
            f"{finding_dict.get('description', '')}"
        )

        payload = {
            "fields": {
                "project": {"key": self._project_key},
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description_text}],
                        }
                    ],
                },
                "issuetype": {"name": self._issue_type},
                "priority": {"name": _JIRA_PRIORITY_MAP.get(severity, "Medium")},
                "labels": ["warlock", "finding", severity],
            }
        }

        url = f"{self._base_url}/rest/api/3/issue"
        result = self._request("POST", url, json_data=payload)
        key = result.get("key", "unknown")
        log.info("Jira issue created for finding: %s (finding_id=%s)", key, finding_id)
        return {"key": key, "id": result.get("id", "")}

    def push_poam(self, poam_dict: dict[str, Any]) -> dict[str, Any]:
        """Create a Jira issue from a POA&M dict.

        Args:
            poam_dict: Must contain ``title``.  Optional: ``milestone``,
                ``scheduled_completion``, ``responsible_party``, ``status``,
                ``weakness_description``, ``poam_id``.

        Returns:
            Dict with ``key`` and ``id`` of the created issue.
        """
        title = poam_dict.get("title", "Untitled POA&M")
        milestone = poam_dict.get("milestone", "N/A")
        completion = poam_dict.get("scheduled_completion", "N/A")
        responsible = poam_dict.get("responsible_party", "N/A")
        poam_id = poam_dict.get("poam_id") or poam_dict.get("id", "N/A")
        weakness = poam_dict.get("weakness_description", "")

        summary = f"[Warlock] POA&M: {title}"
        if len(summary) > 255:
            summary = summary[:252] + "..."

        description_text = (
            f"POA&M ID: {poam_id}\n"
            f"Milestone: {milestone}\n"
            f"Scheduled Completion: {completion}\n"
            f"Responsible Party: {responsible}\n\n"
            f"{weakness}"
        )

        payload = {
            "fields": {
                "project": {"key": self._project_key},
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description_text}],
                        }
                    ],
                },
                "issuetype": {"name": "Task"},
                "labels": ["warlock", "poam"],
            }
        }

        url = f"{self._base_url}/rest/api/3/issue"
        result = self._request("POST", url, json_data=payload)
        key = result.get("key", "unknown")
        log.info("Jira issue created for POA&M: %s (poam_id=%s)", key, poam_id)
        return {"key": key, "id": result.get("id", "")}

    # ------------------------------------------------------------------
    # Pull operations
    # ------------------------------------------------------------------

    def pull_updates(self, since: datetime) -> list[dict[str, Any]]:
        """Fetch Jira issues updated since the given datetime.

        Returns a list of dicts with ``key``, ``status``, ``updated``,
        ``assignee``, and ``resolution``.
        """
        since_str = since.strftime("%Y-%m-%d %H:%M")
        jql = f'project = "{self._project_key}" AND labels = "warlock" AND updated >= "{since_str}"'

        url = f"{self._base_url}/rest/api/3/search"
        params = {
            "jql": jql,
            "maxResults": "100",
            "fields": "key,status,updated,assignee,resolution,summary",
        }

        data = self._request("GET", url, params=params)
        issues = data.get("issues", [])

        results: list[dict[str, Any]] = []
        for issue in issues:
            fields = issue.get("fields", {})
            status_obj = fields.get("status", {})
            assignee_obj = fields.get("assignee") or {}
            resolution_obj = fields.get("resolution") or {}

            jira_status = (status_obj.get("name") or "").lower()
            warlock_status = JIRA_TO_WARLOCK.get(jira_status, "open")

            results.append(
                {
                    "key": issue.get("key", ""),
                    "summary": fields.get("summary", ""),
                    "jira_status": status_obj.get("name", ""),
                    "warlock_status": warlock_status,
                    "updated": fields.get("updated", ""),
                    "assignee": assignee_obj.get("displayName", ""),
                    "resolution": resolution_obj.get("name", ""),
                }
            )

        log.info("Pulled %d updated issues from Jira since %s", len(results), since_str)
        return results

    def sync_status(self, issue_id: str, jira_key: str) -> dict[str, Any]:
        """Bidirectional status sync between Warlock and Jira.

        Fetches the current Jira status for ``jira_key`` and returns the
        mapped Warlock status so the caller can update local records.

        Args:
            issue_id: The Warlock-side identifier (finding_id or poam_id).
            jira_key: The Jira issue key (e.g. "GRC-42").

        Returns:
            Dict with ``issue_id``, ``jira_key``, ``jira_status``,
            ``warlock_status``, and ``synced_at``.
        """
        url = f"{self._base_url}/rest/api/3/issue/{jira_key}"
        params = {"fields": "status,updated,resolution"}
        data = self._request("GET", url, params=params)

        fields = data.get("fields", {})
        status_obj = fields.get("status", {})
        jira_status_name = status_obj.get("name", "")
        warlock_status = JIRA_TO_WARLOCK.get(jira_status_name.lower(), "open")

        result = {
            "issue_id": issue_id,
            "jira_key": jira_key,
            "jira_status": jira_status_name,
            "warlock_status": warlock_status,
            "synced_at": datetime.utcnow().isoformat(),
        }

        log.info(
            "Synced status for %s <-> %s: jira=%s warlock=%s",
            issue_id,
            jira_key,
            jira_status_name,
            warlock_status,
        )
        return result

    # ------------------------------------------------------------------
    # Configuration check
    # ------------------------------------------------------------------

    @staticmethod
    def is_configured() -> bool:
        """Return True if Jira integration settings are present."""
        try:
            settings = get_settings()
            return bool(settings.jira_base_url and settings.jira_email and settings.jira_api_token)
        except Exception:
            return False
