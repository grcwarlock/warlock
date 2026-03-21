"""EventBus subscriber that creates Jira issues for compliance failures.

Subscribes to ``control.assessed`` events, filters by severity and status,
and creates Jira issues via the REST API v3.  Deduplicates by searching for
existing open issues with the same summary before creating new ones.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from typing import Any

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore[assignment]
    _HAS_HTTPX = False

log = logging.getLogger(__name__)

SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

_MAX_RETRIES = 3
_TIMEOUT = 15.0

# Map Warlock severity to Jira priority name
_JIRA_PRIORITY_MAP: dict[str, str] = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}

# Statuses that warrant issue creation
_ACTIONABLE_STATUSES = {"non_compliant", "partial"}


class JiraNotifier:
    """EventBus subscriber that creates Jira issues for compliance failures.

    Config env vars:
        WLK_JIRA_BASE_URL     -- Jira instance URL (e.g. https://company.atlassian.net)
        WLK_JIRA_EMAIL        -- Jira API email
        WLK_JIRA_API_TOKEN    -- Jira API token
        WLK_JIRA_PROJECT_KEY  -- Project key for new issues (e.g. "GRC")
        WLK_JIRA_ISSUE_TYPE   -- Issue type (default: "Bug")
        WLK_JIRA_EVENTS       -- Event types (default: "control.assessed")
        WLK_JIRA_MIN_SEVERITY -- Minimum severity (default: "high")
    """

    __name__ = "JiraNotifier"

    def __init__(self) -> None:
        self._base_url = os.environ.get("WLK_JIRA_BASE_URL", "").strip().rstrip("/")
        self._email = os.environ.get("WLK_JIRA_EMAIL", "").strip()
        self._api_token = os.environ.get("WLK_JIRA_API_TOKEN", "").strip()
        self._project_key = os.environ.get("WLK_JIRA_PROJECT_KEY", "GRC").strip()
        self._issue_type = os.environ.get("WLK_JIRA_ISSUE_TYPE", "Bug").strip()
        self._min_severity = os.environ.get("WLK_JIRA_MIN_SEVERITY", "high").strip().lower()

        raw_events = os.environ.get("WLK_JIRA_EVENTS", "").strip()
        if raw_events:
            self._event_filter: set[str] | None = {
                e.strip() for e in raw_events.split(",") if e.strip()
            }
        else:
            self._event_filter = None

    # ------------------------------------------------------------------
    # EventBus handler interface
    # ------------------------------------------------------------------

    def __call__(self, event: Any) -> None:
        """Handle a PipelineEvent -- called by the EventBus."""
        try:
            if not self._base_url or not self._email or not self._api_token:
                return
            if self._event_filter and event.event_type not in self._event_filter:
                return
            if not self._meets_severity(event):
                return
            if not self._is_actionable(event):
                return
            self._deliver(event)
        except Exception:
            log.exception("JiraNotifier failed for event %s", event.event_type)

    # ------------------------------------------------------------------
    # Filters
    # ------------------------------------------------------------------

    def _meets_severity(self, event: Any) -> bool:
        severity = (event.metadata.get("severity") or "info").lower()
        min_rank = SEVERITY_ORDER.get(self._min_severity, 0)
        event_rank = SEVERITY_ORDER.get(severity, 0)
        return event_rank >= min_rank

    def _is_actionable(self, event: Any) -> bool:
        """Only create issues for non_compliant or partial statuses."""
        status = (event.metadata.get("status") or "").lower()
        return status in _ACTIONABLE_STATUSES

    # ------------------------------------------------------------------
    # Auth header
    # ------------------------------------------------------------------

    def _auth_header(self) -> str:
        """Return Basic auth header value."""
        creds = f"{self._email}:{self._api_token}"
        encoded = base64.b64encode(creds.encode()).decode()
        return f"Basic {encoded}"

    # ------------------------------------------------------------------
    # Deduplication: search for existing open issues
    # ------------------------------------------------------------------

    def _find_existing_issue(self, summary: str) -> str | None:
        """Search Jira for an open issue with the same summary.

        Returns the issue key (e.g. "GRC-42") if found, else None.
        """
        if not _HAS_HTTPX:
            return None

        jql = (
            f'project = "{self._project_key}" '
            f'AND summary ~ "{summary}" '
            f"AND status NOT IN (Done, Closed, Resolved)"
        )
        url = f"{self._base_url}/rest/api/3/search"
        headers = {
            "Authorization": self._auth_header(),
            "Content-Type": "application/json",
        }
        params = {"jql": jql, "maxResults": "1", "fields": "key,summary"}

        try:
            resp = httpx.get(url, headers=headers, params=params, timeout=_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            issues = data.get("issues", [])
            if issues:
                return issues[0]["key"]
        except Exception as exc:
            log.warning("Jira dedup search failed: %s", exc)

        return None

    def _add_comment(self, issue_key: str, event: Any) -> None:
        """Add a comment to an existing Jira issue."""
        if not _HAS_HTTPX:
            return

        metadata = event.metadata or {}
        severity = (metadata.get("severity") or "info").lower()
        status = metadata.get("status") or "N/A"
        resource = metadata.get("resource_id") or metadata.get("resource") or "N/A"

        comment_body = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    f"Warlock GRC: duplicate finding detected. "
                                    f"Severity={severity}, Status={status}, Resource={resource}, "
                                    f"Timestamp={event.timestamp.isoformat() if event.timestamp else 'N/A'}"
                                ),
                            },
                        ],
                    },
                ],
            },
        }

        url = f"{self._base_url}/rest/api/3/issue/{issue_key}/comment"
        headers = {
            "Authorization": self._auth_header(),
            "Content-Type": "application/json",
        }

        try:
            resp = httpx.post(
                url,
                content=json.dumps(comment_body, default=str).encode(),
                headers=headers,
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            log.debug("Jira comment added to %s", issue_key)
        except Exception as exc:
            log.warning("Failed to add Jira comment to %s: %s", issue_key, exc)

    # ------------------------------------------------------------------
    # Issue creation
    # ------------------------------------------------------------------

    def _build_issue_payload(self, event: Any) -> tuple[str, dict[str, Any]]:
        """Build Jira issue creation payload.  Returns (summary, payload)."""
        metadata = event.metadata or {}
        severity = (metadata.get("severity") or "info").lower()
        framework = metadata.get("framework") or "unknown"
        control_id = metadata.get("control_id") or "unknown"
        status = metadata.get("status") or "N/A"
        resource = metadata.get("resource_id") or metadata.get("resource") or "N/A"

        summary = f"[Warlock] {framework}/{control_id} -- {status}"

        description = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": "Compliance Finding"}],
                },
                {
                    "type": "paragraph",
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"Framework: {framework}\n"
                                f"Control: {control_id}\n"
                                f"Status: {status}\n"
                                f"Severity: {severity}\n"
                                f"Resource: {resource}\n"
                                f"Event Type: {event.event_type}\n"
                                f"Payload ID: {event.payload_id}\n"
                                f"Timestamp: {event.timestamp.isoformat() if event.timestamp else 'N/A'}"
                            ),
                        },
                    ],
                },
                {
                    "type": "paragraph",
                    "content": [
                        {
                            "type": "text",
                            "text": "Generated by Warlock GRC pipeline.",
                            "marks": [{"type": "em"}],
                        },
                    ],
                },
            ],
        }

        payload = {
            "fields": {
                "project": {"key": self._project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": self._issue_type},
                "priority": {"name": _JIRA_PRIORITY_MAP.get(severity, "Medium")},
                "labels": ["warlock", "compliance"],
            },
        }

        return summary, payload

    # ------------------------------------------------------------------
    # Delivery with retry
    # ------------------------------------------------------------------

    def _deliver(self, event: Any) -> None:
        """Create a Jira issue (or add comment if duplicate exists)."""
        if not _HAS_HTTPX:
            log.error("httpx not installed -- cannot deliver Jira notification")
            return

        summary, payload = self._build_issue_payload(event)

        # Check for existing open issue
        existing_key = self._find_existing_issue(summary)
        if existing_key:
            log.info("Jira duplicate found (%s) -- adding comment instead", existing_key)
            self._add_comment(existing_key, event)
            return

        # Create new issue
        url = f"{self._base_url}/rest/api/3/issue"
        body = json.dumps(payload, default=str).encode()
        headers = {
            "Authorization": self._auth_header(),
            "Content-Type": "application/json",
        }

        for attempt in range(_MAX_RETRIES):
            try:
                resp = httpx.post(url, content=body, headers=headers, timeout=_TIMEOUT)
                resp.raise_for_status()
                issue_key = resp.json().get("key", "unknown")
                log.info("Jira issue created: %s", issue_key)
                return
            except Exception as exc:
                wait = 2**attempt  # 1s, 2s, 4s
                if attempt < _MAX_RETRIES - 1:
                    log.warning(
                        "Jira POST failed (attempt %d/%d): %s -- retrying in %ds",
                        attempt + 1,
                        _MAX_RETRIES,
                        exc,
                        wait,
                    )
                    time.sleep(wait)
                else:
                    log.error(
                        "Jira POST failed after %d attempts: %s",
                        _MAX_RETRIES,
                        exc,
                    )
