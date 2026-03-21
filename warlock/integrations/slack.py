"""EventBus subscriber that sends pipeline events to Slack via webhook.

Subscribes to ``finding.normalized`` and ``control.assessed`` events, formats
them as Slack Block Kit messages, and POSTs to a configured incoming webhook
URL.  Filters by minimum severity and retries with exponential backoff.
"""

from __future__ import annotations

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

# Slack attachment color by severity
_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#dc3545",  # red
    "high": "#fd7e14",  # orange
    "medium": "#ffc107",  # yellow
    "low": "#6c757d",  # gray
    "info": "#17a2b8",  # teal
}


class SlackNotifier:
    """EventBus subscriber that sends finding and assessment events to Slack.

    Config env vars:
        WLK_SLACK_WEBHOOK_URL  -- Slack incoming webhook URL
        WLK_SLACK_CHANNEL      -- Optional channel override (default: webhook default)
        WLK_SLACK_EVENTS       -- Comma-separated event types to forward (default: all pipeline events)
        WLK_SLACK_MIN_SEVERITY -- Minimum severity to send (default: "medium")
    """

    __name__ = "SlackNotifier"

    def __init__(self) -> None:
        self._webhook_url = os.environ.get("WLK_SLACK_WEBHOOK_URL", "").strip()
        self._channel = os.environ.get("WLK_SLACK_CHANNEL", "").strip()
        self._min_severity = os.environ.get("WLK_SLACK_MIN_SEVERITY", "medium").strip().lower()

        raw_events = os.environ.get("WLK_SLACK_EVENTS", "").strip()
        if raw_events:
            self._event_filter: set[str] | None = {
                e.strip() for e in raw_events.split(",") if e.strip()
            }
        else:
            self._event_filter = None  # accept all

    # ------------------------------------------------------------------
    # EventBus handler interface
    # ------------------------------------------------------------------

    def __call__(self, event: Any) -> None:
        """Handle a PipelineEvent -- called by the EventBus."""
        try:
            if not self._webhook_url:
                return
            if self._event_filter and event.event_type not in self._event_filter:
                return
            if not self._meets_severity(event):
                return
            self._deliver(event)
        except Exception:
            log.exception("SlackNotifier failed for event %s", event.event_type)

    # ------------------------------------------------------------------
    # Severity filter
    # ------------------------------------------------------------------

    def _meets_severity(self, event: Any) -> bool:
        """Return True if the event severity meets or exceeds the minimum."""
        severity = (event.metadata.get("severity") or "info").lower()
        min_rank = SEVERITY_ORDER.get(self._min_severity, 0)
        event_rank = SEVERITY_ORDER.get(severity, 0)
        return event_rank >= min_rank

    # ------------------------------------------------------------------
    # Message building
    # ------------------------------------------------------------------

    def _build_blocks(self, event: Any) -> dict[str, Any]:
        """Build a Slack Block Kit message from a PipelineEvent."""
        metadata = event.metadata or {}
        severity = (metadata.get("severity") or "info").lower()
        resource = metadata.get("resource_id") or metadata.get("resource") or "N/A"
        framework = metadata.get("framework") or "N/A"
        control_id = metadata.get("control_id") or "N/A"
        status = metadata.get("status") or "N/A"
        ts = event.timestamp.strftime("%Y-%m-%d %H:%M UTC") if event.timestamp else "N/A"

        color = _SEVERITY_COLORS.get(severity, "#6c757d")

        payload: dict[str, Any] = {
            "text": f"Warlock GRC: {event.event_type} -- severity={severity}",
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"Warlock: {event.event_type}",
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                                {"type": "mrkdwn", "text": f"*Resource:*\n{resource}"},
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Framework / Control:*\n{framework} / {control_id}",
                                },
                                {"type": "mrkdwn", "text": f"*Status:*\n{status}"},
                            ],
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"Warlock GRC | {ts}",
                                },
                            ],
                        },
                    ],
                },
            ],
        }

        if self._channel:
            payload["channel"] = self._channel

        return payload

    # ------------------------------------------------------------------
    # Delivery with retry
    # ------------------------------------------------------------------

    def _deliver(self, event: Any) -> None:
        """POST the formatted message to Slack with retry + backoff."""
        if not _HAS_HTTPX:
            log.error("httpx not installed -- cannot deliver Slack notification")
            return

        payload = self._build_blocks(event)
        body = json.dumps(payload, default=str).encode()
        headers = {"Content-Type": "application/json"}

        for attempt in range(_MAX_RETRIES):
            try:
                resp = httpx.post(
                    self._webhook_url, content=body, headers=headers, timeout=_TIMEOUT
                )
                resp.raise_for_status()
                log.debug(
                    "Slack notification delivered: event=%s status=%d",
                    event.event_type,
                    resp.status_code,
                )
                return
            except Exception as exc:
                wait = 2**attempt  # 1s, 2s, 4s
                if attempt < _MAX_RETRIES - 1:
                    log.warning(
                        "Slack POST failed (attempt %d/%d): %s -- retrying in %ds",
                        attempt + 1,
                        _MAX_RETRIES,
                        exc,
                        wait,
                    )
                    time.sleep(wait)
                else:
                    log.error(
                        "Slack POST failed after %d attempts: %s",
                        _MAX_RETRIES,
                        exc,
                    )
