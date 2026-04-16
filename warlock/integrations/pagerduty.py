"""EventBus subscriber that triggers PagerDuty alerts for critical compliance events.

Subscribes to ``control.assessed`` events, filters by minimum severity, and
creates/resolves PagerDuty incidents via the Events API v2.  Uses a dedup key
derived from framework + control_id to prevent alert storms.
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

_PD_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
_MAX_RETRIES = 3
_TIMEOUT = 15.0

# Map Warlock severity to PagerDuty severity
_PD_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "info": "info",
}


class PagerDutyNotifier:
    """EventBus subscriber that triggers PagerDuty alerts for critical compliance events.

    Config env vars:
        WLK_PAGERDUTY_ROUTING_KEY  -- PagerDuty Events API v2 routing/integration key
        WLK_PAGERDUTY_EVENTS       -- Event types to trigger on (default: "control.assessed")
        WLK_PAGERDUTY_MIN_SEVERITY -- Minimum severity (default: "high")
    """

    __name__ = "PagerDutyNotifier"

    def __init__(self) -> None:
        # N19: routing_key is a credential — route via SecretsBackend
        from warlock.connectors.secrets_backend import get_secrets_backend

        self._routing_key = (
            get_secrets_backend().get_secret("WLK_PAGERDUTY_ROUTING_KEY") or ""
        ).strip()
        self._min_severity = os.environ.get("WLK_PAGERDUTY_MIN_SEVERITY", "high").strip().lower()

        raw_events = os.environ.get("WLK_PAGERDUTY_EVENTS", "").strip()
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
            if not self._routing_key:
                return
            if self._event_filter and event.event_type not in self._event_filter:
                return
            if not self._meets_severity(event):
                return
            self._deliver(event)
        except Exception:
            log.exception("PagerDutyNotifier failed for event %s", event.event_type)

    # ------------------------------------------------------------------
    # Severity filter
    # ------------------------------------------------------------------

    def _meets_severity(self, event: Any) -> bool:
        severity = (event.metadata.get("severity") or "info").lower()
        min_rank = SEVERITY_ORDER.get(self._min_severity, 0)
        event_rank = SEVERITY_ORDER.get(severity, 0)
        return event_rank >= min_rank

    # ------------------------------------------------------------------
    # Payload building
    # ------------------------------------------------------------------

    def _build_payload(self, event: Any) -> dict[str, Any]:
        """Build PagerDuty Events API v2 payload."""
        metadata = event.metadata or {}
        severity = (metadata.get("severity") or "info").lower()
        framework = metadata.get("framework") or "unknown"
        control_id = metadata.get("control_id") or "unknown"
        status = (metadata.get("status") or "").lower()
        resource = metadata.get("resource_id") or metadata.get("resource") or "N/A"

        # Determine event_action: resolve for compliant, trigger otherwise
        if status == "compliant":
            event_action = "resolve"
        else:
            event_action = "trigger"

        dedup_key = f"warlock-{framework}-{control_id}"

        return {
            "routing_key": self._routing_key,
            "event_action": event_action,
            "dedup_key": dedup_key,
            "payload": {
                "summary": (
                    f"Compliance {status}: {framework}/{control_id} "
                    f"-- severity={severity}, resource={resource}"
                ),
                "source": "warlock-grc",
                "severity": _PD_SEVERITY_MAP.get(severity, "warning"),
                "component": control_id,
                "group": framework,
                "class": "compliance",
                "custom_details": {
                    "event_type": event.event_type,
                    "payload_id": event.payload_id,
                    "severity": severity,
                    "status": status,
                    "resource": resource,
                    "framework": framework,
                    "control_id": control_id,
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                },
            },
        }

    # ------------------------------------------------------------------
    # Delivery with retry
    # ------------------------------------------------------------------

    def _deliver(self, event: Any) -> None:
        """POST to PagerDuty Events API v2 with retry + backoff."""
        if not _HAS_HTTPX:
            log.error("httpx not installed -- cannot deliver PagerDuty notification")
            return

        payload = self._build_payload(event)
        body = json.dumps(payload, default=str).encode()
        headers = {"Content-Type": "application/json"}

        for attempt in range(_MAX_RETRIES):
            try:
                resp = httpx.post(_PD_EVENTS_URL, content=body, headers=headers, timeout=_TIMEOUT)
                resp.raise_for_status()
                log.debug(
                    "PagerDuty event delivered: event=%s dedup_key=%s action=%s status=%d",
                    event.event_type,
                    payload["dedup_key"],
                    payload["event_action"],
                    resp.status_code,
                )
                return
            except Exception as exc:
                wait = 2**attempt  # 1s, 2s, 4s
                if attempt < _MAX_RETRIES - 1:
                    log.warning(
                        "PagerDuty POST failed (attempt %d/%d): %s -- retrying in %ds",
                        attempt + 1,
                        _MAX_RETRIES,
                        exc,
                        wait,
                    )
                    time.sleep(wait)
                else:
                    log.error(
                        "PagerDuty POST failed after %d attempts: %s",
                        _MAX_RETRIES,
                        exc,
                    )
