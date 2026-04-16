"""EventBus subscriber that creates ServiceNow incidents for compliance events.

Subscribes to ``control.assessed`` events, filters by severity, and creates
ServiceNow incidents via the Table API.  Deduplicates by querying for existing
incidents with the same short_description before creating new ones.
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

# Map Warlock severity to ServiceNow urgency/impact (1=High, 2=Medium, 3=Low)
_SNOW_URGENCY_MAP: dict[str, str] = {
    "critical": "1",
    "high": "1",
    "medium": "2",
    "low": "3",
    "info": "3",
}

_SNOW_IMPACT_MAP: dict[str, str] = {
    "critical": "1",
    "high": "2",
    "medium": "2",
    "low": "3",
    "info": "3",
}


class ServiceNowNotifier:
    """EventBus subscriber that creates ServiceNow incidents for compliance events.

    Config env vars:
        WLK_SERVICENOW_INSTANCE         -- Instance name (e.g. "company" for company.service-now.com)
        WLK_SERVICENOW_USERNAME          -- ServiceNow API username
        WLK_SERVICENOW_PASSWORD          -- ServiceNow API password
        WLK_SERVICENOW_EVENTS            -- Event types (default: "control.assessed")
        WLK_SERVICENOW_MIN_SEVERITY      -- Minimum severity (default: "high")
        WLK_SERVICENOW_ASSIGNMENT_GROUP  -- Assignment group sys_id (optional)
    """

    __name__ = "ServiceNowNotifier"

    def __init__(self) -> None:
        # N19: route password through SecretsBackend
        from warlock.connectors.secrets_backend import get_secrets_backend

        backend = get_secrets_backend()
        self._instance = os.environ.get("WLK_SERVICENOW_INSTANCE", "").strip()
        self._username = os.environ.get("WLK_SERVICENOW_USERNAME", "").strip()
        self._password = (backend.get_secret("WLK_SERVICENOW_PASSWORD") or "").strip()
        self._min_severity = os.environ.get("WLK_SERVICENOW_MIN_SEVERITY", "high").strip().lower()
        self._assignment_group = os.environ.get("WLK_SERVICENOW_ASSIGNMENT_GROUP", "").strip()

        raw_events = os.environ.get("WLK_SERVICENOW_EVENTS", "").strip()
        if raw_events:
            self._event_filter: set[str] | None = {
                e.strip() for e in raw_events.split(",") if e.strip()
            }
        else:
            self._event_filter = None

    @property
    def _base_url(self) -> str:
        return f"https://{self._instance}.service-now.com"

    # ------------------------------------------------------------------
    # EventBus handler interface
    # ------------------------------------------------------------------

    def __call__(self, event: Any) -> None:
        """Handle a PipelineEvent -- called by the EventBus."""
        try:
            if not self._instance or not self._username or not self._password:
                return
            if self._event_filter and event.event_type not in self._event_filter:
                return
            if not self._meets_severity(event):
                return
            self._deliver(event)
        except Exception:
            log.exception("ServiceNowNotifier failed for event %s", event.event_type)

    # ------------------------------------------------------------------
    # Severity filter
    # ------------------------------------------------------------------

    def _meets_severity(self, event: Any) -> bool:
        severity = (event.metadata.get("severity") or "info").lower()
        min_rank = SEVERITY_ORDER.get(self._min_severity, 0)
        event_rank = SEVERITY_ORDER.get(severity, 0)
        return event_rank >= min_rank

    # ------------------------------------------------------------------
    # Deduplication: query existing incidents
    # ------------------------------------------------------------------

    def _find_existing_incident(self, short_description: str) -> str | None:
        """Query ServiceNow for an open incident with the same short_description.

        Returns the sys_id if found, else None.
        """
        if not _HAS_HTTPX:
            return None

        url = f"{self._base_url}/api/now/table/incident"
        params = {
            "sysparm_query": (
                f"short_description={short_description}"
                "^stateNOT IN6,7,8"  # exclude Resolved, Closed, Canceled
            ),
            "sysparm_limit": "1",
            "sysparm_fields": "sys_id,number",
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            resp = httpx.get(
                url,
                headers=headers,
                params=params,
                auth=(self._username, self._password),
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            results = resp.json().get("result", [])
            if results:
                return results[0].get("sys_id")
        except Exception as exc:
            log.warning("ServiceNow dedup query failed: %s", exc)

        return None

    # ------------------------------------------------------------------
    # Incident creation
    # ------------------------------------------------------------------

    def _build_incident_payload(self, event: Any) -> tuple[str, dict[str, Any]]:
        """Build ServiceNow incident payload.  Returns (short_description, payload)."""
        metadata = event.metadata or {}
        severity = (metadata.get("severity") or "info").lower()
        framework = metadata.get("framework") or "unknown"
        control_id = metadata.get("control_id") or "unknown"
        status = metadata.get("status") or "N/A"
        resource = metadata.get("resource_id") or metadata.get("resource") or "N/A"

        short_description = f"[Warlock] {framework}/{control_id} -- {status}"

        description = (
            f"Compliance finding detected by Warlock GRC pipeline.\n\n"
            f"Framework: {framework}\n"
            f"Control: {control_id}\n"
            f"Status: {status}\n"
            f"Severity: {severity}\n"
            f"Resource: {resource}\n"
            f"Event Type: {event.event_type}\n"
            f"Payload ID: {event.payload_id}\n"
            f"Timestamp: {event.timestamp.isoformat() if event.timestamp else 'N/A'}"
        )

        payload: dict[str, Any] = {
            "short_description": short_description,
            "description": description,
            "urgency": _SNOW_URGENCY_MAP.get(severity, "2"),
            "impact": _SNOW_IMPACT_MAP.get(severity, "2"),
            "category": "Compliance",
        }

        if self._assignment_group:
            payload["assignment_group"] = self._assignment_group

        return short_description, payload

    # ------------------------------------------------------------------
    # Delivery with retry
    # ------------------------------------------------------------------

    def _deliver(self, event: Any) -> None:
        """Create a ServiceNow incident (skip if duplicate exists)."""
        if not _HAS_HTTPX:
            log.error("httpx not installed -- cannot deliver ServiceNow notification")
            return

        short_description, payload = self._build_incident_payload(event)

        # Check for existing open incident
        existing_id = self._find_existing_incident(short_description)
        if existing_id:
            log.info(
                "ServiceNow duplicate found (sys_id=%s) -- skipping creation",
                existing_id,
            )
            return

        # Create new incident
        url = f"{self._base_url}/api/now/table/incident"
        body = json.dumps(payload, default=str).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        for attempt in range(_MAX_RETRIES):
            try:
                resp = httpx.post(
                    url,
                    content=body,
                    headers=headers,
                    auth=(self._username, self._password),
                    timeout=_TIMEOUT,
                )
                resp.raise_for_status()
                result = resp.json().get("result", {})
                number = result.get("number", "unknown")
                log.info("ServiceNow incident created: %s", number)
                return
            except Exception as exc:
                wait = 2**attempt  # 1s, 2s, 4s
                if attempt < _MAX_RETRIES - 1:
                    log.warning(
                        "ServiceNow POST failed (attempt %d/%d): %s -- retrying in %ds",
                        attempt + 1,
                        _MAX_RETRIES,
                        exc,
                        wait,
                    )
                    time.sleep(wait)
                else:
                    log.error(
                        "ServiceNow POST failed after %d attempts: %s",
                        _MAX_RETRIES,
                        exc,
                    )
