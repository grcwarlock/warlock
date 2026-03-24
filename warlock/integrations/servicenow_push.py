"""Push incidents and change requests to ServiceNow via the Table API.

Provides a ``ServiceNowClient`` that creates incidents from findings,
creates change requests from POA&Ms, checks ticket status, and closes
tickets.  Uses basic auth with the outbound instance credentials from
``get_settings()``.
"""

from __future__ import annotations

import logging
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

# Warlock severity -> ServiceNow urgency (1=High, 2=Medium, 3=Low)
_URGENCY_MAP: dict[str, str] = {
    "critical": "1",
    "high": "1",
    "medium": "2",
    "low": "3",
    "info": "3",
}

# Warlock severity -> ServiceNow impact
_IMPACT_MAP: dict[str, str] = {
    "critical": "1",
    "high": "2",
    "medium": "2",
    "low": "3",
    "info": "3",
}


class ServiceNowClientError(Exception):
    """Raised when a ServiceNow API operation fails."""


class ServiceNowClient:
    """ServiceNow integration client for pushing incidents and change requests.

    Reads configuration from ``get_settings()``:
        - ``servicenow_outbound_instance``
        - ``servicenow_outbound_username``
        - ``servicenow_outbound_password``
        - ``servicenow_assignment_group`` (optional)
    """

    def __init__(
        self,
        *,
        instance: str | None = None,
        username: str | None = None,
        password: str | None = None,
        assignment_group: str | None = None,
    ) -> None:
        if not _HAS_HTTPX:
            raise ServiceNowClientError("httpx is required for ServiceNow integration")

        settings = get_settings()
        self._instance = (instance or settings.servicenow_outbound_instance).strip()
        self._username = (username or settings.servicenow_outbound_username).strip()
        self._password = (password or settings.servicenow_outbound_password).strip()
        self._assignment_group = (assignment_group or settings.servicenow_assignment_group).strip()

        if not self._instance or not self._username or not self._password:
            raise ServiceNowClientError(
                "ServiceNow integration requires instance, username, and password"
            )

    @property
    def _base_url(self) -> str:
        return f"https://{self._instance}.service-now.com"

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _auth(self) -> tuple[str, str]:
        return (self._username, self._password)

    # ------------------------------------------------------------------
    # HTTP helper with retry
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
                    auth=self._auth(),
                    json=json_data,
                    params=params,
                    timeout=_TIMEOUT,
                )
                resp.raise_for_status()
                return resp.json()
            except Exception as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    import time

                    wait = 2**attempt
                    log.warning(
                        "ServiceNow %s %s failed (attempt %d/%d): %s -- retrying in %ds",
                        method,
                        url,
                        attempt + 1,
                        _MAX_RETRIES,
                        exc,
                        wait,
                    )
                    time.sleep(wait)

        raise ServiceNowClientError(
            f"ServiceNow {method} {url} failed after {_MAX_RETRIES} attempts: {last_exc}"
        )

    # ------------------------------------------------------------------
    # Incident operations
    # ------------------------------------------------------------------

    def push_incident(self, finding_dict: dict[str, Any]) -> dict[str, Any]:
        """Create a ServiceNow incident from a finding dict.

        Args:
            finding_dict: Must contain ``title`` and ``severity``.
                Optional: ``description``, ``source``, ``resource_id``,
                ``finding_id``.

        Returns:
            Dict with ``sys_id``, ``number``, and ``link``.
        """
        title = finding_dict.get("title", "Untitled Finding")
        severity = (finding_dict.get("severity") or "medium").lower()
        source = finding_dict.get("source", "warlock")
        resource_id = finding_dict.get("resource_id", "N/A")
        finding_id = finding_dict.get("finding_id") or finding_dict.get("id", "N/A")

        short_description = f"[Warlock] {title}"
        if len(short_description) > 160:
            short_description = short_description[:157] + "..."

        description = (
            f"Compliance finding detected by Warlock GRC.\n\n"
            f"Finding ID: {finding_id}\n"
            f"Source: {source}\n"
            f"Severity: {severity}\n"
            f"Resource: {resource_id}\n\n"
            f"{finding_dict.get('description', '')}"
        )

        payload: dict[str, Any] = {
            "short_description": short_description,
            "description": description,
            "urgency": _URGENCY_MAP.get(severity, "2"),
            "impact": _IMPACT_MAP.get(severity, "2"),
            "category": "Compliance",
            "subcategory": "GRC Finding",
        }

        if self._assignment_group:
            payload["assignment_group"] = self._assignment_group

        url = f"{self._base_url}/api/now/table/incident"
        data = self._request("POST", url, json_data=payload)
        result = data.get("result", {})

        sys_id = result.get("sys_id", "")
        number = result.get("number", "")
        log.info(
            "ServiceNow incident created: %s (sys_id=%s, finding_id=%s)",
            number,
            sys_id,
            finding_id,
        )
        return {
            "sys_id": sys_id,
            "number": number,
            "link": f"{self._base_url}/nav_to.do?uri=incident.do?sys_id={sys_id}",
        }

    # ------------------------------------------------------------------
    # Change request operations
    # ------------------------------------------------------------------

    def push_change_request(self, poam_dict: dict[str, Any]) -> dict[str, Any]:
        """Create a ServiceNow change request from a POA&M dict.

        Args:
            poam_dict: Must contain ``title``.  Optional: ``milestone``,
                ``scheduled_completion``, ``responsible_party``,
                ``weakness_description``, ``poam_id``, ``risk_level``.

        Returns:
            Dict with ``sys_id``, ``number``, and ``link``.
        """
        title = poam_dict.get("title", "Untitled POA&M")
        milestone = poam_dict.get("milestone", "N/A")
        completion = poam_dict.get("scheduled_completion", "N/A")
        responsible = poam_dict.get("responsible_party", "N/A")
        poam_id = poam_dict.get("poam_id") or poam_dict.get("id", "N/A")
        weakness = poam_dict.get("weakness_description", "")
        risk_level = poam_dict.get("risk_level", "moderate")

        short_description = f"[Warlock POA&M] {title}"
        if len(short_description) > 160:
            short_description = short_description[:157] + "..."

        description = (
            f"POA&M remediation plan from Warlock GRC.\n\n"
            f"POA&M ID: {poam_id}\n"
            f"Milestone: {milestone}\n"
            f"Scheduled Completion: {completion}\n"
            f"Responsible Party: {responsible}\n"
            f"Risk Level: {risk_level}\n\n"
            f"{weakness}"
        )

        # Map risk_level to change request risk
        risk_map = {"low": "4", "moderate": "3", "high": "2", "critical": "1"}

        payload: dict[str, Any] = {
            "short_description": short_description,
            "description": description,
            "type": "Standard",
            "risk": risk_map.get(risk_level.lower(), "3"),
            "category": "Compliance",
        }

        if self._assignment_group:
            payload["assignment_group"] = self._assignment_group

        url = f"{self._base_url}/api/now/table/change_request"
        data = self._request("POST", url, json_data=payload)
        result = data.get("result", {})

        sys_id = result.get("sys_id", "")
        number = result.get("number", "")
        log.info(
            "ServiceNow change request created: %s (sys_id=%s, poam_id=%s)",
            number,
            sys_id,
            poam_id,
        )
        return {
            "sys_id": sys_id,
            "number": number,
            "link": f"{self._base_url}/nav_to.do?uri=change_request.do?sys_id={sys_id}",
        }

    # ------------------------------------------------------------------
    # Status and close operations
    # ------------------------------------------------------------------

    def get_status(self, sys_id: str) -> dict[str, Any]:
        """Check the status of a ServiceNow ticket by sys_id.

        Returns:
            Dict with ``sys_id``, ``number``, ``state``, ``state_label``,
            ``assigned_to``, and ``updated_on``.
        """
        if not sys_id:
            raise ServiceNowClientError("sys_id is required")

        url = f"{self._base_url}/api/now/table/incident/{sys_id}"
        params = {
            "sysparm_fields": "sys_id,number,state,assigned_to,sys_updated_on",
        }
        data = self._request("GET", url, params=params)
        result = data.get("result", {})

        # ServiceNow incident states: 1=New, 2=In Progress, 3=On Hold,
        # 6=Resolved, 7=Closed, 8=Canceled
        state_labels = {
            "1": "New",
            "2": "In Progress",
            "3": "On Hold",
            "6": "Resolved",
            "7": "Closed",
            "8": "Canceled",
        }
        state = str(result.get("state", ""))

        return {
            "sys_id": result.get("sys_id", sys_id),
            "number": result.get("number", ""),
            "state": state,
            "state_label": state_labels.get(state, f"Unknown ({state})"),
            "assigned_to": result.get("assigned_to", ""),
            "updated_on": result.get("sys_updated_on", ""),
        }

    def close_ticket(self, sys_id: str, close_notes: str) -> dict[str, Any]:
        """Close a ServiceNow incident.

        Args:
            sys_id: The ServiceNow sys_id of the incident.
            close_notes: Resolution notes.

        Returns:
            Dict with ``sys_id``, ``number``, ``state``, and ``state_label``.
        """
        if not sys_id:
            raise ServiceNowClientError("sys_id is required")
        if not close_notes:
            raise ServiceNowClientError("close_notes is required")

        url = f"{self._base_url}/api/now/table/incident/{sys_id}"
        payload = {
            "state": "7",  # Closed
            "close_code": "Solved (Permanently)",
            "close_notes": close_notes,
        }

        data = self._request("PATCH", url, json_data=payload)
        result = data.get("result", {})
        number = result.get("number", "")

        log.info("ServiceNow incident closed: %s (sys_id=%s)", number, sys_id)
        return {
            "sys_id": sys_id,
            "number": number,
            "state": "7",
            "state_label": "Closed",
        }

    # ------------------------------------------------------------------
    # Configuration check
    # ------------------------------------------------------------------

    @staticmethod
    def is_configured() -> bool:
        """Return True if ServiceNow outbound settings are present."""
        try:
            settings = get_settings()
            return bool(
                settings.servicenow_outbound_instance
                and settings.servicenow_outbound_username
                and settings.servicenow_outbound_password
            )
        except Exception:
            return False
