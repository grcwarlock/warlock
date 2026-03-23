"""Opsgenie normalizer — transforms raw Opsgenie API responses into Findings.

Normalizes alerts and incidents (as alerts), on-call schedules and escalations
(as inventory).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_OPSGENIE_SEVERITY_MAP: dict[str, str] = {
    "P1": "critical",
    "P2": "high",
    "P3": "medium",
    "P4": "low",
    "P5": "info",
}


class OpsgenieNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "opsgenie_alerts": "_normalize_alerts",
        "opsgenie_incidents": "_normalize_incidents",
        "opsgenie_schedules": "_normalize_schedules",
        "opsgenie_escalations": "_normalize_escalations",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "opsgenie" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Opsgenie findings."""
        return {
            "raw_event_id": raw.id,
            "source": "opsgenie",
            "source_type": SourceType.ITSM,
            "provider": "opsgenie",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Alerts --

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for alert in items:
            alert_id = str(alert.get("id", ""))
            message = alert.get("message", "untitled")
            status = alert.get("status", "unknown")
            priority = alert.get("priority", "P3")
            source_name = alert.get("source", "")

            severity = _OPSGENIE_SEVERITY_MAP.get(priority, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Opsgenie alert: {message}",
                    detail={
                        "alert_id": alert_id,
                        "message": message,
                        "status": status,
                        "priority": priority,
                        "source": source_name,
                        "tags": alert.get("tags", []),
                        "created_at": alert.get("createdAt", ""),
                    },
                    resource_id=alert_id,
                    resource_type="opsgenie_alert",
                    resource_name=message,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    # -- Incidents --

    def _normalize_incidents(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for incident in items:
            incident_id = str(incident.get("id", ""))
            message = incident.get("message", "untitled")
            status = incident.get("status", "unknown")
            priority = incident.get("priority", "P3")

            severity = _OPSGENIE_SEVERITY_MAP.get(priority, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Opsgenie incident: {message}",
                    detail={
                        "incident_id": incident_id,
                        "message": message,
                        "status": status,
                        "priority": priority,
                        "tags": incident.get("tags", []),
                        "created_at": incident.get("createdAt", ""),
                    },
                    resource_id=incident_id,
                    resource_type="opsgenie_incident",
                    resource_name=message,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    # -- Schedules --

    def _normalize_schedules(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for schedule in items:
            schedule_id = str(schedule.get("id", ""))
            name = schedule.get("name", "unknown")
            timezone_name = schedule.get("timezone", "")
            enabled = schedule.get("enabled", True)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Opsgenie schedule: {name}",
                    detail={
                        "schedule_id": schedule_id,
                        "name": name,
                        "timezone": timezone_name,
                        "enabled": enabled,
                        "description": schedule.get("description", ""),
                    },
                    resource_id=schedule_id,
                    resource_type="opsgenie_schedule",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    # -- Escalations --

    def _normalize_escalations(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for escalation in items:
            escalation_id = str(escalation.get("id", ""))
            name = escalation.get("name", "unknown")
            rules = escalation.get("rules", [])

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Opsgenie escalation: {name}",
                    detail={
                        "escalation_id": escalation_id,
                        "name": name,
                        "rule_count": len(rules),
                        "description": escalation.get("description", ""),
                    },
                    resource_id=escalation_id,
                    resource_type="opsgenie_escalation",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(OpsgenieNormalizer())
