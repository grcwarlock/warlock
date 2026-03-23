"""PagerDuty normalizer — transforms raw PagerDuty API responses into Findings.

Normalizes incidents (as alerts with urgency-mapped severity), services
(as inventory), on-call schedules (as inventory), and escalation policies
(as inventory).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class PagerDutyNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "pagerduty_incidents": "_normalize_incidents",
        "pagerduty_services": "_normalize_services",
        "pagerduty_oncalls": "_normalize_oncalls",
        "pagerduty_escalation_policies": "_normalize_escalation_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "pagerduty" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all PagerDuty findings."""
        return {
            "raw_event_id": raw.id,
            "source": "pagerduty",
            "source_type": SourceType.ITSM,
            "provider": "pagerduty",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Incidents --

    def _normalize_incidents(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for incident in items:
            urgency = incident.get("urgency", "low")
            status = incident.get("status", "unknown")
            title = incident.get("title", "untitled")
            incident_id = str(incident.get("id", ""))
            incident_number = incident.get("incident_number", "")

            # Map PagerDuty urgency to severity
            severity = "high" if urgency == "high" else "low"
            obs_type = "alert"

            service = incident.get("service", {})
            service_name = service.get("summary", "") if isinstance(service, dict) else ""

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"PagerDuty incident: {title}",
                    detail={
                        "incident_id": incident_id,
                        "incident_number": incident_number,
                        "title": title,
                        "status": status,
                        "urgency": urgency,
                        "service": service_name,
                        "created_at": incident.get("created_at", ""),
                    },
                    resource_id=incident_id,
                    resource_type="pagerduty_incident",
                    resource_name=title,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    # -- Services --

    def _normalize_services(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for service in items:
            service_id = str(service.get("id", ""))
            name = service.get("name", "unknown")
            status = service.get("status", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"PagerDuty service: {name}",
                    detail={
                        "service_id": service_id,
                        "name": name,
                        "status": status,
                        "description": service.get("description", ""),
                        "escalation_policy": service.get("escalation_policy", {}).get("summary", "")
                        if isinstance(service.get("escalation_policy"), dict)
                        else "",
                    },
                    resource_id=service_id,
                    resource_type="pagerduty_service",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    # -- On-call schedules --

    def _normalize_oncalls(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for oncall in items:
            schedule = oncall.get("schedule", {})
            schedule_name = schedule.get("summary", "unknown") if isinstance(schedule, dict) else "unknown"
            schedule_id = schedule.get("id", "") if isinstance(schedule, dict) else ""
            user = oncall.get("user", {})
            user_name = user.get("summary", "unknown") if isinstance(user, dict) else "unknown"
            escalation_level = oncall.get("escalation_level", 1)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"PagerDuty on-call: {user_name} for {schedule_name}",
                    detail={
                        "schedule_id": str(schedule_id),
                        "schedule_name": schedule_name,
                        "user": user_name,
                        "escalation_level": escalation_level,
                        "start": oncall.get("start", ""),
                        "end": oncall.get("end", ""),
                    },
                    resource_id=str(schedule_id),
                    resource_type="pagerduty_oncall",
                    resource_name=schedule_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    # -- Escalation policies --

    def _normalize_escalation_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for policy in items:
            policy_id = str(policy.get("id", ""))
            name = policy.get("name", "unknown")
            num_loops = policy.get("num_loops", 0)
            rules = policy.get("escalation_rules", [])

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"PagerDuty escalation policy: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "num_loops": num_loops,
                        "rule_count": len(rules),
                        "description": policy.get("description", ""),
                    },
                    resource_id=policy_id,
                    resource_type="pagerduty_escalation_policy",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(PagerDutyNormalizer())
