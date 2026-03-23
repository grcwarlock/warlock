"""Drata normalizer — transforms raw Drata API responses into Findings.

Normalizes controls as inventory; monitors with failures as policy_violation;
personnel as inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class DrataNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "drata_controls": "_normalize_controls",
        "drata_monitors": "_normalize_monitors",
        "drata_personnel": "_normalize_personnel",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "drata" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "drata",
            "source_type": SourceType.GRC,
            "provider": "drata",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_controls(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for control in items:
            control_id = str(control.get("id", control.get("slug", "")))
            name = control.get("name", control.get("title", "unknown"))
            status = control.get("status", "passing")
            passing = str(status).lower() in ("passing", "pass", "compliant", "active")

            obs_type = "policy_violation" if not passing else "inventory"
            severity = "high" if not passing else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Drata control: {name}",
                    detail={
                        "control_id": control_id,
                        "name": name,
                        "status": status,
                        "description": control.get("description", ""),
                        "framework": control.get("framework", ""),
                        "owner": control.get("owner", {}).get("name", "")
                        if isinstance(control.get("owner"), dict)
                        else "",
                        "due_date": control.get("dueDate", ""),
                    },
                    resource_id=control_id,
                    resource_type="drata_control",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_monitors(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for monitor in items:
            monitor_id = str(monitor.get("id", ""))
            name = monitor.get("name", monitor.get("title", "unknown"))
            status = monitor.get("status", "passing")
            failing = str(status).lower() in ("failing", "fail", "failed", "error")

            obs_type = "policy_violation" if failing else "inventory"
            severity = "high" if failing else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Drata monitor: {name}",
                    detail={
                        "monitor_id": monitor_id,
                        "name": name,
                        "status": status,
                        "description": monitor.get("description", ""),
                        "last_run": monitor.get("lastRunAt", ""),
                        "control_id": str(monitor.get("controlId", "")),
                    },
                    resource_id=monitor_id,
                    resource_type="drata_monitor",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_personnel(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for person in items:
            person_id = str(person.get("id", ""))
            name = f"{person.get('firstName', '')} {person.get('lastName', '')}".strip()
            email = person.get("email", "unknown")
            training_status = person.get(
                "trainingStatus", person.get("securityTrainingStatus", "incomplete")
            )

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Drata personnel: {name or email}",
                    detail={
                        "person_id": person_id,
                        "name": name,
                        "email": email,
                        "role": person.get("role", person.get("jobTitle", "")),
                        "department": person.get("department", ""),
                        "training_status": training_status,
                        "employee_type": person.get("employeeType", ""),
                    },
                    resource_id=person_id,
                    resource_type="drata_personnel",
                    resource_name=name or email,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(DrataNormalizer())
