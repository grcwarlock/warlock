"""Secureframe normalizer — transforms raw Secureframe API responses into Findings.

Normalizes controls as inventory/policy_violation; tests as policy_violation when
failing; personnel as inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SecureframeNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "secureframe_controls": "_normalize_controls",
        "secureframe_tests": "_normalize_tests",
        "secureframe_personnel": "_normalize_personnel",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "secureframe" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "secureframe",
            "source_type": SourceType.GRC,
            "provider": "secureframe",
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
            passing = str(status).lower() in (
                "passing",
                "pass",
                "compliant",
                "active",
                "implemented",
            )

            obs_type = "policy_violation" if not passing else "inventory"
            severity = "high" if not passing else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Secureframe control: {name}",
                    detail={
                        "control_id": control_id,
                        "name": name,
                        "status": status,
                        "description": control.get("description", ""),
                        "framework": control.get("framework", control.get("frameworkName", "")),
                        "owner": control.get("owner", ""),
                        "due_date": control.get("dueDate", control.get("due_date", "")),
                    },
                    resource_id=control_id,
                    resource_type="secureframe_control",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_tests(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for test in items:
            test_id = str(test.get("id", ""))
            name = test.get("name", test.get("title", "unknown"))
            status = test.get("status", "passing")
            failing = str(status).lower() in (
                "failing",
                "fail",
                "failed",
                "error",
                "na",
                "not_applicable",
            )

            obs_type = "policy_violation" if failing else "inventory"
            severity = "high" if failing else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Secureframe test: {name}",
                    detail={
                        "test_id": test_id,
                        "name": name,
                        "status": status,
                        "description": test.get("description", ""),
                        "control_id": str(test.get("controlId", test.get("control_id", ""))),
                        "last_run": test.get("lastRunAt", test.get("last_run_at", "")),
                        "remediation": test.get(
                            "remediationGuidance", test.get("remediation_guidance", "")
                        ),
                    },
                    resource_id=test_id,
                    resource_type="secureframe_test",
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
            name = person.get(
                "name", f"{person.get('firstName', '')} {person.get('lastName', '')}".strip()
            )
            email = person.get("email", "unknown")
            employment_status = person.get("employmentStatus", person.get("status", "active"))
            training_completed = person.get(
                "securityTrainingCompleted", person.get("trainingCompleted", False)
            )

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Secureframe personnel: {name or email}",
                    detail={
                        "person_id": person_id,
                        "name": name,
                        "email": email,
                        "role": person.get("role", person.get("jobTitle", "")),
                        "department": person.get("department", ""),
                        "employment_status": employment_status,
                        "training_completed": training_completed,
                        "start_date": person.get("startDate", person.get("start_date", "")),
                    },
                    resource_id=person_id,
                    resource_type="secureframe_personnel",
                    resource_name=name or email,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SecureframeNormalizer())
