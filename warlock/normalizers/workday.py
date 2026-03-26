"""Workday normalizer — transforms raw Workday API responses into Findings.

Normalizes workers (employee inventory, termination anomalies, missing fields),
background checks, employment agreements, disciplinary actions, and job changes.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Severity mapping for disciplinary action types
DISCIPLINARY_SEVERITY: dict[str, str] = {
    "verbal_warning": "low",
    "written_warning": "medium",
    "final_warning": "high",
    "suspension": "high",
    "termination": "critical",
    "probation": "medium",
}


class WorkdayNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "workday_employees": "_normalize_employees",
        "workday_background_checks": "_normalize_background_checks",
        "workday_agreements": "_normalize_agreements",
        "workday_disciplinary": "_normalize_disciplinary",
        "workday_job_changes": "_normalize_job_changes",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "workday" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Workday findings."""
        return {
            "raw_event_id": raw.id,
            "source": "workday",
            "source_type": SourceType.HRIS,
            "provider": "workday",
            "account_id": raw.raw_data.get("tenant", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Employees --

    def _normalize_employees(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        workers = raw.raw_data.get("response", [])
        now = datetime.now(timezone.utc)

        for worker in workers:
            wid = worker.get("id", "")
            descriptor = worker.get("descriptor", "unknown")
            status = worker.get("status", "")
            hire_date = worker.get("hireDate", "")
            termination_date = worker.get("terminationDate", "")
            department = worker.get("department", "")
            manager = worker.get("manager", "")

            issues = []

            # Active worker with past termination date
            if status.lower() == "active" and termination_date:
                try:
                    term_dt = datetime.fromisoformat(termination_date.replace("Z", "+00:00"))
                    if term_dt < now:
                        issues.append("active_with_past_termination_date")
                except (ValueError, TypeError):
                    pass

            # Missing department or manager
            if not department:
                issues.append("missing_department")
            if not manager:
                issues.append("missing_manager")

            # Determine severity and observation type
            severity = "info"
            obs_type = "inventory"

            if "active_with_past_termination_date" in issues:
                severity = "high"
                obs_type = "policy_violation"
            elif "missing_department" in issues or "missing_manager" in issues:
                severity = "low"
                obs_type = "misconfiguration"

            title = f"Workday employee: {descriptor}"
            if "active_with_past_termination_date" in issues:
                title += " — Active employee with past termination date"
            elif issues:
                title += f" — {', '.join(issues)}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "worker_id": wid,
                        "descriptor": descriptor,
                        "status": status,
                        "hire_date": hire_date,
                        "termination_date": termination_date,
                        "department": department,
                        "manager": manager,
                        "issues": issues,
                    },
                    resource_id=wid,
                    resource_type="hr_employee",
                    resource_name=descriptor,
                    severity=severity,
                )
            )

        return findings

    # -- Background Checks --

    def _normalize_background_checks(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        records = raw.raw_data.get("response", [])

        for record in records:
            worker_id = record.get("worker_id", "")
            worker_name = record.get("worker_name", "unknown")
            bg = record.get("background_check", {})
            status = bg.get("status", "unknown")

            if status.lower() != "completed":
                severity = "high"
                obs_type = "policy_violation"
                title = f"Background check not completed — {worker_name}"
            else:
                severity = "info"
                obs_type = "inventory"
                title = f"Background check completed — {worker_name}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "worker_id": worker_id,
                        "worker_name": worker_name,
                        "status": status,
                        "background_check": bg,
                    },
                    resource_id=worker_id,
                    resource_type="hr_employee",
                    resource_name=worker_name,
                    severity=severity,
                )
            )

        return findings

    # -- Agreements --

    def _normalize_agreements(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        records = raw.raw_data.get("response", [])

        for record in records:
            worker_id = record.get("worker_id", "")
            worker_name = record.get("worker_name", "unknown")
            employment_agreement_signed = record.get("employment_agreement_signed", False)
            nda_signed = record.get("nda_signed", False)

            # Employment agreement check
            if not employment_agreement_signed:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Employment agreement not signed — {worker_name}",
                        detail={
                            "worker_id": worker_id,
                            "worker_name": worker_name,
                            "agreement_type": "employment_agreement",
                            "signed": False,
                        },
                        resource_id=worker_id,
                        resource_type="hr_employee",
                        resource_name=worker_name,
                        severity="medium",
                    )
                )
            else:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="inventory",
                        title=f"Employment agreement signed — {worker_name}",
                        detail={
                            "worker_id": worker_id,
                            "worker_name": worker_name,
                            "agreement_type": "employment_agreement",
                            "signed": True,
                        },
                        resource_id=worker_id,
                        resource_type="hr_employee",
                        resource_name=worker_name,
                        severity="info",
                    )
                )

            # NDA check
            if not nda_signed:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"NDA not signed — {worker_name}",
                        detail={
                            "worker_id": worker_id,
                            "worker_name": worker_name,
                            "agreement_type": "nda",
                            "signed": False,
                        },
                        resource_id=worker_id,
                        resource_type="hr_employee",
                        resource_name=worker_name,
                        severity="medium",
                    )
                )
            else:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="inventory",
                        title=f"NDA signed — {worker_name}",
                        detail={
                            "worker_id": worker_id,
                            "worker_name": worker_name,
                            "agreement_type": "nda",
                            "signed": True,
                        },
                        resource_id=worker_id,
                        resource_type="hr_employee",
                        resource_name=worker_name,
                        severity="info",
                    )
                )

        return findings

    # -- Disciplinary Actions --

    def _normalize_disciplinary(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        records = raw.raw_data.get("response", [])

        for record in records:
            worker_id = record.get("worker_id", "")
            worker_name = record.get("worker_name", "unknown")
            action_type = record.get("action_type", "unknown")
            action_date = record.get("action_date", "")
            reason = record.get("reason", "")

            severity = DISCIPLINARY_SEVERITY.get(action_type.lower(), "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Disciplinary action: {action_type} — {worker_name}",
                    detail={
                        "worker_id": worker_id,
                        "worker_name": worker_name,
                        "action_type": action_type,
                        "action_date": action_date,
                        "reason": reason,
                    },
                    resource_id=worker_id,
                    resource_type="hr_disciplinary_action",
                    resource_name=worker_name,
                    severity=severity,
                )
            )

        return findings

    # -- Job Changes --

    def _normalize_job_changes(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        records = raw.raw_data.get("response", [])

        for record in records:
            wid = record.get("id", "")
            descriptor = record.get("descriptor", "unknown")
            change_type = record.get("changeType", "unknown")
            effective_date = record.get("effectiveDate", "")
            from_position = record.get("fromPosition", "")
            to_position = record.get("toPosition", "")
            from_department = record.get("fromDepartment", "")
            to_department = record.get("toDepartment", "")

            detail: dict = {
                "worker_id": wid,
                "descriptor": descriptor,
                "change_type": change_type,
                "effective_date": effective_date,
                "from_position": from_position,
                "to_position": to_position,
                "from_department": from_department,
                "to_department": to_department,
            }

            # Transfers should note access review
            title = f"Job change ({change_type}): {descriptor}"
            if change_type.lower() == "transfer":
                detail["access_review_note"] = (
                    "Transfer detected — verify access review was triggered for department change"
                )
                title = f"Transfer: {descriptor} — {from_department} → {to_department}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=title,
                    detail=detail,
                    resource_id=wid,
                    resource_type="hr_job_change",
                    resource_name=descriptor,
                    severity="info",
                )
            )

        return findings


# Register
registry.register(WorkdayNormalizer())
