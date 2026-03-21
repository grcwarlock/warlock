"""BambooHR normalizer — transforms raw BambooHR API responses into Findings.

Handles employee directory, employee details, and change tracking.
Flags terminated employees still active, missing managers, missing required
fields, and recent terminations for access review.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Fields that every employee record should have populated
_REQUIRED_FIELDS = {"department", "jobTitle"}

# Number of days to flag recent terminations for access review
_RECENT_TERMINATION_DAYS = 30


class BambooHRNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "bamboohr_employees": "_normalize_employees",
        "bamboohr_directory": "_normalize_directory",
        "bamboohr_changes": "_normalize_changes",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "bamboohr" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all BambooHR findings."""
        return {
            "raw_event_id": raw.id,
            "source": "bamboohr",
            "source_type": SourceType.HRIS,
            "provider": "bamboohr",
            "observed_at": raw.observed_at,
        }

    # -- Employees --

    def _normalize_employees(self, raw: RawEventData) -> list[FindingData]:
        """Normalize employee records; flag compliance issues."""
        findings = []
        employees = raw.raw_data.get("employees", [])
        now = datetime.now(timezone.utc)

        for emp in employees:
            emp_id = str(emp.get("id", ""))
            display_name = emp.get("displayName", "")
            status = emp.get("status", "")
            department = emp.get("department", "")
            job_title = emp.get("jobTitle", "")
            hire_date = emp.get("hireDate", "")
            termination_date = emp.get("terminationDate", "")
            supervisor = emp.get("supervisor", "")
            supervisor_id = emp.get("supervisorId", "")
            work_email = emp.get("workEmail", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Employee: {display_name} ({status})",
                    detail={
                        "employee_id": emp_id,
                        "display_name": display_name,
                        "status": status,
                        "department": department,
                        "job_title": job_title,
                        "hire_date": hire_date,
                        "termination_date": termination_date,
                        "supervisor": supervisor,
                        "work_email": work_email,
                    },
                    resource_id=emp_id,
                    resource_type="bamboohr_employee",
                    resource_name=display_name,
                    severity="info",
                )
            )

            # Flag terminated employees still marked as active
            if termination_date and status and status.lower() == "active":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Terminated employee still active: {display_name}",
                        detail={
                            "employee_id": emp_id,
                            "display_name": display_name,
                            "status": status,
                            "termination_date": termination_date,
                            "issue": "Employee has a termination date but status is still Active "
                            "— access may not have been revoked",
                        },
                        resource_id=emp_id,
                        resource_type="bamboohr_employee",
                        resource_name=display_name,
                        severity="high",
                    )
                )

            # Flag employees without manager assigned
            if not supervisor and not supervisor_id and status and status.lower() == "active":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Employee without manager: {display_name}",
                        detail={
                            "employee_id": emp_id,
                            "display_name": display_name,
                            "status": status,
                            "department": department,
                            "issue": "Active employee has no manager assigned — "
                            "access approvals and reviews may lack oversight",
                        },
                        resource_id=emp_id,
                        resource_type="bamboohr_employee",
                        resource_name=display_name,
                        severity="medium",
                    )
                )

            # Flag missing required fields
            missing = []
            if not department:
                missing.append("department")
            if not job_title:
                missing.append("jobTitle")
            if missing and status and status.lower() == "active":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Missing fields for {display_name}: {', '.join(missing)}",
                        detail={
                            "employee_id": emp_id,
                            "display_name": display_name,
                            "status": status,
                            "missing_fields": missing,
                            "issue": "Required employee fields are empty — impacts role-based "
                            "access provisioning and audit reporting",
                        },
                        resource_id=emp_id,
                        resource_type="bamboohr_employee",
                        resource_name=display_name,
                        severity="low",
                    )
                )

            # Flag recent terminations for access review
            if termination_date and status and status.lower() != "active":
                try:
                    term_dt = datetime.strptime(termination_date, "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                    days_since = (now - term_dt).days
                    if 0 <= days_since <= _RECENT_TERMINATION_DAYS:
                        findings.append(
                            FindingData(
                                **self._base(raw),
                                observation_type="alert",
                                title=f"Recent termination: {display_name} ({days_since}d ago)",
                                detail={
                                    "employee_id": emp_id,
                                    "display_name": display_name,
                                    "termination_date": termination_date,
                                    "days_since_termination": days_since,
                                    "issue": "Recently terminated employee — verify all system "
                                    "access has been revoked",
                                },
                                resource_id=emp_id,
                                resource_type="bamboohr_employee",
                                resource_name=display_name,
                                severity="medium",
                            )
                        )
                except (ValueError, TypeError):
                    pass

        return findings

    # -- Directory --

    def _normalize_directory(self, raw: RawEventData) -> list[FindingData]:
        """Inventory directory entries."""
        findings = []
        employees = raw.raw_data.get("employees", [])

        for emp in employees:
            emp_id = str(emp.get("id", ""))
            display_name = emp.get("displayName", "")
            department = emp.get("department", "")
            job_title = emp.get("jobTitle", "")
            location = emp.get("location", "")
            work_email = emp.get("workEmail", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Directory: {display_name} — {department}",
                    detail={
                        "employee_id": emp_id,
                        "display_name": display_name,
                        "department": department,
                        "job_title": job_title,
                        "location": location,
                        "work_email": work_email,
                    },
                    resource_id=emp_id,
                    resource_type="bamboohr_directory_entry",
                    resource_name=display_name,
                    severity="info",
                )
            )

        return findings

    # -- Changes --

    def _normalize_changes(self, raw: RawEventData) -> list[FindingData]:
        """Normalize employee changes for audit trail."""
        findings = []
        changes = raw.raw_data.get("changes", {})

        if isinstance(changes, dict):
            for emp_id, change_data in changes.items():
                action = change_data.get("action", "")
                last_changed = change_data.get("lastChanged", "")

                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Employee change: {action} (ID: {emp_id})",
                        detail={
                            "employee_id": str(emp_id),
                            "action": action,
                            "last_changed": last_changed,
                        },
                        resource_id=str(emp_id),
                        resource_type="bamboohr_change",
                        resource_name=f"employee_{emp_id}",
                        severity="info" if action != "Deleted" else "medium",
                    )
                )

        return findings


# Register
registry.register(BambooHRNormalizer())
