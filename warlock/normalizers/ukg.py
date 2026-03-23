"""UKG normalizer — transforms raw UKG Pro API responses into Findings.

Normalizes employee records and employment records as inventory findings.
Terminated employees whose records still appear are flagged as access_anomaly.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class UKGNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "ukg_employees": "_normalize_employees",
        "ukg_employment_records": "_normalize_employment_records",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "ukg" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "ukg",
            "source_type": SourceType.HRIS,
            "provider": "ukg",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_employees(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for emp in items:
            emp_id = str(emp.get("employeeId", emp.get("id", "")))
            full_name = emp.get("fullName", emp.get("name", "unknown"))
            status = emp.get("employmentStatus", emp.get("status", "active")).lower()
            department = emp.get("department", "")
            job_title = emp.get("jobTitle", emp.get("title", ""))

            is_terminated = status in ("terminated", "inactive", "separated")
            obs_type = "access_anomaly" if is_terminated else "inventory"
            severity = "medium" if is_terminated else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"UKG employee: {full_name}",
                    detail={
                        "employee_id": emp_id,
                        "full_name": full_name,
                        "employment_status": status,
                        "department": department,
                        "job_title": job_title,
                        "hire_date": emp.get("hireDate", ""),
                        "termination_date": emp.get("terminationDate", ""),
                        "is_terminated": is_terminated,
                    },
                    resource_id=emp_id,
                    resource_type="ukg_employee",
                    resource_name=full_name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_employment_records(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for record in items:
            record_id = str(record.get("recordId", record.get("id", "")))
            emp_id = str(record.get("employeeId", ""))
            position = record.get("position", record.get("jobCode", "unknown"))
            effective_date = record.get("effectiveDate", "")
            status = record.get("status", "active").lower()
            pay_grade = record.get("payGrade", "")

            is_terminated = status in ("terminated", "inactive")
            obs_type = "access_anomaly" if is_terminated else "inventory"
            severity = "medium" if is_terminated else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"UKG employment record: {position}",
                    detail={
                        "record_id": record_id,
                        "employee_id": emp_id,
                        "position": position,
                        "effective_date": effective_date,
                        "status": status,
                        "pay_grade": pay_grade,
                        "is_terminated": is_terminated,
                    },
                    resource_id=record_id,
                    resource_type="ukg_employment_record",
                    resource_name=position,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(UKGNormalizer())
