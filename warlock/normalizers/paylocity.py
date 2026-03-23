"""Paylocity normalizer — transforms raw Paylocity HRIS API responses into Findings.

Normalizes employees as inventory. Terminated employees still showing as active
in the system are emitted as access_anomaly findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class PaylocityNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Paylocity HRIS."""

    HANDLERS: dict[str, str] = {
        "paylocity_employees": "_normalize_employees",
        "paylocity_earnings": "_normalize_earnings",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "paylocity" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "paylocity",
            "source_type": SourceType.HRIS,
            "provider": "paylocity",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_employees(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for employee in items:
            emp_id = str(employee.get("employeeId", ""))
            first_name = employee.get("firstName", "")
            last_name = employee.get("lastName", "")
            display_name = f"{first_name} {last_name}".strip() or emp_id
            status = employee.get("statusCode", {})
            status_desc = status.get("description", "") if isinstance(status, dict) else str(status)
            is_terminated = "terminated" in status_desc.lower() if status_desc else False
            department = (employee.get("departmentPosition") or {}).get("departmentDescription", "")

            # Primary finding: inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Paylocity employee: {display_name}",
                    detail={
                        "employee_id": emp_id,
                        "display_name": display_name,
                        "status": status_desc,
                        "department": department,
                        "location": employee.get("primaryPayRate", {}).get("description", "")
                        if isinstance(employee.get("primaryPayRate"), dict)
                        else "",
                        "hire_date": employee.get("hireDate", ""),
                    },
                    resource_id=emp_id,
                    resource_type="paylocity_employee",
                    resource_name=display_name,
                    severity="info",
                    confidence=1.0,
                )
            )

            # Access anomaly: terminated employee still in the system as active
            if is_terminated and employee.get("isActive", False):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="access_anomaly",
                        title=f"Terminated employee still active: {display_name}",
                        detail={
                            "employee_id": emp_id,
                            "display_name": display_name,
                            "status": status_desc,
                            "department": department,
                            "termination_date": employee.get("terminationDate", ""),
                        },
                        resource_id=emp_id,
                        resource_type="paylocity_employee",
                        resource_name=display_name,
                        severity="high",
                        confidence=0.9,
                    )
                )

        return findings

    def _normalize_earnings(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for earning in items:
            earning_id = str(earning.get("id", earning.get("earningId", "")))
            name = earning.get("name", earning.get("earningCode", "unknown"))
            emp_id = str(earning.get("employeeId", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Paylocity earning: {name}",
                    detail={
                        "earning_id": earning_id,
                        "name": name,
                        "employee_id": emp_id,
                        "earning_type": earning.get("earningType", ""),
                        "start_date": earning.get("startDate", ""),
                        "end_date": earning.get("endDate", ""),
                    },
                    resource_id=earning_id,
                    resource_type="paylocity_earning",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(PaylocityNormalizer())
