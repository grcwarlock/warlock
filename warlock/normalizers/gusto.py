"""Gusto normalizer — transforms raw Gusto API responses into Findings.

Handles employees, payroll, and company info.
Flags: terminated employees still active, missing department assignment, payroll anomalies.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class GustoNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "gusto_employees": "_normalize_employees",
        "gusto_payroll": "_normalize_payroll",
        "gusto_company": "_normalize_company",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "gusto" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Gusto findings."""
        return {
            "raw_event_id": raw.id,
            "source": "gusto",
            "source_type": SourceType.HRIS,
            "provider": "gusto",
            "observed_at": raw.observed_at,
        }

    # -- Employees --

    def _normalize_employees(self, raw: RawEventData) -> list[FindingData]:
        """Inventory employees; flag terminated still active, missing department."""
        findings = []
        employees = raw.raw_data.get("employees", [])

        for emp in employees:
            emp_id = str(emp.get("id", ""))
            first_name = emp.get("first_name", "")
            last_name = emp.get("last_name", "")
            full_name = f"{first_name} {last_name}".strip()
            email = emp.get("email", "")
            status = emp.get("current_employment_status", "")
            department = emp.get("department", "")
            hire_date = emp.get("date_of_hire", "")
            termination_date = emp.get("termination_date", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Gusto employee: {full_name} ({status})",
                    detail={
                        "employee_id": emp_id,
                        "name": full_name,
                        "email": email,
                        "status": status,
                        "department": department,
                        "hire_date": hire_date,
                        "termination_date": termination_date,
                    },
                    resource_id=emp_id,
                    resource_type="gusto_employee",
                    resource_name=full_name or email,
                    severity="info",
                )
            )

            # Flag terminated employees that still show as active
            if termination_date and status == "active":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Terminated employee still active: {full_name}",
                        detail={
                            "employee_id": emp_id,
                            "name": full_name,
                            "email": email,
                            "status": status,
                            "termination_date": termination_date,
                            "issue": "Employee has a termination date but status is still active — access may not be revoked",
                        },
                        resource_id=emp_id,
                        resource_type="gusto_employee",
                        resource_name=full_name or email,
                        severity="high",
                    )
                )

            # Flag missing department assignment
            if not department and status == "active":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Employee missing department: {full_name}",
                        detail={
                            "employee_id": emp_id,
                            "name": full_name,
                            "email": email,
                            "status": status,
                            "issue": "Active employee has no department assigned — RBAC and access reviews cannot be scoped correctly",
                        },
                        resource_id=emp_id,
                        resource_type="gusto_employee",
                        resource_name=full_name or email,
                        severity="medium",
                    )
                )

        return findings

    # -- Payroll --

    def _normalize_payroll(self, raw: RawEventData) -> list[FindingData]:
        """Inventory payrolls; flag anomalies."""
        findings = []
        payrolls = raw.raw_data.get("payrolls", [])

        for payroll in payrolls:
            payroll_id = str(payroll.get("id", ""))
            pay_period_start = payroll.get("pay_period", {}).get("start_date", "")
            pay_period_end = payroll.get("pay_period", {}).get("end_date", "")
            processed = payroll.get("processed", False)
            total_net_pay = payroll.get("totals", {}).get("net_pay", "0")
            employee_count = len(payroll.get("employee_compensations", []))

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Gusto payroll: {pay_period_start} to {pay_period_end}",
                    detail={
                        "payroll_id": payroll_id,
                        "pay_period_start": pay_period_start,
                        "pay_period_end": pay_period_end,
                        "processed": processed,
                        "total_net_pay": total_net_pay,
                        "employee_count": employee_count,
                    },
                    resource_id=payroll_id,
                    resource_type="gusto_payroll",
                    resource_name=f"payroll:{pay_period_start}",
                    severity="info",
                )
            )

            # Flag unprocessed payrolls with past end dates
            if not processed and pay_period_end:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Unprocessed payroll: {pay_period_start} to {pay_period_end}",
                        detail={
                            "payroll_id": payroll_id,
                            "pay_period_end": pay_period_end,
                            "processed": False,
                            "issue": "Payroll period has ended but payroll has not been processed — potential compliance issue",
                        },
                        resource_id=payroll_id,
                        resource_type="gusto_payroll",
                        resource_name=f"payroll:{pay_period_start}",
                        severity="medium",
                    )
                )

        return findings

    # -- Company --

    def _normalize_company(self, raw: RawEventData) -> list[FindingData]:
        """Inventory company info."""
        findings = []
        company = raw.raw_data.get("company", {})

        company_id = str(company.get("id", ""))
        name = company.get("name", "")
        ein = company.get("ein", "")
        entity_type = company.get("entity_type", "")

        findings.append(
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Gusto company: {name}",
                detail={
                    "company_id": company_id,
                    "name": name,
                    "ein_present": bool(ein),
                    "entity_type": entity_type,
                },
                resource_id=company_id,
                resource_type="gusto_company",
                resource_name=name,
                severity="info",
            )
        )

        return findings


# Register
registry.register(GustoNormalizer())
