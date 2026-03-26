"""Xero (Payroll) normalizer — transforms raw Xero (Payroll) API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class XeroPayrollNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Xero (Payroll)."""

    HANDLERS: dict[str, str] = {
        "xero_employees": "_normalize_xero_employees",
        "xero_pay_runs": "_normalize_xero_pay_runs",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "xero_payroll" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "xero_payroll",
            "source_type": SourceType.HRIS,
            "provider": "xero_payroll",
            "observed_at": raw.observed_at,
        }

    def _normalize_xero_employees(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])
        if isinstance(items, dict):
            items = [items]

        for item in items:
            item_id = str(item.get("id", item.get("name", item.get("key", ""))))
            item_name = str(item.get("name", item.get("label", item.get("title", item_id))))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title="Xero (Payroll) xero employees: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="xero_employees",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_xero_pay_runs(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])
        if isinstance(items, dict):
            items = [items]

        for item in items:
            item_id = str(item.get("id", item.get("name", item.get("key", ""))))
            item_name = str(item.get("name", item.get("label", item.get("title", item_id))))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title="Xero (Payroll) xero pay runs: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="xero_pay_runs",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(XeroPayrollNormalizer())
