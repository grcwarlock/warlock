"""NetSuite normalizer — transforms raw NetSuite API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class NetSuiteNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for NetSuite."""

    HANDLERS: dict[str, str] = {
        "netsuite_employees": "_normalize_netsuite_employees",
        "netsuite_vendors": "_normalize_netsuite_vendors",
        "netsuite_purchase_orders": "_normalize_netsuite_purchase_orders",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "netsuite" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "netsuite",
            "source_type": SourceType.FINANCE,
            "provider": "netsuite",
            "observed_at": raw.observed_at,
        }

    def _normalize_netsuite_employees(self, raw: RawEventData) -> list[FindingData]:
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
                    title="NetSuite netsuite employees: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="netsuite_employees",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_netsuite_vendors(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="alert",
                    title="NetSuite netsuite vendors: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="netsuite_vendors",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_netsuite_purchase_orders(self, raw: RawEventData) -> list[FindingData]:
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
                    title="NetSuite netsuite purchase orders: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="netsuite_purchase_orders",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(NetSuiteNormalizer())
