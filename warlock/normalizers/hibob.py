"""HiBob normalizer — transforms raw HiBob API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class HiBobNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for HiBob."""

    HANDLERS: dict[str, str] = {
        "hibob_employees": "_normalize_hibob_employees",
        "hibob_custom_tables": "_normalize_hibob_custom_tables",
        "hibob_timeoff": "_normalize_hibob_timeoff",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "hibob" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "hibob",
            "source_type": SourceType.HRIS,
            "provider": "hibob",
            "observed_at": raw.observed_at,
        }

    def _normalize_hibob_employees(self, raw: RawEventData) -> list[FindingData]:
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
                    title="HiBob hibob employees: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="hibob_employees",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_hibob_custom_tables(self, raw: RawEventData) -> list[FindingData]:
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
                    title="HiBob hibob custom tables: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="hibob_custom_tables",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_hibob_timeoff(self, raw: RawEventData) -> list[FindingData]:
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
                    title="HiBob hibob timeoff: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="hibob_timeoff",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(HiBobNormalizer())
