"""Zoho People normalizer — transforms raw Zoho People API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ZohoPeopleNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Zoho People."""

    HANDLERS: dict[str, str] = {
        "zoho_people_employees": "_normalize_zoho_people_employees",
        "zoho_people_attendance": "_normalize_zoho_people_attendance",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "zoho_people" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "zoho_people",
            "source_type": SourceType.HRIS,
            "provider": "zoho_people",
            "observed_at": raw.observed_at,
        }

    def _normalize_zoho_people_employees(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Zoho People zoho people employees: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="zoho_people_employees",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_zoho_people_attendance(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Zoho People zoho people attendance: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="zoho_people_attendance",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ZohoPeopleNormalizer())
