"""Ironclad normalizer — transforms raw Ironclad API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class IroncladNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Ironclad."""

    HANDLERS: dict[str, str] = {
        "ironclad_workflows": "_normalize_ironclad_workflows",
        "ironclad_records": "_normalize_ironclad_records",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "ironclad" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "ironclad",
            "source_type": SourceType.LEGAL,
            "provider": "ironclad",
            "observed_at": raw.observed_at,
        }

    def _normalize_ironclad_workflows(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Ironclad ironclad workflows: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="ironclad_workflows",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_ironclad_records(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Ironclad ironclad records: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="ironclad_records",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(IroncladNormalizer())
