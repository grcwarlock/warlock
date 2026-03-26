"""Humaans normalizer — transforms raw Humaans API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class HumaansNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Humaans."""

    HANDLERS: dict[str, str] = {
        "humaans_people": "_normalize_humaans_people",
        "humaans_time_away": "_normalize_humaans_time_away",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "humaans" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "humaans",
            "source_type": SourceType.HRIS,
            "provider": "humaans",
            "observed_at": raw.observed_at,
        }

    def _normalize_humaans_people(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Humaans humaans people: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="humaans_people",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_humaans_time_away(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Humaans humaans time away: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="humaans_time_away",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(HumaansNormalizer())
