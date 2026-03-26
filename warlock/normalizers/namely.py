"""Namely normalizer — transforms raw Namely API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class NamelyNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Namely."""

    HANDLERS: dict[str, str] = {
        "namely_profiles": "_normalize_namely_profiles",
        "namely_groups": "_normalize_namely_groups",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "namely" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "namely",
            "source_type": SourceType.HRIS,
            "provider": "namely",
            "observed_at": raw.observed_at,
        }

    def _normalize_namely_profiles(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Namely namely profiles: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="namely_profiles",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_namely_groups(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Namely namely groups: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="namely_groups",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(NamelyNormalizer())
