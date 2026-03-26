"""Lever normalizer — transforms raw Lever API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class LeverNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Lever."""

    HANDLERS: dict[str, str] = {
        "lever_opportunities": "_normalize_lever_opportunities",
        "lever_postings": "_normalize_lever_postings",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "lever" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "lever",
            "source_type": SourceType.RECRUITING,
            "provider": "lever",
            "observed_at": raw.observed_at,
        }

    def _normalize_lever_opportunities(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Lever lever opportunities: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="lever_opportunities",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_lever_postings(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Lever lever postings: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="lever_postings",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(LeverNormalizer())
