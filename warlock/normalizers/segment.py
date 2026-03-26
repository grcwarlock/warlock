"""Segment normalizer — transforms raw Segment API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SegmentNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Segment."""

    HANDLERS: dict[str, str] = {
        "segment_sources": "_normalize_segment_sources",
        "segment_destinations": "_normalize_segment_destinations",
        "segment_tracking_plans": "_normalize_segment_tracking_plans",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "segment" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "segment",
            "source_type": SourceType.ANALYTICS,
            "provider": "segment",
            "observed_at": raw.observed_at,
        }

    def _normalize_segment_sources(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Segment segment sources: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="segment_sources",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_segment_destinations(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="policy_violation",
                    title="Segment segment destinations: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="segment_destinations",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_segment_tracking_plans(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Segment segment tracking plans: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="segment_tracking_plans",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SegmentNormalizer())
