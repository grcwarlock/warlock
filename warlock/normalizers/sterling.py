"""Sterling normalizer — transforms raw Sterling API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SterlingNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Sterling."""

    HANDLERS: dict[str, str] = {
        "sterling_screenings": "_normalize_sterling_screenings",
        "sterling_candidates": "_normalize_sterling_candidates",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sterling" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "sterling",
            "source_type": SourceType.RECRUITING,
            "provider": "sterling",
            "observed_at": raw.observed_at,
        }

    def _normalize_sterling_screenings(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Sterling sterling screenings: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sterling_screenings",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sterling_candidates(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Sterling sterling candidates: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sterling_candidates",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SterlingNormalizer())
