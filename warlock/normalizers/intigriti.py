"""Intigriti normalizer — transforms raw Intigriti API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class IntigritiNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Intigriti."""

    HANDLERS: dict[str, str] = {
        "intigriti_submissions": "_normalize_intigriti_submissions",
        "intigriti_programs": "_normalize_intigriti_programs",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "intigriti" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "intigriti",
            "source_type": SourceType.SCANNER,
            "provider": "intigriti",
            "observed_at": raw.observed_at,
        }

    def _normalize_intigriti_submissions(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="vulnerability",
                    title="Intigriti intigriti submissions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="intigriti_submissions",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_intigriti_programs(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="vulnerability",
                    title="Intigriti intigriti programs: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="intigriti_programs",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(IntigritiNormalizer())
