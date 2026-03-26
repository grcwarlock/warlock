"""Cornerstone normalizer — transforms raw Cornerstone API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class CornerstoneNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Cornerstone."""

    HANDLERS: dict[str, str] = {
        "cornerstone_users": "_normalize_cornerstone_users",
        "cornerstone_learning_objects": "_normalize_cornerstone_learning_objects",
        "cornerstone_transcripts": "_normalize_cornerstone_transcripts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "cornerstone" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "cornerstone",
            "source_type": SourceType.LMS,
            "provider": "cornerstone",
            "observed_at": raw.observed_at,
        }

    def _normalize_cornerstone_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Cornerstone cornerstone users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="cornerstone_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_cornerstone_learning_objects(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Cornerstone cornerstone learning objects: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="cornerstone_learning_objects",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_cornerstone_transcripts(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Cornerstone cornerstone transcripts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="cornerstone_transcripts",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(CornerstoneNormalizer())
