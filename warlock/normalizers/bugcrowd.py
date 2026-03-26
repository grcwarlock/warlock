"""Bugcrowd normalizer — transforms raw Bugcrowd API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class BugcrowdNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Bugcrowd."""

    HANDLERS: dict[str, str] = {
        "bugcrowd_submissions": "_normalize_bugcrowd_submissions",
        "bugcrowd_programs": "_normalize_bugcrowd_programs",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "bugcrowd" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "bugcrowd",
            "source_type": SourceType.SCANNER,
            "provider": "bugcrowd",
            "observed_at": raw.observed_at,
        }

    def _normalize_bugcrowd_submissions(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Bugcrowd bugcrowd submissions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="bugcrowd_submissions",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_bugcrowd_programs(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Bugcrowd bugcrowd programs: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="bugcrowd_programs",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(BugcrowdNormalizer())
