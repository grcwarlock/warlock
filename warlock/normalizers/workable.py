"""Workable normalizer — transforms raw Workable API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class WorkableNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Workable."""

    HANDLERS: dict[str, str] = {
        "workable_candidates": "_normalize_workable_candidates",
        "workable_jobs": "_normalize_workable_jobs",
        "workable_members": "_normalize_workable_members",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "workable" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "workable",
            "source_type": SourceType.RECRUITING,
            "provider": "workable",
            "observed_at": raw.observed_at,
        }

    def _normalize_workable_candidates(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Workable workable candidates: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="workable_candidates",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_workable_jobs(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Workable workable jobs: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="workable_jobs",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_workable_members(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Workable workable members: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="workable_members",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(WorkableNormalizer())
