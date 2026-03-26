"""Greenhouse normalizer — transforms raw Greenhouse API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class GreenhouseNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Greenhouse."""

    HANDLERS: dict[str, str] = {
        "greenhouse_candidates": "_normalize_greenhouse_candidates",
        "greenhouse_jobs": "_normalize_greenhouse_jobs",
        "greenhouse_offers": "_normalize_greenhouse_offers",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "greenhouse" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "greenhouse",
            "source_type": SourceType.RECRUITING,
            "provider": "greenhouse",
            "observed_at": raw.observed_at,
        }

    def _normalize_greenhouse_candidates(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Greenhouse greenhouse candidates: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="greenhouse_candidates",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_greenhouse_jobs(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Greenhouse greenhouse jobs: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="greenhouse_jobs",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_greenhouse_offers(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Greenhouse greenhouse offers: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="greenhouse_offers",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(GreenhouseNormalizer())
