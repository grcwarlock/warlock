"""Horizon3.ai NodeZero normalizer — transforms raw Horizon3.ai NodeZero API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class Horizon3Normalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Horizon3.ai NodeZero."""

    HANDLERS: dict[str, str] = {
        "horizon3_pentests": "_normalize_horizon3_pentests",
        "horizon3_findings": "_normalize_horizon3_findings",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "horizon3" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "horizon3",
            "source_type": SourceType.SCANNER,
            "provider": "horizon3",
            "observed_at": raw.observed_at,
        }

    def _normalize_horizon3_pentests(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Horizon3.ai NodeZero horizon3 pentests: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="horizon3_pentests",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_horizon3_findings(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Horizon3.ai NodeZero horizon3 findings: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="horizon3_findings",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(Horizon3Normalizer())
