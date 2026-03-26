"""Sumo Logic SIEM normalizer — transforms raw Sumo Logic SIEM API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SumoLogicNewNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Sumo Logic SIEM."""

    HANDLERS: dict[str, str] = {
        "sumologic_collectors": "_normalize_sumologic_collectors",
        "sumologic_searches": "_normalize_sumologic_searches",
        "sumologic_dashboards": "_normalize_sumologic_dashboards",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sumo_logic_new" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "sumo_logic_new",
            "source_type": SourceType.SIEM,
            "provider": "sumo_logic_new",
            "observed_at": raw.observed_at,
        }

    def _normalize_sumologic_collectors(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="alert",
                    title="Sumo Logic SIEM sumologic collectors: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sumologic_collectors",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sumologic_searches(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="alert",
                    title="Sumo Logic SIEM sumologic searches: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sumologic_searches",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sumologic_dashboards(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="alert",
                    title="Sumo Logic SIEM sumologic dashboards: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sumologic_dashboards",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SumoLogicNewNormalizer())
