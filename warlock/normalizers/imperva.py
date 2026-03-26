"""Imperva normalizer — transforms raw Imperva API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ImpervaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Imperva."""

    HANDLERS: dict[str, str] = {
        "imperva_sites": "_normalize_imperva_sites",
        "imperva_waf_rules": "_normalize_imperva_waf_rules",
        "imperva_events": "_normalize_imperva_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "imperva" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "imperva",
            "source_type": SourceType.NETWORK,
            "provider": "imperva",
            "observed_at": raw.observed_at,
        }

    def _normalize_imperva_sites(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Imperva imperva sites: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="imperva_sites",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_imperva_waf_rules(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="misconfiguration",
                    title="Imperva imperva waf rules: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="imperva_waf_rules",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_imperva_events(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Imperva imperva events: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="imperva_events",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ImpervaNormalizer())
