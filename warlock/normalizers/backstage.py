"""Backstage normalizer — transforms raw Backstage API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class BackstageNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Backstage."""

    HANDLERS: dict[str, str] = {
        "backstage_entities": "_normalize_backstage_entities",
        "backstage_locations": "_normalize_backstage_locations",
        "backstage_techdocs": "_normalize_backstage_techdocs",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "backstage" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "backstage",
            "source_type": SourceType.INFRASTRUCTURE,
            "provider": "backstage",
            "observed_at": raw.observed_at,
        }

    def _normalize_backstage_entities(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Backstage backstage entities: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="backstage_entities",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_backstage_locations(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Backstage backstage locations: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="backstage_locations",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_backstage_techdocs(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Backstage backstage techdocs: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="backstage_techdocs",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(BackstageNormalizer())
