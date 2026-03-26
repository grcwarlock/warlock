"""MongoDB Atlas normalizer — transforms raw MongoDB Atlas API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class MongoDBAtlasNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for MongoDB Atlas."""

    HANDLERS: dict[str, str] = {
        "atlas_projects": "_normalize_atlas_projects",
        "atlas_clusters": "_normalize_atlas_clusters",
        "atlas_events": "_normalize_atlas_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "mongodb_atlas" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "mongodb_atlas",
            "source_type": SourceType.CLOUD,
            "provider": "mongodb_atlas",
            "observed_at": raw.observed_at,
        }

    def _normalize_atlas_projects(self, raw: RawEventData) -> list[FindingData]:
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
                    title="MongoDB Atlas atlas projects: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="atlas_projects",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_atlas_clusters(self, raw: RawEventData) -> list[FindingData]:
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
                    title="MongoDB Atlas atlas clusters: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="atlas_clusters",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_atlas_events(self, raw: RawEventData) -> list[FindingData]:
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
                    title="MongoDB Atlas atlas events: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="atlas_events",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(MongoDBAtlasNormalizer())
