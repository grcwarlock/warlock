"""Spot by NetApp normalizer — transforms raw Spot by NetApp API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SpotNetAppNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Spot by NetApp."""

    HANDLERS: dict[str, str] = {
        "spot_groups": "_normalize_spot_groups",
        "spot_ocean_clusters": "_normalize_spot_ocean_clusters",
        "spot_events": "_normalize_spot_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "spot_netapp" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "spot_netapp",
            "source_type": SourceType.FINOPS,
            "provider": "spot_netapp",
            "observed_at": raw.observed_at,
        }

    def _normalize_spot_groups(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Spot by NetApp spot groups: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="spot_groups",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_spot_ocean_clusters(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Spot by NetApp spot ocean clusters: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="spot_ocean_clusters",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_spot_events(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Spot by NetApp spot events: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="spot_events",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SpotNetAppNormalizer())
