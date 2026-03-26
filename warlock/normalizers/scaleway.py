"""Scaleway normalizer — transforms raw Scaleway API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ScalewayNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Scaleway."""

    HANDLERS: dict[str, str] = {
        "scaleway_instances": "_normalize_scaleway_instances",
        "scaleway_vpcs": "_normalize_scaleway_vpcs",
        "scaleway_api_keys": "_normalize_scaleway_api_keys",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "scaleway" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "scaleway",
            "source_type": SourceType.CLOUD,
            "provider": "scaleway",
            "observed_at": raw.observed_at,
        }

    def _normalize_scaleway_instances(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Scaleway scaleway instances: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="scaleway_instances",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_scaleway_vpcs(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Scaleway scaleway vpcs: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="scaleway_vpcs",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_scaleway_api_keys(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Scaleway scaleway api keys: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="scaleway_api_keys",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ScalewayNormalizer())
