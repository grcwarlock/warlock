"""Envoy normalizer — transforms raw Envoy API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class EnvoyNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Envoy."""

    HANDLERS: dict[str, str] = {
        "envoy_locations": "_normalize_envoy_locations",
        "envoy_visitors": "_normalize_envoy_visitors",
        "envoy_employees": "_normalize_envoy_employees",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "envoy" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "envoy",
            "source_type": SourceType.PHYSICAL,
            "provider": "envoy",
            "observed_at": raw.observed_at,
        }

    def _normalize_envoy_locations(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Envoy envoy locations: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="envoy_locations",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_envoy_visitors(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Envoy envoy visitors: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="envoy_visitors",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_envoy_employees(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Envoy envoy employees: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="envoy_employees",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(EnvoyNormalizer())
