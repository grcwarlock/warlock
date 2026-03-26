"""FireHydrant normalizer — transforms raw FireHydrant API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class FireHydrantNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for FireHydrant."""

    HANDLERS: dict[str, str] = {
        "firehydrant_incidents": "_normalize_firehydrant_incidents",
        "firehydrant_services": "_normalize_firehydrant_services",
        "firehydrant_runbooks": "_normalize_firehydrant_runbooks",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "firehydrant" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "firehydrant",
            "source_type": SourceType.INCIDENT_MGMT,
            "provider": "firehydrant",
            "observed_at": raw.observed_at,
        }

    def _normalize_firehydrant_incidents(self, raw: RawEventData) -> list[FindingData]:
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
                    title="FireHydrant firehydrant incidents: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="firehydrant_incidents",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_firehydrant_services(self, raw: RawEventData) -> list[FindingData]:
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
                    title="FireHydrant firehydrant services: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="firehydrant_services",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_firehydrant_runbooks(self, raw: RawEventData) -> list[FindingData]:
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
                    title="FireHydrant firehydrant runbooks: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="firehydrant_runbooks",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(FireHydrantNormalizer())
