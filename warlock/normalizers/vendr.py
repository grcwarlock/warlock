"""Vendr normalizer — transforms raw Vendr API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class VendrNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Vendr."""

    HANDLERS: dict[str, str] = {
        "vendr_contracts": "_normalize_vendr_contracts",
        "vendr_vendors": "_normalize_vendr_vendors",
        "vendr_renewals": "_normalize_vendr_renewals",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "vendr" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "vendr",
            "source_type": SourceType.FINANCE,
            "provider": "vendr",
            "observed_at": raw.observed_at,
        }

    def _normalize_vendr_contracts(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Vendr vendr contracts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="vendr_contracts",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_vendr_vendors(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Vendr vendr vendors: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="vendr_vendors",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_vendr_renewals(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Vendr vendr renewals: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="vendr_renewals",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(VendrNormalizer())
