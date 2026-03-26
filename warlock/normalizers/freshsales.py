"""Freshsales normalizer — transforms raw Freshsales API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class FreshsalesNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Freshsales."""

    HANDLERS: dict[str, str] = {
        "freshsales_contacts": "_normalize_freshsales_contacts",
        "freshsales_deals": "_normalize_freshsales_deals",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "freshsales" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "freshsales",
            "source_type": SourceType.CRM,
            "provider": "freshsales",
            "observed_at": raw.observed_at,
        }

    def _normalize_freshsales_contacts(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Freshsales freshsales contacts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="freshsales_contacts",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_freshsales_deals(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="policy_violation",
                    title="Freshsales freshsales deals: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="freshsales_deals",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(FreshsalesNormalizer())
