"""HubSpot normalizer — transforms raw HubSpot API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class HubSpotNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for HubSpot."""

    HANDLERS: dict[str, str] = {
        "hubspot_contacts": "_normalize_hubspot_contacts",
        "hubspot_deals": "_normalize_hubspot_deals",
        "hubspot_roles": "_normalize_hubspot_roles",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "hubspot" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "hubspot",
            "source_type": SourceType.CRM,
            "provider": "hubspot",
            "observed_at": raw.observed_at,
        }

    def _normalize_hubspot_contacts(self, raw: RawEventData) -> list[FindingData]:
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
                    title="HubSpot hubspot contacts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="hubspot_contacts",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_hubspot_deals(self, raw: RawEventData) -> list[FindingData]:
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
                    title="HubSpot hubspot deals: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="hubspot_deals",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_hubspot_roles(self, raw: RawEventData) -> list[FindingData]:
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
                    title="HubSpot hubspot roles: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="hubspot_roles",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(HubSpotNormalizer())
