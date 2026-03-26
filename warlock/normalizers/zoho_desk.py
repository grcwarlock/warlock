"""Zoho Desk normalizer — transforms raw Zoho Desk API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ZohoDeskNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Zoho Desk."""

    HANDLERS: dict[str, str] = {
        "zoho_desk_tickets": "_normalize_zoho_desk_tickets",
        "zoho_desk_agents": "_normalize_zoho_desk_agents",
        "zoho_desk_departments": "_normalize_zoho_desk_departments",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "zoho_desk" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "zoho_desk",
            "source_type": SourceType.ITSM,
            "provider": "zoho_desk",
            "observed_at": raw.observed_at,
        }

    def _normalize_zoho_desk_tickets(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Zoho Desk zoho desk tickets: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="zoho_desk_tickets",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_zoho_desk_agents(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Zoho Desk zoho desk agents: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="zoho_desk_agents",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_zoho_desk_departments(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Zoho Desk zoho desk departments: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="zoho_desk_departments",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ZohoDeskNormalizer())
