"""Freshdesk normalizer — transforms raw Freshdesk API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class FreshdeskNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Freshdesk."""

    HANDLERS: dict[str, str] = {
        "freshdesk_tickets": "_normalize_freshdesk_tickets",
        "freshdesk_agents": "_normalize_freshdesk_agents",
        "freshdesk_contacts": "_normalize_freshdesk_contacts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "freshdesk" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "freshdesk",
            "source_type": SourceType.ITSM,
            "provider": "freshdesk",
            "observed_at": raw.observed_at,
        }

    def _normalize_freshdesk_tickets(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Freshdesk freshdesk tickets: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="freshdesk_tickets",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_freshdesk_agents(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Freshdesk freshdesk agents: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="freshdesk_agents",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_freshdesk_contacts(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Freshdesk freshdesk contacts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="freshdesk_contacts",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(FreshdeskNormalizer())
