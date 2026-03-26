"""Brex normalizer — transforms raw Brex API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class BrexNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Brex."""

    HANDLERS: dict[str, str] = {
        "brex_users": "_normalize_brex_users",
        "brex_transactions": "_normalize_brex_transactions",
        "brex_cards": "_normalize_brex_cards",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "brex" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "brex",
            "source_type": SourceType.FINANCE,
            "provider": "brex",
            "observed_at": raw.observed_at,
        }

    def _normalize_brex_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Brex brex users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="brex_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_brex_transactions(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Brex brex transactions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="brex_transactions",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_brex_cards(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Brex brex cards: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="brex_cards",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(BrexNormalizer())
