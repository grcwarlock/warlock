"""Trello normalizer — transforms raw Trello API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class TrelloNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Trello."""

    HANDLERS: dict[str, str] = {
        "trello_boards": "_normalize_trello_boards",
        "trello_cards": "_normalize_trello_cards",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "trello" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "trello",
            "source_type": SourceType.PROJECT_MGMT,
            "provider": "trello",
            "observed_at": raw.observed_at,
        }

    def _normalize_trello_boards(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Trello trello boards: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="trello_boards",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_trello_cards(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Trello trello cards: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="trello_cards",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(TrelloNormalizer())
