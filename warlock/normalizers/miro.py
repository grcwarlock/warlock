"""Miro normalizer — transforms raw Miro API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class MiroNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Miro."""

    HANDLERS: dict[str, str] = {
        "miro_boards": "_normalize_miro_boards",
        "miro_members": "_normalize_miro_members",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "miro" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "miro",
            "source_type": SourceType.COLLABORATION,
            "provider": "miro",
            "observed_at": raw.observed_at,
        }

    def _normalize_miro_boards(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Miro miro boards: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="miro_boards",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_miro_members(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Miro miro members: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="miro_members",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(MiroNormalizer())
