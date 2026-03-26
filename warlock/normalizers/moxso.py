"""Moxso normalizer — transforms raw Moxso API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class MoxsoNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Moxso."""

    HANDLERS: dict[str, str] = {
        "moxso_users": "_normalize_moxso_users",
        "moxso_simulations": "_normalize_moxso_simulations",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "moxso" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "moxso",
            "source_type": SourceType.LMS,
            "provider": "moxso",
            "observed_at": raw.observed_at,
        }

    def _normalize_moxso_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Moxso moxso users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="moxso_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_moxso_simulations(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Moxso moxso simulations: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="moxso_simulations",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(MoxsoNormalizer())
