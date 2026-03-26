"""Keeper normalizer — transforms raw Keeper API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class KeeperNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Keeper."""

    HANDLERS: dict[str, str] = {
        "keeper_users": "_normalize_keeper_users",
        "keeper_events": "_normalize_keeper_events",
        "keeper_vaults": "_normalize_keeper_vaults",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "keeper" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "keeper",
            "source_type": SourceType.IAM,
            "provider": "keeper",
            "observed_at": raw.observed_at,
        }

    def _normalize_keeper_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Keeper keeper users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="keeper_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_keeper_events(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Keeper keeper events: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="keeper_events",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_keeper_vaults(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Keeper keeper vaults: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="keeper_vaults",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(KeeperNormalizer())
