"""Zentry normalizer — transforms raw Zentry API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ZentryNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Zentry."""

    HANDLERS: dict[str, str] = {
        "zentry_users": "_normalize_zentry_users",
        "zentry_connections": "_normalize_zentry_connections",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "zentry" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "zentry",
            "source_type": SourceType.IAM,
            "provider": "zentry",
            "observed_at": raw.observed_at,
        }

    def _normalize_zentry_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Zentry zentry users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="zentry_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_zentry_connections(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Zentry zentry connections: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="zentry_connections",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ZentryNormalizer())
