"""Teleport normalizer — transforms raw Teleport API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class TeleportNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Teleport."""

    HANDLERS: dict[str, str] = {
        "teleport_nodes": "_normalize_teleport_nodes",
        "teleport_users": "_normalize_teleport_users",
        "teleport_sessions": "_normalize_teleport_sessions",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "teleport" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "teleport",
            "source_type": SourceType.IAM,
            "provider": "teleport",
            "observed_at": raw.observed_at,
        }

    def _normalize_teleport_nodes(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Teleport teleport nodes: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="teleport_nodes",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_teleport_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Teleport teleport users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="teleport_users",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_teleport_sessions(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Teleport teleport sessions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="teleport_sessions",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(TeleportNormalizer())
