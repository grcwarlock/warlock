"""Hexnode UEM normalizer — transforms raw Hexnode UEM API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class HexnodeNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Hexnode UEM."""

    HANDLERS: dict[str, str] = {
        "hexnode_devices": "_normalize_hexnode_devices",
        "hexnode_policies": "_normalize_hexnode_policies",
        "hexnode_users": "_normalize_hexnode_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "hexnode" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "hexnode",
            "source_type": SourceType.MDM,
            "provider": "hexnode",
            "observed_at": raw.observed_at,
        }

    def _normalize_hexnode_devices(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Hexnode UEM hexnode devices: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="hexnode_devices",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_hexnode_policies(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Hexnode UEM hexnode policies: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="hexnode_policies",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_hexnode_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Hexnode UEM hexnode users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="hexnode_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(HexnodeNormalizer())
