"""Gong normalizer — transforms raw Gong API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class GongNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Gong."""

    HANDLERS: dict[str, str] = {
        "gong_calls": "_normalize_gong_calls",
        "gong_users": "_normalize_gong_users",
        "gong_folders": "_normalize_gong_folders",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "gong" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "gong",
            "source_type": SourceType.CRM,
            "provider": "gong",
            "observed_at": raw.observed_at,
        }

    def _normalize_gong_calls(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Gong gong calls: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="gong_calls",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_gong_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Gong gong users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="gong_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_gong_folders(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Gong gong folders: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="gong_folders",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(GongNormalizer())
