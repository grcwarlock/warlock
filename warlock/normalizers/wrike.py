"""Wrike normalizer — transforms raw Wrike API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class WrikeNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Wrike."""

    HANDLERS: dict[str, str] = {
        "wrike_folders": "_normalize_wrike_folders",
        "wrike_tasks": "_normalize_wrike_tasks",
        "wrike_contacts": "_normalize_wrike_contacts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "wrike" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "wrike",
            "source_type": SourceType.PROJECT_MGMT,
            "provider": "wrike",
            "observed_at": raw.observed_at,
        }

    def _normalize_wrike_folders(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Wrike wrike folders: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="wrike_folders",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_wrike_tasks(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Wrike wrike tasks: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="wrike_tasks",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_wrike_contacts(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Wrike wrike contacts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="wrike_contacts",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(WrikeNormalizer())
