"""Dropbox normalizer — transforms raw Dropbox API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class DropboxNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Dropbox."""

    HANDLERS: dict[str, str] = {
        "dropbox_members": "_normalize_dropbox_members",
        "dropbox_events": "_normalize_dropbox_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "dropbox" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "dropbox",
            "source_type": SourceType.FILE_STORAGE,
            "provider": "dropbox",
            "observed_at": raw.observed_at,
        }

    def _normalize_dropbox_members(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Dropbox dropbox members: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="dropbox_members",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_dropbox_events(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Dropbox dropbox events: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="dropbox_events",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(DropboxNormalizer())
