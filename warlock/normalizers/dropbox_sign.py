"""Dropbox Sign normalizer — transforms raw Dropbox Sign API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class DropboxSignNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Dropbox Sign."""

    HANDLERS: dict[str, str] = {
        "dropbox_sign_requests": "_normalize_dropbox_sign_requests",
        "dropbox_sign_account": "_normalize_dropbox_sign_account",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "dropbox_sign" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "dropbox_sign",
            "source_type": SourceType.LEGAL,
            "provider": "dropbox_sign",
            "observed_at": raw.observed_at,
        }

    def _normalize_dropbox_sign_requests(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Dropbox Sign dropbox sign requests: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="dropbox_sign_requests",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_dropbox_sign_account(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Dropbox Sign dropbox sign account: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="dropbox_sign_account",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(DropboxSignNormalizer())
