"""Egnyte normalizer — transforms raw Egnyte API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class EgnyteNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Egnyte."""

    HANDLERS: dict[str, str] = {
        "egnyte_users": "_normalize_egnyte_users",
        "egnyte_files": "_normalize_egnyte_files",
        "egnyte_audit": "_normalize_egnyte_audit",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "egnyte" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "egnyte",
            "source_type": SourceType.FILE_STORAGE,
            "provider": "egnyte",
            "observed_at": raw.observed_at,
        }

    def _normalize_egnyte_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Egnyte egnyte users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="egnyte_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_egnyte_files(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Egnyte egnyte files: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="egnyte_files",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_egnyte_audit(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Egnyte egnyte audit: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="egnyte_audit",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(EgnyteNormalizer())
