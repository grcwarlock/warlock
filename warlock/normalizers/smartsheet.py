"""Smartsheet normalizer — transforms raw Smartsheet API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SmartsheetNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Smartsheet."""

    HANDLERS: dict[str, str] = {
        "smartsheet_sheets": "_normalize_smartsheet_sheets",
        "smartsheet_users": "_normalize_smartsheet_users",
        "smartsheet_reports": "_normalize_smartsheet_reports",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "smartsheet" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "smartsheet",
            "source_type": SourceType.PROJECT_MGMT,
            "provider": "smartsheet",
            "observed_at": raw.observed_at,
        }

    def _normalize_smartsheet_sheets(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Smartsheet smartsheet sheets: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="smartsheet_sheets",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_smartsheet_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Smartsheet smartsheet users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="smartsheet_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_smartsheet_reports(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Smartsheet smartsheet reports: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="smartsheet_reports",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SmartsheetNormalizer())
