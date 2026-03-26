"""Monday.com normalizer — transforms raw Monday.com API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class MondayNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Monday.com."""

    HANDLERS: dict[str, str] = {
        "monday_boards": "_normalize_monday_boards",
        "monday_items": "_normalize_monday_items",
        "monday_users": "_normalize_monday_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "monday" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "monday",
            "source_type": SourceType.PROJECT_MGMT,
            "provider": "monday",
            "observed_at": raw.observed_at,
        }

    def _normalize_monday_boards(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Monday.com monday boards: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="monday_boards",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_monday_items(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Monday.com monday items: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="monday_items",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_monday_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Monday.com monday users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="monday_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(MondayNormalizer())
