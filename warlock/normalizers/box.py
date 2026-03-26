"""Box normalizer — transforms raw Box API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class BoxNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Box."""

    HANDLERS: dict[str, str] = {
        "box_users": "_normalize_box_users",
        "box_root_items": "_normalize_box_root_items",
        "box_events": "_normalize_box_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "box" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "box",
            "source_type": SourceType.FILE_STORAGE,
            "provider": "box",
            "observed_at": raw.observed_at,
        }

    def _normalize_box_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Box box users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="box_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_box_root_items(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Box box root items: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="box_root_items",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_box_events(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Box box events: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="box_events",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(BoxNormalizer())
