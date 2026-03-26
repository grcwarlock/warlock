"""8x8 normalizer — transforms raw 8x8 API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class EightByEightNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for 8x8."""

    HANDLERS: dict[str, str] = {
        "eight_x_eight_users": "_normalize_eight_x_eight_users",
        "eight_x_eight_calls": "_normalize_eight_x_eight_calls",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "eight_x_eight" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "eight_x_eight",
            "source_type": SourceType.COMMUNICATION,
            "provider": "eight_x_eight",
            "observed_at": raw.observed_at,
        }

    def _normalize_eight_x_eight_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="8x8 eight x eight users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="eight_x_eight_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_eight_x_eight_calls(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="alert",
                    title="8x8 eight x eight calls: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="eight_x_eight_calls",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(EightByEightNormalizer())
