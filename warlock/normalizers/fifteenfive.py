"""15Five normalizer — transforms raw 15Five API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class FifteenFiveNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for 15Five."""

    HANDLERS: dict[str, str] = {
        "fifteenfive_users": "_normalize_fifteenfive_users",
        "fifteenfive_reviews": "_normalize_fifteenfive_reviews",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "fifteenfive" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "fifteenfive",
            "source_type": SourceType.HRIS,
            "provider": "fifteenfive",
            "observed_at": raw.observed_at,
        }

    def _normalize_fifteenfive_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="15Five fifteenfive users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="fifteenfive_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_fifteenfive_reviews(self, raw: RawEventData) -> list[FindingData]:
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
                    title="15Five fifteenfive reviews: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="fifteenfive_reviews",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(FifteenFiveNormalizer())
