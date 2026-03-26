"""Udemy normalizer — transforms raw Udemy API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class UdemyNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Udemy."""

    HANDLERS: dict[str, str] = {
        "udemy_users": "_normalize_udemy_users",
        "udemy_courses": "_normalize_udemy_courses",
        "udemy_analytics": "_normalize_udemy_analytics",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "udemy" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "udemy",
            "source_type": SourceType.LMS,
            "provider": "udemy",
            "observed_at": raw.observed_at,
        }

    def _normalize_udemy_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Udemy udemy users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="udemy_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_udemy_courses(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Udemy udemy courses: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="udemy_courses",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_udemy_analytics(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Udemy udemy analytics: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="udemy_analytics",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(UdemyNormalizer())
