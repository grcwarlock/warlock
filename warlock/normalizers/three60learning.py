"""360Learning normalizer — transforms raw 360Learning API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class Three60LearningNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for 360Learning."""

    HANDLERS: dict[str, str] = {
        "three60learning_users": "_normalize_three60learning_users",
        "three60learning_courses": "_normalize_three60learning_courses",
        "three60learning_enrollments": "_normalize_three60learning_enrollments",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "three60learning" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "three60learning",
            "source_type": SourceType.LMS,
            "provider": "three60learning",
            "observed_at": raw.observed_at,
        }

    def _normalize_three60learning_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="360Learning three60learning users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="three60learning_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_three60learning_courses(self, raw: RawEventData) -> list[FindingData]:
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
                    title="360Learning three60learning courses: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="three60learning_courses",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_three60learning_enrollments(self, raw: RawEventData) -> list[FindingData]:
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
                    title="360Learning three60learning enrollments: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="three60learning_enrollments",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(Three60LearningNormalizer())
