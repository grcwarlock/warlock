"""GO1 normalizer — transforms raw GO1 API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class GO1Normalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for GO1."""

    HANDLERS: dict[str, str] = {
        "go1_enrollments": "_normalize_go1_enrollments",
        "go1_learning_objects": "_normalize_go1_learning_objects",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "go1" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "go1",
            "source_type": SourceType.LMS,
            "provider": "go1",
            "observed_at": raw.observed_at,
        }

    def _normalize_go1_enrollments(self, raw: RawEventData) -> list[FindingData]:
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
                    title="GO1 go1 enrollments: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="go1_enrollments",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_go1_learning_objects(self, raw: RawEventData) -> list[FindingData]:
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
                    title="GO1 go1 learning objects: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="go1_learning_objects",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(GO1Normalizer())
