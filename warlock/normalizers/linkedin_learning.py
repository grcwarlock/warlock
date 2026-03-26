"""LinkedIn Learning normalizer — transforms raw LinkedIn Learning API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class LinkedInLearningNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for LinkedIn Learning."""

    HANDLERS: dict[str, str] = {
        "linkedin_learning_assets": "_normalize_linkedin_learning_assets",
        "linkedin_learning_completions": "_normalize_linkedin_learning_completions",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "linkedin_learning" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "linkedin_learning",
            "source_type": SourceType.LMS,
            "provider": "linkedin_learning",
            "observed_at": raw.observed_at,
        }

    def _normalize_linkedin_learning_assets(self, raw: RawEventData) -> list[FindingData]:
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
                    title="LinkedIn Learning linkedin learning assets: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="linkedin_learning_assets",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_linkedin_learning_completions(self, raw: RawEventData) -> list[FindingData]:
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
                    title="LinkedIn Learning linkedin learning completions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="linkedin_learning_completions",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(LinkedInLearningNormalizer())
