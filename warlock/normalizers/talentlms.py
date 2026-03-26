"""TalentLMS normalizer — transforms raw TalentLMS API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class TalentLMSNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for TalentLMS."""

    HANDLERS: dict[str, str] = {
        "talentlms_users": "_normalize_talentlms_users",
        "talentlms_courses": "_normalize_talentlms_courses",
        "talentlms_completions": "_normalize_talentlms_completions",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "talentlms" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "talentlms",
            "source_type": SourceType.LMS,
            "provider": "talentlms",
            "observed_at": raw.observed_at,
        }

    def _normalize_talentlms_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="TalentLMS talentlms users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="talentlms_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_talentlms_courses(self, raw: RawEventData) -> list[FindingData]:
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
                    title="TalentLMS talentlms courses: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="talentlms_courses",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_talentlms_completions(self, raw: RawEventData) -> list[FindingData]:
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
                    title="TalentLMS talentlms completions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="talentlms_completions",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(TalentLMSNormalizer())
