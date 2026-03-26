"""Cyral normalizer — transforms raw Cyral API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class CyralNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Cyral."""

    HANDLERS: dict[str, str] = {
        "cyral_repos": "_normalize_cyral_repos",
        "cyral_policies": "_normalize_cyral_policies",
        "cyral_activities": "_normalize_cyral_activities",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "cyral" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "cyral",
            "source_type": SourceType.DATA_GOVERNANCE,
            "provider": "cyral",
            "observed_at": raw.observed_at,
        }

    def _normalize_cyral_repos(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Cyral cyral repos: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="cyral_repos",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_cyral_policies(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Cyral cyral policies: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="cyral_policies",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_cyral_activities(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Cyral cyral activities: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="cyral_activities",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(CyralNormalizer())
