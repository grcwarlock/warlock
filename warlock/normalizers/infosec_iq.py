"""Infosec IQ normalizer — transforms raw Infosec IQ API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class InfosecIQNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Infosec IQ."""

    HANDLERS: dict[str, str] = {
        "infosec_learners": "_normalize_infosec_learners",
        "infosec_campaigns": "_normalize_infosec_campaigns",
        "infosec_completions": "_normalize_infosec_completions",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "infosec_iq" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "infosec_iq",
            "source_type": SourceType.LMS,
            "provider": "infosec_iq",
            "observed_at": raw.observed_at,
        }

    def _normalize_infosec_learners(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Infosec IQ infosec learners: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="infosec_learners",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_infosec_campaigns(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Infosec IQ infosec campaigns: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="infosec_campaigns",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_infosec_completions(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Infosec IQ infosec completions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="infosec_completions",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(InfosecIQNormalizer())
