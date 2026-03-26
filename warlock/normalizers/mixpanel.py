"""Mixpanel normalizer — transforms raw Mixpanel API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class MixpanelNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Mixpanel."""

    HANDLERS: dict[str, str] = {
        "mixpanel_users": "_normalize_mixpanel_users",
        "mixpanel_events": "_normalize_mixpanel_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "mixpanel" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "mixpanel",
            "source_type": SourceType.ANALYTICS,
            "provider": "mixpanel",
            "observed_at": raw.observed_at,
        }

    def _normalize_mixpanel_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Mixpanel mixpanel users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="mixpanel_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_mixpanel_events(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Mixpanel mixpanel events: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="mixpanel_events",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(MixpanelNormalizer())
