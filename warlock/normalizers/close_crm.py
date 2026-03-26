"""Close normalizer — transforms raw Close API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class CloseCRMNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Close."""

    HANDLERS: dict[str, str] = {
        "close_leads": "_normalize_close_leads",
        "close_users": "_normalize_close_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "close_crm" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "close_crm",
            "source_type": SourceType.CRM,
            "provider": "close_crm",
            "observed_at": raw.observed_at,
        }

    def _normalize_close_leads(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Close close leads: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="close_leads",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_close_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Close close users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="close_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(CloseCRMNormalizer())
