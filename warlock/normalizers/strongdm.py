"""StrongDM normalizer — transforms raw StrongDM API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class StrongDMNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for StrongDM."""

    HANDLERS: dict[str, str] = {
        "strongdm_nodes": "_normalize_strongdm_nodes",
        "strongdm_accounts": "_normalize_strongdm_accounts",
        "strongdm_activities": "_normalize_strongdm_activities",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "strongdm" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "strongdm",
            "source_type": SourceType.IAM,
            "provider": "strongdm",
            "observed_at": raw.observed_at,
        }

    def _normalize_strongdm_nodes(self, raw: RawEventData) -> list[FindingData]:
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
                    title="StrongDM strongdm nodes: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="strongdm_nodes",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_strongdm_accounts(self, raw: RawEventData) -> list[FindingData]:
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
                    title="StrongDM strongdm accounts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="strongdm_accounts",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_strongdm_activities(self, raw: RawEventData) -> list[FindingData]:
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
                    title="StrongDM strongdm activities: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="strongdm_activities",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(StrongDMNormalizer())
