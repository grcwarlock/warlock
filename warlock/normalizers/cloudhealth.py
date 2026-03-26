"""CloudHealth normalizer — transforms raw CloudHealth API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class CloudHealthNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for CloudHealth."""

    HANDLERS: dict[str, str] = {
        "cloudhealth_accounts": "_normalize_cloudhealth_accounts",
        "cloudhealth_cost": "_normalize_cloudhealth_cost",
        "cloudhealth_olap": "_normalize_cloudhealth_olap",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "cloudhealth" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "cloudhealth",
            "source_type": SourceType.FINOPS,
            "provider": "cloudhealth",
            "observed_at": raw.observed_at,
        }

    def _normalize_cloudhealth_accounts(self, raw: RawEventData) -> list[FindingData]:
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
                    title="CloudHealth cloudhealth accounts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="cloudhealth_accounts",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_cloudhealth_cost(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="alert",
                    title="CloudHealth cloudhealth cost: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="cloudhealth_cost",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_cloudhealth_olap(self, raw: RawEventData) -> list[FindingData]:
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
                    title="CloudHealth cloudhealth olap: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="cloudhealth_olap",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(CloudHealthNormalizer())
