"""Saviynt normalizer — transforms raw Saviynt API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SaviyntNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Saviynt."""

    HANDLERS: dict[str, str] = {
        "saviynt_users": "_normalize_saviynt_users",
        "saviynt_entitlements": "_normalize_saviynt_entitlements",
        "saviynt_access_reviews": "_normalize_saviynt_access_reviews",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "saviynt" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "saviynt",
            "source_type": SourceType.IAM,
            "provider": "saviynt",
            "observed_at": raw.observed_at,
        }

    def _normalize_saviynt_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Saviynt saviynt users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="saviynt_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_saviynt_entitlements(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Saviynt saviynt entitlements: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="saviynt_entitlements",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_saviynt_access_reviews(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Saviynt saviynt access reviews: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="saviynt_access_reviews",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SaviyntNormalizer())
