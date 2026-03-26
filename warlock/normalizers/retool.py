"""Retool normalizer — transforms raw Retool API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class RetoolNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Retool."""

    HANDLERS: dict[str, str] = {
        "retool_users": "_normalize_retool_users",
        "retool_groups": "_normalize_retool_groups",
        "retool_apps": "_normalize_retool_apps",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "retool" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "retool",
            "source_type": SourceType.COLLABORATION,
            "provider": "retool",
            "observed_at": raw.observed_at,
        }

    def _normalize_retool_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Retool retool users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="retool_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_retool_groups(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Retool retool groups: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="retool_groups",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_retool_apps(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Retool retool apps: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="retool_apps",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(RetoolNormalizer())
