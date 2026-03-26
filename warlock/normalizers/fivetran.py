"""Fivetran normalizer — transforms raw Fivetran API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class FivetranNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Fivetran."""

    HANDLERS: dict[str, str] = {
        "fivetran_connectors": "_normalize_fivetran_connectors",
        "fivetran_groups": "_normalize_fivetran_groups",
        "fivetran_users": "_normalize_fivetran_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "fivetran" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "fivetran",
            "source_type": SourceType.INFRASTRUCTURE,
            "provider": "fivetran",
            "observed_at": raw.observed_at,
        }

    def _normalize_fivetran_connectors(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Fivetran fivetran connectors: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="fivetran_connectors",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_fivetran_groups(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="misconfiguration",
                    title="Fivetran fivetran groups: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="fivetran_groups",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_fivetran_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Fivetran fivetran users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="fivetran_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(FivetranNormalizer())
