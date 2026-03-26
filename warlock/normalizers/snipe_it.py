"""Snipe-IT normalizer — transforms raw Snipe-IT API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SnipeITNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Snipe-IT."""

    HANDLERS: dict[str, str] = {
        "snipeit_hardware": "_normalize_snipeit_hardware",
        "snipeit_licenses": "_normalize_snipeit_licenses",
        "snipeit_users": "_normalize_snipeit_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "snipe_it" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "snipe_it",
            "source_type": SourceType.ITAM,
            "provider": "snipe_it",
            "observed_at": raw.observed_at,
        }

    def _normalize_snipeit_hardware(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Snipe-IT snipeit hardware: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="snipeit_hardware",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_snipeit_licenses(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Snipe-IT snipeit licenses: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="snipeit_licenses",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_snipeit_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Snipe-IT snipeit users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="snipeit_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SnipeITNormalizer())
