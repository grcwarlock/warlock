"""Miradore normalizer — transforms raw Miradore API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class MiradoreNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Miradore."""

    HANDLERS: dict[str, str] = {
        "miradore_devices": "_normalize_miradore_devices",
        "miradore_applications": "_normalize_miradore_applications",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "miradore" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "miradore",
            "source_type": SourceType.MDM,
            "provider": "miradore",
            "observed_at": raw.observed_at,
        }

    def _normalize_miradore_devices(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Miradore miradore devices: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="miradore_devices",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_miradore_applications(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Miradore miradore applications: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="miradore_applications",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(MiradoreNormalizer())
