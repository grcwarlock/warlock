"""NinjaOne normalizer — transforms raw NinjaOne API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class NinjaOneNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for NinjaOne."""

    HANDLERS: dict[str, str] = {
        "ninjaone_devices": "_normalize_ninjaone_devices",
        "ninjaone_alerts": "_normalize_ninjaone_alerts",
        "ninjaone_policies": "_normalize_ninjaone_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "ninjaone" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "ninjaone",
            "source_type": SourceType.MDM,
            "provider": "ninjaone",
            "observed_at": raw.observed_at,
        }

    def _normalize_ninjaone_devices(self, raw: RawEventData) -> list[FindingData]:
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
                    title="NinjaOne ninjaone devices: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="ninjaone_devices",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_ninjaone_alerts(self, raw: RawEventData) -> list[FindingData]:
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
                    title="NinjaOne ninjaone alerts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="ninjaone_alerts",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_ninjaone_policies(self, raw: RawEventData) -> list[FindingData]:
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
                    title="NinjaOne ninjaone policies: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="ninjaone_policies",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(NinjaOneNormalizer())
