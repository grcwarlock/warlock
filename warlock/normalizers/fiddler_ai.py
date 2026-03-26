"""Fiddler AI normalizer — transforms raw Fiddler AI API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class FiddlerAINormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Fiddler AI."""

    HANDLERS: dict[str, str] = {
        "fiddler_models": "_normalize_fiddler_models",
        "fiddler_alerts": "_normalize_fiddler_alerts",
        "fiddler_monitoring": "_normalize_fiddler_monitoring",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "fiddler_ai" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "fiddler_ai",
            "source_type": SourceType.AI_GOVERNANCE,
            "provider": "fiddler_ai",
            "observed_at": raw.observed_at,
        }

    def _normalize_fiddler_models(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Fiddler AI fiddler models: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="fiddler_models",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_fiddler_alerts(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Fiddler AI fiddler alerts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="fiddler_alerts",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_fiddler_monitoring(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Fiddler AI fiddler monitoring: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="fiddler_monitoring",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(FiddlerAINormalizer())
