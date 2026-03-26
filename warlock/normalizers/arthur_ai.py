"""Arthur AI normalizer — transforms raw Arthur AI API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ArthurAINormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Arthur AI."""

    HANDLERS: dict[str, str] = {
        "arthur_models": "_normalize_arthur_models",
        "arthur_alerts": "_normalize_arthur_alerts",
        "arthur_inferences": "_normalize_arthur_inferences",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "arthur_ai" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "arthur_ai",
            "source_type": SourceType.AI_GOVERNANCE,
            "provider": "arthur_ai",
            "observed_at": raw.observed_at,
        }

    def _normalize_arthur_models(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Arthur AI arthur models: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="arthur_models",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_arthur_alerts(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Arthur AI arthur alerts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="arthur_alerts",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_arthur_inferences(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Arthur AI arthur inferences: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="arthur_inferences",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ArthurAINormalizer())
