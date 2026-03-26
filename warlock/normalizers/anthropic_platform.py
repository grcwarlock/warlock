"""Anthropic normalizer — transforms raw Anthropic API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AnthropicPlatformNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Anthropic."""

    HANDLERS: dict[str, str] = {
        "anthropic_models": "_normalize_anthropic_models",
        "anthropic_usage": "_normalize_anthropic_usage",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "anthropic_platform" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "anthropic_platform",
            "source_type": SourceType.AI_ML,
            "provider": "anthropic_platform",
            "observed_at": raw.observed_at,
        }

    def _normalize_anthropic_models(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Anthropic anthropic models: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="anthropic_models",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_anthropic_usage(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Anthropic anthropic usage: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="anthropic_usage",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AnthropicPlatformNormalizer())
