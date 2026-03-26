"""OpenAI normalizer — transforms raw OpenAI API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class OpenAIPlatformNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for OpenAI."""

    HANDLERS: dict[str, str] = {
        "openai_models": "_normalize_openai_models",
        "openai_usage": "_normalize_openai_usage",
        "openai_assistants": "_normalize_openai_assistants",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "openai_platform" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "openai_platform",
            "source_type": SourceType.AI_ML,
            "provider": "openai_platform",
            "observed_at": raw.observed_at,
        }

    def _normalize_openai_models(self, raw: RawEventData) -> list[FindingData]:
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
                    title="OpenAI openai models: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="openai_models",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_openai_usage(self, raw: RawEventData) -> list[FindingData]:
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
                    title="OpenAI openai usage: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="openai_usage",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_openai_assistants(self, raw: RawEventData) -> list[FindingData]:
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
                    title="OpenAI openai assistants: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="openai_assistants",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(OpenAIPlatformNormalizer())
