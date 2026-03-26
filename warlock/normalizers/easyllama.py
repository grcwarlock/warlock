"""EasyLlama normalizer — transforms raw EasyLlama API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class EasyLlamaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for EasyLlama."""

    HANDLERS: dict[str, str] = {
        "easyllama_learners": "_normalize_easyllama_learners",
        "easyllama_trainings": "_normalize_easyllama_trainings",
        "easyllama_completions": "_normalize_easyllama_completions",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "easyllama" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "easyllama",
            "source_type": SourceType.LMS,
            "provider": "easyllama",
            "observed_at": raw.observed_at,
        }

    def _normalize_easyllama_learners(self, raw: RawEventData) -> list[FindingData]:
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
                    title="EasyLlama easyllama learners: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="easyllama_learners",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_easyllama_trainings(self, raw: RawEventData) -> list[FindingData]:
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
                    title="EasyLlama easyllama trainings: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="easyllama_trainings",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_easyllama_completions(self, raw: RawEventData) -> list[FindingData]:
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
                    title="EasyLlama easyllama completions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="easyllama_completions",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(EasyLlamaNormalizer())
