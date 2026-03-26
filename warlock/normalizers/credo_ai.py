"""Credo AI normalizer — transforms raw Credo AI API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class CredoAINormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Credo AI."""

    HANDLERS: dict[str, str] = {
        "credo_models": "_normalize_credo_models",
        "credo_assessments": "_normalize_credo_assessments",
        "credo_policies": "_normalize_credo_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "credo_ai" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "credo_ai",
            "source_type": SourceType.AI_GOVERNANCE,
            "provider": "credo_ai",
            "observed_at": raw.observed_at,
        }

    def _normalize_credo_models(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Credo AI credo models: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="credo_models",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_credo_assessments(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Credo AI credo assessments: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="credo_assessments",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_credo_policies(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Credo AI credo policies: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="credo_policies",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(CredoAINormalizer())
