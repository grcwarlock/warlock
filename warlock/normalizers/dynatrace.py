"""Dynatrace normalizer — transforms raw Dynatrace API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class DynatraceNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Dynatrace."""

    HANDLERS: dict[str, str] = {
        "dynatrace_entities": "_normalize_dynatrace_entities",
        "dynatrace_problems": "_normalize_dynatrace_problems",
        "dynatrace_security_problems": "_normalize_dynatrace_security_problems",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "dynatrace" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "dynatrace",
            "source_type": SourceType.OBSERVABILITY,
            "provider": "dynatrace",
            "observed_at": raw.observed_at,
        }

    def _normalize_dynatrace_entities(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="alert",
                    title="Dynatrace dynatrace entities: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="dynatrace_entities",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_dynatrace_problems(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Dynatrace dynatrace problems: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="dynatrace_problems",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_dynatrace_security_problems(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="alert",
                    title="Dynatrace dynatrace security problems: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="dynatrace_security_problems",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(DynatraceNormalizer())
