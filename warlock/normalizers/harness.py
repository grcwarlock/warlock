"""Harness normalizer — transforms raw Harness API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class HarnessNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Harness."""

    HANDLERS: dict[str, str] = {
        "harness_pipelines": "_normalize_harness_pipelines",
        "harness_executions": "_normalize_harness_executions",
        "harness_connectors": "_normalize_harness_connectors",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "harness" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "harness",
            "source_type": SourceType.CI_CD,
            "provider": "harness",
            "observed_at": raw.observed_at,
        }

    def _normalize_harness_pipelines(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Harness harness pipelines: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="harness_pipelines",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_harness_executions(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Harness harness executions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="harness_executions",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_harness_connectors(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Harness harness connectors: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="harness_connectors",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(HarnessNormalizer())
