"""Traceable AI normalizer — transforms raw Traceable AI API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class TraceableAINormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Traceable AI."""

    HANDLERS: dict[str, str] = {
        "traceable_apis": "_normalize_traceable_apis",
        "traceable_vulnerabilities": "_normalize_traceable_vulnerabilities",
        "traceable_events": "_normalize_traceable_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "traceable_ai" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "traceable_ai",
            "source_type": SourceType.NETWORK,
            "provider": "traceable_ai",
            "observed_at": raw.observed_at,
        }

    def _normalize_traceable_apis(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Traceable AI traceable apis: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="traceable_apis",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_traceable_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Traceable AI traceable vulnerabilities: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="traceable_vulnerabilities",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_traceable_events(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Traceable AI traceable events: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="traceable_events",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(TraceableAINormalizer())
