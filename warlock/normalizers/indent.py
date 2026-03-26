"""Indent normalizer — transforms raw Indent API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class IndentNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Indent."""

    HANDLERS: dict[str, str] = {
        "indent_petitions": "_normalize_indent_petitions",
        "indent_resources": "_normalize_indent_resources",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "indent" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "indent",
            "source_type": SourceType.IAM,
            "provider": "indent",
            "observed_at": raw.observed_at,
        }

    def _normalize_indent_petitions(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Indent indent petitions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="indent_petitions",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_indent_resources(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Indent indent resources: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="indent_resources",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(IndentNormalizer())
