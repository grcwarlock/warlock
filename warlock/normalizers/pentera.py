"""Pentera normalizer — transforms raw Pentera API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class PenteraNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Pentera."""

    HANDLERS: dict[str, str] = {
        "pentera_tests": "_normalize_pentera_tests",
        "pentera_findings": "_normalize_pentera_findings",
        "pentera_assets": "_normalize_pentera_assets",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "pentera" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "pentera",
            "source_type": SourceType.SCANNER,
            "provider": "pentera",
            "observed_at": raw.observed_at,
        }

    def _normalize_pentera_tests(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="vulnerability",
                    title="Pentera pentera tests: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="pentera_tests",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_pentera_findings(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="vulnerability",
                    title="Pentera pentera findings: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="pentera_findings",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_pentera_assets(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="vulnerability",
                    title="Pentera pentera assets: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="pentera_assets",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(PenteraNormalizer())
