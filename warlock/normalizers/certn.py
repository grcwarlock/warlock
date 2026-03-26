"""Certn normalizer — transforms raw Certn API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class CertnNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Certn."""

    HANDLERS: dict[str, str] = {
        "certn_applications": "_normalize_certn_applications",
        "certn_reports": "_normalize_certn_reports",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "certn" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "certn",
            "source_type": SourceType.RECRUITING,
            "provider": "certn",
            "observed_at": raw.observed_at,
        }

    def _normalize_certn_applications(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Certn certn applications: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="certn_applications",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_certn_reports(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Certn certn reports: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="certn_reports",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(CertnNormalizer())
