"""Vantage normalizer — transforms raw Vantage API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class VantageFinOpsNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Vantage."""

    HANDLERS: dict[str, str] = {
        "vantage_costs": "_normalize_vantage_costs",
        "vantage_cost_reports": "_normalize_vantage_cost_reports",
        "vantage_providers": "_normalize_vantage_providers",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "vantage_finops" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "vantage_finops",
            "source_type": SourceType.FINOPS,
            "provider": "vantage_finops",
            "observed_at": raw.observed_at,
        }

    def _normalize_vantage_costs(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Vantage vantage costs: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="vantage_costs",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_vantage_cost_reports(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Vantage vantage cost reports: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="vantage_cost_reports",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_vantage_providers(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Vantage vantage providers: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="vantage_providers",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(VantageFinOpsNormalizer())
