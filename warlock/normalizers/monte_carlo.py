"""Monte Carlo normalizer — transforms raw Monte Carlo API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class MonteCarloNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Monte Carlo."""

    HANDLERS: dict[str, str] = {
        "montecarlo_tables": "_normalize_montecarlo_tables",
        "montecarlo_incidents": "_normalize_montecarlo_incidents",
        "montecarlo_monitors": "_normalize_montecarlo_monitors",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "monte_carlo" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "monte_carlo",
            "source_type": SourceType.DATA_OBSERVABILITY,
            "provider": "monte_carlo",
            "observed_at": raw.observed_at,
        }

    def _normalize_montecarlo_tables(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Monte Carlo montecarlo tables: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="montecarlo_tables",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_montecarlo_incidents(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Monte Carlo montecarlo incidents: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="montecarlo_incidents",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_montecarlo_monitors(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Monte Carlo montecarlo monitors: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="montecarlo_monitors",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(MonteCarloNormalizer())
