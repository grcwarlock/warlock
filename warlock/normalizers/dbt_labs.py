"""dbt Labs normalizer — transforms raw dbt Labs API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class DbtLabsNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for dbt Labs."""

    HANDLERS: dict[str, str] = {
        "dbt_projects": "_normalize_dbt_projects",
        "dbt_runs": "_normalize_dbt_runs",
        "dbt_environments": "_normalize_dbt_environments",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "dbt_labs" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "dbt_labs",
            "source_type": SourceType.INFRASTRUCTURE,
            "provider": "dbt_labs",
            "observed_at": raw.observed_at,
        }

    def _normalize_dbt_projects(self, raw: RawEventData) -> list[FindingData]:
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
                    title="dbt Labs dbt projects: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="dbt_projects",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_dbt_runs(self, raw: RawEventData) -> list[FindingData]:
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
                    title="dbt Labs dbt runs: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="dbt_runs",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_dbt_environments(self, raw: RawEventData) -> list[FindingData]:
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
                    title="dbt Labs dbt environments: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="dbt_environments",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(DbtLabsNormalizer())
