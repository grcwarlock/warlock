"""Asana normalizer — transforms raw Asana API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AsanaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Asana."""

    HANDLERS: dict[str, str] = {
        "asana_projects": "_normalize_asana_projects",
        "asana_tasks": "_normalize_asana_tasks",
        "asana_users": "_normalize_asana_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "asana" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "asana",
            "source_type": SourceType.PROJECT_MGMT,
            "provider": "asana",
            "observed_at": raw.observed_at,
        }

    def _normalize_asana_projects(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Asana asana projects: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="asana_projects",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_asana_tasks(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Asana asana tasks: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="asana_tasks",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_asana_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Asana asana users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="asana_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AsanaNormalizer())
