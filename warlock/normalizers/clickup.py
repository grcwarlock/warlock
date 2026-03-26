"""ClickUp normalizer — transforms raw ClickUp API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ClickUpNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for ClickUp."""

    HANDLERS: dict[str, str] = {
        "clickup_teams": "_normalize_clickup_teams",
        "clickup_spaces": "_normalize_clickup_spaces",
        "clickup_tasks": "_normalize_clickup_tasks",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "clickup" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "clickup",
            "source_type": SourceType.PROJECT_MGMT,
            "provider": "clickup",
            "observed_at": raw.observed_at,
        }

    def _normalize_clickup_teams(self, raw: RawEventData) -> list[FindingData]:
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
                    title="ClickUp clickup teams: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="clickup_teams",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_clickup_spaces(self, raw: RawEventData) -> list[FindingData]:
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
                    title="ClickUp clickup spaces: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="clickup_spaces",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_clickup_tasks(self, raw: RawEventData) -> list[FindingData]:
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
                    title="ClickUp clickup tasks: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="clickup_tasks",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ClickUpNormalizer())
