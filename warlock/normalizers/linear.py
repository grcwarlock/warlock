"""Linear normalizer — transforms raw Linear API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class LinearNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Linear."""

    HANDLERS: dict[str, str] = {
        "linear_issues": "_normalize_linear_issues",
        "linear_teams": "_normalize_linear_teams",
        "linear_users": "_normalize_linear_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "linear" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "linear",
            "source_type": SourceType.PROJECT_MGMT,
            "provider": "linear",
            "observed_at": raw.observed_at,
        }

    def _normalize_linear_issues(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Linear linear issues: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="linear_issues",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_linear_teams(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Linear linear teams: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="linear_teams",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_linear_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Linear linear users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="linear_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(LinearNormalizer())
