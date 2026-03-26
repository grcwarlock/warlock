"""JetBrains normalizer — transforms raw JetBrains API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class JetBrainsNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for JetBrains."""

    HANDLERS: dict[str, str] = {
        "jetbrains_users": "_normalize_jetbrains_users",
        "jetbrains_projects": "_normalize_jetbrains_projects",
        "jetbrains_permissions": "_normalize_jetbrains_permissions",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "jetbrains" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "jetbrains",
            "source_type": SourceType.CODE,
            "provider": "jetbrains",
            "observed_at": raw.observed_at,
        }

    def _normalize_jetbrains_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="JetBrains jetbrains users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="jetbrains_users",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_jetbrains_projects(self, raw: RawEventData) -> list[FindingData]:
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
                    title="JetBrains jetbrains projects: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="jetbrains_projects",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_jetbrains_permissions(self, raw: RawEventData) -> list[FindingData]:
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
                    title="JetBrains jetbrains permissions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="jetbrains_permissions",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(JetBrainsNormalizer())
