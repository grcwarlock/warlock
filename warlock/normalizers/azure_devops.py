"""Azure DevOps normalizer — transforms raw Azure DevOps API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AzureDevOpsNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Azure DevOps."""

    HANDLERS: dict[str, str] = {
        "azdo_builds": "_normalize_azdo_builds",
        "azdo_releases": "_normalize_azdo_releases",
        "azdo_work_items": "_normalize_azdo_work_items",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "azure_devops" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "azure_devops",
            "source_type": SourceType.CI_CD,
            "provider": "azure_devops",
            "observed_at": raw.observed_at,
        }

    def _normalize_azdo_builds(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Azure DevOps azdo builds: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="azdo_builds",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_azdo_releases(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Azure DevOps azdo releases: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="azdo_releases",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_azdo_work_items(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Azure DevOps azdo work items: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="azdo_work_items",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AzureDevOpsNormalizer())
