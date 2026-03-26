"""Azure Repos normalizer — transforms raw Azure Repos API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AzureReposNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Azure Repos."""

    HANDLERS: dict[str, str] = {
        "azure_repos": "_normalize_azure_repos",
        "azure_pull_requests": "_normalize_azure_pull_requests",
        "azure_branch_policies": "_normalize_azure_branch_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "azure_repos" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "azure_repos",
            "source_type": SourceType.CODE,
            "provider": "azure_repos",
            "observed_at": raw.observed_at,
        }

    def _normalize_azure_repos(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Azure Repos azure repos: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="azure_repos",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_azure_pull_requests(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Azure Repos azure pull requests: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="azure_pull_requests",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_azure_branch_policies(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Azure Repos azure branch policies: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="azure_branch_policies",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AzureReposNormalizer())
