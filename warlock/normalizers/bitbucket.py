"""Bitbucket normalizer — transforms raw Bitbucket API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class BitbucketNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Bitbucket."""

    HANDLERS: dict[str, str] = {
        "bitbucket_repos": "_normalize_bitbucket_repos",
        "bitbucket_branch_protections": "_normalize_bitbucket_branch_protections",
        "bitbucket_commits": "_normalize_bitbucket_commits",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "bitbucket" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "bitbucket",
            "source_type": SourceType.CODE,
            "provider": "bitbucket",
            "observed_at": raw.observed_at,
        }

    def _normalize_bitbucket_repos(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Bitbucket bitbucket repos: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="bitbucket_repos",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_bitbucket_branch_protections(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Bitbucket bitbucket branch protections: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="bitbucket_branch_protections",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_bitbucket_commits(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Bitbucket bitbucket commits: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="bitbucket_commits",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(BitbucketNormalizer())
