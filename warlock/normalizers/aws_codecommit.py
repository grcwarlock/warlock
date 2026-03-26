"""AWS CodeCommit normalizer — transforms raw AWS CodeCommit API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AWSCodeCommitNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for AWS CodeCommit."""

    HANDLERS: dict[str, str] = {
        "codecommit_repos": "_normalize_codecommit_repos",
        "codecommit_approval_rules": "_normalize_codecommit_approval_rules",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "aws_codecommit" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "aws_codecommit",
            "source_type": SourceType.CODE,
            "provider": "aws_codecommit",
            "observed_at": raw.observed_at,
        }

    def _normalize_codecommit_repos(self, raw: RawEventData) -> list[FindingData]:
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
                    title="AWS CodeCommit codecommit repos: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="codecommit_repos",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_codecommit_approval_rules(self, raw: RawEventData) -> list[FindingData]:
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
                    title="AWS CodeCommit codecommit approval rules: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="codecommit_approval_rules",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AWSCodeCommitNormalizer())
