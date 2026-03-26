"""Wiz Code normalizer — transforms raw Wiz Code API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class WizCodeNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Wiz Code."""

    HANDLERS: dict[str, str] = {
        "wiz_code_repos": "_normalize_wiz_code_repos",
        "wiz_code_issues": "_normalize_wiz_code_issues",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "wiz_code" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "wiz_code",
            "source_type": SourceType.CODE,
            "provider": "wiz_code",
            "observed_at": raw.observed_at,
        }

    def _normalize_wiz_code_repos(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Wiz Code wiz code repos: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="wiz_code_repos",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_wiz_code_issues(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Wiz Code wiz code issues: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="wiz_code_issues",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(WizCodeNormalizer())
