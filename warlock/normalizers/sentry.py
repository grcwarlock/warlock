"""Sentry normalizer — transforms raw Sentry API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SentryNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Sentry."""

    HANDLERS: dict[str, str] = {
        "sentry_projects": "_normalize_sentry_projects",
        "sentry_issues": "_normalize_sentry_issues",
        "sentry_events": "_normalize_sentry_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sentry" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "sentry",
            "source_type": SourceType.OBSERVABILITY,
            "provider": "sentry",
            "observed_at": raw.observed_at,
        }

    def _normalize_sentry_projects(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="alert",
                    title="Sentry sentry projects: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sentry_projects",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sentry_issues(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Sentry sentry issues: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sentry_issues",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sentry_events(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="alert",
                    title="Sentry sentry events: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sentry_events",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SentryNormalizer())
