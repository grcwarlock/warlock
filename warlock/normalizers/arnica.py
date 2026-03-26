"""Arnica normalizer — transforms raw Arnica API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ArnicaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Arnica."""

    HANDLERS: dict[str, str] = {
        "arnica_repositories": "_normalize_arnica_repositories",
        "arnica_risks": "_normalize_arnica_risks",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "arnica" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "arnica",
            "source_type": SourceType.CODE,
            "provider": "arnica",
            "observed_at": raw.observed_at,
        }

    def _normalize_arnica_repositories(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Arnica arnica repositories: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="arnica_repositories",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_arnica_risks(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Arnica arnica risks: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="arnica_risks",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ArnicaNormalizer())
