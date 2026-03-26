"""Heroku normalizer — transforms raw Heroku API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class HerokuNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Heroku."""

    HANDLERS: dict[str, str] = {
        "heroku_apps": "_normalize_heroku_apps",
        "heroku_teams": "_normalize_heroku_teams",
        "heroku_addons": "_normalize_heroku_addons",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "heroku" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "heroku",
            "source_type": SourceType.CLOUD,
            "provider": "heroku",
            "observed_at": raw.observed_at,
        }

    def _normalize_heroku_apps(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Heroku heroku apps: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="heroku_apps",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_heroku_teams(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Heroku heroku teams: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="heroku_teams",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_heroku_addons(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Heroku heroku addons: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="heroku_addons",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(HerokuNormalizer())
