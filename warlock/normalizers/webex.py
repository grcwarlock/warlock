"""Webex normalizer — transforms raw Webex API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class WebexNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Webex."""

    HANDLERS: dict[str, str] = {
        "webex_people": "_normalize_webex_people",
        "webex_rooms": "_normalize_webex_rooms",
        "webex_events": "_normalize_webex_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "webex" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "webex",
            "source_type": SourceType.COMMUNICATION,
            "provider": "webex",
            "observed_at": raw.observed_at,
        }

    def _normalize_webex_people(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Webex webex people: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="webex_people",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_webex_rooms(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Webex webex rooms: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="webex_rooms",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_webex_events(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Webex webex events: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="webex_events",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(WebexNormalizer())
