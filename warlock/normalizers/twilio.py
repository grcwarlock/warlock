"""Twilio normalizer — transforms raw Twilio API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class TwilioNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Twilio."""

    HANDLERS: dict[str, str] = {
        "twilio_calls": "_normalize_twilio_calls",
        "twilio_messages": "_normalize_twilio_messages",
        "twilio_api_keys": "_normalize_twilio_api_keys",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "twilio" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "twilio",
            "source_type": SourceType.COMMUNICATION,
            "provider": "twilio",
            "observed_at": raw.observed_at,
        }

    def _normalize_twilio_calls(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Twilio twilio calls: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="twilio_calls",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_twilio_messages(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Twilio twilio messages: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="twilio_messages",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_twilio_api_keys(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Twilio twilio api keys: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="twilio_api_keys",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(TwilioNormalizer())
