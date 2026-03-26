"""SendGrid normalizer — transforms raw SendGrid API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SendGridNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for SendGrid."""

    HANDLERS: dict[str, str] = {
        "sendgrid_teammates": "_normalize_sendgrid_teammates",
        "sendgrid_api_keys": "_normalize_sendgrid_api_keys",
        "sendgrid_bounces": "_normalize_sendgrid_bounces",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sendgrid" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "sendgrid",
            "source_type": SourceType.EMAIL,
            "provider": "sendgrid",
            "observed_at": raw.observed_at,
        }

    def _normalize_sendgrid_teammates(self, raw: RawEventData) -> list[FindingData]:
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
                    title="SendGrid sendgrid teammates: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sendgrid_teammates",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sendgrid_api_keys(self, raw: RawEventData) -> list[FindingData]:
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
                    title="SendGrid sendgrid api keys: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sendgrid_api_keys",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sendgrid_bounces(self, raw: RawEventData) -> list[FindingData]:
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
                    title="SendGrid sendgrid bounces: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sendgrid_bounces",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SendGridNormalizer())
