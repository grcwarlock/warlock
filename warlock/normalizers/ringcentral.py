"""RingCentral normalizer — transforms raw RingCentral API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class RingCentralNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for RingCentral."""

    HANDLERS: dict[str, str] = {
        "ringcentral_extensions": "_normalize_ringcentral_extensions",
        "ringcentral_call_log": "_normalize_ringcentral_call_log",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "ringcentral" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "ringcentral",
            "source_type": SourceType.COMMUNICATION,
            "provider": "ringcentral",
            "observed_at": raw.observed_at,
        }

    def _normalize_ringcentral_extensions(self, raw: RawEventData) -> list[FindingData]:
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
                    title="RingCentral ringcentral extensions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="ringcentral_extensions",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_ringcentral_call_log(self, raw: RawEventData) -> list[FindingData]:
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
                    title="RingCentral ringcentral call log: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="ringcentral_call_log",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(RingCentralNormalizer())
