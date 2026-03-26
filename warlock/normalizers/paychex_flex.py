"""Paychex Flex normalizer — transforms raw Paychex Flex API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class PaychexFlexNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Paychex Flex."""

    HANDLERS: dict[str, str] = {
        "paychex_workers": "_normalize_paychex_workers",
        "paychex_company_workers": "_normalize_paychex_company_workers",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "paychex_flex" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "paychex_flex",
            "source_type": SourceType.HRIS,
            "provider": "paychex_flex",
            "observed_at": raw.observed_at,
        }

    def _normalize_paychex_workers(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Paychex Flex paychex workers: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="paychex_workers",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_paychex_company_workers(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Paychex Flex paychex company workers: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="paychex_company_workers",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(PaychexFlexNormalizer())
