"""Personio normalizer — transforms raw Personio API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class PersonioNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Personio."""

    HANDLERS: dict[str, str] = {
        "personio_employees": "_normalize_personio_employees",
        "personio_attendances": "_normalize_personio_attendances",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "personio" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "personio",
            "source_type": SourceType.HRIS,
            "provider": "personio",
            "observed_at": raw.observed_at,
        }

    def _normalize_personio_employees(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Personio personio employees: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="personio_employees",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_personio_attendances(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Personio personio attendances: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="personio_attendances",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(PersonioNormalizer())
