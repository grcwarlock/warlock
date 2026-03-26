"""Ketch normalizer — transforms raw Ketch API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class KetchNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Ketch."""

    HANDLERS: dict[str, str] = {
        "ketch_policies": "_normalize_ketch_policies",
        "ketch_consent": "_normalize_ketch_consent",
        "ketch_data_subjects": "_normalize_ketch_data_subjects",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "ketch" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "ketch",
            "source_type": SourceType.GRC,
            "provider": "ketch",
            "observed_at": raw.observed_at,
        }

    def _normalize_ketch_policies(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Ketch ketch policies: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="ketch_policies",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_ketch_consent(self, raw: RawEventData) -> list[FindingData]:
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
                    observation_type="policy_violation",
                    title="Ketch ketch consent: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="ketch_consent",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_ketch_data_subjects(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Ketch ketch data subjects: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="ketch_data_subjects",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(KetchNormalizer())
