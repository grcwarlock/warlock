"""Checkr normalizer — transforms raw Checkr API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class CheckrNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Checkr."""

    HANDLERS: dict[str, str] = {
        "checkr_candidates": "_normalize_checkr_candidates",
        "checkr_reports": "_normalize_checkr_reports",
        "checkr_invitations": "_normalize_checkr_invitations",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "checkr" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "checkr",
            "source_type": SourceType.RECRUITING,
            "provider": "checkr",
            "observed_at": raw.observed_at,
        }

    def _normalize_checkr_candidates(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Checkr checkr candidates: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="checkr_candidates",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_checkr_reports(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Checkr checkr reports: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="checkr_reports",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_checkr_invitations(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Checkr checkr invitations: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="checkr_invitations",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(CheckrNormalizer())
