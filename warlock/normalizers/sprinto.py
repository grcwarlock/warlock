"""Sprinto normalizer — transforms raw Sprinto API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SprintoNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Sprinto."""

    HANDLERS: dict[str, str] = {
        "sprinto_controls": "_normalize_sprinto_controls",
        "sprinto_evidence": "_normalize_sprinto_evidence",
        "sprinto_policies": "_normalize_sprinto_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sprinto" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "sprinto",
            "source_type": SourceType.GRC,
            "provider": "sprinto",
            "observed_at": raw.observed_at,
        }

    def _normalize_sprinto_controls(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Sprinto sprinto controls: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sprinto_controls",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sprinto_evidence(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Sprinto sprinto evidence: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sprinto_evidence",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sprinto_policies(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Sprinto sprinto policies: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="sprinto_policies",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SprintoNormalizer())
