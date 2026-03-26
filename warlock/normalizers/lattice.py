"""Lattice normalizer — transforms raw Lattice API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class LatticeNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Lattice."""

    HANDLERS: dict[str, str] = {
        "lattice_users": "_normalize_lattice_users",
        "lattice_goals": "_normalize_lattice_goals",
        "lattice_reviews": "_normalize_lattice_reviews",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "lattice" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "lattice",
            "source_type": SourceType.HRIS,
            "provider": "lattice",
            "observed_at": raw.observed_at,
        }

    def _normalize_lattice_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Lattice lattice users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="lattice_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_lattice_goals(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Lattice lattice goals: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="lattice_goals",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_lattice_reviews(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Lattice lattice reviews: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="lattice_reviews",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(LatticeNormalizer())
