"""Doppler normalizer — transforms raw Doppler API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class DopplerNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Doppler."""

    HANDLERS: dict[str, str] = {
        "doppler_projects": "_normalize_doppler_projects",
        "doppler_configs": "_normalize_doppler_configs",
        "doppler_activity": "_normalize_doppler_activity",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "doppler" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "doppler",
            "source_type": SourceType.IAM,
            "provider": "doppler",
            "observed_at": raw.observed_at,
        }

    def _normalize_doppler_projects(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Doppler doppler projects: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="doppler_projects",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_doppler_configs(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Doppler doppler configs: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="doppler_configs",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_doppler_activity(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Doppler doppler activity: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="doppler_activity",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(DopplerNormalizer())
