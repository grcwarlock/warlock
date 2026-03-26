"""Qlik normalizer — transforms raw Qlik API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class QlikNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Qlik."""

    HANDLERS: dict[str, str] = {
        "qlik_apps": "_normalize_qlik_apps",
        "qlik_users": "_normalize_qlik_users",
        "qlik_spaces": "_normalize_qlik_spaces",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "qlik" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "qlik",
            "source_type": SourceType.ANALYTICS,
            "provider": "qlik",
            "observed_at": raw.observed_at,
        }

    def _normalize_qlik_apps(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Qlik qlik apps: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="qlik_apps",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_qlik_users(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Qlik qlik users: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="qlik_users",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_qlik_spaces(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Qlik qlik spaces: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="qlik_spaces",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(QlikNormalizer())
