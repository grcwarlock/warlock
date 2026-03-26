"""incident.io normalizer — transforms raw incident.io API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class IncidentIONormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for incident.io."""

    HANDLERS: dict[str, str] = {
        "incidentio_incidents": "_normalize_incidentio_incidents",
        "incidentio_actions": "_normalize_incidentio_actions",
        "incidentio_roles": "_normalize_incidentio_roles",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "incident_io" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "incident_io",
            "source_type": SourceType.INCIDENT_MGMT,
            "provider": "incident_io",
            "observed_at": raw.observed_at,
        }

    def _normalize_incidentio_incidents(self, raw: RawEventData) -> list[FindingData]:
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
                    title="incident.io incidentio incidents: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="incidentio_incidents",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_incidentio_actions(self, raw: RawEventData) -> list[FindingData]:
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
                    title="incident.io incidentio actions: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="incidentio_actions",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_incidentio_roles(self, raw: RawEventData) -> list[FindingData]:
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
                    title="incident.io incidentio roles: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="incidentio_roles",
                    resource_name=item_name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(IncidentIONormalizer())
