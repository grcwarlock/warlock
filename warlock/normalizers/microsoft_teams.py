"""Microsoft Teams normalizer — transforms raw Microsoft Teams API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class MicrosoftTeamsNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Microsoft Teams."""

    HANDLERS: dict[str, str] = {
        "ms_teams_list": "_normalize_ms_teams_list",
        "ms_teams_channels": "_normalize_ms_teams_channels",
        "ms_teams_security_alerts": "_normalize_ms_teams_security_alerts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "microsoft_teams" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "microsoft_teams",
            "source_type": SourceType.COLLABORATION,
            "provider": "microsoft_teams",
            "observed_at": raw.observed_at,
        }

    def _normalize_ms_teams_list(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Microsoft Teams ms teams list: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="ms_teams_list",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_ms_teams_channels(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Microsoft Teams ms teams channels: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="ms_teams_channels",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_ms_teams_security_alerts(self, raw: RawEventData) -> list[FindingData]:
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
                    title="Microsoft Teams ms teams security alerts: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="ms_teams_security_alerts",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(MicrosoftTeamsNormalizer())
