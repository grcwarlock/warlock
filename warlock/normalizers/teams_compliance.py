"""MS Teams Compliance normalizer — transforms raw Teams / Graph API responses into Findings.

Normalizes call records (as inventory), teams inventory (as inventory), and
security alerts (as alert with severity mapped from Graph severity levels).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class TeamsComplianceNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "teams_call_records": "_normalize_call_records",
        "teams_inventory": "_normalize_teams",
        "teams_security_alerts": "_normalize_alerts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "teams_compliance" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "teams_compliance",
            "source_type": SourceType.COLLABORATION,
            "provider": "teams_compliance",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_call_records(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for record in items:
            record_id = str(record.get("id", ""))
            call_type = record.get("type", "unknown")
            start_time = record.get("startDateTime", "")
            end_time = record.get("endDateTime", "")
            participants = record.get("participants", [])

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Teams call record: {call_type}",
                    detail={
                        "record_id": record_id,
                        "call_type": call_type,
                        "start_time": start_time,
                        "end_time": end_time,
                        "participant_count": len(participants),
                        "modalities": record.get("modalities", []),
                    },
                    resource_id=record_id,
                    resource_type="teams_call_record",
                    resource_name=call_type,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_teams(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for team in items:
            team_id = str(team.get("id", ""))
            display_name = team.get("displayName", "unknown")
            visibility = team.get("visibility", "unknown")
            description = team.get("description", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Teams team: {display_name}",
                    detail={
                        "team_id": team_id,
                        "display_name": display_name,
                        "visibility": visibility,
                        "description": description,
                        "classification": team.get("classification", ""),
                        "is_archived": team.get("isArchived", False),
                    },
                    resource_id=team_id,
                    resource_type="teams_team",
                    resource_name=display_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        _severity_map = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info",
            "unknown": "info",
        }

        for alert in items:
            alert_id = str(alert.get("id", ""))
            title = alert.get("title", "Unknown alert")
            graph_severity = alert.get("severity", "informational").lower()
            status = alert.get("status", "unknown")
            category = alert.get("category", "")

            severity = _severity_map.get(graph_severity, "info")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Teams security alert: {title}",
                    detail={
                        "alert_id": alert_id,
                        "title": title,
                        "severity": graph_severity,
                        "status": status,
                        "category": category,
                        "created_at": alert.get("createdDateTime", ""),
                        "description": alert.get("description", ""),
                    },
                    resource_id=alert_id,
                    resource_type="teams_security_alert",
                    resource_name=title,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(TeamsComplianceNormalizer())
