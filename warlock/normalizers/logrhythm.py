"""LogRhythm normalizer — transforms raw LogRhythm API responses into Findings.

Normalizes hosts and log sources (as inventory), and alarms (as alert
with severity mapped from LogRhythm alarm priority).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class LogRhythmNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for LogRhythm SIEM."""

    HANDLERS: dict[str, str] = {
        "logrhythm_hosts": "_normalize_hosts",
        "logrhythm_alarms": "_normalize_alarms",
        "logrhythm_log_sources": "_normalize_log_sources",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "logrhythm" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "logrhythm",
            "source_type": SourceType.SIEM,
            "provider": "logrhythm",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    @staticmethod
    def _map_priority(priority: int | str) -> str:
        """Map LogRhythm alarm priority (1-100) to severity."""
        try:
            p = int(priority)
        except (TypeError, ValueError):
            return "info"
        if p >= 80:
            return "critical"
        if p >= 60:
            return "high"
        if p >= 40:
            return "medium"
        if p >= 20:
            return "low"
        return "info"

    def _normalize_hosts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for host in items:
            host_id = str(host.get("id", ""))
            name = host.get("name", "unknown")
            status = host.get("recordStatusName", "unknown")
            os_type = host.get("osTypeName", "")
            risk = host.get("riskRatingName", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"LogRhythm host: {name}",
                    detail={
                        "host_id": host_id,
                        "name": name,
                        "status": status,
                        "os_type": os_type,
                        "risk_rating": risk,
                        "entity_name": host.get("entityName", ""),
                    },
                    resource_id=host_id,
                    resource_type="logrhythm_host",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_alarms(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for alarm in items:
            alarm_id = str(alarm.get("alarmId", alarm.get("id", "")))
            name = alarm.get("alarmRuleName", alarm.get("name", "unknown"))
            status = alarm.get("alarmStatus", "unknown")
            priority = alarm.get("alarmPriority", alarm.get("priority", 0))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"LogRhythm alarm: {name}",
                    detail={
                        "alarm_id": alarm_id,
                        "name": name,
                        "status": status,
                        "priority": priority,
                        "entity_name": alarm.get("entityName", ""),
                        "date_inserted": alarm.get("dateInserted", ""),
                    },
                    resource_id=alarm_id,
                    resource_type="logrhythm_alarm",
                    resource_name=name,
                    severity=self._map_priority(priority),
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_log_sources(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for source in items:
            source_id = str(source.get("id", ""))
            name = source.get("name", "unknown")
            status = source.get("recordStatusName", "unknown")
            log_source_type = source.get("logSourceTypeName", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"LogRhythm log source: {name}",
                    detail={
                        "source_id": source_id,
                        "name": name,
                        "status": status,
                        "log_source_type": log_source_type,
                        "entity_name": source.get("entityName", ""),
                        "host_name": source.get("hostName", ""),
                    },
                    resource_id=source_id,
                    resource_type="logrhythm_log_source",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(LogRhythmNormalizer())
