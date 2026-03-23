"""Sumo Logic normalizer — transforms raw Sumo Logic API responses into Findings.

Normalizes collectors and dashboards as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SumoLogicNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "sumo_collectors": "_normalize_collectors",
        "sumo_dashboards": "_normalize_dashboards",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sumo_logic" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "sumo_logic",
            "source_type": SourceType.SIEM,
            "provider": "sumo_logic",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_collectors(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for collector in items:
            collector_id = str(collector.get("id", ""))
            name = collector.get("name", "unknown")
            alive = collector.get("alive", True)
            collector_type = collector.get("collectorType", collector.get("collectorType", "Hosted"))

            # Dead collectors are a compliance concern (logging gap)
            obs_type = "misconfiguration" if not alive else "inventory"
            severity = "medium" if not alive else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Sumo Logic collector: {name}",
                    detail={
                        "collector_id": collector_id,
                        "name": name,
                        "alive": alive,
                        "collector_type": collector_type,
                        "description": collector.get("description", ""),
                        "category": collector.get("category", ""),
                        "last_heartbeat": collector.get("lastHeartbeatAt", ""),
                        "source_count": collector.get("numSources", 0),
                    },
                    resource_id=collector_id,
                    resource_type="sumo_collector",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_dashboards(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for dashboard in items:
            dashboard_id = str(dashboard.get("id", ""))
            title = dashboard.get("title", dashboard.get("name", "unknown"))
            description = dashboard.get("description", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Sumo Logic dashboard: {title}",
                    detail={
                        "dashboard_id": dashboard_id,
                        "title": title,
                        "description": description,
                        "folder_id": dashboard.get("folderId", ""),
                        "refresh_interval": dashboard.get("refreshInterval", 0),
                        "time_range": str(dashboard.get("timeRange", "")),
                    },
                    resource_id=dashboard_id,
                    resource_type="sumo_dashboard",
                    resource_name=title,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SumoLogicNormalizer())
