"""Datadog normalizer — transforms raw Datadog API responses into Findings.

Handles monitors, security signals, SLOs, and host inventory.
Flags monitors in Alert/Warn state, high-severity security signals,
SLOs breaching error budget, and hosts without agent.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Monitor states that indicate a problem
ALERT_STATES = {"Alert", "Warn", "No Data"}


class DatadogNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "datadog_monitors": "_normalize_monitors",
        "datadog_security_signals": "_normalize_security_signals",
        "datadog_slos": "_normalize_slos",
        "datadog_hosts": "_normalize_hosts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "datadog" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Datadog findings."""
        return {
            "raw_event_id": raw.id,
            "source": "datadog",
            "source_type": SourceType.OBSERVABILITY,
            "provider": "datadog",
            "observed_at": raw.observed_at,
        }

    # -- Monitors --

    def _normalize_monitors(self, raw: RawEventData) -> list[FindingData]:
        """Inventory monitors; flag those in Alert/Warn/No Data state."""
        findings = []
        monitors = raw.raw_data.get("monitors", [])

        for mon in monitors:
            mon_id = str(mon.get("id", ""))
            name = mon.get("name", "")
            mon_type = mon.get("type", "")
            overall_state = mon.get("overall_state", "")
            query = mon.get("query", "")
            tags = mon.get("tags", [])
            created = mon.get("created", "")
            modified = mon.get("modified", "")
            message = mon.get("message", "")
            priority = mon.get("priority", None)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Datadog monitor: {name} ({overall_state})",
                    detail={
                        "monitor_id": mon_id,
                        "name": name,
                        "type": mon_type,
                        "overall_state": overall_state,
                        "query": query,
                        "tags": tags,
                        "created": created,
                        "modified": modified,
                        "priority": priority,
                    },
                    resource_id=mon_id,
                    resource_type="datadog_monitor",
                    resource_name=name,
                    severity="info",
                )
            )

            # Flag alerting monitors
            if overall_state in ALERT_STATES:
                sev = "high" if overall_state == "Alert" else "medium"
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Monitor alerting: {name} ({overall_state})",
                        detail={
                            "monitor_id": mon_id,
                            "name": name,
                            "type": mon_type,
                            "overall_state": overall_state,
                            "query": query,
                            "message": message,
                            "tags": tags,
                            "issue": f"Monitor is in {overall_state} state — operational risk",
                        },
                        resource_id=mon_id,
                        resource_type="datadog_monitor",
                        resource_name=name,
                        severity=sev,
                    )
                )

        return findings

    # -- Security Signals --

    def _normalize_security_signals(self, raw: RawEventData) -> list[FindingData]:
        """Normalize security signals; flag high/critical severity."""
        findings = []
        signals = raw.raw_data.get("signals", [])

        for sig in signals:
            sig_id = sig.get("id", "")
            attributes = sig.get("attributes", {})
            title = attributes.get("title", "")
            message = attributes.get("message", "")
            severity_str = attributes.get("severity", "info").lower()
            status = attributes.get("status", "")
            timestamp = attributes.get("timestamp", "")
            tags = attributes.get("tags", [])
            source_str = attributes.get("source", "")

            # Map Datadog severity to warlock severity
            sev_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "info",
            }
            severity = sev_map.get(severity_str, "medium")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Security signal: {title}",
                    detail={
                        "signal_id": sig_id,
                        "title": title,
                        "message": message,
                        "severity": severity_str,
                        "status": status,
                        "timestamp": timestamp,
                        "tags": tags,
                        "source": source_str,
                    },
                    resource_id=sig_id,
                    resource_type="datadog_security_signal",
                    resource_name=title,
                    severity=severity,
                )
            )

        return findings

    # -- SLOs --

    def _normalize_slos(self, raw: RawEventData) -> list[FindingData]:
        """Inventory SLOs; flag those breaching error budget."""
        findings = []
        slos = raw.raw_data.get("slos", [])

        for slo in slos:
            slo_id = slo.get("id", "")
            name = slo.get("name", "")
            slo_type = slo.get("type", "")
            description = slo.get("description", "")
            tags = slo.get("tags", [])
            target_threshold = slo.get("target_threshold", 0)
            overall_status = slo.get("overall_status", [])
            thresholds = slo.get("thresholds", [])
            created_at = slo.get("created_at", "")
            modified_at = slo.get("modified_at", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"SLO: {name} (target: {target_threshold}%)",
                    detail={
                        "slo_id": slo_id,
                        "name": name,
                        "type": slo_type,
                        "description": description,
                        "tags": tags,
                        "target_threshold": target_threshold,
                        "thresholds": thresholds,
                        "created_at": created_at,
                        "modified_at": modified_at,
                    },
                    resource_id=slo_id,
                    resource_type="datadog_slo",
                    resource_name=name,
                    severity="info",
                )
            )

            # Check error budget from overall_status
            if isinstance(overall_status, list):
                for status in overall_status:
                    if isinstance(status, dict):
                        error_budget_remaining = status.get("error_budget_remaining", None)
                        sli_value = status.get("sli_value", None)
                        timeframe = status.get("timeframe", "")

                        if error_budget_remaining is not None and error_budget_remaining <= 0:
                            findings.append(
                                FindingData(
                                    **self._base(raw),
                                    observation_type="alert",
                                    title=f"SLO error budget exhausted: {name} ({timeframe})",
                                    detail={
                                        "slo_id": slo_id,
                                        "name": name,
                                        "timeframe": timeframe,
                                        "error_budget_remaining": error_budget_remaining,
                                        "sli_value": sli_value,
                                        "target_threshold": target_threshold,
                                        "issue": "SLO error budget is exhausted — service reliability target is breached",
                                    },
                                    resource_id=slo_id,
                                    resource_type="datadog_slo",
                                    resource_name=name,
                                    severity="high",
                                )
                            )
                        elif error_budget_remaining is not None and error_budget_remaining < 20:
                            findings.append(
                                FindingData(
                                    **self._base(raw),
                                    observation_type="alert",
                                    title=f"SLO error budget low: {name} ({timeframe}, {error_budget_remaining}% remaining)",
                                    detail={
                                        "slo_id": slo_id,
                                        "name": name,
                                        "timeframe": timeframe,
                                        "error_budget_remaining": error_budget_remaining,
                                        "sli_value": sli_value,
                                        "target_threshold": target_threshold,
                                        "issue": "SLO error budget is below 20% — at risk of breaching target",
                                    },
                                    resource_id=slo_id,
                                    resource_type="datadog_slo",
                                    resource_name=name,
                                    severity="medium",
                                )
                            )

        return findings

    # -- Hosts --

    def _normalize_hosts(self, raw: RawEventData) -> list[FindingData]:
        """Inventory hosts; flag those without agent or with stale data."""
        findings = []
        hosts = raw.raw_data.get("hosts", [])

        for host in hosts:
            host_name = host.get("name", "")
            host_id = str(host.get("id", host_name))
            aliases = host.get("aliases", [])
            apps = host.get("apps", [])
            is_muted = host.get("is_muted", False)
            last_reported = host.get("last_reported_time", 0)
            sources = host.get("sources", [])
            meta = host.get("meta", {})
            agent_version = meta.get("agent_version", "") if isinstance(meta, dict) else ""
            platform = meta.get("platform", "") if isinstance(meta, dict) else ""
            host.get("tags_by_source", {})

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Datadog host: {host_name}",
                    detail={
                        "host_name": host_name,
                        "host_id": host_id,
                        "aliases": aliases,
                        "apps": apps,
                        "is_muted": is_muted,
                        "last_reported_time": last_reported,
                        "sources": sources,
                        "agent_version": agent_version,
                        "platform": platform,
                    },
                    resource_id=host_id,
                    resource_type="datadog_host",
                    resource_name=host_name,
                    severity="info",
                )
            )

            # Flag hosts without agent
            if not agent_version:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Host without Datadog agent: {host_name}",
                        detail={
                            "host_name": host_name,
                            "host_id": host_id,
                            "sources": sources,
                            "issue": "Host has no Datadog agent — limited observability and monitoring coverage",
                        },
                        resource_id=host_id,
                        resource_type="datadog_host",
                        resource_name=host_name,
                        severity="medium",
                    )
                )

            # Flag muted hosts
            if is_muted:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Host muted: {host_name}",
                        detail={
                            "host_name": host_name,
                            "host_id": host_id,
                            "is_muted": True,
                            "issue": "Host is muted — alerts are suppressed, reducing detection coverage",
                        },
                        resource_id=host_id,
                        resource_type="datadog_host",
                        resource_name=host_name,
                        severity="low",
                    )
                )

        return findings


# Register
registry.register(DatadogNormalizer())
