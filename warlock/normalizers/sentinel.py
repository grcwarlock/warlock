"""Sentinel normalizer — transforms raw Sentinel API responses into Findings.

Handles incidents (severity mapping, status, assignee) and analytics rule
status (enabled/disabled detection coverage).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SentinelNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "sentinel_incidents": "_normalize_incidents",
        "sentinel_analytics_rules": "_normalize_analytics_rules",
        "sentinel_hunting_queries": "_normalize_hunting_queries",
        "sentinel_data_connectors": "_normalize_data_connectors",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sentinel" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Sentinel findings."""
        return {
            "raw_event_id": raw.id,
            "source": "sentinel",
            "source_type": SourceType.SIEM,
            "provider": "sentinel",
            "account_id": raw.raw_data.get("subscription_id", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Incidents --

    def _normalize_incidents(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        incidents = raw.raw_data.get("response", [])

        for incident in incidents:
            props = incident.get("properties", {})
            severity_raw = props.get("severity", "Informational").lower()
            severity_map = {
                "high": "high",
                "critical": "critical",
                "medium": "medium",
                "low": "low",
                "informational": "info",
            }
            severity = severity_map.get(severity_raw, "info")

            status = props.get("status", "New")
            title = props.get("title", "Unknown incident")
            incident_id = incident.get("name", "")
            owner = props.get("owner", {})
            assigned_to = owner.get("assignedTo", "") or owner.get("email", "")

            related_alerts = props.get("relatedAnalyticRuleIds", [])
            alert_count = props.get("additionalData", {}).get("alertsCount", 0)

            findings.append(FindingData(
                **self._base(raw),
                observation_type="alert",
                title=f"Sentinel incident: {title}",
                detail={
                    "incident_id": incident_id,
                    "severity": severity_raw,
                    "status": status,
                    "assigned_to": assigned_to,
                    "related_analytic_rule_ids": related_alerts,
                    "alert_count": alert_count,
                    "incident_url": incident.get("id", ""),
                    "created_time": props.get("createdTimeUtc", ""),
                    "last_modified_time": props.get("lastModifiedTimeUtc", ""),
                    "classification": props.get("classification", ""),
                    "labels": [lbl.get("labelName", "") for lbl in props.get("labels", [])],
                },
                resource_id=incident.get("id", ""),
                resource_type="sentinel_incident",
                resource_name=title,
                severity=severity,
            ))

        return findings

    # -- Analytics rules --

    def _normalize_analytics_rules(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        rules = raw.raw_data.get("response", [])

        enabled_count = 0
        disabled_count = 0

        for rule in rules:
            props = rule.get("properties", {})
            enabled = props.get("enabled", False)
            if enabled:
                enabled_count += 1
            else:
                disabled_count += 1

            rule_name = props.get("displayName", rule.get("name", "unknown"))
            severity_raw = props.get("severity", "Informational").lower()

            findings.append(FindingData(
                **self._base(raw),
                observation_type="misconfiguration" if not enabled else "inventory",
                title=f"Analytics rule: {rule_name}" + (" — disabled" if not enabled else ""),
                detail={
                    "rule_id": rule.get("name", ""),
                    "display_name": rule_name,
                    "enabled": enabled,
                    "severity": severity_raw,
                    "kind": rule.get("kind", ""),
                    "tactics": props.get("tactics", []),
                    "techniques": props.get("techniques", []),
                },
                resource_id=rule.get("id", ""),
                resource_type="sentinel_analytics_rule",
                resource_name=rule_name,
                severity="medium" if not enabled else "info",
            ))

        # Summary finding for coverage
        total = enabled_count + disabled_count
        if total > 0:
            coverage_pct = round((enabled_count / total) * 100, 1)
            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Analytics rule coverage: {coverage_pct}% ({enabled_count}/{total} enabled)",
                detail={
                    "enabled_count": enabled_count,
                    "disabled_count": disabled_count,
                    "total": total,
                    "coverage_percent": coverage_pct,
                },
                resource_id="sentinel:analytics_rules:summary",
                resource_type="sentinel_analytics_rules",
                resource_name="analytics_rule_coverage",
                severity="info" if coverage_pct >= 80 else "medium",
            ))

        return findings

    # -- Hunting queries --

    def _normalize_hunting_queries(self, raw: RawEventData) -> list[FindingData]:
        queries = raw.raw_data.get("response", [])
        return [FindingData(
            **self._base(raw),
            observation_type="inventory",
            title=f"Sentinel hunting queries — {len(queries)} configured",
            detail={"query_count": len(queries)},
            resource_id="sentinel:hunting_queries:summary",
            resource_type="sentinel_hunting_queries",
            resource_name="hunting_queries",
            severity="info",
        )]

    # -- Data connectors --

    def _normalize_data_connectors(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        connectors = raw.raw_data.get("response", [])

        for connector in connectors:
            props = connector.get("properties", {})
            connector_name = props.get("connectorUiConfig", {}).get("title", connector.get("name", "unknown"))
            kind = connector.get("kind", "unknown")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Data connector: {connector_name} ({kind})",
                detail={
                    "connector_id": connector.get("name", ""),
                    "kind": kind,
                    "connector_name": connector_name,
                },
                resource_id=connector.get("id", ""),
                resource_type="sentinel_data_connector",
                resource_name=connector_name,
                severity="info",
            ))

        return findings


# Register
registry.register(SentinelNormalizer())
