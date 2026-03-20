"""Elastic Security normalizer — transforms raw Elastic API responses into Findings.

Handles security alerts (severity, status) and detection rule coverage
(enabled/disabled rules).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ElasticNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "elastic_security_alerts": "_normalize_security_alerts",
        "elastic_detection_rules": "_normalize_detection_rules",
        "elastic_agent_status": "_normalize_agent_status",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "elastic" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Elastic findings."""
        return {
            "raw_event_id": raw.id,
            "source": "elastic",
            "source_type": SourceType.SIEM,
            "provider": "elastic",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Security alerts --

    def _normalize_security_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        hits = response.get("hits", {}).get("hits", [])

        for hit in hits:
            source = hit.get("_source", {})
            alert = source.get("kibana.alert", source)

            # Handle both nested and flat key formats
            severity_raw = (
                alert.get("severity", "") or source.get("kibana.alert.severity", "unknown")
            ).lower()
            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
            }
            severity = severity_map.get(severity_raw, "info")

            rule_name = alert.get("rule", {}).get("name", "") or source.get(
                "kibana.alert.rule.name", "Unknown alert"
            )
            alert_id = hit.get("_id", "")
            status = alert.get("workflow_status", "") or source.get(
                "kibana.alert.workflow_status", "open"
            )

            host_name = source.get("host", {}).get("name", "")
            user_name = source.get("user", {}).get("name", "")
            risk_score = alert.get("risk_score", 0) or source.get("kibana.alert.risk_score", 0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Elastic alert: {rule_name}",
                    detail={
                        "alert_id": alert_id,
                        "rule_name": rule_name,
                        "severity": severity_raw,
                        "status": status,
                        "risk_score": risk_score,
                        "host": host_name,
                        "user": user_name,
                        "timestamp": source.get("@timestamp", ""),
                        "rule_id": (
                            alert.get("rule", {}).get("id", "")
                            or source.get("kibana.alert.rule.id", "")
                        ),
                        "mitre_tactics": source.get("threat", [{}])[0]
                        .get("tactic", {})
                        .get("name", "")
                        if source.get("threat")
                        else "",
                    },
                    resource_id=alert_id,
                    resource_type="elastic_security_alert",
                    resource_name=rule_name,
                    severity=severity,
                )
            )

        return findings

    # -- Detection rules --

    def _normalize_detection_rules(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        rules = response.get("data", [])

        enabled_count = 0
        disabled_count = 0

        for rule in rules:
            enabled = rule.get("enabled", False)
            if enabled:
                enabled_count += 1
            else:
                disabled_count += 1

            name = rule.get("name", "unknown")
            severity_raw = rule.get("severity", "low").lower()

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration" if not enabled else "inventory",
                    title=f"Detection rule: {name}" + (" — disabled" if not enabled else ""),
                    detail={
                        "rule_id": rule.get("id", ""),
                        "name": name,
                        "enabled": enabled,
                        "severity": severity_raw,
                        "type": rule.get("type", ""),
                        "risk_score": rule.get("risk_score", 0),
                        "tags": rule.get("tags", []),
                        "threat": rule.get("threat", []),
                        "interval": rule.get("interval", ""),
                        "updated_at": rule.get("updated_at", ""),
                    },
                    resource_id=rule.get("id", ""),
                    resource_type="elastic_detection_rule",
                    resource_name=name,
                    severity="medium" if not enabled else "info",
                )
            )

        # Coverage summary
        total = enabled_count + disabled_count
        if total > 0:
            coverage_pct = round((enabled_count / total) * 100, 1)
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Detection rule coverage: {coverage_pct}% ({enabled_count}/{total} enabled)",
                    detail={
                        "enabled_count": enabled_count,
                        "disabled_count": disabled_count,
                        "total": total,
                        "coverage_percent": coverage_pct,
                    },
                    resource_id="elastic:detection_rules:summary",
                    resource_type="elastic_detection_rules",
                    resource_name="detection_rule_coverage",
                    severity="info" if coverage_pct >= 80 else "medium",
                )
            )

        return findings

    # -- Agent status --

    def _normalize_agent_status(self, raw: RawEventData) -> list[FindingData]:
        response = raw.raw_data.get("response", {})
        results = response.get("results", response)

        online = results.get("online", 0)
        offline = results.get("offline", 0)
        error = results.get("error", 0)
        updating = results.get("updating", 0)
        inactive = results.get("inactive", 0)
        total = results.get("total", online + offline + error + updating + inactive)

        issues = []
        if offline > 0:
            issues.append(f"{offline}_agents_offline")
        if error > 0:
            issues.append(f"{error}_agents_in_error")

        severity = "info"
        if error > 0:
            severity = "high"
        elif offline > 0:
            severity = "medium"

        return [
            FindingData(
                **self._base(raw),
                observation_type="misconfiguration" if issues else "inventory",
                title=f"Elastic agents: {online}/{total} online"
                + (f" — {', '.join(issues)}" if issues else ""),
                detail={
                    "online": online,
                    "offline": offline,
                    "error": error,
                    "updating": updating,
                    "inactive": inactive,
                    "total": total,
                    "issues": issues,
                },
                resource_id="elastic:agents:summary",
                resource_type="elastic_agents",
                resource_name="agent_status",
                severity=severity,
            )
        ]


# Register
registry.register(ElasticNormalizer())
