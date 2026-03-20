"""Splunk normalizer — transforms raw Splunk API responses into Findings.

Handles notable events (severity, status) and correlation rule status
(enabled/disabled detection coverage).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SplunkNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "splunk_notable_events": "_normalize_notable_events",
        "splunk_saved_searches": "_normalize_saved_searches",
        "splunk_correlation_rules": "_normalize_correlation_rules",
        "splunk_index_health": "_normalize_index_health",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "splunk" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Splunk findings."""
        return {
            "raw_event_id": raw.id,
            "source": "splunk",
            "source_type": SourceType.SIEM,
            "provider": "splunk",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Notable events --

    def _normalize_notable_events(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        events = raw.raw_data.get("response", [])

        for event in events:
            if not isinstance(event, dict):
                continue
            result = event.get("result", event)

            urgency = result.get("urgency", "informational").lower()
            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "informational": "info",
                "info": "info",
            }
            severity = severity_map.get(urgency, "info")

            rule_name = result.get("search_name", result.get("rule_name", "Unknown"))
            event_id = result.get("event_id", result.get("_cd", ""))
            status_label = result.get("status_label", result.get("status", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Notable event: {rule_name}",
                    detail={
                        "event_id": event_id,
                        "rule_name": rule_name,
                        "urgency": urgency,
                        "status": status_label,
                        "owner": result.get("owner", ""),
                        "security_domain": result.get("security_domain", ""),
                        "src": result.get("src", ""),
                        "dest": result.get("dest", ""),
                        "user": result.get("user", ""),
                        "description": result.get(
                            "rule_description", result.get("description", "")
                        ),
                        "time": result.get("_time", ""),
                    },
                    resource_id=event_id,
                    resource_type="splunk_notable_event",
                    resource_name=rule_name,
                    severity=severity,
                )
            )

        return findings

    # -- Saved searches --

    def _normalize_saved_searches(self, raw: RawEventData) -> list[FindingData]:
        entries = raw.raw_data.get("response", [])
        return [
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Splunk saved searches — {len(entries)} configured",
                detail={"saved_search_count": len(entries)},
                resource_id="splunk:saved_searches:summary",
                resource_type="splunk_saved_searches",
                resource_name="saved_searches",
                severity="info",
            )
        ]

    # -- Correlation rules --

    def _normalize_correlation_rules(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        entries = raw.raw_data.get("response", [])

        enabled_count = 0
        disabled_count = 0

        for entry in entries:
            content = entry.get("content", {}) if isinstance(entry, dict) else {}
            name = entry.get("name", "unknown") if isinstance(entry, dict) else "unknown"
            disabled = content.get("disabled", "0")
            is_disabled = str(disabled) == "1" or disabled is True
            if is_disabled:
                disabled_count += 1
            else:
                enabled_count += 1

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration" if is_disabled else "inventory",
                    title=f"Correlation rule: {name}" + (" — disabled" if is_disabled else ""),
                    detail={
                        "rule_name": name,
                        "enabled": not is_disabled,
                        "severity": content.get("action.correlationsearch.label", ""),
                        "description": content.get("description", ""),
                    },
                    resource_id=entry.get("id", "") if isinstance(entry, dict) else "",
                    resource_type="splunk_correlation_rule",
                    resource_name=name,
                    severity="medium" if is_disabled else "info",
                )
            )

        # Summary finding
        total = enabled_count + disabled_count
        if total > 0:
            coverage_pct = round((enabled_count / total) * 100, 1)
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Correlation rule coverage: {coverage_pct}% ({enabled_count}/{total} enabled)",
                    detail={
                        "enabled_count": enabled_count,
                        "disabled_count": disabled_count,
                        "total": total,
                        "coverage_percent": coverage_pct,
                    },
                    resource_id="splunk:correlation_rules:summary",
                    resource_type="splunk_correlation_rules",
                    resource_name="correlation_rule_coverage",
                    severity="info" if coverage_pct >= 80 else "medium",
                )
            )

        return findings

    # -- Index health --

    def _normalize_index_health(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        entries = raw.raw_data.get("response", [])

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            content = entry.get("content", {})
            name = entry.get("name", "unknown")
            disabled = str(content.get("disabled", "0")) == "1"
            total_event_count = content.get("totalEventCount", "0")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Index: {name}" + (" — disabled" if disabled else ""),
                    detail={
                        "index_name": name,
                        "disabled": disabled,
                        "total_event_count": total_event_count,
                        "current_db_size_mb": content.get("currentDBSizeMB", "0"),
                        "max_total_data_size_mb": content.get("maxTotalDataSizeMB", "0"),
                    },
                    resource_id=entry.get("id", ""),
                    resource_type="splunk_index",
                    resource_name=name,
                    severity="info",
                )
            )

        return findings


# Register
registry.register(SplunkNormalizer())
