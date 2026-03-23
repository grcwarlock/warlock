"""Noname Security normalizer — transforms raw Noname Security API responses into Findings.

Normalizes APIs as inventory, issues and alerts as alert observations.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_NONAME_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


class NonameNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Noname Security telemetry."""

    HANDLERS: dict[str, str] = {
        "noname_apis": "_normalize_apis",
        "noname_issues": "_normalize_issues",
        "noname_alerts": "_normalize_alerts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "noname" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        return getattr(self, handler_name)(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "noname",
            "source_type": SourceType.CUSTOM,
            "provider": "noname",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_apis(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for api in raw.raw_data.get("response", []):
            api_id = str(api.get("id", ""))
            name = api.get("name", api.get("hostname", "unknown"))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Noname API: {name}",
                    detail={
                        "api_id": api_id,
                        "name": name,
                        "hostname": api.get("hostname", ""),
                        "base_path": api.get("basePath", ""),
                        "methods": api.get("methods", []),
                        "risk_level": api.get("riskLevel", ""),
                        "last_seen": api.get("lastSeen", ""),
                    },
                    resource_id=api_id,
                    resource_type="noname_api",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_issues(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for issue in raw.raw_data.get("response", []):
            issue_id = str(issue.get("id", ""))
            title = issue.get("title", issue.get("name", "unknown"))
            raw_severity = issue.get("severity", issue.get("riskLevel", "medium")).lower()
            severity = _NONAME_SEVERITY.get(raw_severity, "medium")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Noname issue: {title}",
                    detail={
                        "issue_id": issue_id,
                        "title": title,
                        "severity": raw_severity,
                        "api": issue.get("api", ""),
                        "category": issue.get("category", ""),
                        "description": issue.get("description", ""),
                        "created_at": issue.get("createdAt", ""),
                        "status": issue.get("status", ""),
                    },
                    resource_id=issue_id,
                    resource_type="noname_issue",
                    resource_name=title,
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for alert in raw.raw_data.get("response", []):
            alert_id = str(alert.get("id", ""))
            title = alert.get("title", alert.get("type", "unknown"))
            raw_severity = alert.get("severity", "medium").lower()
            severity = _NONAME_SEVERITY.get(raw_severity, "medium")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Noname alert: {title}",
                    detail={
                        "alert_id": alert_id,
                        "title": title,
                        "severity": raw_severity,
                        "api": alert.get("api", ""),
                        "description": alert.get("description", ""),
                        "created_at": alert.get("createdAt", ""),
                    },
                    resource_id=alert_id,
                    resource_type="noname_alert",
                    resource_name=title,
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings


# Register
registry.register(NonameNormalizer())
