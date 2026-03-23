"""Salt Security normalizer — transforms raw Salt Security API responses into Findings.

Normalizes APIs as inventory, alerts and findings as alert observations.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_SALT_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


class SaltSecurityNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Salt Security telemetry."""

    HANDLERS: dict[str, str] = {
        "salt_security_apis": "_normalize_apis",
        "salt_security_alerts": "_normalize_alerts",
        "salt_security_findings": "_normalize_findings",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "salt_security" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        return getattr(self, handler_name)(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "salt_security",
            "source_type": SourceType.CUSTOM,
            "provider": "salt_security",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_apis(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for api in raw.raw_data.get("response", []):
            api_id = str(api.get("id", ""))
            name = api.get("name", api.get("title", "unknown"))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Salt Security API: {name}",
                    detail={
                        "api_id": api_id,
                        "name": name,
                        "base_path": api.get("basePath", ""),
                        "host": api.get("host", ""),
                        "protocol": api.get("protocol", ""),
                        "risk_score": api.get("riskScore", 0),
                        "alert_count": api.get("alertCount", 0),
                    },
                    resource_id=api_id,
                    resource_type="salt_security_api",
                    resource_name=name,
                    severity="info",
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
            severity = _SALT_SEVERITY.get(raw_severity, "medium")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Salt Security alert: {title}",
                    detail={
                        "alert_id": alert_id,
                        "title": title,
                        "severity": raw_severity,
                        "api": alert.get("api", ""),
                        "category": alert.get("category", ""),
                        "description": alert.get("description", ""),
                        "created_at": alert.get("createdAt", ""),
                    },
                    resource_id=alert_id,
                    resource_type="salt_security_alert",
                    resource_name=title,
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_findings(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for finding in raw.raw_data.get("response", []):
            finding_id = str(finding.get("id", ""))
            title = finding.get("title", finding.get("name", "unknown"))
            raw_severity = finding.get("severity", "medium").lower()
            severity = _SALT_SEVERITY.get(raw_severity, "medium")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Salt Security finding: {title}",
                    detail={
                        "finding_id": finding_id,
                        "title": title,
                        "severity": raw_severity,
                        "category": finding.get("category", ""),
                        "api": finding.get("api", ""),
                        "remediation": finding.get("remediation", ""),
                        "created_at": finding.get("createdAt", ""),
                    },
                    resource_id=finding_id,
                    resource_type="salt_security_finding",
                    resource_name=title,
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings


# Register
registry.register(SaltSecurityNormalizer())
