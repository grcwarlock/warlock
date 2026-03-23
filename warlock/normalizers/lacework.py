"""Lacework normalizer — transforms alerts, vulnerabilities, and compliance into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_LACEWORK_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    # Lacework also uses numeric severity
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "low",
    "5": "info",
}


class LaceworkNormalizer(BaseNormalizer):
    """Dispatches Lacework event types to type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "lacework_alerts": "_normalize_alerts",
        "lacework_vulnerabilities": "_normalize_vulnerabilities",
        "lacework_compliance": "_normalize_compliance",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "lacework" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "lacework",
            "source_type": SourceType.CSPM,
            "provider": "lacework",
            "account_id": raw.raw_data.get("account", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for alert in raw.raw_data.get("response", []):
            alert_id = str(alert.get("alertId", alert.get("id", "")))
            raw_severity = str(alert.get("severity", "Medium")).lower()
            severity = _LACEWORK_SEVERITY_MAP.get(raw_severity, "medium")
            alert_type = alert.get("alertType", alert.get("type", "unknown"))
            title = alert.get("startTime", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Lacework alert: {alert_type}",
                    detail={
                        "alert_id": alert_id,
                        "alert_type": alert_type,
                        "severity": raw_severity,
                        "status": alert.get("status", ""),
                        "start_time": alert.get("startTime", ""),
                        "end_time": alert.get("endTime", ""),
                        "policy_id": alert.get("policyId", ""),
                        "account_id": alert.get("accountId", ""),
                    },
                    resource_id=alert_id,
                    resource_type="lacework_alert",
                    resource_name=alert_type,
                    severity=severity,
                    confidence=0.9,
                )
            )
        return findings

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for vuln in raw.raw_data.get("response", []):
            vuln_id = str(vuln.get("evalGuid", vuln.get("id", "")))
            cve_id = vuln.get("vulnId", "")
            raw_severity = str(vuln.get("severity", "Low")).lower()
            severity = _LACEWORK_SEVERITY_MAP.get(raw_severity, "medium")
            image_id = vuln.get("imageId", "")
            package_name = vuln.get("packageName", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Lacework vulnerability: {cve_id or vuln_id}",
                    detail={
                        "vuln_id": vuln_id,
                        "cve_id": cve_id,
                        "severity": raw_severity,
                        "image_id": image_id,
                        "package_name": package_name,
                        "package_version": vuln.get("packageVersion", ""),
                        "fix_available": vuln.get("fixAvailable", False),
                        "status": vuln.get("status", ""),
                    },
                    resource_id=image_id or vuln_id,
                    resource_type="lacework_container_vulnerability",
                    resource_name=cve_id or vuln_id,
                    severity=severity,
                    confidence=0.95,
                )
            )
        return findings

    def _normalize_compliance(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for check in raw.raw_data.get("response", []):
            check_id = str(check.get("id", check.get("ruleId", "")))
            title = check.get("title", check.get("rule", "Lacework compliance check"))
            status = str(check.get("status", "unknown")).lower()
            raw_severity = str(check.get("severity", "Low")).lower()
            severity = _LACEWORK_SEVERITY_MAP.get(raw_severity, "medium")

            obs_type = "policy_violation" if status in ("non-compliant", "failed", "fail") else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Lacework compliance: {title}",
                    detail={
                        "check_id": check_id,
                        "title": title,
                        "status": status,
                        "severity": raw_severity,
                        "framework": check.get("reportType", check.get("framework", "")),
                        "recommendations": check.get("recommendations", ""),
                        "affected_resources": check.get("suppressedCount", 0),
                    },
                    resource_id=check_id,
                    resource_type="lacework_compliance_check",
                    resource_name=title,
                    severity=severity,
                    confidence=0.9,
                )
            )
        return findings


registry.register(LaceworkNormalizer())
