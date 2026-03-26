"""Defender normalizer — transforms raw MS Defender API responses into Findings.

Handles machine risk data, alerts, vulnerabilities, and recommendations.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Defender severity string → standard
DEFENDER_SEVERITY_MAP: dict[str, str] = {
    "Informational": "info",
    "Low": "low",
    "Medium": "medium",
    "High": "high",
    "Critical": "critical",
}

# Machine risk score → severity
RISK_SCORE_MAP: dict[str, str] = {
    "None": "info",
    "Informational": "info",
    "Low": "low",
    "Medium": "medium",
    "High": "high",
    "Critical": "critical",
}


class DefenderNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "defender_machines": "_normalize_machines",
        "defender_alerts": "_normalize_alerts",
        "defender_vulnerabilities": "_normalize_vulnerabilities",
        "defender_recommendations": "_normalize_recommendations",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "defender" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Defender findings."""
        return {
            "raw_event_id": raw.id,
            "source": "defender",
            "source_type": SourceType.EDR,
            "provider": "defender",
            "observed_at": raw.observed_at,
        }

    # -- Machines --

    def _normalize_machines(self, raw: RawEventData) -> list[FindingData]:
        """One finding per machine with risk assessment."""
        findings = []
        machines = raw.raw_data.get("records", [])

        for machine in machines:
            machine_id = machine.get("id", "")
            name = machine.get("computerDnsName", machine.get("machineName", "unknown"))
            os_platform = machine.get("osPlatform", "")
            os_version = machine.get("osVersion", "")
            risk_score = machine.get("riskScore", "None")
            exposure_level = machine.get("exposureLevel", "None")
            health_status = machine.get("healthStatus", "Unknown")
            onboarding_status = machine.get("onboardingStatus", "")

            severity = RISK_SCORE_MAP.get(risk_score, "info")

            issues = []
            if health_status not in ("Active", "Inactive"):
                issues.append(f"health_status_{health_status}")
            if onboarding_status != "Onboarded":
                issues.append(f"onboarding_{onboarding_status}")
            if risk_score in ("High", "Critical"):
                issues.append(f"risk_score_{risk_score}")
            if exposure_level in ("High", "Critical"):
                issues.append(f"exposure_{exposure_level}")

            obs_type = "inventory"
            if issues:
                obs_type = "policy_violation"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Defender machine {name}"
                    + (f" — {', '.join(issues)}" if issues else ""),
                    detail={
                        "machine_id": machine_id,
                        "computer_dns_name": name,
                        "os_platform": os_platform,
                        "os_version": os_version,
                        "risk_score": risk_score,
                        "exposure_level": exposure_level,
                        "health_status": health_status,
                        "onboarding_status": onboarding_status,
                        "issues": issues,
                    },
                    resource_id=machine_id,
                    resource_type="endpoint",
                    resource_name=name,
                    severity=severity,
                )
            )

        return findings

    # -- Alerts --

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        """One finding per alert."""
        findings = []
        alerts = raw.raw_data.get("records", [])

        for alert in alerts:
            alert_id = alert.get("id", "")
            title = alert.get("title", "Unknown alert")
            severity_str = alert.get("severity", "Informational")
            severity = DEFENDER_SEVERITY_MAP.get(severity_str, "info")
            status = alert.get("status", "")
            category = alert.get("category", "")
            machine_id = alert.get("machineId", "")
            computer_name = alert.get("computerDnsName", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Defender alert: {title}" + (f" ({category})" if category else ""),
                    detail={
                        "alert_id": alert_id,
                        "title": title,
                        "severity": severity_str,
                        "status": status,
                        "category": category,
                        "machine_id": machine_id,
                        "computer_dns_name": computer_name,
                        "description": alert.get("description", ""),
                        "recommended_action": alert.get("recommendedAction", ""),
                    },
                    resource_id=machine_id,
                    resource_type="endpoint",
                    resource_name=computer_name,
                    severity=severity,
                )
            )

        return findings

    # -- Vulnerabilities --

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        """One finding per vulnerability."""
        findings = []
        vulns = raw.raw_data.get("records", [])

        for vuln in vulns:
            vuln_id = vuln.get("id", "")
            cve_id = vuln.get("cveId", vuln_id)
            name = vuln.get("name", cve_id)
            severity_str = vuln.get("severity", "Informational")
            severity = DEFENDER_SEVERITY_MAP.get(severity_str, "info")
            exposed_machines = vuln.get("exposedMachines", 0)
            published_on = vuln.get("publishedOn", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Vulnerability {cve_id}"
                    + (f" — {exposed_machines} machine(s) exposed" if exposed_machines else ""),
                    detail={
                        "vulnerability_id": vuln_id,
                        "cve_id": cve_id,
                        "name": name,
                        "severity": severity_str,
                        "exposed_machines": exposed_machines,
                        "published_on": published_on,
                        "description": vuln.get("description", ""),
                        "cvss_v3": vuln.get("cvssV3", 0.0),
                    },
                    resource_id=cve_id,
                    resource_type="vulnerability",
                    resource_name=name,
                    severity=severity,
                )
            )

        return findings

    # -- Recommendations --

    def _normalize_recommendations(self, raw: RawEventData) -> list[FindingData]:
        """One finding per security recommendation."""
        findings = []
        recs = raw.raw_data.get("records", [])

        for rec in recs:
            rec_id = rec.get("id", "")
            title = rec.get("recommendationName", "Unknown recommendation")
            severity_str = rec.get("severityScore", "Informational")
            severity = DEFENDER_SEVERITY_MAP.get(severity_str, "info")
            status = rec.get("status", "")
            exposed = rec.get("exposedMachinesCount", 0)
            category = rec.get("recommendationCategory", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"Recommendation: {title}"
                    + (f" — {exposed} machine(s)" if exposed else ""),
                    detail={
                        "recommendation_id": rec_id,
                        "title": title,
                        "severity": severity_str,
                        "status": status,
                        "category": category,
                        "exposed_machines_count": exposed,
                        "remediation_type": rec.get("remediationType", ""),
                        "vendor": rec.get("vendor", ""),
                        "product_name": rec.get("productName", ""),
                    },
                    resource_id=rec_id,
                    resource_type="recommendation",
                    resource_name=title,
                    severity=severity,
                )
            )

        return findings


# Register
registry.register(DefenderNormalizer())
