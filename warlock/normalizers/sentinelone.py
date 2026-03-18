"""SentinelOne normalizer — transforms raw S1 API responses into Findings.

Handles threats, agent compliance status, applications, and policies.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# SentinelOne threat confidence → severity
S1_CONFIDENCE_SEVERITY: dict[str, str] = {
    "malicious": "critical",
    "suspicious": "high",
    "n/a": "medium",
}

# SentinelOne agent health → severity
S1_HEALTH_SEVERITY: dict[str, str] = {
    "infected": "critical",
    "pending_uninstall": "high",
    "decommissioned": "medium",
    "shutdown": "low",
    "healthy": "info",
}


class SentinelOneNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "s1_threats": "_normalize_threats",
        "s1_agents": "_normalize_agents",
        "s1_applications": "_normalize_applications",
        "s1_policies": "_normalize_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sentinelone" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all SentinelOne findings."""
        return {
            "raw_event_id": raw.id,
            "source": "sentinelone",
            "source_type": SourceType.EDR,
            "provider": "sentinelone",
            "observed_at": raw.observed_at,
        }

    # -- Threats --

    def _normalize_threats(self, raw: RawEventData) -> list[FindingData]:
        """One finding per threat."""
        findings = []
        threats = raw.raw_data.get("records", [])

        for threat in threats:
            threat_id = threat.get("id", "")
            classification = threat.get("classification", "unknown")
            confidence = threat.get("confidenceLevel", "n/a").lower()
            severity = S1_CONFIDENCE_SEVERITY.get(confidence, "medium")

            agent_info = threat.get("agentRealtimeInfo", threat.get("agentDetectionInfo", {}))
            hostname = agent_info.get("agentComputerName", "unknown")
            agent_id = agent_info.get("agentId", "")
            os_name = agent_info.get("agentOsName", "")

            threat_info = threat.get("threatInfo", {})
            threat_name = threat_info.get("threatName", threat.get("threatName", "unknown"))
            status = threat_info.get("mitigationStatus", threat.get("mitigationStatus", ""))
            file_path = threat_info.get("filePath", threat.get("filePath", ""))
            engines = threat_info.get("engines", [])

            findings.append(FindingData(
                **self._base(raw),
                observation_type="alert",
                title=f"SentinelOne threat: {threat_name} on {hostname} ({classification})",
                detail={
                    "threat_id": threat_id,
                    "threat_name": threat_name,
                    "classification": classification,
                    "confidence_level": confidence,
                    "mitigation_status": status,
                    "file_path": file_path,
                    "engines": engines,
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "os_name": os_name,
                },
                resource_id=agent_id,
                resource_type="endpoint",
                resource_name=hostname,
                severity=severity,
            ))

        return findings

    # -- Agents (compliance) --

    def _normalize_agents(self, raw: RawEventData) -> list[FindingData]:
        """One finding per agent with compliance checks."""
        findings = []
        agents = raw.raw_data.get("records", [])

        for agent in agents:
            agent_id = agent.get("id", "")
            hostname = agent.get("computerName", "unknown")
            os_name = agent.get("osName", "")
            os_version = agent.get("osRevision", "")
            agent_version = agent.get("agentVersion", "")
            is_active = agent.get("isActive", False)
            is_up_to_date = agent.get("isUpToDate", False)
            infected = agent.get("infected", False)
            network_status = agent.get("networkStatus", "")
            scan_status = agent.get("scanStatus", "")

            issues = []
            if not is_active:
                issues.append("agent_inactive")
            if not is_up_to_date:
                issues.append("agent_outdated")
            if infected:
                issues.append("endpoint_infected")
            if network_status == "disconnected":
                issues.append("agent_disconnected")
            if scan_status == "none":
                issues.append("no_recent_scan")

            severity = "info"
            obs_type = "inventory"
            if infected:
                severity = "critical"
                obs_type = "alert"
            elif issues:
                severity = "medium"
                obs_type = "policy_violation"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"SentinelOne agent {hostname}" + (f" — {', '.join(issues)}" if issues else ""),
                detail={
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "os_name": os_name,
                    "os_version": os_version,
                    "agent_version": agent_version,
                    "is_active": is_active,
                    "is_up_to_date": is_up_to_date,
                    "infected": infected,
                    "network_status": network_status,
                    "scan_status": scan_status,
                    "threat_count": agent.get("activeThreats", 0),
                    "issues": issues,
                },
                resource_id=agent_id,
                resource_type="endpoint",
                resource_name=hostname,
                severity=severity,
            ))

        return findings

    # -- Applications --

    def _normalize_applications(self, raw: RawEventData) -> list[FindingData]:
        """Inventory of installed applications."""
        total = raw.raw_data.get("total", 0)
        apps = raw.raw_data.get("records", [])

        findings = [FindingData(
            **self._base(raw),
            observation_type="inventory",
            title=f"SentinelOne — {total} installed application(s) tracked",
            detail={"total_applications": total},
            resource_id="sentinelone:applications",
            resource_type="application_inventory",
            resource_name="application-inventory",
            severity="info",
        )]

        # Flag applications with known risk indicators
        for app in apps:
            risk = app.get("riskLevel", "")
            if risk and risk.lower() in ("high", "critical"):
                app_name = app.get("name", "unknown")
                agent_name = app.get("agentComputerName", "unknown")
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"High-risk application: {app_name} on {agent_name}",
                    detail={
                        "application_name": app_name,
                        "version": app.get("version", ""),
                        "publisher": app.get("publisher", ""),
                        "risk_level": risk,
                        "agent_computer_name": agent_name,
                    },
                    resource_id=app.get("agentId", ""),
                    resource_type="application",
                    resource_name=app_name,
                    severity="high" if risk.lower() == "high" else "critical",
                ))

        return findings

    # -- Policies --

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        """One finding per policy."""
        findings = []
        policies = raw.raw_data.get("records", [])

        for policy in policies:
            policy_id = policy.get("id", "")
            name = policy.get("name", "unknown")
            is_default = policy.get("isDefault", False)
            scope = policy.get("scope", "")

            # Check for weak settings
            issues = []
            anti_tamper = policy.get("antiTamperingEnabled", True)
            if not anti_tamper:
                issues.append("anti_tampering_disabled")
            engine_on = policy.get("engines", {}).get("onWrite", True)
            if not engine_on:
                issues.append("on_write_engine_disabled")

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "medium"
                obs_type = "misconfiguration"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"SentinelOne policy: {name}" + (f" — {', '.join(issues)}" if issues else ""),
                detail={
                    "policy_id": policy_id,
                    "name": name,
                    "is_default": is_default,
                    "scope": scope,
                    "issues": issues,
                },
                resource_id=policy_id,
                resource_type="policy",
                resource_name=name,
                severity=severity,
            ))

        return findings


# Register
registry.register(SentinelOneNormalizer())
