"""CrowdStrike normalizer — transforms raw Falcon API responses into Findings.

Handles detections, spotlight vulnerabilities, device compliance, and
zero trust assessments.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# CrowdStrike severity mapping: numeric (1-5) → standard
CS_SEVERITY_MAP: dict[int, str] = {
    1: "info",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}

# CrowdStrike vulnerability severity string → standard
CS_VULN_SEVERITY_MAP: dict[str, str] = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "None": "info",
    "Unknown": "info",
}


class CrowdStrikeNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "falcon_detection_details": "_normalize_detections",
        "falcon_vulnerabilities": "_normalize_vulnerabilities",
        "falcon_device_details": "_normalize_devices",
        "falcon_devices": "_normalize_device_inventory",
        "falcon_zero_trust": "_normalize_zero_trust",
        "falcon_sensor_policies": "_normalize_sensor_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "crowdstrike" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all CrowdStrike findings."""
        return {
            "raw_event_id": raw.id,
            "source": "crowdstrike",
            "source_type": SourceType.EDR,
            "provider": "crowdstrike",
            "observed_at": raw.observed_at,
        }

    # -- Detections --

    def _normalize_detections(self, raw: RawEventData) -> list[FindingData]:
        """One finding per detection."""
        findings = []
        detections = raw.raw_data.get("detections", [])

        for det in detections:
            severity_num = det.get("max_severity", 0)
            if isinstance(severity_num, dict):
                severity_num = severity_num.get("value", 0)
            severity = CS_SEVERITY_MAP.get(int(severity_num), "info")

            device = det.get("device", {})
            hostname = device.get("hostname", "unknown")
            device_id = device.get("device_id", "")
            tactic = det.get("behaviors", [{}])[0].get("tactic", "") if det.get("behaviors") else ""
            technique = det.get("behaviors", [{}])[0].get("technique", "") if det.get("behaviors") else ""

            status = det.get("status", "new")
            detection_id = det.get("detection_id", "")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="alert",
                title=f"CrowdStrike detection on {hostname}: {tactic}/{technique}" if tactic else f"CrowdStrike detection on {hostname}",
                detail={
                    "detection_id": detection_id,
                    "status": status,
                    "max_severity": severity_num,
                    "tactic": tactic,
                    "technique": technique,
                    "behaviors": det.get("behaviors", []),
                    "device": device,
                },
                resource_id=device_id,
                resource_type="endpoint",
                resource_name=hostname,
                severity=severity,
            ))

        return findings

    # -- Spotlight Vulnerabilities --

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        """One finding per vulnerability."""
        findings = []
        vulns = raw.raw_data.get("vulnerabilities", [])

        for vuln in vulns:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", vuln.get("id", "unknown"))
            severity_str = cve.get("base_score_severity", vuln.get("severity", "Unknown"))
            severity = CS_VULN_SEVERITY_MAP.get(severity_str, "info")

            host_info = vuln.get("host_info", {})
            hostname = host_info.get("hostname", "unknown")
            device_id = host_info.get("device_id", "")

            app = vuln.get("app", {})
            product = app.get("product_name_version", "")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="vulnerability",
                title=f"Vulnerability {cve_id} on {hostname}" + (f" ({product})" if product else ""),
                detail={
                    "cve_id": cve_id,
                    "cve": cve,
                    "status": vuln.get("status", ""),
                    "app": app,
                    "host_info": host_info,
                    "remediation": vuln.get("remediation", {}),
                },
                resource_id=device_id,
                resource_type="endpoint",
                resource_name=hostname,
                severity=severity,
            ))

        return findings

    # -- Device Details (compliance) --

    def _normalize_devices(self, raw: RawEventData) -> list[FindingData]:
        """One finding per device with compliance checks."""
        findings = []
        devices = raw.raw_data.get("devices", [])

        for device in devices:
            hostname = device.get("hostname", "unknown")
            device_id = device.get("device_id", "")
            platform = device.get("platform_name", "")
            os_version = device.get("os_version", "")
            agent_version = device.get("agent_version", "")
            status = device.get("status", "")
            reduced_functionality = device.get("reduced_functionality_mode", "no")

            issues = []
            if status != "normal":
                issues.append(f"device_status_{status}")
            if reduced_functionality == "yes":
                issues.append("reduced_functionality_mode")
            if not device.get("device_policies", {}).get("prevention", {}).get("applied", False):
                issues.append("prevention_policy_not_applied")

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "medium"
                obs_type = "policy_violation"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"Endpoint {hostname} ({platform})" + (f" — {', '.join(issues)}" if issues else ""),
                detail={
                    "device_id": device_id,
                    "hostname": hostname,
                    "platform": platform,
                    "os_version": os_version,
                    "agent_version": agent_version,
                    "status": status,
                    "reduced_functionality": reduced_functionality,
                    "policies": device.get("device_policies", {}),
                    "issues": issues,
                },
                resource_id=device_id,
                resource_type="endpoint",
                resource_name=hostname,
                severity=severity,
            ))

        return findings

    # -- Device inventory (ID list only) --

    def _normalize_device_inventory(self, raw: RawEventData) -> list[FindingData]:
        total = raw.raw_data.get("total", 0)
        return [FindingData(
            **self._base(raw),
            observation_type="inventory",
            title=f"CrowdStrike Falcon — {total} managed endpoint(s)",
            detail={"total_devices": total},
            resource_id="crowdstrike:fleet",
            resource_type="endpoint_fleet",
            resource_name="crowdstrike-fleet",
            severity="info",
        )]

    # -- Zero Trust Assessment --

    def _normalize_zero_trust(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        assessments = raw.raw_data.get("assessments", [])

        for assessment in assessments:
            score = assessment.get("overall", assessment.get("score", 0))
            aid = assessment.get("aid", "")

            severity = "info"
            if isinstance(score, (int, float)):
                if score < 50:
                    severity = "high"
                elif score < 75:
                    severity = "medium"
                elif score < 90:
                    severity = "low"

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory" if severity == "info" else "policy_violation",
                title=f"Zero Trust Assessment — score {score}",
                detail={"assessment": assessment, "score": score},
                resource_id=aid,
                resource_type="endpoint",
                resource_name=aid,
                severity=severity,
            ))

        return findings

    # -- Sensor Policies --

    def _normalize_sensor_policies(self, raw: RawEventData) -> list[FindingData]:
        total = raw.raw_data.get("total", 0)
        return [FindingData(
            **self._base(raw),
            observation_type="inventory",
            title=f"CrowdStrike — {total} sensor update policy/policies",
            detail={"policy_ids": raw.raw_data.get("policy_ids", []), "total": total},
            resource_id="crowdstrike:sensor_policies",
            resource_type="sensor_policy",
            resource_name="sensor-policies",
            severity="info",
        )]


# Register
registry.register(CrowdStrikeNormalizer())
