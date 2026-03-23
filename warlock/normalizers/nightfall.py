"""Nightfall AI normalizer — transforms DLP scan results, alerts, and policies into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_CONFIDENCE_SEVERITY_MAP: dict[str, str] = {
    "VERY_LIKELY": "critical",
    "LIKELY": "high",
    "POSSIBLE": "medium",
    "UNLIKELY": "low",
    "VERY_UNLIKELY": "info",
}


class NightfallNormalizer(BaseNormalizer):
    """Dispatches Nightfall DLP event types to type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "nightfall_scans": "_normalize_scans",
        "nightfall_policies": "_normalize_policies",
        "nightfall_alerts": "_normalize_alerts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "nightfall" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "nightfall",
            "source_type": SourceType.DLP,
            "provider": "nightfall",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_scans(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for scan in raw.raw_data.get("response", []):
            scan_id = str(scan.get("id", ""))
            status = scan.get("status", "unknown")
            finding_list = scan.get("findings", [])

            for finding in finding_list:
                confidence = finding.get("confidence", "POSSIBLE")
                severity = _CONFIDENCE_SEVERITY_MAP.get(confidence, "medium")
                detector = finding.get("detector", {})
                detector_name = detector.get("name", "unknown") if isinstance(detector, dict) else str(detector)
                location = finding.get("location", {})
                resource = location.get("byteRange", {}) if isinstance(location, dict) else {}

                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Nightfall DLP finding: {detector_name}",
                        detail={
                            "scan_id": scan_id,
                            "scan_status": status,
                            "detector": detector_name,
                            "confidence": confidence,
                            "fragment": finding.get("fragment", ""),
                            "location": str(resource),
                        },
                        resource_id=scan_id,
                        resource_type="nightfall_scan",
                        resource_name=scan_id,
                        severity=severity,
                        confidence=0.9,
                    )
                )

            # If no individual findings, emit one inventory record for the scan
            if not finding_list:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="inventory",
                        title=f"Nightfall scan: {scan_id}",
                        detail={
                            "scan_id": scan_id,
                            "status": status,
                            "created_at": scan.get("createdAt", ""),
                        },
                        resource_id=scan_id,
                        resource_type="nightfall_scan",
                        resource_name=scan_id,
                        severity="info",
                        confidence=1.0,
                    )
                )
        return findings

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for policy in raw.raw_data.get("response", []):
            policy_id = str(policy.get("id", ""))
            name = policy.get("name", "unknown")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Nightfall DLP policy: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "status": policy.get("status", ""),
                        "detection_rules": len(policy.get("detectionRules", [])),
                        "contexts": len(policy.get("contexts", [])),
                    },
                    resource_id=policy_id,
                    resource_type="nightfall_policy",
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
            confidence = alert.get("confidence", "POSSIBLE")
            severity = _CONFIDENCE_SEVERITY_MAP.get(confidence, "medium")
            detector_name = alert.get("detectorName", "unknown")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Nightfall alert: {detector_name}",
                    detail={
                        "alert_id": alert_id,
                        "detector_name": detector_name,
                        "confidence": confidence,
                        "status": alert.get("status", ""),
                        "created_at": alert.get("createdAt", ""),
                        "policy_name": alert.get("policyName", ""),
                    },
                    resource_id=alert_id,
                    resource_type="nightfall_alert",
                    resource_name=alert_id,
                    severity=severity,
                    confidence=0.85,
                )
            )
        return findings


registry.register(NightfallNormalizer())
