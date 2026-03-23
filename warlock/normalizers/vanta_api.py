"""Vanta API normalizer — transforms raw Vanta extended API responses into Findings.

Normalizes monitors as inventory/policy_violation; tests as policy_violation when
failing; vulnerabilities as vulnerability findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}


class VantaApiNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "vanta_api_monitors": "_normalize_monitors",
        "vanta_api_tests": "_normalize_tests",
        "vanta_api_vulnerabilities": "_normalize_vulnerabilities",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "vanta_api" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "vanta_api",
            "source_type": SourceType.GRC,
            "provider": "vanta_api",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_monitors(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for monitor in items:
            monitor_id = str(monitor.get("uid", monitor.get("id", "")))
            name = monitor.get("displayName", monitor.get("name", "unknown"))
            status = monitor.get("status", "passing")
            failing = str(status).lower() in ("failing", "fail", "failed", "error")

            obs_type = "policy_violation" if failing else "inventory"
            severity = "high" if failing else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Vanta API monitor: {name}",
                    detail={
                        "monitor_id": monitor_id,
                        "name": name,
                        "status": status,
                        "description": monitor.get("description", ""),
                        "integration": monitor.get("integration", ""),
                        "last_evaluated": monitor.get("lastEvaluatedAt", ""),
                    },
                    resource_id=monitor_id,
                    resource_type="vanta_monitor",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_tests(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for test in items:
            test_id = str(test.get("uid", test.get("id", "")))
            name = test.get("testName", test.get("name", "unknown"))
            outcome = test.get("outcome", test.get("status", "passing"))
            failing = str(outcome).lower() in ("failing", "fail", "failed", "error")

            obs_type = "policy_violation" if failing else "inventory"
            severity = "high" if failing else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Vanta API test: {name}",
                    detail={
                        "test_id": test_id,
                        "test_name": name,
                        "outcome": outcome,
                        "description": test.get("description", ""),
                        "control_id": str(test.get("controlId", "")),
                        "remediation": test.get("remediationGuidance", ""),
                    },
                    resource_id=test_id,
                    resource_type="vanta_test",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for vuln in items:
            vuln_id = str(vuln.get("uid", vuln.get("id", "")))
            title = vuln.get("title", vuln.get("name", "unknown"))
            raw_severity = str(vuln.get("severity", "info")).lower()
            severity = _SEVERITY_MAP.get(raw_severity, "info")
            status = vuln.get("status", "open")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Vanta vulnerability: {title}",
                    detail={
                        "vuln_id": vuln_id,
                        "title": title,
                        "severity": severity,
                        "status": status,
                        "description": vuln.get("description", ""),
                        "resource": str(vuln.get("resource", "")),
                        "cve": vuln.get("cve", ""),
                        "remediation": vuln.get("remediationGuidance", ""),
                    },
                    resource_id=vuln_id,
                    resource_type="vanta_vulnerability",
                    resource_name=title,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(VantaApiNormalizer())
