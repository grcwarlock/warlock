"""Ermetic (Tenable CIEM) normalizer — transforms raw Ermetic API responses into Findings.

Normalizes identities and permissions as inventory findings,
CSPM/CIEM findings as vulnerability findings with severity mapping.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "info",
    "INFO": "info",
}


class ErmeticNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Ermetic CSPM/CIEM findings."""

    HANDLERS: dict[str, str] = {
        "ermetic_identities": "_normalize_identities",
        "ermetic_permissions": "_normalize_permissions",
        "ermetic_findings": "_normalize_findings",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "ermetic" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "ermetic",
            "source_type": SourceType.CSPM,
            "provider": "ermetic",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_identities(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("identities", response.get("data", []))

        for identity in items:
            identity_id = str(identity.get("id", ""))
            name = identity.get("name", identity.get("arn", "unknown"))
            identity_type = identity.get("type", identity.get("identityType", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Ermetic identity: {name}",
                    detail={
                        "identity_id": identity_id,
                        "name": name,
                        "type": identity_type,
                        "account_id": identity.get("accountId", ""),
                        "is_active": identity.get("isActive", True),
                        "last_activity": identity.get("lastActivity", ""),
                        "risk_score": identity.get("riskScore", 0),
                    },
                    resource_id=identity_id,
                    resource_type="ermetic_identity",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_permissions(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("permissions", response.get("data", []))

        for perm in items:
            perm_id = str(perm.get("id", ""))
            identity_name = perm.get("identityName", perm.get("identity", "unknown"))
            resource_name = perm.get("resourceName", perm.get("resource", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Ermetic permission: {identity_name} on {resource_name}",
                    detail={
                        "permission_id": perm_id,
                        "identity": identity_name,
                        "resource": resource_name,
                        "actions": perm.get("actions", []),
                        "is_used": perm.get("isUsed", False),
                        "risk_level": perm.get("riskLevel", ""),
                    },
                    resource_id=perm_id,
                    resource_type="ermetic_permission",
                    resource_name=resource_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_findings(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("findings", response.get("data", []))

        for finding in items:
            finding_id = str(finding.get("id", ""))
            title = finding.get("title", finding.get("name", "Ermetic Finding"))
            severity_raw = str(finding.get("severity", "LOW")).upper()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")
            resource_name = finding.get("resourceName", finding.get("resource", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Ermetic finding: {title}",
                    detail={
                        "finding_id": finding_id,
                        "title": title,
                        "severity": severity_raw,
                        "category": finding.get("category", ""),
                        "resource": resource_name,
                        "account_id": finding.get("accountId", ""),
                        "remediation": finding.get("remediation", ""),
                        "detected_at": finding.get("detectedAt", ""),
                    },
                    resource_id=finding_id,
                    resource_type="ermetic_finding",
                    resource_name=resource_name or title,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ErmeticNormalizer())
