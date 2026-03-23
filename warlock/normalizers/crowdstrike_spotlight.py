"""CrowdStrike Spotlight normalizer — transforms vulnerability and remediation data into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_CROWDSTRIKE_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "info",
    "UNKNOWN": "info",
    # Lowercase variants
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "none": "info",
    "unknown": "info",
}


class CrowdStrikeSpotlightNormalizer(BaseNormalizer):
    """Dispatches CrowdStrike Spotlight event types to type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "crowdstrike_spotlight_vulnerabilities": "_normalize_vulnerabilities",
        "crowdstrike_spotlight_remediations": "_normalize_remediations",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "crowdstrike_spotlight" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "crowdstrike_spotlight",
            "source_type": SourceType.SCANNER,
            "provider": "crowdstrike_spotlight",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for vuln in raw.raw_data.get("response", []):
            vuln_id = str(vuln.get("id", ""))
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "") if isinstance(cve, dict) else str(cve)
            cve_description = cve.get("description", "") if isinstance(cve, dict) else ""
            raw_severity = cve.get("severity", "UNKNOWN") if isinstance(cve, dict) else "UNKNOWN"
            severity = _CROWDSTRIKE_SEVERITY_MAP.get(str(raw_severity).upper(), "medium")

            aid = vuln.get("aid", "")
            host_info = vuln.get("host_info", {})
            hostname = host_info.get("hostname", "") if isinstance(host_info, dict) else ""
            platform = host_info.get("platform", "") if isinstance(host_info, dict) else ""

            app = vuln.get("app", {})
            product_name = app.get("product_name_version", "") if isinstance(app, dict) else str(app)

            status = vuln.get("status", "open")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"CrowdStrike Spotlight: {cve_id or vuln_id}",
                    detail={
                        "vuln_id": vuln_id,
                        "cve_id": cve_id,
                        "cve_description": cve_description,
                        "severity": raw_severity,
                        "status": status,
                        "aid": aid,
                        "hostname": hostname,
                        "platform": platform,
                        "product": product_name,
                        "created_at": vuln.get("created_timestamp", ""),
                        "updated_at": vuln.get("updated_timestamp", ""),
                        "remediation_ids": vuln.get("remediation", {}).get("ids", []) if isinstance(vuln.get("remediation"), dict) else [],
                    },
                    resource_id=aid or vuln_id,
                    resource_type="crowdstrike_host",
                    resource_name=hostname or aid,
                    severity=severity,
                    confidence=0.95,
                )
            )
        return findings

    def _normalize_remediations(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        # The remediations query endpoint returns IDs; the combined endpoint has full details.
        # Treat each remediation ID as an inventory item.
        for remediation_id in raw.raw_data.get("response", []):
            rid = str(remediation_id) if not isinstance(remediation_id, dict) else str(remediation_id.get("id", ""))
            action = remediation_id.get("action", "") if isinstance(remediation_id, dict) else ""
            vendor_url = remediation_id.get("vendor_url", "") if isinstance(remediation_id, dict) else ""

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"CrowdStrike Spotlight remediation: {rid}",
                    detail={
                        "remediation_id": rid,
                        "action": action,
                        "vendor_url": vendor_url,
                    },
                    resource_id=rid,
                    resource_type="crowdstrike_remediation",
                    resource_name=rid,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings


registry.register(CrowdStrikeSpotlightNormalizer())
