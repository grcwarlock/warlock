"""Rapid7 InsightVM normalizer — transforms assets, vulnerabilities, and scans into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# CVSS score to severity mapping (NIST NVD convention)
def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


class Rapid7Normalizer(BaseNormalizer):
    """Dispatches Rapid7 InsightVM event types to type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "rapid7_assets": "_normalize_assets",
        "rapid7_vulnerabilities": "_normalize_vulnerabilities",
        "rapid7_scans": "_normalize_scans",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "rapid7" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "rapid7",
            "source_type": SourceType.SCANNER,
            "provider": "rapid7",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_assets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for asset in raw.raw_data.get("response", []):
            asset_id = str(asset.get("id", ""))
            host = asset.get("hostName", asset.get("ip", "unknown"))
            os_info = asset.get("os", {})
            os_name = os_info.get("description", "") if isinstance(os_info, dict) else str(os_info)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Rapid7 asset: {host}",
                    detail={
                        "asset_id": asset_id,
                        "hostname": host,
                        "ip": asset.get("ip", ""),
                        "os": os_name,
                        "risk_score": asset.get("riskScore", 0),
                        "assessed_for_vulnerabilities": asset.get("assessedForVulnerabilities", False),
                        "last_assessed_for_vulnerabilities": str(asset.get("lastAssessedForVulnerabilities", "")),
                    },
                    resource_id=asset_id,
                    resource_type="rapid7_asset",
                    resource_name=host,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for vuln in raw.raw_data.get("response", []):
            vuln_id = str(vuln.get("id", ""))
            title = vuln.get("title", vuln_id)
            cvss = vuln.get("cvss", {})
            cvss_v3 = cvss.get("v3", {}) if isinstance(cvss, dict) else {}
            cvss_score = float(cvss_v3.get("score", cvss.get("score", 0.0)) if isinstance(cvss_v3, dict) else 0.0)
            severity = _cvss_to_severity(cvss_score)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Rapid7 vulnerability: {title}",
                    detail={
                        "vuln_id": vuln_id,
                        "title": title,
                        "cvss_score": cvss_score,
                        "cvss_v3": cvss_v3,
                        "added": str(vuln.get("added", "")),
                        "modified": str(vuln.get("modified", "")),
                        "published": str(vuln.get("published", "")),
                        "denial_of_service": vuln.get("denialOfService", False),
                        "exploit_count": vuln.get("exploits", 0),
                        "malware_count": vuln.get("malwareKits", 0),
                    },
                    resource_id=vuln_id,
                    resource_type="rapid7_vulnerability",
                    resource_name=title,
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_scans(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for scan in raw.raw_data.get("response", []):
            scan_id = str(scan.get("id", ""))
            scan_name = scan.get("scanName", scan_id)
            status = scan.get("status", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Rapid7 scan: {scan_name}",
                    detail={
                        "scan_id": scan_id,
                        "scan_name": scan_name,
                        "status": status,
                        "assets_discovered": scan.get("assets", {}).get("discovered", 0) if isinstance(scan.get("assets"), dict) else 0,
                        "vulnerabilities_discovered": scan.get("vulnerabilities", {}).get("total", 0) if isinstance(scan.get("vulnerabilities"), dict) else 0,
                        "started": str(scan.get("startTime", "")),
                        "ended": str(scan.get("endTime", "")),
                    },
                    resource_id=scan_id,
                    resource_type="rapid7_scan",
                    resource_name=scan_name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings


registry.register(Rapid7Normalizer())
