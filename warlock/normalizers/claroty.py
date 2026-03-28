"""Claroty xDome normalizer — transforms raw Claroty API responses into Findings.

Normalizes OT/ICS asset inventory, alerts, and vulnerabilities.
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


class ClarotyNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "claroty_assets": "_normalize_assets",
        "claroty_alerts": "_normalize_alerts",
        "claroty_vulnerabilities": "_normalize_vulnerabilities",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "claroty" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "claroty",
            "source_type": SourceType.INFRASTRUCTURE,
            "provider": "claroty",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_assets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for asset in items:
            asset_id = str(asset.get("id", asset.get("asset_id", "")))
            name = asset.get("name", asset.get("hostname", f"Asset {asset_id}"))
            asset_type = asset.get("type", asset.get("category", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"OT asset: {name} ({asset_type})",
                    detail={
                        "asset_id": asset_id,
                        "name": name,
                        "asset_type": asset_type,
                        "vendor": asset.get("vendor", ""),
                        "firmware_version": asset.get("firmware_version", ""),
                        "ip_address": asset.get("ip", asset.get("ipv4", "")),
                        "mac_address": asset.get("mac", ""),
                        "protocol": asset.get("protocol", ""),
                        "zone": asset.get("zone", asset.get("network_zone", "")),
                        "risk_score": asset.get("risk_score", None),
                    },
                    resource_id=asset_id,
                    resource_type=f"ot_{asset_type}",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for alert in items:
            alert_id = str(alert.get("id", alert.get("alert_id", "")))
            title = alert.get("title", alert.get("name", f"Alert {alert_id}"))
            severity_raw = str(alert.get("severity", "medium")).lower()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"OT alert: {title}",
                    detail={
                        "alert_id": alert_id,
                        "title": title,
                        "category": alert.get("category", ""),
                        "description": alert.get("description", ""),
                        "source_ip": alert.get("src_ip", ""),
                        "dest_ip": alert.get("dst_ip", ""),
                        "protocol": alert.get("protocol", ""),
                        "zone": alert.get("zone", ""),
                        "status": alert.get("status", ""),
                    },
                    resource_id=alert.get("asset_id", alert_id),
                    resource_type="ot_alert",
                    resource_name=title,
                    severity=severity,
                    confidence=0.9,
                )
            )

        return findings

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for vuln in items:
            vuln_id = str(vuln.get("id", vuln.get("cve_id", "")))
            title = vuln.get("title", vuln.get("name", f"CVE {vuln_id}"))
            severity_raw = str(vuln.get("severity", "medium")).lower()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"OT vulnerability: {title}",
                    detail={
                        "vuln_id": vuln_id,
                        "cve_id": vuln.get("cve_id", ""),
                        "title": title,
                        "description": vuln.get("description", ""),
                        "affected_assets": vuln.get("affected_asset_count", 0),
                        "cvss_score": vuln.get("cvss_score", None),
                        "remediation": vuln.get("remediation", ""),
                    },
                    resource_id=vuln_id,
                    resource_type="ot_vulnerability",
                    resource_name=title,
                    severity=severity,
                    confidence=0.9,
                )
            )

        return findings


# Register
registry.register(ClarotyNormalizer())
