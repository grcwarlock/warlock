"""Nozomi Networks normalizer — transforms raw Nozomi API responses into Findings.

Normalizes OT/IoT asset inventory, alerts, vulnerabilities, and network links.
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


class NozomiNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "nozomi_assets": "_normalize_assets",
        "nozomi_alerts": "_normalize_alerts",
        "nozomi_vulnerabilities": "_normalize_vulnerabilities",
        "nozomi_network_links": "_normalize_links",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "nozomi" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "nozomi",
            "source_type": SourceType.INFRASTRUCTURE,
            "provider": "nozomi",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_assets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for asset in items:
            asset_id = str(asset.get("id", asset.get("node_id", "")))
            name = asset.get("name", asset.get("label", f"Asset {asset_id}"))
            asset_type = asset.get("type", asset.get("os_or_firmware", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"OT/IoT asset: {name} ({asset_type})",
                    detail={
                        "asset_id": asset_id,
                        "name": name,
                        "asset_type": asset_type,
                        "vendor": asset.get("vendor", ""),
                        "ip_address": asset.get("ip", ""),
                        "mac_address": asset.get("mac_address", ""),
                        "zone": asset.get("zone", ""),
                        "protocols": asset.get("protocols", []),
                        "risk_score": asset.get("risk", None),
                        "last_activity": asset.get("last_activity", ""),
                    },
                    resource_id=asset_id,
                    resource_type=f"iot_{asset_type}",
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
            title = alert.get("name", alert.get("description", f"Alert {alert_id}"))
            severity_raw = str(alert.get("risk", alert.get("severity", "medium"))).lower()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"OT/IoT alert: {title}",
                    detail={
                        "alert_id": alert_id,
                        "title": title,
                        "type_id": alert.get("type_id", ""),
                        "source_ip": alert.get("src_ip", ""),
                        "dest_ip": alert.get("dst_ip", ""),
                        "protocol": alert.get("protocol", ""),
                        "zone": alert.get("zone", ""),
                        "is_incident": alert.get("is_incident", False),
                    },
                    resource_id=alert.get("node_id", alert_id),
                    resource_type="iot_alert",
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
            vuln_id = str(vuln.get("id", vuln.get("cve", "")))
            title = vuln.get("name", vuln.get("cve", f"Vulnerability {vuln_id}"))
            severity_raw = str(vuln.get("severity", "medium")).lower()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"OT/IoT vulnerability: {title}",
                    detail={
                        "vuln_id": vuln_id,
                        "cve": vuln.get("cve", ""),
                        "description": vuln.get("description", ""),
                        "affected_nodes": vuln.get("affected_node_count", 0),
                        "cvss_score": vuln.get("cvss_v3_score", None),
                    },
                    resource_id=vuln_id,
                    resource_type="iot_vulnerability",
                    resource_name=title,
                    severity=severity,
                    confidence=0.9,
                )
            )

        return findings

    def _normalize_links(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for link in items:
            link_id = str(link.get("id", ""))
            src = link.get("from", link.get("src_ip", "unknown"))
            dst = link.get("to", link.get("dst_ip", "unknown"))
            protocol = link.get("protocol", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"OT network link: {src} -> {dst} ({protocol})",
                    detail={
                        "link_id": link_id,
                        "source": src,
                        "destination": dst,
                        "protocol": protocol,
                        "bytes_transferred": link.get("bytes", 0),
                        "last_activity": link.get("last_activity", ""),
                    },
                    resource_id=link_id,
                    resource_type="iot_network_link",
                    resource_name=f"{src}->{dst}",
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(NozomiNormalizer())
