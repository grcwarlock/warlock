"""Dragos Platform normalizer — transforms raw Dragos API responses into Findings.

Normalizes OT threat detections, asset inventory, vulnerabilities, and zones.
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


class DragosNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "dragos_detections": "_normalize_detections",
        "dragos_assets": "_normalize_assets",
        "dragos_vulnerabilities": "_normalize_vulnerabilities",
        "dragos_zones": "_normalize_zones",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "dragos" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "dragos",
            "source_type": SourceType.INFRASTRUCTURE,
            "provider": "dragos",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_detections(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for detection in items:
            det_id = str(detection.get("id", detection.get("detection_id", "")))
            title = detection.get("title", detection.get("name", f"Detection {det_id}"))
            severity_raw = str(detection.get("severity", "medium")).lower()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"OT threat: {title}",
                    detail={
                        "detection_id": det_id,
                        "title": title,
                        "threat_group": detection.get("threat_group", ""),
                        "tactic": detection.get("tactic", ""),
                        "technique": detection.get("technique", ""),
                        "source_ip": detection.get("src_ip", ""),
                        "dest_ip": detection.get("dst_ip", ""),
                        "protocol": detection.get("protocol", ""),
                        "confidence": detection.get("confidence", ""),
                        "status": detection.get("status", ""),
                    },
                    resource_id=detection.get("asset_id", det_id),
                    resource_type="ot_detection",
                    resource_name=title,
                    severity=severity,
                    confidence=0.85,
                )
            )

        return findings

    def _normalize_assets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for asset in items:
            asset_id = str(asset.get("id", asset.get("asset_id", "")))
            name = asset.get("name", asset.get("hostname", f"Asset {asset_id}"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"OT asset: {name}",
                    detail={
                        "asset_id": asset_id,
                        "name": name,
                        "asset_type": asset.get("type", ""),
                        "vendor": asset.get("vendor", ""),
                        "model": asset.get("model", ""),
                        "firmware": asset.get("firmware_version", ""),
                        "ip_address": asset.get("ip", ""),
                        "zone": asset.get("zone", ""),
                        "last_seen": asset.get("last_seen", ""),
                    },
                    resource_id=asset_id,
                    resource_type="ot_asset",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
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
                        "description": vuln.get("description", ""),
                        "affected_assets": vuln.get("affected_asset_count", 0),
                        "cvss_score": vuln.get("cvss_score", None),
                    },
                    resource_id=vuln_id,
                    resource_type="ot_vulnerability",
                    resource_name=title,
                    severity=severity,
                    confidence=0.9,
                )
            )

        return findings

    def _normalize_zones(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for zone in items:
            zone_id = str(zone.get("id", zone.get("zone_id", "")))
            name = zone.get("name", f"Zone {zone_id}")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"OT network zone: {name}",
                    detail={
                        "zone_id": zone_id,
                        "name": name,
                        "description": zone.get("description", ""),
                        "asset_count": zone.get("asset_count", 0),
                        "purdue_level": zone.get("purdue_level", ""),
                    },
                    resource_id=zone_id,
                    resource_type="ot_zone",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(DragosNormalizer())
