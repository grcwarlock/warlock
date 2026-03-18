"""Qualys normalizer — transforms raw Qualys VMDR responses into Findings.

Handles host detections (QID-based), compliance posture, and asset inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class QualysNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "host_detections": "_normalize_detections",
        "compliance_posture": "_normalize_compliance",
        "asset_inventory": "_normalize_assets",
        "knowledge_base": "_normalize_kb",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "qualys" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Qualys findings."""
        return {
            "raw_event_id": raw.id,
            "source": "qualys",
            "source_type": SourceType.SCANNER,
            "provider": "qualys",
            "observed_at": raw.observed_at,
        }

    # -- Host Detections --

    def _normalize_detections(self, raw: RawEventData) -> list[FindingData]:
        """One finding per host detection (QID-based)."""
        findings = []
        detections_data = raw.raw_data.get("detections", {})

        # Navigate Qualys XML-derived structure: RESPONSE > HOST_LIST > HOST
        response = detections_data.get("RESPONSE", detections_data)
        host_list = response.get("HOST_LIST", {})
        hosts = host_list.get("HOST", [])
        if isinstance(hosts, dict):
            hosts = [hosts]

        for host in hosts:
            host_ip = host.get("IP", "")
            host_id = host.get("ID", "")
            hostname = host.get("DNS", "") or host.get("NETBIOS", "")

            detection_list = host.get("DETECTION_LIST", {})
            detections = detection_list.get("DETECTION", [])
            if isinstance(detections, dict):
                detections = [detections]

            for detection in detections:
                qid = detection.get("QID", "")
                severity_raw = detection.get("SEVERITY", "3")
                try:
                    severity_num = int(severity_raw)
                except (ValueError, TypeError):
                    severity_num = 3

                severity_map = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}
                severity = severity_map.get(severity_num, "medium")

                title_text = detection.get("TITLE", "") or f"QID {qid}"
                cve_id = detection.get("CVE_ID", "")

                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"{title_text}" + (f" ({cve_id})" if cve_id else ""),
                    detail={
                        "qid": qid,
                        "type": detection.get("TYPE", ""),
                        "severity": severity_num,
                        "cve_id": cve_id,
                        "status": detection.get("STATUS", ""),
                        "results": detection.get("RESULTS", ""),
                        "first_found": detection.get("FIRST_FOUND_DATETIME", ""),
                        "last_found": detection.get("LAST_FOUND_DATETIME", ""),
                        "host_ip": host_ip,
                        "hostname": hostname,
                    },
                    resource_id=host_id,
                    resource_type="host",
                    resource_name=hostname or host_ip,
                    severity=severity,
                ))

        return findings

    # -- Compliance --

    def _normalize_compliance(self, raw: RawEventData) -> list[FindingData]:
        """One finding per compliance posture entry."""
        findings = []
        posture_data = raw.raw_data.get("posture", {})

        response = posture_data.get("RESPONSE", posture_data)
        info_list = response.get("COMPLIANCE_POSTURE", {})
        entries = info_list.get("ENTRY", [])
        if isinstance(entries, dict):
            entries = [entries]

        for entry in entries:
            status = entry.get("STATUS", "").upper()
            if status == "PASSED":
                continue

            control_id = entry.get("CONTROL_ID", "")
            title = entry.get("CONTROL_TITLE", "") or f"Control {control_id}"

            severity = "medium"
            criticality = entry.get("CRITICALITY", "").upper()
            if criticality in ("CRITICAL", "URGENT"):
                severity = "critical"
            elif criticality == "SERIOUS":
                severity = "high"

            findings.append(FindingData(
                **self._base(raw),
                observation_type="policy_violation",
                title=f"Compliance: {title}",
                detail={
                    "control_id": control_id,
                    "status": status,
                    "criticality": criticality,
                    "policy": entry.get("POLICY", ""),
                    "technology": entry.get("TECHNOLOGY", ""),
                    "rationale": entry.get("RATIONALE", ""),
                    "remediation": entry.get("REMEDIATION", ""),
                },
                resource_id=entry.get("HOST_ID", ""),
                resource_type="host",
                resource_name=entry.get("HOST_IP", ""),
                severity=severity,
            ))

        return findings

    # -- Assets --

    def _normalize_assets(self, raw: RawEventData) -> list[FindingData]:
        """One finding per host asset."""
        findings = []
        hosts_data = raw.raw_data.get("hosts", {})

        response = hosts_data.get("RESPONSE", hosts_data)
        host_list = response.get("HOST_LIST", {})
        hosts = host_list.get("HOST", [])
        if isinstance(hosts, dict):
            hosts = [hosts]

        for host in hosts:
            host_ip = host.get("IP", "")
            hostname = host.get("DNS", "") or host.get("NETBIOS", "")
            host_id = host.get("ID", "")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Asset: {hostname or host_ip or host_id}",
                detail={
                    "host_id": host_id,
                    "ip": host_ip,
                    "hostname": hostname,
                    "os": host.get("OS", ""),
                    "last_scan": host.get("LAST_SCAN_DATETIME", ""),
                    "tracking_method": host.get("TRACKING_METHOD", ""),
                    "tags": host.get("TAGS", ""),
                },
                resource_id=host_id,
                resource_type="host",
                resource_name=hostname or host_ip,
                severity="info",
            ))

        return findings

    # -- Knowledge Base --

    def _normalize_kb(self, raw: RawEventData) -> list[FindingData]:
        """Knowledge base entries are reference data; emit as inventory."""
        findings = []
        kb_data = raw.raw_data.get("knowledge_base", {})

        response = kb_data.get("RESPONSE", kb_data)
        vuln_list = response.get("VULN_LIST", {})
        vulns = vuln_list.get("VULN", [])
        if isinstance(vulns, dict):
            vulns = [vulns]

        for vuln in vulns:
            qid = vuln.get("QID", "")
            title = vuln.get("TITLE", "") or f"QID {qid}"

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"KB: {title}",
                detail={
                    "qid": qid,
                    "vuln_type": vuln.get("VULN_TYPE", ""),
                    "severity_level": vuln.get("SEVERITY_LEVEL", ""),
                    "cve_list": vuln.get("CVE_LIST", ""),
                    "diagnosis": vuln.get("DIAGNOSIS", ""),
                    "solution": vuln.get("SOLUTION", ""),
                    "consequence": vuln.get("CONSEQUENCE", ""),
                },
                resource_id=f"qid:{qid}",
                resource_type="knowledge_base",
                resource_name=title,
                severity="info",
            ))

        return findings


# Register
registry.register(QualysNormalizer())
