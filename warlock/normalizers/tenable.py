"""Tenable normalizer — transforms raw Tenable.io responses into Findings.

Handles vulnerability exports, compliance audit results, and asset inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class TenableNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "vuln_export": "_normalize_vulns",
        "compliance_audits": "_normalize_compliance",
        "asset_export": "_normalize_assets",
        "agent_status": "_normalize_agents",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "tenable" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Tenable findings."""
        return {
            "raw_event_id": raw.id,
            "source": "tenable",
            "source_type": SourceType.SCANNER,
            "provider": "tenable",
            "observed_at": raw.observed_at,
        }

    # -- Vulnerabilities --

    def _normalize_vulns(self, raw: RawEventData) -> list[FindingData]:
        """One finding per vulnerability instance."""
        findings = []
        vulns = raw.raw_data.get("vulnerabilities", [])

        for vuln in vulns:
            plugin = vuln.get("plugin", {})
            severity_id = vuln.get("severity_id", 0)
            severity_map = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
            severity = severity_map.get(severity_id, "info")

            cve_list = plugin.get("cve", []) or []
            cvss_base = plugin.get("cvss_base_score", 0) or 0
            cvss3_base = plugin.get("cvss3_base_score", 0) or 0

            asset = vuln.get("asset", {})
            host_ip = asset.get("ipv4", "") or asset.get("ipv6", "")
            hostname = asset.get("hostname", "") or asset.get("fqdn", "")
            asset_uuid = asset.get("uuid", "")

            plugin_name = plugin.get("name", "Unknown vulnerability")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="vulnerability",
                title=f"{plugin_name}" + (f" ({', '.join(cve_list[:3])})" if cve_list else ""),
                detail={
                    "plugin_id": vuln.get("plugin_id", ""),
                    "plugin_name": plugin_name,
                    "cve": cve_list,
                    "cvss_base_score": cvss_base,
                    "cvss3_base_score": cvss3_base,
                    "severity_id": severity_id,
                    "state": vuln.get("state", ""),
                    "protocol": vuln.get("port", {}).get("protocol", ""),
                    "port": vuln.get("port", {}).get("port", 0),
                    "host_ip": host_ip,
                    "hostname": hostname,
                    "first_found": vuln.get("first_found", ""),
                    "last_found": vuln.get("last_found", ""),
                    "output": vuln.get("output", ""),
                },
                resource_id=asset_uuid,
                resource_type="host",
                resource_name=hostname or host_ip,
                severity=severity,
            ))

        return findings

    # -- Compliance --

    def _normalize_compliance(self, raw: RawEventData) -> list[FindingData]:
        """One finding per compliance audit check."""
        findings = []
        audits = raw.raw_data.get("audits", [])

        for audit in audits:
            status = audit.get("status", "").upper()
            if status in ("PASSED", "PASS"):
                continue  # only report failures

            audit_name = audit.get("check_name", "") or audit.get("description", "Compliance check")
            severity = "medium"
            if status in ("FAILED", "FAIL"):
                severity = "high"
            elif status == "WARNING":
                severity = "medium"
            elif status == "ERROR":
                severity = "high"

            asset_info = audit.get("asset", {})
            asset_uuid = asset_info.get("uuid", "") if isinstance(asset_info, dict) else ""
            hostname = asset_info.get("hostname", "") if isinstance(asset_info, dict) else ""

            findings.append(FindingData(
                **self._base(raw),
                observation_type="policy_violation",
                title=f"Compliance: {audit_name}",
                detail={
                    "check_name": audit_name,
                    "status": status,
                    "reference": audit.get("reference", ""),
                    "solution": audit.get("solution", ""),
                    "see_also": audit.get("see_also", ""),
                    "audit_file": audit.get("audit_file", ""),
                    "benchmark": audit.get("benchmark", ""),
                },
                resource_id=asset_uuid,
                resource_type="host",
                resource_name=hostname,
                severity=severity,
            ))

        return findings

    # -- Assets --

    def _normalize_assets(self, raw: RawEventData) -> list[FindingData]:
        """One finding per asset for inventory."""
        findings = []
        assets = raw.raw_data.get("assets", [])

        for asset in assets:
            hostname = asset.get("hostname", "") or asset.get("fqdn", "")
            ipv4 = asset.get("ipv4", [])
            ip_str = ipv4[0] if isinstance(ipv4, list) and ipv4 else str(ipv4)

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Asset: {hostname or ip_str or asset.get('id', '?')}",
                detail={
                    "id": asset.get("id", ""),
                    "hostname": hostname,
                    "fqdn": asset.get("fqdn", ""),
                    "ipv4": ipv4,
                    "ipv6": asset.get("ipv6", []),
                    "operating_system": asset.get("operating_system", []),
                    "mac_address": asset.get("mac_address", []),
                    "agent_uuid": asset.get("agent_uuid", ""),
                    "last_seen": asset.get("last_seen", ""),
                    "sources": asset.get("sources", []),
                },
                resource_id=asset.get("id", ""),
                resource_type="host",
                resource_name=hostname or ip_str,
                severity="info",
            ))

        return findings

    # -- Agents --

    def _normalize_agents(self, raw: RawEventData) -> list[FindingData]:
        """One finding per agent for inventory/status."""
        findings = []
        agents = raw.raw_data.get("agents", [])

        for agent in agents:
            status = agent.get("status", "unknown")
            severity = "info"
            if status in ("offline", "unlinked"):
                severity = "low"

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Agent: {agent.get('name', '?')} ({status})",
                detail={
                    "agent_id": agent.get("id", ""),
                    "name": agent.get("name", ""),
                    "status": status,
                    "platform": agent.get("platform", ""),
                    "ip": agent.get("ip", ""),
                    "last_connect": agent.get("last_connect", ""),
                    "plugin_feed_id": agent.get("plugin_feed_id", ""),
                    "core_version": agent.get("core_version", ""),
                },
                resource_id=str(agent.get("id", "")),
                resource_type="agent",
                resource_name=agent.get("name", ""),
                severity=severity,
            ))

        return findings


# Register
registry.register(TenableNormalizer())
