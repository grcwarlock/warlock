"""Nessus normalizer — transforms raw Nessus API responses into Findings.

Handles scan inventory, vulnerability findings (by severity/plugin),
host details, and flags critical/high vulns, exploitable vulns,
compliance failures, and stale scans.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Nessus severity mapping: 0=info, 1=low, 2=medium, 3=high, 4=critical
_SEVERITY_MAP = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

# Stale scan threshold in days
_STALE_SCAN_DAYS = 30


class NessusNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "nessus_scans": "_normalize_scans",
        "nessus_vulnerabilities": "_normalize_vulnerabilities",
        "nessus_host_details": "_normalize_host_details",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "nessus" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Nessus findings."""
        return {
            "raw_event_id": raw.id,
            "source": "nessus",
            "source_type": SourceType.SCANNER,
            "provider": "nessus",
            "observed_at": raw.observed_at,
        }

    # -- Scans --

    def _normalize_scans(self, raw: RawEventData) -> list[FindingData]:
        """Inventory scans; flag stale scans (>30 days old)."""
        findings = []
        scans = raw.raw_data.get("scans", [])
        now = datetime.now(timezone.utc)

        for scan in scans:
            scan_id = str(scan.get("id", ""))
            scan_name = scan.get("name", "")
            status = scan.get("status", "")
            last_mod = scan.get("last_modification_date", 0)
            creation_date = scan.get("creation_date", 0)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Nessus scan: {scan_name} ({status})",
                    detail={
                        "scan_id": scan_id,
                        "name": scan_name,
                        "status": status,
                        "last_modification_date": last_mod,
                        "creation_date": creation_date,
                    },
                    resource_id=scan_id,
                    resource_type="nessus_scan",
                    resource_name=scan_name,
                    severity="info",
                )
            )

            # Flag stale scans — last modified > 30 days ago
            if last_mod:
                try:
                    last_mod_dt = datetime.fromtimestamp(last_mod, tz=timezone.utc)
                    days_since = (now - last_mod_dt).days
                    if days_since > _STALE_SCAN_DAYS:
                        findings.append(
                            FindingData(
                                **self._base(raw),
                                observation_type="misconfiguration",
                                title=f"Stale scan: {scan_name} ({days_since} days old)",
                                detail={
                                    "scan_id": scan_id,
                                    "name": scan_name,
                                    "status": status,
                                    "last_modification_date": last_mod,
                                    "days_since_last_run": days_since,
                                    "threshold_days": _STALE_SCAN_DAYS,
                                    "issue": f"Scan has not run in {days_since} days "
                                    f"(threshold: {_STALE_SCAN_DAYS})",
                                },
                                resource_id=scan_id,
                                resource_type="nessus_scan",
                                resource_name=scan_name,
                                severity="medium",
                            )
                        )
                except (ValueError, TypeError, OSError):
                    pass

        return findings

    # -- Vulnerabilities --

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        """Normalize vulnerabilities; flag critical/high and exploitable vulns."""
        findings = []
        scan_id = str(raw.raw_data.get("scan_id", ""))
        scan_name = raw.raw_data.get("scan_name", "")
        vulns = raw.raw_data.get("vulnerabilities", [])

        for vuln in vulns:
            plugin_id = str(vuln.get("plugin_id", ""))
            plugin_name = vuln.get("plugin_name", "")
            severity_int = vuln.get("severity", 0)
            severity = _SEVERITY_MAP.get(severity_int, "info")
            count = vuln.get("count", 0)
            plugin_family = vuln.get("plugin_family", "")
            vuln_index = vuln.get("vuln_index", "")

            # Check for exploitability indicators
            has_exploit = vuln.get("exploit_available", False)
            exploit_frameworks = (
                vuln.get("exploit_framework_exploithub", False)
                or vuln.get("exploit_framework_metasploit", False)
                or vuln.get("exploit_framework_canvas", False)
                or vuln.get("exploit_framework_core", False)
            )
            exploitable = has_exploit or exploit_frameworks

            # Inventory for every vulnerability
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Vuln: {plugin_name} ({severity})",
                    detail={
                        "scan_id": scan_id,
                        "scan_name": scan_name,
                        "plugin_id": plugin_id,
                        "plugin_name": plugin_name,
                        "plugin_family": plugin_family,
                        "severity": severity,
                        "severity_index": severity_int,
                        "count": count,
                        "vuln_index": vuln_index,
                        "exploitable": exploitable,
                    },
                    resource_id=plugin_id,
                    resource_type="nessus_vulnerability",
                    resource_name=plugin_name,
                    severity=severity,
                )
            )

            # Flag critical/high vulnerabilities
            if severity in ("critical", "high"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"{severity.upper()} vuln: {plugin_name} ({count} hosts)",
                        detail={
                            "scan_id": scan_id,
                            "scan_name": scan_name,
                            "plugin_id": plugin_id,
                            "plugin_name": plugin_name,
                            "plugin_family": plugin_family,
                            "severity": severity,
                            "host_count": count,
                            "exploitable": exploitable,
                            "issue": f"{severity.capitalize()} vulnerability affecting "
                            f"{count} host(s)",
                        },
                        resource_id=plugin_id,
                        resource_type="nessus_vulnerability",
                        resource_name=plugin_name,
                        severity=severity,
                    )
                )

            # Flag exploitable vulnerabilities
            if exploitable and severity in ("critical", "high", "medium"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Exploitable vuln: {plugin_name}",
                        detail={
                            "scan_id": scan_id,
                            "plugin_id": plugin_id,
                            "plugin_name": plugin_name,
                            "severity": severity,
                            "host_count": count,
                            "exploitable": True,
                            "issue": "Public exploit available for this vulnerability",
                        },
                        resource_id=plugin_id,
                        resource_type="nessus_vulnerability",
                        resource_name=plugin_name,
                        severity="critical" if severity == "critical" else "high",
                    )
                )

            # Flag compliance check failures
            if plugin_family == "Policy Compliance" and severity_int > 0:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Compliance failure: {plugin_name}",
                        detail={
                            "scan_id": scan_id,
                            "plugin_id": plugin_id,
                            "plugin_name": plugin_name,
                            "plugin_family": plugin_family,
                            "severity": severity,
                            "host_count": count,
                            "issue": "Compliance audit check failed",
                        },
                        resource_id=plugin_id,
                        resource_type="nessus_compliance_check",
                        resource_name=plugin_name,
                        severity=severity,
                    )
                )

        return findings

    # -- Host Details --

    def _normalize_host_details(self, raw: RawEventData) -> list[FindingData]:
        """Inventory hosts from scan results."""
        findings = []
        scan_id = str(raw.raw_data.get("scan_id", ""))
        hosts = raw.raw_data.get("hosts", [])

        for host in hosts:
            info = host.get("info", {})
            host_ip = info.get("host-ip", "")
            host_fqdn = info.get("host-fqdn", "")
            hostname = host_fqdn or host_ip
            operating_system = info.get("operating-system", "")
            host_start = info.get("host_start", "")
            host_end = info.get("host_end", "")

            # Count severity levels from host vulnerabilities
            vulns = host.get("vulnerabilities", [])
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for v in vulns:
                sev = _SEVERITY_MAP.get(v.get("severity", 0), "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + v.get("count", 0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Scanned host: {hostname}",
                    detail={
                        "scan_id": scan_id,
                        "host_ip": host_ip,
                        "host_fqdn": host_fqdn,
                        "operating_system": operating_system,
                        "host_start": host_start,
                        "host_end": host_end,
                        "severity_counts": severity_counts,
                    },
                    resource_id=host_ip,
                    resource_type="nessus_host",
                    resource_name=hostname,
                    severity="info",
                )
            )

        return findings


# Register
registry.register(NessusNormalizer())
