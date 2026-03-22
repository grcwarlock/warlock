"""Veracode normalizer — transforms raw Veracode REST API responses into Findings.

Handles applications, findings, policy compliance, and SCA results.
Flags: policy-violating apps, very high/high findings, overdue remediations,
vulnerable components.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class VeracodeNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "veracode_applications": "_normalize_applications",
        "veracode_findings": "_normalize_findings",
        "veracode_policy": "_normalize_policy",
        "veracode_sca": "_normalize_sca",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "veracode" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Veracode findings."""
        return {
            "raw_event_id": raw.id,
            "source": "veracode",
            "source_type": SourceType.CODE,
            "provider": "veracode",
            "observed_at": raw.observed_at,
        }

    # -- Applications --

    def _normalize_applications(self, raw: RawEventData) -> list[FindingData]:
        """Inventory Veracode application profiles."""
        findings = []
        apps = raw.raw_data.get("applications", [])

        for app in apps:
            app_guid = app.get("guid", "")
            profile = app.get("profile", {})
            app_name = profile.get("name", "")
            business_unit = (
                profile.get("business_unit", {}).get("name", "")
                if isinstance(profile.get("business_unit"), dict)
                else ""
            )
            policy_compliance = app.get("policy_compliance_status", "")
            last_scan = app.get("last_completed_scan_date", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Veracode application: {app_name}",
                    detail={
                        "app_guid": app_guid,
                        "app_name": app_name,
                        "business_unit": business_unit,
                        "policy_compliance_status": policy_compliance,
                        "last_completed_scan_date": last_scan,
                    },
                    resource_id=app_guid,
                    resource_type="veracode_application",
                    resource_name=app_name,
                    severity="info",
                )
            )

        return findings

    # -- Findings --

    def _normalize_findings(self, raw: RawEventData) -> list[FindingData]:
        """Normalize static/dynamic analysis findings; flag very high/high severity."""
        findings = []
        veracode_findings = raw.raw_data.get("findings", [])

        for f in veracode_findings:
            finding_id = str(f.get("issue_id", f.get("id", "")))
            scan_type = f.get("scan_type", "")
            severity_num = f.get("finding_details", {}).get("severity", f.get("severity", 0))
            cwe_id = f.get("finding_details", {}).get("cwe", {}).get("id", "")
            cwe_name = f.get("finding_details", {}).get("cwe", {}).get("name", "")
            category = (
                f.get("finding_category", {}).get("name", "")
                if isinstance(f.get("finding_category"), dict)
                else ""
            )
            status = f.get("finding_status", {}).get("status", f.get("status", ""))
            resolution = f.get("finding_status", {}).get("resolution", "")
            resolution_status = f.get("finding_status", {}).get("resolution_status", "")
            app_name = f.get("context", f.get("app_name", ""))
            file_path = f.get("finding_details", {}).get("file_path", "")
            line = f.get("finding_details", {}).get("file_line_number", "")

            # Map Veracode severity (0-5) to standard
            severity_map = {0: "info", 1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}
            severity = (
                severity_map.get(severity_num, "info") if isinstance(severity_num, int) else "info"
            )

            # Inventory every finding
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Veracode {scan_type} finding: CWE-{cwe_id} {cwe_name}",
                    detail={
                        "finding_id": finding_id,
                        "scan_type": scan_type,
                        "severity": severity,
                        "severity_num": severity_num,
                        "cwe_id": cwe_id,
                        "cwe_name": cwe_name,
                        "category": category,
                        "status": status,
                        "resolution": resolution,
                        "resolution_status": resolution_status,
                        "app_name": app_name,
                        "file_path": file_path,
                        "line": line,
                    },
                    resource_id=finding_id,
                    resource_type="veracode_finding",
                    resource_name=f"CWE-{cwe_id}:{finding_id}",
                    severity=severity,
                )
            )

            # Flag very high/high unresolved findings
            if severity in ("critical", "high") and resolution_status not in ("APPROVED", "FIXED"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Unresolved {severity} finding: CWE-{cwe_id} {cwe_name}",
                        detail={
                            "finding_id": finding_id,
                            "scan_type": scan_type,
                            "severity": severity,
                            "cwe_id": cwe_id,
                            "cwe_name": cwe_name,
                            "status": status,
                            "resolution_status": resolution_status,
                            "app_name": app_name,
                            "issue": f"Critical/high Veracode finding (CWE-{cwe_id}) remains unresolved",
                        },
                        resource_id=finding_id,
                        resource_type="veracode_finding",
                        resource_name=f"CWE-{cwe_id}:{finding_id}",
                        severity=severity,
                    )
                )

        return findings

    # -- Policy Compliance --

    def _normalize_policy(self, raw: RawEventData) -> list[FindingData]:
        """Normalize policy compliance; flag non-compliant applications."""
        findings = []
        policy_results = raw.raw_data.get("policy_results", [])

        for pr in policy_results:
            app_guid = pr.get("app_guid", "")
            app_name = pr.get("app_name", "")
            policy_name = pr.get("policy_name", "")
            compliance_status = pr.get("policy_compliance_status", "")
            last_scan = pr.get("last_completed_scan_date", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Veracode policy status: {app_name} — {compliance_status}",
                    detail={
                        "app_guid": app_guid,
                        "app_name": app_name,
                        "policy_name": policy_name,
                        "compliance_status": compliance_status,
                        "last_completed_scan_date": last_scan,
                    },
                    resource_id=app_guid,
                    resource_type="veracode_policy_status",
                    resource_name=app_name,
                    severity="info",
                )
            )

            # Flag policy-violating applications
            if compliance_status and compliance_status.upper() not in (
                "PASS",
                "PASSED",
                "COMPLIANT",
                "CONDITIONAL_PASS",
            ):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Application violates policy: {app_name}",
                        detail={
                            "app_guid": app_guid,
                            "app_name": app_name,
                            "policy_name": policy_name,
                            "compliance_status": compliance_status,
                            "last_completed_scan_date": last_scan,
                            "issue": f"Application '{app_name}' does not meet Veracode policy '{policy_name}' — status: {compliance_status}",
                        },
                        resource_id=app_guid,
                        resource_type="veracode_policy_status",
                        resource_name=app_name,
                        severity="high",
                    )
                )

            # Flag apps with no recent scan
            if not last_scan:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Application never scanned: {app_name}",
                        detail={
                            "app_guid": app_guid,
                            "app_name": app_name,
                            "policy_name": policy_name,
                            "issue": "Application is registered in Veracode but has no completed scan — compliance status unknown",
                        },
                        resource_id=app_guid,
                        resource_type="veracode_policy_status",
                        resource_name=app_name,
                        severity="high",
                    )
                )

        return findings

    # -- SCA (Software Composition Analysis) --

    def _normalize_sca(self, raw: RawEventData) -> list[FindingData]:
        """Normalize SCA results; flag vulnerable components."""
        findings = []
        sca_results = raw.raw_data.get("sca_results", [])

        for ws in sca_results:
            ws_id = ws.get("workspace_id", "")
            ws_name = ws.get("workspace_name", "")
            issues = ws.get("issues", [])

            for issue in issues:
                issue_id = str(issue.get("id", ""))
                library = issue.get("library", {})
                lib_name = library.get("name", "") if isinstance(library, dict) else ""
                lib_version = library.get("version", "") if isinstance(library, dict) else ""
                vulnerability = issue.get("vulnerability", {})
                vuln_id = (
                    vulnerability.get("cve", vulnerability.get("id", ""))
                    if isinstance(vulnerability, dict)
                    else ""
                )
                severity_score = (
                    vulnerability.get("cvss_score", 0) if isinstance(vulnerability, dict) else 0
                )
                vuln_title = (
                    vulnerability.get("title", "") if isinstance(vulnerability, dict) else ""
                )

                # Map CVSS to severity
                if isinstance(severity_score, (int, float)):
                    if severity_score >= 9.0:
                        severity = "critical"
                    elif severity_score >= 7.0:
                        severity = "high"
                    elif severity_score >= 4.0:
                        severity = "medium"
                    elif severity_score > 0:
                        severity = "low"
                    else:
                        severity = "info"
                else:
                    severity = "info"

                # Inventory
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="vulnerability",
                        title=f"Vulnerable component: {lib_name}@{lib_version} ({vuln_id})",
                        detail={
                            "issue_id": issue_id,
                            "workspace_id": ws_id,
                            "workspace_name": ws_name,
                            "library_name": lib_name,
                            "library_version": lib_version,
                            "vulnerability_id": vuln_id,
                            "vulnerability_title": vuln_title,
                            "cvss_score": severity_score,
                            "severity": severity,
                        },
                        resource_id=issue_id or f"{lib_name}@{lib_version}:{vuln_id}",
                        resource_type="veracode_sca_issue",
                        resource_name=f"{lib_name}@{lib_version}",
                        severity=severity,
                    )
                )

                # Flag critical/high vulnerable components
                if severity in ("critical", "high"):
                    findings.append(
                        FindingData(
                            **self._base(raw),
                            observation_type="alert",
                            title=f"High-risk vulnerable dependency: {lib_name}@{lib_version}",
                            detail={
                                "issue_id": issue_id,
                                "workspace_name": ws_name,
                                "library_name": lib_name,
                                "library_version": lib_version,
                                "vulnerability_id": vuln_id,
                                "cvss_score": severity_score,
                                "issue": f"Dependency {lib_name}@{lib_version} has {severity} vulnerability ({vuln_id}, CVSS {severity_score})",
                            },
                            resource_id=issue_id or f"{lib_name}@{lib_version}:{vuln_id}",
                            resource_type="veracode_sca_issue",
                            resource_name=f"{lib_name}@{lib_version}",
                            severity=severity,
                        )
                    )

        return findings


# Register
registry.register(VeracodeNormalizer())
