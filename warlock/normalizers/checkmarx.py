"""Checkmarx normalizer — transforms raw Checkmarx API responses into Findings.

Handles projects, scan results, and vulnerability findings.
Flags critical/high vulnerabilities (SQL injection, XSS, path traversal),
unscanned projects, and projects with scan failures.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Vulnerability categories considered critical
CRITICAL_VULN_CATEGORIES = {
    "SQL_Injection",
    "Sql_Injection",
    "SQL Injection",
    "Stored_XSS",
    "Reflected_XSS",
    "DOM_XSS",
    "Cross_Site_Scripting",
    "XSS",
    "Path_Traversal",
    "Directory_Traversal",
    "Command_Injection",
    "Code_Injection",
    "SSRF",
    "XXE",
    "Deserialization",
    "LDAP_Injection",
}


class CheckmarxNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "checkmarx_projects": "_normalize_projects",
        "checkmarx_scan_results": "_normalize_scan_results",
        "checkmarx_vulnerabilities": "_normalize_vulnerabilities",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "checkmarx" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Checkmarx findings."""
        return {
            "raw_event_id": raw.id,
            "source": "checkmarx",
            "source_type": SourceType.CODE,
            "provider": "checkmarx",
            "observed_at": raw.observed_at,
        }

    # -- Projects --

    def _normalize_projects(self, raw: RawEventData) -> list[FindingData]:
        """Inventory projects; flag unscanned projects."""
        findings = []
        projects = raw.raw_data.get("projects", [])

        for project in projects:
            project_id = project.get("id", "")
            project_name = project.get("name", "")
            repo_url = project.get("repoUrl", "")
            main_branch = project.get("mainBranch", "")
            last_scan_id = project.get("lastScanId", "")
            tags = project.get("tags", {})
            created_at = project.get("createdAt", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Checkmarx project: {project_name}",
                    detail={
                        "project_id": project_id,
                        "name": project_name,
                        "repo_url": repo_url,
                        "main_branch": main_branch,
                        "last_scan_id": last_scan_id,
                        "tags": tags,
                        "created_at": created_at,
                    },
                    resource_id=project_id,
                    resource_type="checkmarx_project",
                    resource_name=project_name,
                    severity="info",
                )
            )

            # Flag unscanned projects
            if not last_scan_id:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Checkmarx project never scanned: {project_name}",
                        detail={
                            "project_id": project_id,
                            "name": project_name,
                            "repo_url": repo_url,
                            "issue": "Project has no scan history — code vulnerabilities may be undetected",
                        },
                        resource_id=project_id,
                        resource_type="checkmarx_project",
                        resource_name=project_name,
                        severity="high",
                    )
                )

        return findings

    # -- Scan Results --

    def _normalize_scan_results(self, raw: RawEventData) -> list[FindingData]:
        """Inventory scans; flag failed or cancelled scans."""
        findings = []
        scans = raw.raw_data.get("scans", [])

        for scan in scans:
            scan_id = scan.get("id", "")
            project_id = scan.get("projectId", "")
            project_name = scan.get("projectName", scan.get("project", {}).get("name", ""))
            status = scan.get("status", "")
            scan_type = scan.get("type", "")
            created_at = scan.get("createdAt", "")
            updated_at = scan.get("updatedAt", "")
            engines = scan.get("engines", [])
            source_type_val = scan.get("sourceType", "")
            branch = scan.get("branch", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Checkmarx scan: {project_name} ({status})",
                    detail={
                        "scan_id": scan_id,
                        "project_id": project_id,
                        "project_name": project_name,
                        "status": status,
                        "scan_type": scan_type,
                        "engines": engines,
                        "branch": branch,
                        "source_type": source_type_val,
                        "created_at": created_at,
                        "updated_at": updated_at,
                    },
                    resource_id=scan_id,
                    resource_type="checkmarx_scan",
                    resource_name=f"{project_name}:{scan_id[:8]}",
                    severity="info",
                )
            )

            # Flag failed or cancelled scans
            if status.lower() in ("failed", "cancelled", "canceled"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Checkmarx scan {status}: {project_name}",
                        detail={
                            "scan_id": scan_id,
                            "project_id": project_id,
                            "project_name": project_name,
                            "status": status,
                            "branch": branch,
                            "issue": f"Scan {status} — security vulnerabilities may be undetected",
                        },
                        resource_id=scan_id,
                        resource_type="checkmarx_scan",
                        resource_name=f"{project_name}:{scan_id[:8]}",
                        severity="medium",
                    )
                )

        return findings

    # -- Vulnerabilities --

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        """Normalize vulnerability findings; flag critical categories."""
        findings = []
        vulns = raw.raw_data.get("vulnerabilities", [])

        for vuln in vulns:
            vuln_id = vuln.get("id", vuln.get("resultHash", ""))
            query_name = vuln.get("queryName", vuln.get("data", {}).get("queryName", ""))
            category = vuln.get("category", vuln.get("data", {}).get("group", ""))
            severity_val = vuln.get("severity", "").lower()
            state = vuln.get("state", "")
            status = vuln.get("status", "")
            file_name = vuln.get("fileName", vuln.get("data", {}).get("fileName", ""))
            line = vuln.get("line", vuln.get("data", {}).get("line", 0))
            language = vuln.get("language", vuln.get("data", {}).get("languageName", ""))
            scan_id = vuln.get("scanId", "")
            description = vuln.get("description", "")
            cwe_id = vuln.get("cweId", vuln.get("data", {}).get("cweId", ""))

            # Map Checkmarx severity to standard
            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "info",
                "information": "info",
            }
            severity = severity_map.get(severity_val, "medium")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"SAST: {query_name} in {file_name}",
                    detail={
                        "vuln_id": vuln_id,
                        "query_name": query_name,
                        "category": category,
                        "severity": severity_val,
                        "state": state,
                        "status": status,
                        "file_name": file_name,
                        "line": line,
                        "language": language,
                        "scan_id": scan_id,
                        "description": description,
                        "cwe_id": cwe_id,
                    },
                    resource_id=vuln_id,
                    resource_type="checkmarx_vulnerability",
                    resource_name=f"{query_name}:{file_name}",
                    severity=severity,
                )
            )

            # Flag critical vulnerability categories
            if category in CRITICAL_VULN_CATEGORIES or query_name in CRITICAL_VULN_CATEGORIES:
                if severity in ("critical", "high"):
                    findings.append(
                        FindingData(
                            **self._base(raw),
                            observation_type="alert",
                            title=f"Critical SAST finding: {query_name} ({category})",
                            detail={
                                "vuln_id": vuln_id,
                                "query_name": query_name,
                                "category": category,
                                "file_name": file_name,
                                "line": line,
                                "cwe_id": cwe_id,
                                "issue": f"High-risk vulnerability category {category} requires immediate remediation",
                            },
                            resource_id=vuln_id,
                            resource_type="checkmarx_vulnerability",
                            resource_name=f"{query_name}:{file_name}",
                            severity="critical",
                        )
                    )

        return findings


# Register
registry.register(CheckmarxNormalizer())
