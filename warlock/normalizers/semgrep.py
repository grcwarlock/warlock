"""Semgrep normalizer — transforms raw Semgrep App API responses into Findings.

Handles deployments, findings, policies, and projects.
Flags: critical/high SAST findings, projects without scanning, stale scans.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SemgrepNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "semgrep_deployments": "_normalize_deployments",
        "semgrep_findings": "_normalize_findings",
        "semgrep_policies": "_normalize_policies",
        "semgrep_projects": "_normalize_projects",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "semgrep" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Semgrep findings."""
        return {
            "raw_event_id": raw.id,
            "source": "semgrep",
            "source_type": SourceType.CODE,
            "provider": "semgrep",
            "observed_at": raw.observed_at,
        }

    # -- Deployments --

    def _normalize_deployments(self, raw: RawEventData) -> list[FindingData]:
        """Inventory Semgrep deployments (orgs)."""
        findings = []
        deployments = raw.raw_data.get("deployments", [])

        for dep in deployments:
            dep_id = str(dep.get("id", dep.get("slug", "")))
            dep_name = dep.get("name", dep.get("slug", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Semgrep deployment: {dep_name}",
                    detail={
                        "deployment_id": dep_id,
                        "deployment_name": dep_name,
                        "slug": dep.get("slug", ""),
                    },
                    resource_id=dep_id,
                    resource_type="semgrep_deployment",
                    resource_name=dep_name,
                    severity="info",
                )
            )

        return findings

    # -- Findings --

    def _normalize_findings(self, raw: RawEventData) -> list[FindingData]:
        """Normalize SAST findings; flag critical/high severity."""
        findings = []
        sast_findings = raw.raw_data.get("findings", [])

        for f in sast_findings:
            finding_id = str(f.get("id", ""))
            rule_id = f.get("rule", {}).get("id", f.get("rule_id", ""))
            rule_name = f.get("rule", {}).get("name", f.get("rule_name", rule_id))
            severity = f.get("severity", f.get("rule", {}).get("severity", "info")).lower()
            repo = f.get("repository", {}).get("name", f.get("repo_name", ""))
            file_path = f.get("location", {}).get("file_path", f.get("file_path", ""))
            line_start = f.get("location", {}).get("line", f.get("line", ""))
            state = f.get("state", f.get("triage_state", ""))
            confidence = f.get("confidence", f.get("rule", {}).get("confidence", ""))
            category = f.get("rule", {}).get("category", "")

            # Inventory every finding
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"SAST finding: {rule_name} in {repo}",
                    detail={
                        "finding_id": finding_id,
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "severity": severity,
                        "repository": repo,
                        "file_path": file_path,
                        "line_start": line_start,
                        "state": state,
                        "confidence": confidence,
                        "category": category,
                    },
                    resource_id=finding_id,
                    resource_type="semgrep_finding",
                    resource_name=f"{rule_name}:{repo}",
                    severity=severity if severity in ("critical", "high", "medium", "low") else "info",
                )
            )

            # Flag critical/high findings that are not resolved
            if severity in ("critical", "high") and state not in ("fixed", "resolved", "dismissed"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Unresolved {severity} SAST finding: {rule_name}",
                        detail={
                            "finding_id": finding_id,
                            "rule_id": rule_id,
                            "rule_name": rule_name,
                            "severity": severity,
                            "repository": repo,
                            "file_path": file_path,
                            "line_start": line_start,
                            "state": state,
                            "issue": f"Critical/high SAST finding remains unresolved in {repo}",
                        },
                        resource_id=finding_id,
                        resource_type="semgrep_finding",
                        resource_name=f"{rule_name}:{repo}",
                        severity=severity,
                    )
                )

        return findings

    # -- Policies --

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        """Inventory Semgrep scanning policies."""
        findings = []
        policies = raw.raw_data.get("policies", [])

        for policy in policies:
            policy_id = str(policy.get("id", policy.get("slug", "")))
            policy_name = policy.get("name", policy.get("slug", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Semgrep policy: {policy_name}",
                    detail={
                        "policy_id": policy_id,
                        "policy_name": policy_name,
                        "rules_count": len(policy.get("rules", [])),
                    },
                    resource_id=policy_id,
                    resource_type="semgrep_policy",
                    resource_name=policy_name,
                    severity="info",
                )
            )

        return findings

    # -- Projects --

    def _normalize_projects(self, raw: RawEventData) -> list[FindingData]:
        """Inventory projects; flag projects without recent scans."""
        findings = []
        projects = raw.raw_data.get("projects", [])

        for project in projects:
            project_id = str(project.get("id", project.get("name", "")))
            project_name = project.get("name", "")
            last_scan = project.get("latest_scan", {})
            last_scan_at = last_scan.get("completed_at", last_scan.get("created_at", "")) if isinstance(last_scan, dict) else ""

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Semgrep project: {project_name}",
                    detail={
                        "project_id": project_id,
                        "project_name": project_name,
                        "last_scan_at": last_scan_at,
                        "url": project.get("url", ""),
                    },
                    resource_id=project_id,
                    resource_type="semgrep_project",
                    resource_name=project_name,
                    severity="info",
                )
            )

            # Flag projects with no scan data
            if not last_scan or not last_scan_at:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Project without scanning: {project_name}",
                        detail={
                            "project_id": project_id,
                            "project_name": project_name,
                            "issue": "Project is registered in Semgrep but has no completed scan — code is not being analyzed",
                        },
                        resource_id=project_id,
                        resource_type="semgrep_project",
                        resource_name=project_name,
                        severity="high",
                    )
                )

        return findings


# Register
registry.register(SemgrepNormalizer())
