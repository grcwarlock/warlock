"""GitLab normalizer — transforms raw GitLab API responses into Findings.

Handles projects, vulnerabilities, audit events, and runners.
Flags: public repos, projects without MR approvals, critical/high vulns,
shared runners without tag restrictions.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class GitLabNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "gitlab_projects": "_normalize_projects",
        "gitlab_vulnerabilities": "_normalize_vulnerabilities",
        "gitlab_audit_events": "_normalize_audit_events",
        "gitlab_runners": "_normalize_runners",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "gitlab" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all GitLab findings."""
        return {
            "raw_event_id": raw.id,
            "source": "gitlab",
            "source_type": SourceType.CODE,
            "provider": "gitlab",
            "observed_at": raw.observed_at,
        }

    # -- Projects --

    def _normalize_projects(self, raw: RawEventData) -> list[FindingData]:
        """Inventory projects; flag public repos and missing MR approvals."""
        findings = []
        projects = raw.raw_data.get("projects", [])

        for project in projects:
            proj_id = str(project.get("id", ""))
            name = project.get("name", "")
            path = project.get("path_with_namespace", "")
            visibility = project.get("visibility", "")
            archived = project.get("archived", False)
            approval_rules = project.get("approval_rules", [])

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"GitLab project: {path} ({visibility})",
                    detail={
                        "project_id": proj_id,
                        "name": name,
                        "path_with_namespace": path,
                        "visibility": visibility,
                        "archived": archived,
                        "approval_rule_count": len(approval_rules),
                    },
                    resource_id=proj_id,
                    resource_type="gitlab_project",
                    resource_name=path or name,
                    severity="info",
                )
            )

            # Flag public repositories
            if visibility == "public" and not archived:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Public repository: {path}",
                        detail={
                            "project_id": proj_id,
                            "path_with_namespace": path,
                            "visibility": "public",
                            "issue": "Repository is publicly accessible — source code and history are exposed to the internet",
                        },
                        resource_id=proj_id,
                        resource_type="gitlab_project",
                        resource_name=path or name,
                        severity="high",
                    )
                )

            # Flag projects without MR approval rules
            if not approval_rules and not archived:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"No merge request approval rules: {path}",
                        detail={
                            "project_id": proj_id,
                            "path_with_namespace": path,
                            "approval_rule_count": 0,
                            "issue": "Project has no merge request approval rules — code can be merged without peer review",
                        },
                        resource_id=proj_id,
                        resource_type="gitlab_project",
                        resource_name=path or name,
                        severity="medium",
                    )
                )

        return findings

    # -- Vulnerabilities --

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        """Flag critical and high severity vulnerabilities."""
        findings = []
        vulns = raw.raw_data.get("vulnerabilities", [])

        for vuln in vulns:
            vuln_id = str(vuln.get("id", ""))
            title = vuln.get("title", vuln.get("name", ""))
            severity = vuln.get("severity", "unknown").lower()
            state = vuln.get("state", "")
            scanner = vuln.get("scanner", {}).get("name", "") if isinstance(vuln.get("scanner"), dict) else ""
            project_name = vuln.get("project", {}).get("name", "") if isinstance(vuln.get("project"), dict) else ""
            report_type = vuln.get("report_type", "")

            # Map GitLab severity to warlock severity
            sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
            mapped_severity = sev_map.get(severity, "medium")

            if mapped_severity in ("critical", "high"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="vulnerability",
                        title=f"GitLab {report_type} vulnerability: {title}",
                        detail={
                            "vulnerability_id": vuln_id,
                            "title": title,
                            "severity": severity,
                            "state": state,
                            "scanner": scanner,
                            "report_type": report_type,
                            "project": project_name,
                            "issue": f"{severity.title()} severity {report_type} vulnerability detected by {scanner}",
                        },
                        resource_id=vuln_id,
                        resource_type="gitlab_vulnerability",
                        resource_name=title,
                        severity=mapped_severity,
                    )
                )

        return findings

    # -- Audit Events --

    def _normalize_audit_events(self, raw: RawEventData) -> list[FindingData]:
        """Inventory audit events; flag sensitive actions."""
        findings = []
        events = raw.raw_data.get("events", [])

        for event in events:
            event_id = str(event.get("id", ""))
            author = event.get("author_name", "")
            entity_type = event.get("entity_type", "")
            entity_path = event.get("entity_path", "")
            details = event.get("details", {}) if isinstance(event.get("details"), dict) else {}
            action = details.get("custom_message", details.get("action", ""))
            created_at = event.get("created_at", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"GitLab audit event: {action} by {author}",
                    detail={
                        "event_id": event_id,
                        "author": author,
                        "entity_type": entity_type,
                        "entity_path": entity_path,
                        "action": action,
                        "created_at": created_at,
                    },
                    resource_id=event_id,
                    resource_type="gitlab_audit_event",
                    resource_name=f"{action}:{author}",
                    severity="info",
                )
            )

        return findings

    # -- Runners --

    def _normalize_runners(self, raw: RawEventData) -> list[FindingData]:
        """Inventory runners; flag shared runners without tag restrictions."""
        findings = []
        runners = raw.raw_data.get("runners", [])

        for runner in runners:
            runner_id = str(runner.get("id", ""))
            description = runner.get("description", "")
            runner_type = runner.get("runner_type", runner.get("is_shared", ""))
            is_shared = runner.get("is_shared", False) or runner_type == "instance_type"
            active = runner.get("active", True)
            tag_list = runner.get("tag_list", [])
            run_untagged = runner.get("run_untagged", True)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"GitLab runner: {description} ({runner_type})",
                    detail={
                        "runner_id": runner_id,
                        "description": description,
                        "runner_type": runner_type,
                        "is_shared": is_shared,
                        "active": active,
                        "tag_list": tag_list,
                        "run_untagged": run_untagged,
                    },
                    resource_id=runner_id,
                    resource_type="gitlab_runner",
                    resource_name=description or runner_id,
                    severity="info",
                )
            )

            # Flag shared runners that run untagged jobs
            if is_shared and active and run_untagged:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Shared runner accepts untagged jobs: {description}",
                        detail={
                            "runner_id": runner_id,
                            "description": description,
                            "is_shared": True,
                            "run_untagged": True,
                            "issue": "Shared runner accepts untagged jobs — any project can execute arbitrary code on this runner",
                        },
                        resource_id=runner_id,
                        resource_type="gitlab_runner",
                        resource_name=description or runner_id,
                        severity="medium",
                    )
                )

        return findings


# Register
registry.register(GitLabNormalizer())
