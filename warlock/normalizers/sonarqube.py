"""SonarQube normalizer — transforms raw SonarQube API responses into Findings.

Handles projects, issues (bugs/vulnerabilities/code smells), and quality gates.
Flags quality gate failures, critical/blocker vulnerabilities, security hotspots
not reviewed, and projects with no recent scans.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SonarQubeNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "sonarqube_projects": "_normalize_projects",
        "sonarqube_issues": "_normalize_issues",
        "sonarqube_quality_gates": "_normalize_quality_gates",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sonarqube" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all SonarQube findings."""
        return {
            "raw_event_id": raw.id,
            "source": "sonarqube",
            "source_type": SourceType.CODE,
            "provider": "sonarqube",
            "observed_at": raw.observed_at,
        }

    # -- Projects --

    def _normalize_projects(self, raw: RawEventData) -> list[FindingData]:
        """Inventory projects; flag quality gate failures and unscanned projects."""
        findings = []
        projects = raw.raw_data.get("projects", [])

        for project in projects:
            project_key = project.get("key", "")
            project_name = project.get("name", "")
            qualifier = project.get("qualifier", "")
            visibility = project.get("visibility", "")
            last_analysis = project.get("lastAnalysisDate", "")
            revision = project.get("revision", "")

            # Quality gate status from measures
            measures = project.get("measures", [])
            gate_status = ""
            for m in measures:
                if m.get("metric") == "alert_status":
                    gate_status = m.get("value", "")
                    break

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"SonarQube project: {project_name}",
                    detail={
                        "project_key": project_key,
                        "name": project_name,
                        "qualifier": qualifier,
                        "visibility": visibility,
                        "last_analysis_date": last_analysis,
                        "revision": revision,
                        "quality_gate_status": gate_status,
                    },
                    resource_id=project_key,
                    resource_type="sonarqube_project",
                    resource_name=project_name,
                    severity="info",
                )
            )

            # Flag quality gate failures
            if gate_status == "ERROR":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Quality gate failed: {project_name}",
                        detail={
                            "project_key": project_key,
                            "name": project_name,
                            "quality_gate_status": gate_status,
                            "issue": "Project fails quality gate — code does not meet minimum quality standards",
                        },
                        resource_id=project_key,
                        resource_type="sonarqube_project",
                        resource_name=project_name,
                        severity="high",
                    )
                )

            # Flag projects with no recent analysis
            if not last_analysis:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"SonarQube project never analyzed: {project_name}",
                        detail={
                            "project_key": project_key,
                            "name": project_name,
                            "issue": "Project has no analysis history — code quality and vulnerabilities unknown",
                        },
                        resource_id=project_key,
                        resource_type="sonarqube_project",
                        resource_name=project_name,
                        severity="medium",
                    )
                )

        return findings

    # -- Issues --

    def _normalize_issues(self, raw: RawEventData) -> list[FindingData]:
        """Normalize issues; flag critical/blocker vulnerabilities and unreviewed hotspots."""
        findings = []
        issues = raw.raw_data.get("issues", [])

        for issue in issues:
            issue_key = issue.get("key", "")
            rule = issue.get("rule", "")
            severity_val = issue.get("severity", "").lower()
            issue_type = issue.get("type", "")  # BUG, VULNERABILITY, CODE_SMELL, SECURITY_HOTSPOT
            component = issue.get("component", "")
            project = issue.get("project", "")
            message = issue.get("message", "")
            status = issue.get("status", "")
            resolution = issue.get("resolution", "")
            line = issue.get("line", 0)
            effort = issue.get("effort", "")
            debt = issue.get("debt", "")
            author = issue.get("author", "")
            creation_date = issue.get("creationDate", "")
            tags = issue.get("tags", [])

            # Map SonarQube severity to standard
            severity_map = {
                "blocker": "critical",
                "critical": "high",
                "major": "medium",
                "minor": "low",
                "info": "info",
            }
            severity = severity_map.get(severity_val, "medium")

            # Map issue type to observation type
            obs_type_map = {
                "VULNERABILITY": "vulnerability",
                "BUG": "vulnerability",
                "CODE_SMELL": "misconfiguration",
                "SECURITY_HOTSPOT": "vulnerability",
            }
            obs_type = obs_type_map.get(issue_type, "misconfiguration")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"SonarQube {issue_type}: {message[:100]}",
                    detail={
                        "issue_key": issue_key,
                        "rule": rule,
                        "severity": severity_val,
                        "type": issue_type,
                        "component": component,
                        "project": project,
                        "message": message,
                        "status": status,
                        "resolution": resolution,
                        "line": line,
                        "effort": effort,
                        "debt": debt,
                        "author": author,
                        "creation_date": creation_date,
                        "tags": tags,
                    },
                    resource_id=issue_key,
                    resource_type="sonarqube_issue",
                    resource_name=f"{rule}:{component}",
                    severity=severity,
                )
            )

            # Flag critical/blocker vulnerabilities
            if issue_type == "VULNERABILITY" and severity_val in ("blocker", "critical"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Critical SonarQube vulnerability: {message[:80]}",
                        detail={
                            "issue_key": issue_key,
                            "rule": rule,
                            "severity": severity_val,
                            "component": component,
                            "project": project,
                            "message": message,
                            "issue": "Critical/blocker vulnerability requires immediate remediation",
                        },
                        resource_id=issue_key,
                        resource_type="sonarqube_issue",
                        resource_name=f"{rule}:{component}",
                        severity="critical",
                    )
                )

            # Flag unreviewed security hotspots
            if issue_type == "SECURITY_HOTSPOT" and status not in ("REVIEWED", "CLOSED"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Unreviewed security hotspot: {message[:80]}",
                        detail={
                            "issue_key": issue_key,
                            "rule": rule,
                            "component": component,
                            "project": project,
                            "status": status,
                            "issue": "Security hotspot not reviewed — potential vulnerability unaddressed",
                        },
                        resource_id=issue_key,
                        resource_type="sonarqube_issue",
                        resource_name=f"{rule}:{component}",
                        severity="medium",
                    )
                )

        return findings

    # -- Quality Gates --

    def _normalize_quality_gates(self, raw: RawEventData) -> list[FindingData]:
        """Inventory quality gate definitions."""
        findings = []
        gates = raw.raw_data.get("quality_gates", [])
        default_gate = raw.raw_data.get("default", "")

        for gate in gates:
            gate_id = str(gate.get("id", ""))
            gate_name = gate.get("name", "")
            is_default = gate.get("isDefault", False) or gate_id == str(default_gate)
            is_built_in = gate.get("isBuiltIn", False)
            conditions = gate.get("conditions", [])

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Quality gate: {gate_name}",
                    detail={
                        "gate_id": gate_id,
                        "name": gate_name,
                        "is_default": is_default,
                        "is_built_in": is_built_in,
                        "conditions_count": len(conditions),
                        "conditions": conditions,
                    },
                    resource_id=gate_id,
                    resource_type="sonarqube_quality_gate",
                    resource_name=gate_name,
                    severity="info",
                )
            )

            # Flag quality gates with no conditions
            if not conditions and is_default:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Default quality gate has no conditions: {gate_name}",
                        detail={
                            "gate_id": gate_id,
                            "name": gate_name,
                            "is_default": True,
                            "issue": "Default quality gate has no conditions — all projects will pass regardless of quality",
                        },
                        resource_id=gate_id,
                        resource_type="sonarqube_quality_gate",
                        resource_name=gate_name,
                        severity="high",
                    )
                )

        return findings


# Register
registry.register(SonarQubeNormalizer())
