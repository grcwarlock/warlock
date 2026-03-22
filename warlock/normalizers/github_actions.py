"""GitHub Actions normalizer — transforms raw GitHub API responses into Findings.

Handles workflow runs, secrets, runners, and code scanning alerts.
Flags: failed security workflow runs, self-hosted runners without latest version,
stale secrets, critical/high code scanning alerts.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class GitHubActionsNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "gha_workflow_runs": "_normalize_workflow_runs",
        "gha_secrets": "_normalize_secrets",
        "gha_runners": "_normalize_runners",
        "gha_code_scanning": "_normalize_code_scanning",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "github_actions" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all GitHub Actions findings."""
        return {
            "raw_event_id": raw.id,
            "source": "github_actions",
            "source_type": SourceType.CI_CD,
            "provider": "github",
            "observed_at": raw.observed_at,
        }

    # -- Workflow Runs --

    def _normalize_workflow_runs(self, raw: RawEventData) -> list[FindingData]:
        """Inventory workflow runs; flag failed security workflows."""
        findings = []
        runs = raw.raw_data.get("runs", [])

        security_keywords = {
            "security",
            "sast",
            "dast",
            "codeql",
            "scan",
            "audit",
            "compliance",
            "snyk",
            "semgrep",
        }

        for run in runs:
            run_id = str(run.get("id", ""))
            name = run.get("name", "")
            conclusion = run.get("conclusion", "")
            status = run.get("status", "")
            html_url = run.get("html_url", "")
            repo_name = (
                run.get("repository", {}).get("full_name", "")
                if isinstance(run.get("repository"), dict)
                else ""
            )
            head_branch = run.get("head_branch", "")
            run_number = run.get("run_number", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"GHA workflow run: {name} #{run_number} ({conclusion or status})",
                    detail={
                        "run_id": run_id,
                        "name": name,
                        "conclusion": conclusion,
                        "status": status,
                        "html_url": html_url,
                        "repository": repo_name,
                        "head_branch": head_branch,
                        "run_number": run_number,
                    },
                    resource_id=run_id,
                    resource_type="gha_workflow_run",
                    resource_name=f"{repo_name}:{name}",
                    severity="info",
                )
            )

            # Flag failed security workflow runs
            name_lower = name.lower()
            is_security_workflow = any(kw in name_lower for kw in security_keywords)
            if is_security_workflow and conclusion == "failure":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Security workflow failed: {name} #{run_number} in {repo_name}",
                        detail={
                            "run_id": run_id,
                            "name": name,
                            "conclusion": "failure",
                            "repository": repo_name,
                            "html_url": html_url,
                            "issue": f"Security workflow '{name}' failed in {repo_name} — security checks may not be running",
                        },
                        resource_id=run_id,
                        resource_type="gha_workflow_run",
                        resource_name=f"{repo_name}:{name}",
                        severity="high",
                    )
                )

        return findings

    # -- Secrets --

    def _normalize_secrets(self, raw: RawEventData) -> list[FindingData]:
        """Inventory org secrets; flag stale secrets."""
        findings = []
        secrets = raw.raw_data.get("secrets", [])

        now = datetime.now(timezone.utc)

        for secret in secrets:
            name = secret.get("name", "")
            created_at = secret.get("created_at", "")
            updated_at = secret.get("updated_at", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"GHA org secret: {name}",
                    detail={
                        "name": name,
                        "created_at": created_at,
                        "updated_at": updated_at,
                    },
                    resource_id=name,
                    resource_type="gha_secret",
                    resource_name=name,
                    severity="info",
                )
            )

            # Flag stale secrets (not updated in 90+ days)
            if updated_at:
                try:
                    updated = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                    days_since_update = (now - updated).days
                    if days_since_update > 90:
                        findings.append(
                            FindingData(
                                **self._base(raw),
                                observation_type="policy_violation",
                                title=f"Stale GitHub Actions secret: {name} ({days_since_update} days)",
                                detail={
                                    "name": name,
                                    "updated_at": updated_at,
                                    "days_since_update": days_since_update,
                                    "issue": f"Secret '{name}' has not been rotated in {days_since_update} days — exceeds 90-day rotation policy",
                                },
                                resource_id=name,
                                resource_type="gha_secret",
                                resource_name=name,
                                severity="medium",
                            )
                        )
                except (ValueError, TypeError):
                    pass

        return findings

    # -- Runners --

    def _normalize_runners(self, raw: RawEventData) -> list[FindingData]:
        """Inventory runners; flag self-hosted runners without latest version."""
        findings = []
        runners = raw.raw_data.get("runners", [])

        for runner in runners:
            runner_id = str(runner.get("id", ""))
            name = runner.get("name", "")
            os_name = runner.get("os", "")
            status = runner.get("status", "")
            busy = runner.get("busy", False)
            labels = (
                [lbl.get("name", "") for lbl in runner.get("labels", [])]
                if isinstance(runner.get("labels"), list)
                else []
            )

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"GHA runner: {name} ({os_name}, {status})",
                    detail={
                        "runner_id": runner_id,
                        "name": name,
                        "os": os_name,
                        "status": status,
                        "busy": busy,
                        "labels": labels,
                    },
                    resource_id=runner_id,
                    resource_type="gha_runner",
                    resource_name=name,
                    severity="info",
                )
            )

            # Flag offline self-hosted runners
            is_self_hosted = "self-hosted" in labels
            if is_self_hosted and status == "offline":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Self-hosted runner offline: {name}",
                        detail={
                            "runner_id": runner_id,
                            "name": name,
                            "os": os_name,
                            "status": "offline",
                            "labels": labels,
                            "issue": f"Self-hosted runner '{name}' is offline — may be running outdated software or misconfigured",
                        },
                        resource_id=runner_id,
                        resource_type="gha_runner",
                        resource_name=name,
                        severity="high",
                    )
                )

        return findings

    # -- Code Scanning --

    def _normalize_code_scanning(self, raw: RawEventData) -> list[FindingData]:
        """Normalize GHAS code scanning alerts; flag critical/high severity."""
        findings = []
        alerts = raw.raw_data.get("alerts", [])

        for alert in alerts:
            alert_number = str(alert.get("number", ""))
            state = alert.get("state", "")
            rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}
            rule_id = rule.get("id", "")
            rule_severity = rule.get("security_severity_level", rule.get("severity", ""))
            rule_description = rule.get("description", "")
            tool = alert.get("tool", {}) if isinstance(alert.get("tool"), dict) else {}
            tool_name = tool.get("name", "")
            html_url = alert.get("html_url", "")
            repo_name = (
                alert.get("repository", {}).get("full_name", "")
                if isinstance(alert.get("repository"), dict)
                else ""
            )

            severity = "info"
            if rule_severity in ("critical",):
                severity = "critical"
            elif rule_severity in ("high",):
                severity = "high"
            elif rule_severity in ("medium", "warning"):
                severity = "medium"
            elif rule_severity in ("low", "note"):
                severity = "low"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability"
                    if severity in ("critical", "high")
                    else "alert",
                    title=f"Code scanning alert: {rule_description or rule_id} ({tool_name})",
                    detail={
                        "alert_number": alert_number,
                        "state": state,
                        "rule_id": rule_id,
                        "rule_severity": rule_severity,
                        "rule_description": rule_description,
                        "tool_name": tool_name,
                        "html_url": html_url,
                        "repository": repo_name,
                        "issue": f"Code scanning alert from {tool_name}: {rule_description}"
                        if severity in ("critical", "high")
                        else "",
                    },
                    resource_id=f"{repo_name}:{alert_number}",
                    resource_type="gha_code_scanning_alert",
                    resource_name=f"{rule_id}@{repo_name}",
                    severity=severity,
                )
            )

        return findings


# Register
registry.register(GitHubActionsNormalizer())
