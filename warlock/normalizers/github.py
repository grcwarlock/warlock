"""GitHub normalizer — transforms raw GitHub API responses into Findings.

Normalizes repos, branch protections, audit log events, Dependabot alerts,
and secret scanning alerts with CI/CD security finding generation.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class GitHubNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "github_repos": "_normalize_repos",
        "github_branch_protections": "_normalize_branch_protections",
        "github_audit_log": "_normalize_audit_log",
        "github_dependabot_alerts": "_normalize_dependabot_alerts",
        "github_secret_scanning_alerts": "_normalize_secret_scanning_alerts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "github" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "github",
            "source_type": SourceType.CODE,
            "provider": "github",
            "account_id": raw.raw_data.get("org", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Repos --

    def _normalize_repos(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        repos = raw.raw_data.get("response", [])

        for repo in repos:
            full_name = repo.get("full_name", "")
            repo_id = str(repo.get("id", ""))
            visibility = repo.get("visibility", repo.get("private", ""))
            is_private = repo.get("private", True)

            obs_type = "inventory"
            severity = "info"

            if not is_private:
                obs_type = "misconfiguration"
                severity = "medium"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"GitHub repo: {full_name} ({visibility})"
                    + (" -- public repository" if not is_private else ""),
                    detail={
                        "full_name": full_name,
                        "visibility": visibility,
                        "private": is_private,
                        "default_branch": repo.get("default_branch", ""),
                        "archived": repo.get("archived", False),
                        "fork": repo.get("fork", False),
                        "has_vulnerability_alerts": repo.get(
                            "has_vulnerability_alerts_enabled", False
                        ),
                        "language": repo.get("language", ""),
                    },
                    resource_id=repo_id,
                    resource_type="code_repository",
                    resource_name=full_name,
                    severity=severity,
                )
            )

        return findings

    # -- Branch Protections --

    def _normalize_branch_protections(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        protections = raw.raw_data.get("response", [])

        for protection in protections:
            repo = protection.get("_repo", "")
            branch = protection.get("_branch", "")
            unprotected = protection.get("_unprotected", False)

            issues = []
            severity = "info"
            obs_type = "inventory"

            if unprotected:
                issues.append("no_branch_protection")
                severity = "high"
                obs_type = "misconfiguration"
            else:
                # Check required pull request reviews
                pr_reviews = protection.get("required_pull_request_reviews")
                if not pr_reviews:
                    issues.append("no_required_reviews")
                    if severity != "high":
                        severity = "medium"
                    obs_type = "misconfiguration"

                # Check required status checks
                status_checks = protection.get("required_status_checks")
                if not status_checks:
                    issues.append("no_status_checks")
                    if severity != "high":
                        severity = "medium"
                    obs_type = "misconfiguration"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"GitHub branch protection: {repo}:{branch}"
                    + (f" -- {', '.join(issues)}" if issues else ""),
                    detail={
                        "repo": repo,
                        "branch": branch,
                        "unprotected": unprotected,
                        "enforce_admins": protection.get("enforce_admins", {}).get("enabled", False)
                        if not unprotected
                        else False,
                        "required_signatures": protection.get("required_signatures", {}).get(
                            "enabled", False
                        )
                        if not unprotected
                        else False,
                        "issues": issues,
                        "protection": protection if not unprotected else {},
                    },
                    resource_id=f"{repo}:{branch}",
                    resource_type="branch_protection",
                    resource_name=f"{repo}:{branch}",
                    severity=severity,
                )
            )

        return findings

    # -- Audit Log --

    def _normalize_audit_log(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        events = raw.raw_data.get("response", [])

        SENSITIVE_ACTIONS = {
            "org.add_member",
            "org.remove_member",
            "repo.access",
            "repo.change_visibility",
            "repo.destroy",
            "repo.create",
            "org.update_default_repository_permission",
            "org.invite_member",
            "environment.create_actions_secret",
            "org.create_actions_secret",
        }

        for event in events:
            action = event.get("action", "unknown")
            actor = event.get("actor", "")
            created_at = event.get("created_at", event.get("@timestamp", ""))

            is_sensitive = action in SENSITIVE_ACTIONS
            obs_type = "alert" if is_sensitive else "inventory"
            severity = "medium" if is_sensitive else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"GitHub audit: {action}" + (f" by {actor}" if actor else ""),
                    detail={
                        "action": action,
                        "actor": actor,
                        "created_at": created_at,
                        "repo": event.get("repo", ""),
                        "org": event.get("org", ""),
                        "event": event,
                    },
                    resource_id=str(event.get("_document_id", event.get("id", ""))),
                    resource_type="code_audit_event",
                    resource_name=action,
                    severity=severity,
                )
            )

        return findings

    # -- Dependabot Alerts --

    def _normalize_dependabot_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        alerts = raw.raw_data.get("response", [])

        for alert in alerts:
            number = alert.get("number", "")
            repo = alert.get("repository", {})
            repo_name = repo.get("full_name", "")
            security_advisory = alert.get("security_advisory", {})
            dependency = alert.get("dependency", {})
            package = dependency.get("package", {})

            # Map severity
            alert_severity = (security_advisory.get("severity", "medium")).lower()
            if alert_severity not in ("critical", "high", "medium", "low"):
                alert_severity = "medium"

            cve_id = security_advisory.get("cve_id", "")
            summary = security_advisory.get("summary", "")
            package_name = package.get("name", "")
            ecosystem = package.get("ecosystem", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Dependabot: {summary}"
                    + (f" ({cve_id})" if cve_id else "")
                    + f" in {repo_name}",
                    detail={
                        "number": number,
                        "repo": repo_name,
                        "cve_id": cve_id,
                        "summary": summary,
                        "severity": alert_severity,
                        "package_name": package_name,
                        "ecosystem": ecosystem,
                        "manifest_path": dependency.get("manifest_path", ""),
                        "ghsa_id": security_advisory.get("ghsa_id", ""),
                        "cvss_score": security_advisory.get("cvss", {}).get("score"),
                        "alert": alert,
                    },
                    resource_id=f"{repo_name}/dependabot/{number}",
                    resource_type="code_vulnerability",
                    resource_name=f"{package_name} ({repo_name})",
                    severity=alert_severity,
                )
            )

        return findings

    # -- Secret Scanning Alerts --

    def _normalize_secret_scanning_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        alerts = raw.raw_data.get("response", [])

        for alert in alerts:
            number = alert.get("number", "")
            repo = alert.get("repository", {})
            repo_name = repo.get("full_name", "")
            secret_type = alert.get("secret_type_display_name", alert.get("secret_type", ""))
            created_at = alert.get("created_at", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Secret leak: {secret_type} in {repo_name}",
                    detail={
                        "number": number,
                        "repo": repo_name,
                        "secret_type": secret_type,
                        "secret_type_raw": alert.get("secret_type", ""),
                        "state": alert.get("state", ""),
                        "created_at": created_at,
                        "html_url": alert.get("html_url", ""),
                        "alert": alert,
                    },
                    resource_id=f"{repo_name}/secret-scanning/{number}",
                    resource_type="code_secret_leak",
                    resource_name=f"{secret_type} ({repo_name})",
                    severity="critical",
                )
            )

        return findings


# Register
registry.register(GitHubNormalizer())
