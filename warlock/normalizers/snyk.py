"""Snyk normalizer — transforms raw Snyk API responses into Findings.

Normalizes projects (stale scan detection), vulnerability issues (CVE, CVSS,
fix availability), and audit log events.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SnykNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "snyk_projects": "_normalize_projects",
        "snyk_issues": "_normalize_issues",
        "snyk_audit_logs": "_normalize_audit_logs",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "snyk" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Snyk findings."""
        return {
            "raw_event_id": raw.id,
            "source": "snyk",
            "source_type": SourceType.CODE,
            "provider": "snyk",
            "account_id": raw.raw_data.get("org_id", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Projects --

    def _normalize_projects(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        projects = raw.raw_data.get("response", [])
        now = datetime.now(timezone.utc)
        stale_threshold = now - timedelta(days=7)

        for project in projects:
            attrs = project.get("attributes", project)
            project_id = project.get("id", attrs.get("id", ""))
            name = attrs.get("name", "unknown")
            project_type = attrs.get("type", "")
            last_tested_str = attrs.get("last_tested_date", attrs.get("lastTestedDate", ""))

            issues = []
            severity = "info"
            obs_type = "inventory"

            if last_tested_str:
                try:
                    last_tested = datetime.fromisoformat(
                        last_tested_str.replace("Z", "+00:00")
                    )
                    if last_tested < stale_threshold:
                        issues.append("not_tested_in_7_days")
                        severity = "medium"
                        obs_type = "misconfiguration"
                except (ValueError, TypeError):
                    pass
            elif last_tested_str == "" or last_tested_str is None:
                # Never tested
                issues.append("never_tested")
                severity = "medium"
                obs_type = "misconfiguration"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"Snyk project: {name}"
                      + (f" -- {', '.join(issues)}" if issues else ""),
                detail={
                    "project_id": project_id,
                    "name": name,
                    "type": project_type,
                    "last_tested_date": last_tested_str,
                    "origin": attrs.get("origin", ""),
                    "status": attrs.get("status", ""),
                    "issues": issues,
                    "project": project,
                },
                resource_id=project_id,
                resource_type="code_project",
                resource_name=name,
                severity=severity,
            ))

        return findings

    # -- Issues (Vulnerabilities) --

    def _normalize_issues(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        issues = raw.raw_data.get("response", [])

        for issue in issues:
            attrs = issue.get("attributes", issue)
            issue_id = issue.get("id", attrs.get("id", ""))
            title = attrs.get("title", "unknown")

            # Severity mapping from Snyk
            snyk_severity = (
                attrs.get("effective_severity_level")
                or attrs.get("severity", "medium")
            ).lower()
            if snyk_severity not in ("critical", "high", "medium", "low"):
                snyk_severity = "medium"

            # Extract CVE / CVSS / package info
            problems = attrs.get("problems", [])
            cves = []
            for problem in problems:
                if problem.get("source", "") == "CVE" or problem.get("id", "").startswith("CVE-"):
                    cves.append(problem.get("id", ""))

            cvss_score = attrs.get("cvss_score") or attrs.get("cvssScore")
            package_name = (
                attrs.get("package_name")
                or attrs.get("pkgName")
                or attrs.get("package", "")
            )
            package_version = (
                attrs.get("package_version")
                or attrs.get("version", "")
            )

            # Fix availability
            is_fixable = attrs.get("is_fixable", attrs.get("isFixable", False))
            fix_versions = attrs.get("fix_versions", attrs.get("fixedIn", []))

            # Coordinates for resource identification
            coordinates = attrs.get("coordinates", [])
            project_name = ""
            if coordinates:
                first = coordinates[0] if isinstance(coordinates, list) else coordinates
                project_name = first.get("project_name", "") if isinstance(first, dict) else ""

            findings.append(FindingData(
                **self._base(raw),
                observation_type="vulnerability",
                title=f"Snyk: {title}" + (f" ({', '.join(cves)})" if cves else ""),
                detail={
                    "issue_id": issue_id,
                    "title": title,
                    "severity": snyk_severity,
                    "cves": cves,
                    "cvss_score": cvss_score,
                    "package_name": package_name,
                    "package_version": package_version,
                    "is_fixable": is_fixable,
                    "fix_versions": fix_versions,
                    "exploit_maturity": attrs.get("exploit_maturity", ""),
                    "language": attrs.get("language", ""),
                    "project_name": project_name,
                    "issue": issue,
                },
                resource_id=issue_id,
                resource_type="code_vulnerability",
                resource_name=f"{package_name}@{package_version}" if package_name else title,
                severity=snyk_severity,
            ))

        return findings

    # -- Audit Logs --

    def _normalize_audit_logs(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        events = raw.raw_data.get("response", [])

        # Events that indicate policy/security changes worth alerting on
        ALERT_EVENTS = {
            "org.policy.edit",
            "org.policy.delete",
            "org.user.role.edit",
            "org.user.invite.create",
            "org.user.remove",
            "org.project.ignore.create",
            "org.project.delete",
            "org.service_account.create",
            "org.service_account.delete",
            "org.integration.edit",
            "org.integration.delete",
        }

        for event in events:
            event_type = event.get("event", event.get("action", "unknown"))
            user_id = event.get("userId", event.get("user_id", ""))
            user_name = event.get("userEmail", event.get("user_email", user_id))
            created = event.get("created", event.get("created_at", ""))

            is_alert = event_type in ALERT_EVENTS
            obs_type = "alert" if is_alert else "inventory"
            severity = "medium" if is_alert else "info"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"Snyk audit: {event_type}" + (f" by {user_name}" if user_name else ""),
                detail={
                    "event_type": event_type,
                    "user_id": user_id,
                    "user_name": user_name,
                    "created": created,
                    "event": event,
                },
                resource_id=event.get("id", event.get("event_id", "")),
                resource_type="code_audit_event",
                resource_name=event_type,
                severity=severity,
            ))

        return findings


# Register
registry.register(SnykNormalizer())
