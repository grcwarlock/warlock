"""Jira normalizer — transforms raw Jira API responses into Findings.

Handles security bugs, SLA status, and change requests.
Flags: overdue security bugs, SLA breaches, unapproved changes.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class JiraNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "jira_security_bugs": "_normalize_security_bugs",
        "jira_sla_status": "_normalize_sla_status",
        "jira_change_requests": "_normalize_change_requests",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "jira" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Jira findings."""
        return {
            "raw_event_id": raw.id,
            "source": "jira",
            "source_type": SourceType.ITSM,
            "provider": "jira",
            "observed_at": raw.observed_at,
        }

    # -- Security Bugs --

    def _normalize_security_bugs(self, raw: RawEventData) -> list[FindingData]:
        """Inventory security bugs; flag critical/high priority unresolved ones."""
        findings = []
        issues = raw.raw_data.get("issues", [])

        for issue in issues:
            issue_key = issue.get("key", "")
            fields = issue.get("fields", {}) if isinstance(issue.get("fields"), dict) else {}
            summary = fields.get("summary", "")
            status_obj = fields.get("status", {}) if isinstance(fields.get("status"), dict) else {}
            status = status_obj.get("name", "")
            priority_obj = fields.get("priority", {}) if isinstance(fields.get("priority"), dict) else {}
            priority = priority_obj.get("name", "")
            assignee_obj = fields.get("assignee", {}) if isinstance(fields.get("assignee"), dict) else {}
            assignee = assignee_obj.get("displayName", "Unassigned") if assignee_obj else "Unassigned"
            created = fields.get("created", "")
            updated = fields.get("updated", "")
            duedate = fields.get("duedate", "")
            resolution = fields.get("resolution")

            # Map Jira priority to warlock severity
            priority_sev = {
                "Highest": "critical",
                "High": "high",
                "Medium": "medium",
                "Low": "low",
                "Lowest": "info",
            }
            severity = priority_sev.get(priority, "medium")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Security bug: {issue_key} — {summary}",
                    detail={
                        "issue_key": issue_key,
                        "summary": summary,
                        "status": status,
                        "priority": priority,
                        "assignee": assignee,
                        "created": created,
                        "updated": updated,
                        "duedate": duedate,
                        "resolved": resolution is not None,
                    },
                    resource_id=issue_key,
                    resource_type="jira_issue",
                    resource_name=f"{issue_key}: {summary}",
                    severity="info",
                )
            )

            # Flag unresolved critical/high security bugs
            if resolution is None and severity in ("critical", "high"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Unresolved {priority} security bug: {issue_key}",
                        detail={
                            "issue_key": issue_key,
                            "summary": summary,
                            "status": status,
                            "priority": priority,
                            "assignee": assignee,
                            "created": created,
                            "issue": f"{priority} priority security bug remains unresolved — {summary}",
                        },
                        resource_id=issue_key,
                        resource_type="jira_issue",
                        resource_name=f"{issue_key}: {summary}",
                        severity=severity,
                    )
                )

        return findings

    # -- SLA Status --

    def _normalize_sla_status(self, raw: RawEventData) -> list[FindingData]:
        """Flag overdue security bugs as SLA breaches."""
        findings = []
        overdue_issues = raw.raw_data.get("overdue_issues", [])

        for issue in overdue_issues:
            issue_key = issue.get("key", "")
            fields = issue.get("fields", {}) if isinstance(issue.get("fields"), dict) else {}
            summary = fields.get("summary", "")
            priority_obj = fields.get("priority", {}) if isinstance(fields.get("priority"), dict) else {}
            priority = priority_obj.get("name", "")
            assignee_obj = fields.get("assignee", {}) if isinstance(fields.get("assignee"), dict) else {}
            assignee = assignee_obj.get("displayName", "Unassigned") if assignee_obj else "Unassigned"
            duedate = fields.get("duedate", "")
            created = fields.get("created", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="policy_violation",
                    title=f"SLA breach — overdue security bug: {issue_key}",
                    detail={
                        "issue_key": issue_key,
                        "summary": summary,
                        "priority": priority,
                        "assignee": assignee,
                        "duedate": duedate,
                        "created": created,
                        "issue": f"Security bug {issue_key} is past its due date ({duedate}) — SLA breach",
                    },
                    resource_id=issue_key,
                    resource_type="jira_issue",
                    resource_name=f"{issue_key}: {summary}",
                    severity="high",
                )
            )

        return findings

    # -- Change Requests --

    def _normalize_change_requests(self, raw: RawEventData) -> list[FindingData]:
        """Inventory change requests; flag unapproved ones."""
        findings = []
        issues = raw.raw_data.get("issues", [])

        for issue in issues:
            issue_key = issue.get("key", "")
            fields = issue.get("fields", {}) if isinstance(issue.get("fields"), dict) else {}
            summary = fields.get("summary", "")
            status_obj = fields.get("status", {}) if isinstance(fields.get("status"), dict) else {}
            status = status_obj.get("name", "")
            assignee_obj = fields.get("assignee", {}) if isinstance(fields.get("assignee"), dict) else {}
            assignee = assignee_obj.get("displayName", "Unassigned") if assignee_obj else "Unassigned"
            created = fields.get("created", "")
            updated = fields.get("updated", "")
            resolution = fields.get("resolution")
            labels = fields.get("labels", [])

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Change request: {issue_key} — {summary}",
                    detail={
                        "issue_key": issue_key,
                        "summary": summary,
                        "status": status,
                        "assignee": assignee,
                        "created": created,
                        "updated": updated,
                        "resolved": resolution is not None,
                        "labels": labels,
                    },
                    resource_id=issue_key,
                    resource_type="jira_change_request",
                    resource_name=f"{issue_key}: {summary}",
                    severity="info",
                )
            )

            # Flag changes that bypassed approval (status moved to Done without Approved step)
            unapproved_statuses = ("Done", "Closed", "Resolved", "Deployed")
            approved_labels = ("approved", "change-approved", "cab-approved")
            has_approval = any(lbl.lower() in approved_labels for lbl in labels)

            if status in unapproved_statuses and not has_approval and resolution is not None:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Unapproved change request: {issue_key}",
                        detail={
                            "issue_key": issue_key,
                            "summary": summary,
                            "status": status,
                            "labels": labels,
                            "issue": f"Change request {issue_key} was resolved without approval label — may have bypassed change management process",
                        },
                        resource_id=issue_key,
                        resource_type="jira_change_request",
                        resource_name=f"{issue_key}: {summary}",
                        severity="high",
                    )
                )

        return findings


# Register
registry.register(JiraNormalizer())
