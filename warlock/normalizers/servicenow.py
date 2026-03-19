"""ServiceNow normalizer — transforms raw ServiceNow Table API responses into Findings.

Normalizes change requests, incidents, problems, knowledge articles, risks,
and GRC policies with compliance-oriented observation types and severity levels.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ServiceNowNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "snow_change_requests": "_normalize_change_requests",
        "snow_incidents": "_normalize_incidents",
        "snow_problems": "_normalize_problems",
        "snow_knowledge_articles": "_normalize_knowledge_articles",
        "snow_risks": "_normalize_risks",
        "snow_policies": "_normalize_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "servicenow" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all ServiceNow findings."""
        return {
            "raw_event_id": raw.id,
            "source": "servicenow",
            "source_type": SourceType.ITSM,
            "provider": "servicenow",
            "account_id": raw.raw_data.get("instance", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Change Requests --

    def _normalize_change_requests(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        changes = raw.raw_data.get("response", [])

        for change in changes:
            sys_id = change.get("sys_id", "")
            number = change.get("number", "")
            approval = change.get("approval", "")
            change_type = change.get("type", "")
            backout_plan = change.get("backout_plan", "")
            short_desc = change.get("short_description", "")

            issues = []
            obs_type = "inventory"
            severity = "info"

            if approval != "approved":
                issues.append("unapproved_change")
                obs_type = "policy_violation"
                severity = "high"

            if change_type == "emergency" and approval != "approved":
                issues.append("emergency_without_post_approval")
                obs_type = "policy_violation"
                severity = "medium" if severity == "info" else severity

            if not backout_plan or not backout_plan.strip():
                issues.append("no_rollback_plan")
                if obs_type == "inventory":
                    obs_type = "misconfiguration"
                    severity = "medium"

            title = f"Change request {number}: {short_desc}"
            if issues:
                title += f" — {', '.join(issues)}"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=title,
                detail={
                    "sys_id": sys_id,
                    "number": number,
                    "approval": approval,
                    "type": change_type,
                    "backout_plan_present": bool(backout_plan and backout_plan.strip()),
                    "short_description": short_desc,
                    "issues": issues,
                    "record": change,
                },
                resource_id=sys_id,
                resource_type="itsm_change_request",
                resource_name=number,
                severity=severity,
            ))

        return findings

    # -- Incidents --

    def _normalize_incidents(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        incidents = raw.raw_data.get("response", [])
        priority_severity_map = {"1": "critical", "2": "high", "3": "medium"}

        for incident in incidents:
            sys_id = incident.get("sys_id", "")
            number = incident.get("number", "")
            state = incident.get("state", "")
            priority = incident.get("priority", "")
            short_desc = incident.get("short_description", "")
            sla_due = incident.get("sla_due", "")

            obs_type = "inventory"
            severity = "info"
            issues = []

            # Resolved incidents → inventory
            resolved_states = {"6", "7", "8"}  # resolved, closed, canceled
            is_resolved = str(state) in resolved_states

            if not is_resolved:
                # Check if past SLA
                is_past_sla = False
                if sla_due:
                    try:
                        due_dt = datetime.fromisoformat(
                            sla_due.replace("Z", "+00:00")
                        )
                        if datetime.now(timezone.utc) > due_dt:
                            is_past_sla = True
                    except (ValueError, TypeError):
                        pass

                if is_past_sla:
                    obs_type = "alert"
                    severity = priority_severity_map.get(str(priority), "medium")
                    issues.append("past_sla")

            title = f"Incident {number}: {short_desc}"
            if issues:
                title += f" — {', '.join(issues)}"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=title,
                detail={
                    "sys_id": sys_id,
                    "number": number,
                    "state": state,
                    "priority": priority,
                    "sla_due": sla_due,
                    "short_description": short_desc,
                    "issues": issues,
                    "record": incident,
                },
                resource_id=sys_id,
                resource_type="itsm_incident",
                resource_name=number,
                severity=severity,
            ))

        return findings

    # -- Problems --

    def _normalize_problems(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        problems = raw.raw_data.get("response", [])

        for problem in problems:
            sys_id = problem.get("sys_id", "")
            number = problem.get("number", "")
            state = problem.get("state", "")
            cause_notes = problem.get("cause_notes", "")
            short_desc = problem.get("short_description", "")

            obs_type = "inventory"
            severity = "info"
            issues = []

            # Open problems without root cause
            closed_states = {"4", "7"}  # resolved, closed
            is_open = str(state) not in closed_states

            if is_open and (not cause_notes or not cause_notes.strip()):
                obs_type = "misconfiguration"
                severity = "medium"
                issues.append("no_root_cause")

            title = f"Problem {number}: {short_desc}"
            if issues:
                title += f" — {', '.join(issues)}"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=title,
                detail={
                    "sys_id": sys_id,
                    "number": number,
                    "state": state,
                    "cause_notes_present": bool(cause_notes and cause_notes.strip()),
                    "short_description": short_desc,
                    "issues": issues,
                    "record": problem,
                },
                resource_id=sys_id,
                resource_type="itsm_problem",
                resource_name=number,
                severity=severity,
            ))

        return findings

    # -- Knowledge Articles --

    def _normalize_knowledge_articles(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        articles = raw.raw_data.get("response", [])
        stale_threshold = datetime.now(timezone.utc) - timedelta(days=365)

        for article in articles:
            sys_id = article.get("sys_id", "")
            number = article.get("number", "")
            title_text = article.get("short_description", "") or article.get("title", "")
            sys_updated_on = article.get("sys_updated_on", "")

            obs_type = "inventory"
            severity = "info"
            issues = []

            if sys_updated_on:
                try:
                    updated_dt = datetime.fromisoformat(
                        sys_updated_on.replace("Z", "+00:00")
                    )
                    if updated_dt < stale_threshold:
                        obs_type = "misconfiguration"
                        severity = "low"
                        issues.append("not_reviewed_365_days")
                except (ValueError, TypeError):
                    pass

            title = f"Knowledge article {number}: {title_text}"
            if issues:
                title += f" — {', '.join(issues)}"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=title,
                detail={
                    "sys_id": sys_id,
                    "number": number,
                    "title": title_text,
                    "sys_updated_on": sys_updated_on,
                    "issues": issues,
                    "record": article,
                },
                resource_id=sys_id,
                resource_type="itsm_knowledge_article",
                resource_name=number,
                severity=severity,
            ))

        return findings

    # -- Risks --

    def _normalize_risks(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        risks = raw.raw_data.get("response", [])

        for risk in risks:
            sys_id = risk.get("sys_id", "")
            number = risk.get("number", "")
            title_text = risk.get("short_description", "") or risk.get("title", "")
            acceptance_owner = risk.get("acceptance_owner", "")
            expiry = risk.get("expiry", "") or risk.get("acceptance_expiry", "")

            obs_type = "inventory"
            severity = "info"
            issues = []

            if not acceptance_owner or not acceptance_owner.strip():
                issues.append("no_acceptance_owner")
            if not expiry or not expiry.strip():
                issues.append("no_expiry")

            if issues:
                obs_type = "misconfiguration"
                severity = "medium"

            title = f"Risk {number}: {title_text}"
            if issues:
                title += f" — {', '.join(issues)}"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=title,
                detail={
                    "sys_id": sys_id,
                    "number": number,
                    "title": title_text,
                    "acceptance_owner": acceptance_owner,
                    "expiry": expiry,
                    "issues": issues,
                    "record": risk,
                },
                resource_id=sys_id,
                resource_type="itsm_risk",
                resource_name=number,
                severity=severity,
            ))

        return findings

    # -- GRC Policies --

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        policies = raw.raw_data.get("response", [])
        now = datetime.now(timezone.utc)

        for policy in policies:
            sys_id = policy.get("sys_id", "")
            number = policy.get("number", "")
            title_text = policy.get("short_description", "") or policy.get("name", "")
            review_date = policy.get("review_date", "") or policy.get("next_review_date", "")

            obs_type = "inventory"
            severity = "info"
            issues = []

            if review_date:
                try:
                    review_dt = datetime.fromisoformat(
                        review_date.replace("Z", "+00:00")
                    )
                    if review_dt < now:
                        obs_type = "policy_violation"
                        severity = "medium"
                        issues.append("expired_review_date")
                except (ValueError, TypeError):
                    pass

            title = f"GRC policy {number}: {title_text}"
            if issues:
                title += f" — {', '.join(issues)}"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=title,
                detail={
                    "sys_id": sys_id,
                    "number": number,
                    "title": title_text,
                    "review_date": review_date,
                    "issues": issues,
                    "record": policy,
                },
                resource_id=sys_id,
                resource_type="itsm_policy",
                resource_name=number,
                severity=severity,
            ))

        return findings


# Register
registry.register(ServiceNowNormalizer())
