"""Infracost normalizer — transforms raw Infracost Cloud API responses into Findings.

Normalizes projects and runs (as inventory), and policy violations (as
misconfiguration findings when cost thresholds are breached).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class InfracostNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Infracost Cloud."""

    HANDLERS: dict[str, str] = {
        "infracost_projects": "_normalize_projects",
        "infracost_runs": "_normalize_runs",
        "infracost_policies": "_normalize_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "infracost" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "infracost",
            "source_type": SourceType.OBSERVABILITY,
            "provider": "infracost",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_projects(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for project in items:
            project_id = str(project.get("id", ""))
            name = project.get("name", "unknown")
            monthly_cost = project.get("monthlyCost", 0.0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Infracost project: {name}",
                    detail={
                        "project_id": project_id,
                        "name": name,
                        "monthly_cost_usd": monthly_cost,
                        "currency": project.get("currency", "USD"),
                        "repo": project.get("repoUrl", ""),
                    },
                    resource_id=project_id,
                    resource_type="infracost_project",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_runs(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for run in items:
            run_id = str(run.get("id", ""))
            project_name = run.get("projectName", "unknown")
            status = run.get("status", "unknown")
            diff_monthly_cost = run.get("diffMonthlyCost", 0.0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Infracost run: {project_name} ({status})",
                    detail={
                        "run_id": run_id,
                        "project_name": project_name,
                        "status": status,
                        "diff_monthly_cost_usd": diff_monthly_cost,
                        "created_at": run.get("createdAt", ""),
                        "git_branch": run.get("gitBranch", ""),
                    },
                    resource_id=run_id,
                    resource_type="infracost_run",
                    resource_name=project_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for policy in items:
            policy_id = str(policy.get("id", ""))
            name = policy.get("name", "unknown")
            policy_type = policy.get("type", "")
            is_violated = policy.get("isViolated", False)
            threshold = policy.get("threshold", 0.0)

            obs_type = "misconfiguration" if is_violated else "inventory"
            severity = "medium" if is_violated else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Infracost policy {'violation' if is_violated else ''}: {name}".strip(),
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "type": policy_type,
                        "is_violated": is_violated,
                        "threshold": threshold,
                        "actual_value": policy.get("actualValue", 0.0),
                    },
                    resource_id=policy_id,
                    resource_type="infracost_policy",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(InfracostNormalizer())
