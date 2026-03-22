"""CircleCI normalizer — transforms raw CircleCI API responses into Findings.

Handles pipelines, workflows, projects, and contexts.
Flags: failed security workflows, pipelines triggered by unknown users,
projects without branch protection, contexts with stale variables.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class CircleCINormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "circleci_pipelines": "_normalize_pipelines",
        "circleci_workflows": "_normalize_workflows",
        "circleci_projects": "_normalize_projects",
        "circleci_contexts": "_normalize_contexts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "circleci" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all CircleCI findings."""
        return {
            "raw_event_id": raw.id,
            "source": "circleci",
            "source_type": SourceType.CI_CD,
            "provider": "circleci",
            "observed_at": raw.observed_at,
        }

    # -- Pipelines --

    def _normalize_pipelines(self, raw: RawEventData) -> list[FindingData]:
        """Inventory pipelines; flag pipelines triggered by unknown users."""
        findings = []
        pipelines = raw.raw_data.get("pipelines", [])

        for pipeline in pipelines:
            pipeline_id = pipeline.get("id", "")
            state = pipeline.get("state", "")
            project_slug = pipeline.get("project_slug", "")
            created_at = pipeline.get("created_at", "")
            trigger = pipeline.get("trigger", {}) if isinstance(pipeline.get("trigger"), dict) else {}
            trigger_type = trigger.get("type", "")
            actor = trigger.get("actor", {}) if isinstance(trigger.get("actor"), dict) else {}
            actor_login = actor.get("login", "")
            vcs = pipeline.get("vcs", {}) if isinstance(pipeline.get("vcs"), dict) else {}
            branch = vcs.get("branch", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"CircleCI pipeline: {project_slug} ({state})",
                    detail={
                        "pipeline_id": pipeline_id,
                        "state": state,
                        "project_slug": project_slug,
                        "created_at": created_at,
                        "trigger_type": trigger_type,
                        "actor_login": actor_login,
                        "branch": branch,
                    },
                    resource_id=pipeline_id,
                    resource_type="circleci_pipeline",
                    resource_name=f"{project_slug}:pipeline-{pipeline_id[:8]}",
                    severity="info",
                )
            )

            # Flag pipelines triggered by unknown/empty actors
            if not actor_login and trigger_type not in ("scheduled_pipeline", "schedule"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Pipeline triggered by unknown actor: {project_slug}",
                        detail={
                            "pipeline_id": pipeline_id,
                            "project_slug": project_slug,
                            "trigger_type": trigger_type,
                            "actor_login": "",
                            "issue": f"Pipeline in {project_slug} was triggered without an identified actor — potential unauthorized trigger",
                        },
                        resource_id=pipeline_id,
                        resource_type="circleci_pipeline",
                        resource_name=f"{project_slug}:pipeline-{pipeline_id[:8]}",
                        severity="medium",
                    )
                )

        return findings

    # -- Workflows --

    def _normalize_workflows(self, raw: RawEventData) -> list[FindingData]:
        """Inventory workflows; flag failed security workflows."""
        findings = []
        workflows = raw.raw_data.get("workflows", [])

        security_keywords = {"security", "sast", "dast", "scan", "audit", "compliance", "vuln"}

        for wf in workflows:
            wf_id = wf.get("id", "")
            name = wf.get("name", "")
            status = wf.get("status", "")
            created_at = wf.get("created_at", "")
            stopped_at = wf.get("stopped_at", "")
            pipeline_id = wf.get("_pipeline_id", wf.get("pipeline_id", ""))
            project_slug = wf.get("_project_slug", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"CircleCI workflow: {name} ({status})",
                    detail={
                        "workflow_id": wf_id,
                        "name": name,
                        "status": status,
                        "created_at": created_at,
                        "stopped_at": stopped_at,
                        "pipeline_id": pipeline_id,
                        "project_slug": project_slug,
                    },
                    resource_id=wf_id,
                    resource_type="circleci_workflow",
                    resource_name=f"{project_slug}:{name}",
                    severity="info",
                )
            )

            # Flag failed security workflows
            name_lower = name.lower()
            is_security_wf = any(kw in name_lower for kw in security_keywords)
            if is_security_wf and status == "failed":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Security workflow failed: {name} in {project_slug}",
                        detail={
                            "workflow_id": wf_id,
                            "name": name,
                            "status": "failed",
                            "project_slug": project_slug,
                            "issue": f"Security workflow '{name}' failed — security checks may not be running",
                        },
                        resource_id=wf_id,
                        resource_type="circleci_workflow",
                        resource_name=f"{project_slug}:{name}",
                        severity="high",
                    )
                )

        return findings

    # -- Projects --

    def _normalize_projects(self, raw: RawEventData) -> list[FindingData]:
        """Inventory projects; flag projects without branch protection settings."""
        findings = []
        projects = raw.raw_data.get("projects", [])

        for project in projects:
            slug = project.get("slug", project.get("project_slug", ""))
            name = project.get("name", slug)
            vcs_info = project.get("vcs_info", {}) if isinstance(project.get("vcs_info"), dict) else {}
            vcs_url = vcs_info.get("vcs_url", project.get("vcs_url", ""))
            default_branch = vcs_info.get("default_branch", project.get("default_branch", ""))

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"CircleCI project: {name}",
                    detail={
                        "slug": slug,
                        "name": name,
                        "vcs_url": vcs_url,
                        "default_branch": default_branch,
                    },
                    resource_id=slug,
                    resource_type="circleci_project",
                    resource_name=name,
                    severity="info",
                )
            )

        return findings

    # -- Contexts --

    def _normalize_contexts(self, raw: RawEventData) -> list[FindingData]:
        """Inventory contexts; flag contexts with stale variables."""
        findings = []
        contexts = raw.raw_data.get("contexts", [])

        now = datetime.now(timezone.utc)

        for ctx in contexts:
            ctx_id = ctx.get("id", "")
            ctx_name = ctx.get("name", "")
            created_at = ctx.get("created_at", "")
            variables = ctx.get("_variables", [])

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"CircleCI context: {ctx_name} ({len(variables)} variables)",
                    detail={
                        "context_id": ctx_id,
                        "name": ctx_name,
                        "created_at": created_at,
                        "variable_count": len(variables),
                        "variable_names": [v.get("variable", "") for v in variables],
                    },
                    resource_id=ctx_id,
                    resource_type="circleci_context",
                    resource_name=ctx_name,
                    severity="info",
                )
            )

            # Flag contexts with stale variables (not updated in 90+ days)
            for var in variables:
                var_name = var.get("variable", "")
                var_created = var.get("created_at", "")
                if var_created:
                    try:
                        created = datetime.fromisoformat(var_created.replace("Z", "+00:00"))
                        days_since = (now - created).days
                        if days_since > 90:
                            findings.append(
                                FindingData(
                                    **self._base(raw),
                                    observation_type="policy_violation",
                                    title=f"Stale context variable: {ctx_name}/{var_name} ({days_since} days)",
                                    detail={
                                        "context_id": ctx_id,
                                        "context_name": ctx_name,
                                        "variable": var_name,
                                        "created_at": var_created,
                                        "days_since_creation": days_since,
                                        "issue": f"Variable '{var_name}' in context '{ctx_name}' was created {days_since} days ago and may not have been rotated",
                                    },
                                    resource_id=f"{ctx_id}:{var_name}",
                                    resource_type="circleci_context_variable",
                                    resource_name=f"{ctx_name}:{var_name}",
                                    severity="medium",
                                )
                            )
                    except (ValueError, TypeError):
                        pass

        return findings


# Register
registry.register(CircleCINormalizer())
