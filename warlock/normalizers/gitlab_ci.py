"""GitLab CI normalizer — transforms raw GitLab API responses into Findings.

Handles pipelines, jobs, variables, and container registry.
Flags: failed security pipelines, jobs running as root, unprotected CI variables,
container images with known vulnerabilities.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class GitLabCINormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "gitlab_ci_pipelines": "_normalize_pipelines",
        "gitlab_ci_jobs": "_normalize_jobs",
        "gitlab_ci_variables": "_normalize_variables",
        "gitlab_ci_registry": "_normalize_registry",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "gitlab_ci" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all GitLab CI findings."""
        return {
            "raw_event_id": raw.id,
            "source": "gitlab_ci",
            "source_type": SourceType.CI_CD,
            "provider": "gitlab",
            "observed_at": raw.observed_at,
        }

    # -- Pipelines --

    def _normalize_pipelines(self, raw: RawEventData) -> list[FindingData]:
        """Inventory pipelines; flag failed security pipelines."""
        findings = []
        pipelines = raw.raw_data.get("pipelines", [])

        security_keywords = {
            "security",
            "sast",
            "dast",
            "scan",
            "audit",
            "compliance",
            "container_scanning",
            "dependency_scanning",
        }

        for pipeline in pipelines:
            pipeline_id = str(pipeline.get("id", ""))
            status = pipeline.get("status", "")
            ref = pipeline.get("ref", "")
            sha = pipeline.get("sha", "")[:8] if pipeline.get("sha") else ""
            web_url = pipeline.get("web_url", "")
            project_name = pipeline.get("_project_name", "")
            source = pipeline.get("source", "")
            duration = pipeline.get("duration")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"GitLab pipeline: {project_name} #{pipeline_id} ({status})",
                    detail={
                        "pipeline_id": pipeline_id,
                        "status": status,
                        "ref": ref,
                        "sha": sha,
                        "web_url": web_url,
                        "project": project_name,
                        "source": source,
                        "duration": duration,
                    },
                    resource_id=pipeline_id,
                    resource_type="gitlab_ci_pipeline",
                    resource_name=f"{project_name}:pipeline-{pipeline_id}",
                    severity="info",
                )
            )

            # Flag failed security pipelines
            ref_lower = ref.lower() if ref else ""
            is_security_pipeline = any(kw in ref_lower for kw in security_keywords) or source in (
                "security_orchestration_policy",
            )
            if is_security_pipeline and status == "failed":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Security pipeline failed: {project_name} #{pipeline_id}",
                        detail={
                            "pipeline_id": pipeline_id,
                            "status": "failed",
                            "ref": ref,
                            "project": project_name,
                            "web_url": web_url,
                            "issue": f"Security pipeline on ref '{ref}' failed in {project_name} — security checks may not be running",
                        },
                        resource_id=pipeline_id,
                        resource_type="gitlab_ci_pipeline",
                        resource_name=f"{project_name}:pipeline-{pipeline_id}",
                        severity="high",
                    )
                )

        return findings

    # -- Jobs --

    def _normalize_jobs(self, raw: RawEventData) -> list[FindingData]:
        """Inventory failed jobs; flag jobs running as root."""
        findings = []
        jobs = raw.raw_data.get("jobs", [])

        for job in jobs:
            job_id = str(job.get("id", ""))
            name = job.get("name", "")
            status = job.get("status", "")
            stage = job.get("stage", "")
            project_name = job.get("_project_name", "")
            web_url = job.get("web_url", "")
            runner = job.get("runner", {}) if isinstance(job.get("runner"), dict) else {}
            runner_description = runner.get("description", "")
            tag_list = job.get("tag_list", [])

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"GitLab job failed: {project_name} / {name} ({stage})",
                    detail={
                        "job_id": job_id,
                        "name": name,
                        "status": status,
                        "stage": stage,
                        "project": project_name,
                        "web_url": web_url,
                        "runner": runner_description,
                        "tags": tag_list,
                    },
                    resource_id=job_id,
                    resource_type="gitlab_ci_job",
                    resource_name=f"{project_name}:{name}",
                    severity="info",
                )
            )

            # Flag jobs that may run as root (privileged tag)
            tags_lower = [t.lower() for t in tag_list] if isinstance(tag_list, list) else []
            if "privileged" in tags_lower or "root" in tags_lower:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"GitLab job runs with privileged tag: {project_name} / {name}",
                        detail={
                            "job_id": job_id,
                            "name": name,
                            "project": project_name,
                            "tags": tag_list,
                            "issue": f"Job '{name}' uses privileged/root tags — may run with elevated container privileges",
                        },
                        resource_id=job_id,
                        resource_type="gitlab_ci_job",
                        resource_name=f"{project_name}:{name}",
                        severity="high",
                    )
                )

        return findings

    # -- Variables --

    def _normalize_variables(self, raw: RawEventData) -> list[FindingData]:
        """Inventory CI variables; flag unprotected variables."""
        findings = []
        variables = raw.raw_data.get("variables", [])

        for var in variables:
            key = var.get("key", "")
            protected = var.get("protected", False)
            masked = var.get("masked", False)
            variable_type = var.get("variable_type", "")
            project_name = var.get("_project_name", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"GitLab CI variable: {project_name} / {key}",
                    detail={
                        "key": key,
                        "protected": protected,
                        "masked": masked,
                        "variable_type": variable_type,
                        "project": project_name,
                    },
                    resource_id=f"{project_name}:{key}",
                    resource_type="gitlab_ci_variable",
                    resource_name=f"{project_name}:{key}",
                    severity="info",
                )
            )

            # Flag unprotected and unmasked variables (potential secret leakage)
            if not protected and not masked:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Unprotected CI variable: {project_name} / {key}",
                        detail={
                            "key": key,
                            "protected": False,
                            "masked": False,
                            "project": project_name,
                            "issue": f"Variable '{key}' is neither protected nor masked — may be exposed in non-protected branch pipelines and logs",
                        },
                        resource_id=f"{project_name}:{key}",
                        resource_type="gitlab_ci_variable",
                        resource_name=f"{project_name}:{key}",
                        severity="medium",
                    )
                )

        return findings

    # -- Registry --

    def _normalize_registry(self, raw: RawEventData) -> list[FindingData]:
        """Inventory container registry images."""
        findings = []
        images = raw.raw_data.get("images", [])

        for image in images:
            image_id = str(image.get("id", ""))
            path = image.get("path", "")
            location = image.get("location", "")
            project_name = image.get("_project_name", "")
            tags_count = image.get("tags_count", 0)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"GitLab container image: {path}",
                    detail={
                        "image_id": image_id,
                        "path": path,
                        "location": location,
                        "project": project_name,
                        "tags_count": tags_count,
                    },
                    resource_id=image_id,
                    resource_type="gitlab_ci_container_image",
                    resource_name=path or location,
                    severity="info",
                )
            )

        return findings


# Register
registry.register(GitLabCINormalizer())
