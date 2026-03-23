"""GitLab CI connector — Layer 1 implementation for CI/CD Pipeline Security.

Collects pipelines (status, duration), jobs (failed/passed),
variables (group/project level — names only), and container registry images
via the GitLab REST API v4.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


class GitLabCIConnector(BaseConnector):
    """Collects compliance telemetry from GitLab REST API v4."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[gitlab_ci]")
        if not self.get_secret("WLK_GITLAB_TOKEN"):
            errors.append("WLK_GITLAB_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self._base_url()}/version")
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="gitlab_ci",
            source_type=SourceType.CI_CD,
            provider="gitlab",
        )

        client = self._client()
        base = self._base_url()

        self._collect_pipelines(client, base, result)
        self._collect_jobs(client, base, result)
        self._collect_variables(client, base, result)
        self._collect_registry(client, base, result)

        result.complete()
        return result

    # -- Helpers --

    def _base_url(self) -> str:
        url = self.get_secret("WLK_GITLAB_URL")
        if url:
            return url.rstrip("/") + "/api/v4"
        return "https://gitlab.com/api/v4"

    def _client(self) -> httpx.Client:
        token = self.get_secret("WLK_GITLAB_TOKEN")
        return httpx.Client(
            headers={"PRIVATE-TOKEN": token},
            timeout=self.config.timeout_seconds,
        )

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="gitlab_ci",
            source_type=SourceType.CI_CD,
            provider="gitlab",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_pipelines(self, client: httpx.Client, base: str, result: ConnectorResult) -> None:
        """Collect recent pipelines across accessible projects."""
        try:
            projects_resp = client.get(
                f"{base}/projects", params={"membership": "true", "per_page": "50"}
            )
            projects_resp.raise_for_status()
            projects = projects_resp.json()

            all_pipelines = []
            for project in projects[:50]:
                project_id = project.get("id", "")
                project_name = project.get("path_with_namespace", "")
                try:
                    resp = client.get(
                        f"{base}/projects/{project_id}/pipelines",
                        params={"per_page": "25"},
                    )
                    resp.raise_for_status()
                    pipelines = resp.json()
                    for p in pipelines:
                        p["_project_name"] = project_name
                    all_pipelines.extend(pipelines)
                except Exception:
                    log.debug("Failed to fetch pipelines for project %s", project_id)

            result.events.append(
                self._raw_event("gitlab_ci_pipelines", {"pipelines": all_pipelines})
            )
        except Exception as e:
            log.debug("GitLab CI pipelines collection failed: %s", e)
            result.errors.append(f"gitlab_ci_pipelines: {e}")

    def _collect_jobs(self, client: httpx.Client, base: str, result: ConnectorResult) -> None:
        """Collect recent failed jobs across accessible projects."""
        try:
            projects_resp = client.get(
                f"{base}/projects", params={"membership": "true", "per_page": "50"}
            )
            projects_resp.raise_for_status()
            projects = projects_resp.json()

            all_jobs = []
            for project in projects[:50]:
                project_id = project.get("id", "")
                project_name = project.get("path_with_namespace", "")
                try:
                    resp = client.get(
                        f"{base}/projects/{project_id}/jobs",
                        params={"per_page": "25", "scope[]": "failed"},
                    )
                    resp.raise_for_status()
                    jobs = resp.json()
                    for j in jobs:
                        j["_project_name"] = project_name
                    all_jobs.extend(jobs)
                except Exception:
                    log.debug("Failed to fetch jobs for project %s", project_id)

            result.events.append(self._raw_event("gitlab_ci_jobs", {"jobs": all_jobs}))
        except Exception as e:
            log.debug("GitLab CI jobs collection failed: %s", e)
            result.errors.append(f"gitlab_ci_jobs: {e}")

    def _collect_variables(self, client: httpx.Client, base: str, result: ConnectorResult) -> None:
        """Collect CI/CD variables metadata (names only, not values)."""
        try:
            projects_resp = client.get(
                f"{base}/projects", params={"membership": "true", "per_page": "50"}
            )
            projects_resp.raise_for_status()
            projects = projects_resp.json()

            all_variables = []
            for project in projects[:50]:
                project_id = project.get("id", "")
                project_name = project.get("path_with_namespace", "")
                try:
                    resp = client.get(f"{base}/projects/{project_id}/variables")
                    resp.raise_for_status()
                    variables = resp.json()
                    for v in variables:
                        v["_project_name"] = project_name
                        # Strip actual values for security
                        v.pop("value", None)
                    all_variables.extend(variables)
                except Exception:
                    log.debug("Failed to fetch variables for project %s", project_id)

            result.events.append(
                self._raw_event("gitlab_ci_variables", {"variables": all_variables})
            )
        except Exception as e:
            log.debug("GitLab CI variables collection failed: %s", e)
            result.errors.append(f"gitlab_ci_variables: {e}")

    def _collect_registry(self, client: httpx.Client, base: str, result: ConnectorResult) -> None:
        """Collect container registry repositories and tags."""
        try:
            projects_resp = client.get(
                f"{base}/projects", params={"membership": "true", "per_page": "50"}
            )
            projects_resp.raise_for_status()
            projects = projects_resp.json()

            all_images = []
            for project in projects[:50]:
                project_id = project.get("id", "")
                project_name = project.get("path_with_namespace", "")
                try:
                    resp = client.get(f"{base}/projects/{project_id}/registry/repositories")
                    resp.raise_for_status()
                    repos = resp.json()
                    for repo in repos:
                        repo["_project_name"] = project_name
                    all_images.extend(repos)
                except Exception:
                    log.debug("Failed to fetch registry for project %s", project_id)

            result.events.append(self._raw_event("gitlab_ci_registry", {"images": all_images}))
        except Exception as e:
            log.debug("GitLab CI registry collection failed: %s", e)
            result.errors.append(f"gitlab_ci_registry: {e}")


# Register
registry.register("gitlab_ci", GitLabCIConnector)
