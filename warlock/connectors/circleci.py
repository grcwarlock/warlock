"""CircleCI connector — Layer 1 implementation for CI/CD Pipeline Security.

Collects pipelines (status, trigger), workflows (status, duration),
projects (settings), and contexts (environment variable stores)
via the CircleCI API v2.
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

_API_BASE = "https://circleci.com/api/v2"


class CircleCIConnector(BaseConnector):
    """Collects compliance telemetry from CircleCI API v2."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[circleci]")
        if not self.get_secret("WLK_CIRCLECI_TOKEN"):
            errors.append("WLK_CIRCLECI_TOKEN not set")
        if not self.get_secret("WLK_CIRCLECI_ORG"):
            errors.append("WLK_CIRCLECI_ORG not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{_API_BASE}/me")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="circleci",
            source_type=SourceType.CI_CD,
            provider="circleci",
        )

        client = self._client()
        org = self.get_secret("WLK_CIRCLECI_ORG")

        self._collect_pipelines(client, org, result)
        self._collect_workflows(client, org, result)
        self._collect_projects(client, org, result)
        self._collect_contexts(client, org, result)

        result.complete()
        return result

    # -- Helpers --

    def _client(self) -> httpx.Client:
        token = self.get_secret("WLK_CIRCLECI_TOKEN")
        return httpx.Client(
            headers={"Circle-Token": token},
            timeout=self.config.timeout_seconds,
        )

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="circleci",
            source_type=SourceType.CI_CD,
            provider="circleci",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_pipelines(self, client: httpx.Client, org: str, result: ConnectorResult) -> None:
        """Collect recent pipelines for the org."""
        try:
            resp = client.get(f"{_API_BASE}/pipeline", params={"org-slug": org})
            resp.raise_for_status()
            pipelines = resp.json().get("items", [])
            result.events.append(self._raw_event("circleci_pipelines", {"pipelines": pipelines}))
        except Exception as e:
            log.debug("CircleCI pipelines collection failed: %s", e)
            result.errors.append(f"circleci_pipelines: {e}")

    def _collect_workflows(self, client: httpx.Client, org: str, result: ConnectorResult) -> None:
        """Collect workflows from recent pipelines."""
        try:
            # First get recent pipelines
            resp = client.get(f"{_API_BASE}/pipeline", params={"org-slug": org})
            resp.raise_for_status()
            pipelines = resp.json().get("items", [])

            all_workflows = []
            for pipeline in pipelines[:25]:  # Cap to avoid rate limits
                pipeline_id = pipeline.get("id", "")
                try:
                    wf_resp = client.get(f"{_API_BASE}/pipeline/{pipeline_id}/workflow")
                    wf_resp.raise_for_status()
                    workflows = wf_resp.json().get("items", [])
                    for wf in workflows:
                        wf["_pipeline_id"] = pipeline_id
                        wf["_project_slug"] = pipeline.get("project_slug", "")
                    all_workflows.extend(workflows)
                except Exception:
                    log.debug("Failed to fetch workflows for pipeline %s", pipeline_id)

            result.events.append(self._raw_event("circleci_workflows", {"workflows": all_workflows}))
        except Exception as e:
            log.debug("CircleCI workflows collection failed: %s", e)
            result.errors.append(f"circleci_workflows: {e}")

    def _collect_projects(self, client: httpx.Client, org: str, result: ConnectorResult) -> None:
        """Collect project settings and configuration."""
        try:
            # CircleCI v2 doesn't have a direct "list projects" endpoint for org.
            # Use pipeline data to discover project slugs.
            resp = client.get(f"{_API_BASE}/pipeline", params={"org-slug": org})
            resp.raise_for_status()
            pipelines = resp.json().get("items", [])

            seen_slugs: set[str] = set()
            all_projects = []
            for pipeline in pipelines:
                slug = pipeline.get("project_slug", "")
                if slug and slug not in seen_slugs:
                    seen_slugs.add(slug)
                    try:
                        proj_resp = client.get(f"{_API_BASE}/project/{slug}")
                        proj_resp.raise_for_status()
                        all_projects.append(proj_resp.json())
                    except Exception:
                        log.debug("Failed to fetch project settings for %s", slug)

            result.events.append(self._raw_event("circleci_projects", {"projects": all_projects}))
        except Exception as e:
            log.debug("CircleCI projects collection failed: %s", e)
            result.errors.append(f"circleci_projects: {e}")

    def _collect_contexts(self, client: httpx.Client, org: str, result: ConnectorResult) -> None:
        """Collect organization contexts (environment variable stores)."""
        try:
            resp = client.get(f"{_API_BASE}/context", params={"owner-slug": org})
            resp.raise_for_status()
            contexts = resp.json().get("items", [])

            # For each context, list variable names (not values)
            for ctx in contexts:
                ctx_id = ctx.get("id", "")
                try:
                    vars_resp = client.get(f"{_API_BASE}/context/{ctx_id}/environment-variable")
                    vars_resp.raise_for_status()
                    env_vars = vars_resp.json().get("items", [])
                    ctx["_variables"] = [{"variable": v.get("variable", ""), "created_at": v.get("created_at", "")} for v in env_vars]
                except Exception:
                    log.debug("Failed to fetch context variables for %s", ctx_id)
                    ctx["_variables"] = []

            result.events.append(self._raw_event("circleci_contexts", {"contexts": contexts}))
        except Exception as e:
            log.debug("CircleCI contexts collection failed: %s", e)
            result.errors.append(f"circleci_contexts: {e}")


# Register
registry.register("circleci", CircleCIConnector)
