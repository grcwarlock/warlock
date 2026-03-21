"""GitLab connector — Layer 1 implementation for code security.

Collects projects (visibility, MR approval rules), security dashboard
vulnerabilities, audit events, and runner configurations via the
GitLab REST API v4.
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


class GitLabConnector(BaseConnector):
    """Collects compliance telemetry from GitLab REST API v4."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[gitlab]")
        if not self.get_secret("WLK_GITLAB_TOKEN"):
            errors.append("WLK_GITLAB_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self._base_url()}/version")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="gitlab",
            source_type=SourceType.CODE,
            provider="gitlab",
        )

        self._collect_projects(result)
        self._collect_vulnerabilities(result)
        self._collect_audit_events(result)
        self._collect_runners(result)

        result.complete()
        return result

    # -- Helpers --

    def _base_url(self) -> str:
        custom_url = self.get_secret("WLK_GITLAB_URL")
        if custom_url:
            return custom_url.rstrip("/") + "/api/v4"
        return "https://gitlab.com/api/v4"

    def _client(self) -> httpx.Client:
        token = self.get_secret("WLK_GITLAB_TOKEN")
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={"PRIVATE-TOKEN": token},
        )

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="gitlab",
            source_type=SourceType.CODE,
            provider="gitlab",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_projects(self, result: ConnectorResult) -> None:
        """Collect GitLab projects with visibility and MR approval settings."""
        try:
            client = self._client()
            resp = client.get(
                f"{self._base_url()}/projects",
                params={"membership": "true", "per_page": "100", "statistics": "false"},
            )
            resp.raise_for_status()
            projects = resp.json()

            enriched = []
            for project in projects:
                proj_data = {
                    "id": project.get("id"),
                    "name": project.get("name", ""),
                    "path_with_namespace": project.get("path_with_namespace", ""),
                    "visibility": project.get("visibility", ""),
                    "default_branch": project.get("default_branch", ""),
                    "archived": project.get("archived", False),
                }

                # Fetch MR approval rules for each project
                try:
                    approvals_resp = client.get(
                        f"{self._base_url()}/projects/{project['id']}/approval_rules",
                    )
                    if approvals_resp.status_code == 200:
                        proj_data["approval_rules"] = approvals_resp.json()
                    else:
                        proj_data["approval_rules"] = []
                except Exception:
                    proj_data["approval_rules"] = []

                enriched.append(proj_data)

            result.events.append(self._raw_event("gitlab_projects", {"projects": enriched}))
        except Exception as e:
            log.debug("GitLab projects collection failed: %s", e)
            result.errors.append(f"gitlab_projects: {e}")

    def _collect_vulnerabilities(self, result: ConnectorResult) -> None:
        """Collect SAST/DAST vulnerabilities from security dashboard."""
        try:
            client = self._client()
            resp = client.get(
                f"{self._base_url()}/vulnerabilities",
                params={"per_page": "100", "state": "detected"},
            )
            resp.raise_for_status()
            vulns = resp.json()
            result.events.append(self._raw_event("gitlab_vulnerabilities", {"vulnerabilities": vulns}))
        except Exception as e:
            log.debug("GitLab vulnerabilities collection failed: %s", e)
            result.errors.append(f"gitlab_vulnerabilities: {e}")

    def _collect_audit_events(self, result: ConnectorResult) -> None:
        """Collect instance/group audit events."""
        try:
            client = self._client()
            resp = client.get(
                f"{self._base_url()}/audit_events",
                params={"per_page": "100"},
            )
            resp.raise_for_status()
            events = resp.json()
            result.events.append(self._raw_event("gitlab_audit_events", {"events": events}))
        except Exception as e:
            log.debug("GitLab audit events collection failed: %s", e)
            result.errors.append(f"gitlab_audit_events: {e}")

    def _collect_runners(self, result: ConnectorResult) -> None:
        """Collect CI/CD runner configurations."""
        try:
            client = self._client()
            resp = client.get(
                f"{self._base_url()}/runners/all",
                params={"per_page": "100"},
            )
            resp.raise_for_status()
            runners = resp.json()
            result.events.append(self._raw_event("gitlab_runners", {"runners": runners}))
        except Exception as e:
            log.debug("GitLab runners collection failed: %s", e)
            result.errors.append(f"gitlab_runners: {e}")


# Register
registry.register("gitlab", GitLabConnector)
