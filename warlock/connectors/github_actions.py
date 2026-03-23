"""GitHub Actions connector — Layer 1 implementation for CI/CD Pipeline Security.

Collects workflow runs (status, conclusion), secrets (metadata only),
runners (self-hosted status), and GHAS code scanning alerts
via the GitHub REST API v3.
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


class GitHubActionsConnector(BaseConnector):
    """Collects compliance telemetry from GitHub Actions REST API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[github_actions]")
        if not self.get_secret("WLK_GITHUB_TOKEN"):
            errors.append("WLK_GITHUB_TOKEN not set")
        if not self.get_secret("WLK_GITHUB_ORG"):
            errors.append("WLK_GITHUB_ORG not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            org = self.get_secret("WLK_GITHUB_ORG")
            resp = client.get(f"https://api.github.com/orgs/{org}")
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="github_actions",
            source_type=SourceType.CI_CD,
            provider="github",
        )

        client = self._client()
        org = self.get_secret("WLK_GITHUB_ORG")

        self._collect_workflow_runs(client, org, result)
        self._collect_secrets(client, org, result)
        self._collect_runners(client, org, result)
        self._collect_code_scanning(client, org, result)

        result.complete()
        return result

    # -- Helpers --

    def _client(self) -> httpx.Client:
        token = self.get_secret("WLK_GITHUB_TOKEN")
        return httpx.Client(
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=self.config.timeout_seconds,
        )

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="github_actions",
            source_type=SourceType.CI_CD,
            provider="github",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_workflow_runs(
        self, client: httpx.Client, org: str, result: ConnectorResult
    ) -> None:
        """Collect recent workflow runs across org repos."""
        try:
            repos_resp = client.get(
                f"https://api.github.com/orgs/{org}/repos", params={"per_page": "100"}
            )
            repos_resp.raise_for_status()
            repos = repos_resp.json()

            all_runs = []
            for repo in repos[:50]:  # Cap to avoid rate limits
                repo_name = repo.get("full_name", "")
                try:
                    runs_resp = client.get(
                        f"https://api.github.com/repos/{repo_name}/actions/runs",
                        params={"per_page": "25"},
                    )
                    runs_resp.raise_for_status()
                    runs = runs_resp.json().get("workflow_runs", [])
                    all_runs.extend(runs)
                except Exception:
                    log.debug("Failed to fetch workflow runs for %s", repo_name)

            result.events.append(self._raw_event("gha_workflow_runs", {"runs": all_runs}))
        except Exception as e:
            log.debug("GitHub Actions workflow runs collection failed: %s", e)
            result.errors.append(f"gha_workflow_runs: {e}")

    def _collect_secrets(self, client: httpx.Client, org: str, result: ConnectorResult) -> None:
        """Collect org-level Actions secrets metadata (names only, not values)."""
        try:
            resp = client.get(
                f"https://api.github.com/orgs/{org}/actions/secrets", params={"per_page": "100"}
            )
            resp.raise_for_status()
            secrets = resp.json().get("secrets", [])
            result.events.append(self._raw_event("gha_secrets", {"secrets": secrets}))
        except Exception as e:
            log.debug("GitHub Actions secrets collection failed: %s", e)
            result.errors.append(f"gha_secrets: {e}")

    def _collect_runners(self, client: httpx.Client, org: str, result: ConnectorResult) -> None:
        """Collect self-hosted runners and their status."""
        try:
            resp = client.get(
                f"https://api.github.com/orgs/{org}/actions/runners", params={"per_page": "100"}
            )
            resp.raise_for_status()
            runners = resp.json().get("runners", [])
            result.events.append(self._raw_event("gha_runners", {"runners": runners}))
        except Exception as e:
            log.debug("GitHub Actions runners collection failed: %s", e)
            result.errors.append(f"gha_runners: {e}")

    def _collect_code_scanning(
        self, client: httpx.Client, org: str, result: ConnectorResult
    ) -> None:
        """Collect GHAS code scanning alerts across org repos."""
        try:
            resp = client.get(
                f"https://api.github.com/orgs/{org}/code-scanning/alerts",
                params={"per_page": "100", "state": "open"},
            )
            resp.raise_for_status()
            alerts = resp.json()
            result.events.append(self._raw_event("gha_code_scanning", {"alerts": alerts}))
        except Exception as e:
            log.debug("GitHub Actions code scanning collection failed: %s", e)
            result.errors.append(f"gha_code_scanning: {e}")


# Register
registry.register("github_actions", GitHubActionsConnector)
