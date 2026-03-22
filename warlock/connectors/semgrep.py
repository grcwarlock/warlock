"""Semgrep connector — Layer 1 implementation for SAST / code security.

Collects deployments, findings, policies, and projects
via the Semgrep App API with Bearer token auth.
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


class SemgrepConnector(BaseConnector):
    """Collects compliance telemetry from Semgrep App API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[semgrep]")
        if not self.get_secret("WLK_SEMGREP_TOKEN"):
            errors.append("WLK_SEMGREP_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get("/deployments")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="semgrep",
            source_type=SourceType.CODE,
            provider="semgrep",
        )

        client = self._client()

        self._collect_deployments(client, result)
        self._collect_findings(client, result)
        self._collect_policies(client, result)
        self._collect_projects(client, result)

        result.complete()
        return result

    # -- Client helper --

    def _client(self) -> httpx.Client:
        token = self.get_secret("WLK_SEMGREP_TOKEN")
        return httpx.Client(
            base_url="https://semgrep.dev/api/v1",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            timeout=self.config.timeout_seconds,
        )

    # -- Event helper --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="semgrep",
            source_type=SourceType.CODE,
            provider="semgrep",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_deployments(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect Semgrep deployment/org info."""
        try:
            resp = client.get("/deployments")
            resp.raise_for_status()
            deployments = resp.json().get("deployments", [])
            result.events.append(
                self._raw_event("semgrep_deployments", {"deployments": deployments})
            )
        except Exception as e:
            log.debug("Semgrep deployments collection failed: %s", e)
            result.errors.append(f"semgrep_deployments: {e}")

    def _collect_findings(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect SAST findings across all repos."""
        try:
            # Get deployment slug first
            dep_resp = client.get("/deployments")
            dep_resp.raise_for_status()
            deployments = dep_resp.json().get("deployments", [])
            if not deployments:
                return

            slug = deployments[0].get("slug", "")
            resp = client.get(
                f"/deployments/{slug}/findings",
                params={"limit": 500},
            )
            resp.raise_for_status()
            findings = resp.json().get("findings", [])
            result.events.append(self._raw_event("semgrep_findings", {"findings": findings}))
        except Exception as e:
            log.debug("Semgrep findings collection failed: %s", e)
            result.errors.append(f"semgrep_findings: {e}")

    def _collect_policies(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect Semgrep scanning policies."""
        try:
            dep_resp = client.get("/deployments")
            dep_resp.raise_for_status()
            deployments = dep_resp.json().get("deployments", [])
            if not deployments:
                return

            slug = deployments[0].get("slug", "")
            resp = client.get(f"/deployments/{slug}/policies")
            resp.raise_for_status()
            policies = resp.json().get("policies", [])
            result.events.append(self._raw_event("semgrep_policies", {"policies": policies}))
        except Exception as e:
            log.debug("Semgrep policies collection failed: %s", e)
            result.errors.append(f"semgrep_policies: {e}")

    def _collect_projects(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect Semgrep projects (repos being scanned)."""
        try:
            dep_resp = client.get("/deployments")
            dep_resp.raise_for_status()
            deployments = dep_resp.json().get("deployments", [])
            if not deployments:
                return

            slug = deployments[0].get("slug", "")
            resp = client.get(
                f"/deployments/{slug}/projects",
                params={"limit": 500},
            )
            resp.raise_for_status()
            projects = resp.json().get("projects", [])
            result.events.append(self._raw_event("semgrep_projects", {"projects": projects}))
        except Exception as e:
            log.debug("Semgrep projects collection failed: %s", e)
            result.errors.append(f"semgrep_projects: {e}")


# Register
registry.register("semgrep", SemgrepConnector)
