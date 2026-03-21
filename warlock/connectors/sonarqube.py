"""SonarQube connector — Layer 1 implementation for code quality / SAST.

Collects projects (quality gate status), issues (bugs/vulnerabilities/code smells),
and quality profiles via SonarQube Web API.
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


class SonarQubeConnector(BaseConnector):
    """Collects compliance telemetry from SonarQube Web API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[sonarqube]")
        if not self.get_secret("WLK_SONARQUBE_BASE_URL"):
            errors.append("WLK_SONARQUBE_BASE_URL not set")
        if not self.get_secret("WLK_SONARQUBE_TOKEN"):
            errors.append("WLK_SONARQUBE_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            base_url = self.get_secret("WLK_SONARQUBE_BASE_URL").rstrip("/")
            resp = client.get(f"{base_url}/api/system/status")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sonarqube",
            source_type=SourceType.CODE,
            provider="sonarqube",
        )

        client = self._client()
        base_url = self.get_secret("WLK_SONARQUBE_BASE_URL").rstrip("/")

        self._collect_projects(client, base_url, result)
        self._collect_issues(client, base_url, result)
        self._collect_quality_gates(client, base_url, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _client(self) -> httpx.Client:
        """Build an httpx client with token-based Basic auth (token as username, empty password)."""
        token = self.get_secret("WLK_SONARQUBE_TOKEN")
        headers = {"Content-Type": "application/json"}
        return httpx.Client(
            headers=headers,
            auth=(token, ""),
            timeout=self.config.timeout_seconds,
        )

    # -- Pagination --

    def _paginate(
        self,
        client: httpx.Client,
        url: str,
        result_key: str = "components",
    ) -> list:
        """Page-based pagination for SonarQube API."""
        max_pages = self.config.settings.get("max_pages", 20)
        per_page = self.config.settings.get("per_page", 100)
        all_items: list = []

        for page in range(1, max_pages + 1):
            resp = client.get(url, params={"ps": per_page, "p": page})
            resp.raise_for_status()
            body = resp.json()

            items = body.get(result_key, [])
            if not items:
                break

            all_items.extend(items)

            paging = body.get("paging", {})
            total = paging.get("total", 0)
            if total and len(all_items) >= total:
                break

        return all_items

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="sonarqube",
            source_type=SourceType.CODE,
            provider="sonarqube",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_projects(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect all SonarQube projects with quality gate status."""
        try:
            url = f"{base_url}/api/components/search_projects"
            projects = self._paginate(client, url, result_key="components")
            result.events.append(
                self._raw_event(
                    "sonarqube_projects",
                    {"projects": projects},
                )
            )
        except Exception as e:
            log.debug("SonarQube projects collection failed: %s", e)
            result.errors.append(f"sonarqube_projects: {e}")

    def _collect_issues(self, client: httpx.Client, base_url: str, result: ConnectorResult) -> None:
        """Collect issues (bugs, vulnerabilities, code smells) by severity."""
        try:
            url = f"{base_url}/api/issues/search"
            issues = self._paginate(client, url, result_key="issues")
            result.events.append(
                self._raw_event(
                    "sonarqube_issues",
                    {"issues": issues},
                )
            )
        except Exception as e:
            log.debug("SonarQube issues collection failed: %s", e)
            result.errors.append(f"sonarqube_issues: {e}")

    def _collect_quality_gates(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect quality gate definitions and project statuses."""
        try:
            url = f"{base_url}/api/qualitygates/list"
            resp = client.get(url)
            resp.raise_for_status()
            body = resp.json()
            gates = body.get("qualitygates", [])
            default_gate = body.get("default", "")
            result.events.append(
                self._raw_event(
                    "sonarqube_quality_gates",
                    {"quality_gates": gates, "default": default_gate},
                )
            )
        except Exception as e:
            log.debug("SonarQube quality gates collection failed: %s", e)
            result.errors.append(f"sonarqube_quality_gates: {e}")


# Register
registry.register("sonarqube", SonarQubeConnector)
