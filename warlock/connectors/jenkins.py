"""Jenkins connector — Layer 1 implementation for CI/CD Pipeline Security.

Collects jobs (build history, status), nodes (agents, executors),
credentials (credential stores), and security realm configuration
via the Jenkins REST API.
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


class JenkinsConnector(BaseConnector):
    """Collects compliance telemetry from Jenkins REST API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[jenkins]")
        if not self.get_secret("WLK_JENKINS_URL"):
            errors.append("WLK_JENKINS_URL not set")
        if not self.get_secret("WLK_JENKINS_USER"):
            errors.append("WLK_JENKINS_USER not set")
        if not self.get_secret("WLK_JENKINS_TOKEN"):
            errors.append("WLK_JENKINS_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self._base_url()}/api/json")
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="jenkins",
            source_type=SourceType.CI_CD,
            provider="jenkins",
        )

        client = self._client()
        base = self._base_url()

        self._collect_jobs(client, base, result)
        self._collect_nodes(client, base, result)
        self._collect_credentials(client, base, result)
        self._collect_security(client, base, result)

        result.complete()
        return result

    # -- Helpers --

    def _base_url(self) -> str:
        return self.get_secret("WLK_JENKINS_URL").rstrip("/")

    def _client(self) -> httpx.Client:
        user = self.get_secret("WLK_JENKINS_USER")
        token = self.get_secret("WLK_JENKINS_TOKEN")
        return httpx.Client(
            auth=(user, token),
            timeout=self.config.timeout_seconds,
        )

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="jenkins",
            source_type=SourceType.CI_CD,
            provider="jenkins",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_jobs(self, client: httpx.Client, base: str, result: ConnectorResult) -> None:
        """Collect Jenkins jobs with build history and status."""
        try:
            resp = client.get(
                f"{base}/api/json",
                params={
                    "tree": "jobs[name,url,color,lastBuild[number,result,timestamp,duration],healthReport[description,score]]"
                },
            )
            resp.raise_for_status()
            jobs = resp.json().get("jobs", [])
            result.events.append(self._raw_event("jenkins_jobs", {"jobs": jobs}))
        except Exception as e:
            log.debug("Jenkins jobs collection failed: %s", e)
            result.errors.append(f"jenkins_jobs: {e}")

    def _collect_nodes(self, client: httpx.Client, base: str, result: ConnectorResult) -> None:
        """Collect Jenkins nodes (agents and executors)."""
        try:
            resp = client.get(
                f"{base}/computer/api/json",
                params={
                    "tree": "computer[displayName,offline,temporarilyOffline,idle,numExecutors,monitorData[*]]"
                },
            )
            resp.raise_for_status()
            nodes = resp.json().get("computer", [])
            result.events.append(self._raw_event("jenkins_nodes", {"nodes": nodes}))
        except Exception as e:
            log.debug("Jenkins nodes collection failed: %s", e)
            result.errors.append(f"jenkins_nodes: {e}")

    def _collect_credentials(
        self, client: httpx.Client, base: str, result: ConnectorResult
    ) -> None:
        """Collect Jenkins credential store metadata (names/types, not values)."""
        try:
            resp = client.get(
                f"{base}/credentials/store/system/domain/_/api/json",
                params={"tree": "credentials[id,typeName,displayName,description]"},
            )
            resp.raise_for_status()
            credentials = resp.json().get("credentials", [])
            result.events.append(
                self._raw_event("jenkins_credentials", {"credentials": credentials})
            )
        except Exception as e:
            log.debug("Jenkins credentials collection failed: %s", e)
            result.errors.append(f"jenkins_credentials: {e}")

    def _collect_security(self, client: httpx.Client, base: str, result: ConnectorResult) -> None:
        """Collect Jenkins security realm and authorization configuration."""
        try:
            resp = client.get(f"{base}/configureSecurity/api/json")
            resp.raise_for_status()
            security = resp.json()
            result.events.append(self._raw_event("jenkins_security", {"security": security}))
        except Exception as e:
            log.debug("Jenkins security collection failed: %s", e)
            result.errors.append(f"jenkins_security: {e}")


# Register
registry.register("jenkins", JenkinsConnector)
