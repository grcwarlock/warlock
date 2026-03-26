"""Azure Repos connector — Layer 1 implementation for CODE.

Collects data from the Azure Repos API.
Uses Bearer token authentication via AZURE_DEVOPS_PAT.
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

AZURE_REPOS_BASE_URL = "https://dev.azure.com/{org}"

AZURE_REPOS_ENDPOINTS: list[tuple[str, str]] = [
    ("/_apis/git/repositories", "azure_repos"),
    ("/_apis/git/repositories/{id}/pullrequests", "azure_pull_requests"),
    ("/_apis/git/repositories/{id}/policies", "azure_branch_policies"),
]


class AzureReposConnector(BaseConnector):
    """Collects compliance telemetry from the Azure Repos API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("AZURE_DEVOPS_PAT"):
            errors.append("AZURE_DEVOPS_PAT env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("AZURE_DEVOPS_PAT")
            base_url = self.config.settings.get("base_url", AZURE_REPOS_BASE_URL)
            resp = httpx.get(
                base_url,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="azure_repos",
            source_type=SourceType.CODE,
            provider="azure_repos",
        )

        token = self.get_secret("AZURE_DEVOPS_PAT")
        base_url = self.config.settings.get("base_url", AZURE_REPOS_BASE_URL)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type in AZURE_REPOS_ENDPOINTS:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    data = resp.json()
                    items = (
                        data
                        if isinstance(data, list)
                        else data.get("data", data.get("results", data.get("items", [data])))
                    )
                    result.events.append(
                        RawEventData(
                            source="azure_repos",
                            source_type=SourceType.CODE,
                            provider="azure_repos",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "response": items,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Azure Repos %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result


# Register
registry.register("azure_repos", AzureReposConnector)
