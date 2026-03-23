"""Wiz connector — Layer 1 implementation for cloud security scanning.

Collects issues, cloud configuration findings, vulnerability findings,
and security graph data via Wiz GraphQL API.
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


# GraphQL queries
ISSUES_QUERY = """
query WarlockIssues($first: Int, $after: String) {
    issues(
        first: $first
        after: $after
        filterBy: { severity: [CRITICAL, HIGH], status: [OPEN, IN_PROGRESS] }
    ) {
        nodes {
            id
            title
            severity
            status
            type
            entity { id type name }
            createdAt
            updatedAt
            dueAt
            resolvedAt
            notes { text }
            sourceRule { id name }
            projects { id name }
        }
        pageInfo { hasNextPage endCursor }
    }
}
"""

CONFIG_FINDINGS_QUERY = """
query WarlockConfigFindings($first: Int, $after: String) {
    configurationFindings(
        first: $first
        after: $after
        filterBy: { severity: [CRITICAL, HIGH], status: [OPEN] }
    ) {
        nodes {
            id
            title
            severity
            status
            result
            resource { id type name nativeType region subscription { id name } }
            rule { id name description remediationInstructions severity }
            analyzedAt
        }
        pageInfo { hasNextPage endCursor }
    }
}
"""

VULN_FINDINGS_QUERY = """
query WarlockVulnFindings($first: Int, $after: String) {
    vulnerabilityFindings(
        first: $first
        after: $after
        filterBy: { severity: [CRITICAL, HIGH] }
    ) {
        nodes {
            id
            name
            severity
            status
            CVEDescription
            CVSSScore
            hasCISAKEVExploit
            hasExploit
            version
            fixedVersion
            detailedName
            vendorSeverity
            vulnerableAsset { id type name region subscription { id name } }
            firstDetectedAt
            lastDetectedAt
        }
        pageInfo { hasNextPage endCursor }
    }
}
"""

GRAPH_QUERY = """
query WarlockGraph($first: Int, $after: String) {
    graphSearch(
        first: $first
        after: $after
        query: { type: [SECURITY_TOOL_FINDING], select: true }
    ) {
        nodes { entities { id type name properties } }
        pageInfo { hasNextPage endCursor }
    }
}
"""


class WizConnector(BaseConnector):
    """Collects compliance telemetry from Wiz GraphQL API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[wiz]")
        if not self.get_secret("WIZ_CLIENT_ID"):
            errors.append("WIZ_CLIENT_ID env var not set")
        if not self.get_secret("WIZ_CLIENT_SECRET"):
            errors.append("WIZ_CLIENT_SECRET env var not set")
        if not self.config.settings.get("api_url"):
            errors.append("settings.api_url not set (e.g. https://api.us1.app.wiz.io)")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._authenticate()
            return bool(token)
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        if httpx is None:
            raise RuntimeError("WizConnector requires httpx. Install with: pip install httpx")
        result = ConnectorResult(
            connector_name=self.name,
            source="wiz",
            source_type=SourceType.SCANNER,
            provider="wiz",
        )

        token = self._authenticate()
        client = self._client(token)

        self._collect_issues(client, result)
        self._collect_config_findings(client, result)
        self._collect_vuln_findings(client, result)
        self._collect_graph(client, result)

        result.complete()
        return result

    def _authenticate(self) -> str:
        """OAuth2 client_credentials flow to get JWT token."""
        auth_url = self.config.settings.get("auth_url", "https://auth.app.wiz.io/oauth/token")
        resp = httpx.post(
            auth_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.get_secret("WIZ_CLIENT_ID"),
                "client_secret": self.get_secret("WIZ_CLIENT_SECRET"),
                "audience": "wiz-api",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _client(self, token: str) -> httpx.Client:
        return httpx.Client(
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=self.config.timeout_seconds,
        )

    @property
    def _api_url(self) -> str:
        return self.config.settings.get("api_url", "https://api.us1.app.wiz.io").rstrip("/")

    def _graphql(self, client: httpx.Client, query: str, variables: dict | None = None) -> dict:
        """Execute a GraphQL query."""
        resp = client.post(
            f"{self._api_url}/graphql",
            json={"query": query, "variables": variables or {}},
        )
        resp.raise_for_status()
        body = resp.json()
        if "errors" in body:
            raise RuntimeError(f"GraphQL errors: {body['errors']}")
        return body.get("data", {})

    def _paginate(self, client: httpx.Client, query: str, root_key: str) -> list:
        """Paginate through a GraphQL connection."""
        page_size = self.config.settings.get("page_size", 500)
        max_pages = self.config.settings.get("max_pages", 20)
        all_nodes: list = []
        cursor = None

        for _ in range(max_pages):
            variables = {"first": page_size}
            if cursor:
                variables["after"] = cursor

            data = self._graphql(client, query, variables)
            connection = data.get(root_key, {})
            nodes = connection.get("nodes", [])
            all_nodes.extend(nodes)

            page_info = connection.get("pageInfo", {})
            if not page_info.get("hasNextPage", False):
                break
            cursor = page_info.get("endCursor")

        return all_nodes

    def _collect_issues(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect Wiz issues (critical/high)."""
        try:
            issues = self._paginate(client, ISSUES_QUERY, "issues")
            result.events.append(
                RawEventData(
                    source="wiz",
                    source_type=SourceType.SCANNER,
                    provider="wiz",
                    event_type="wiz_issues",
                    raw_data={"issues": issues},
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("Wiz issues collection failed: %s", e)
            result.errors.append(f"wiz_issues: {e}")

    def _collect_config_findings(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect cloud configuration findings."""
        try:
            findings = self._paginate(client, CONFIG_FINDINGS_QUERY, "configurationFindings")
            result.events.append(
                RawEventData(
                    source="wiz",
                    source_type=SourceType.SCANNER,
                    provider="wiz",
                    event_type="wiz_config_findings",
                    raw_data={"findings": findings},
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("Wiz config findings collection failed: %s", e)
            result.errors.append(f"wiz_config_findings: {e}")

    def _collect_vuln_findings(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect vulnerability findings."""
        try:
            findings = self._paginate(client, VULN_FINDINGS_QUERY, "vulnerabilityFindings")
            result.events.append(
                RawEventData(
                    source="wiz",
                    source_type=SourceType.SCANNER,
                    provider="wiz",
                    event_type="wiz_vuln_findings",
                    raw_data={"findings": findings},
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("Wiz vuln findings collection failed: %s", e)
            result.errors.append(f"wiz_vuln_findings: {e}")

    def _collect_graph(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect security graph data."""
        try:
            graph_data = self._paginate(client, GRAPH_QUERY, "graphSearch")
            result.events.append(
                RawEventData(
                    source="wiz",
                    source_type=SourceType.SCANNER,
                    provider="wiz",
                    event_type="wiz_graph",
                    raw_data={"graph": graph_data},
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("Wiz graph collection failed: %s", e)
            result.errors.append(f"wiz_graph: {e}")


# Register
registry.register("wiz", WizConnector)
