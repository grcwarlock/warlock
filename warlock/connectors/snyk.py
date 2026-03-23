"""Snyk connector — Layer 1 implementation for code security.

Collects projects, vulnerability issues, and audit logs from the Snyk REST API.
Uses API token authentication with cursor-based pagination.
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

SNYK_BASE_URL = "https://api.snyk.io"


class SnykConnector(BaseConnector):
    """Collects code security telemetry from Snyk REST APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[snyk]")
        if not self.get_secret("WLK_SNYK_API_TOKEN"):
            errors.append("WLK_SNYK_API_TOKEN env var is not set")
        if not self.config.settings.get("org_id"):
            errors.append("'org_id' must be set in connector settings")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("WLK_SNYK_API_TOKEN")
            resp = httpx.get(
                f"{SNYK_BASE_URL}/rest/self?version=2024-06-21",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="snyk",
            source_type=SourceType.CODE,
            provider="snyk",
        )

        org_id = self.config.settings["org_id"]
        token = self.get_secret("WLK_SNYK_API_TOKEN")
        headers = self._headers(token)

        client = httpx.Client(
            base_url=SNYK_BASE_URL,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            # 1. Projects (REST API)
            try:
                data = self._paginate_rest(
                    client,
                    f"/rest/orgs/{org_id}/projects",
                    params={"version": "2024-06-21", "limit": "100"},
                )
                result.events.append(
                    RawEventData(
                        source="snyk",
                        source_type=SourceType.CODE,
                        provider="snyk",
                        event_type="snyk_projects",
                        raw_data={
                            "endpoint": f"/rest/orgs/{org_id}/projects",
                            "org_id": org_id,
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("Snyk projects failed: %s", e)
                result.errors.append(f"projects: {e}")

            # 2. Issues / Vulnerabilities
            try:
                data = self._paginate_rest(
                    client,
                    f"/rest/orgs/{org_id}/issues",
                    params={
                        "version": "2024-06-21",
                        "limit": "100",
                        "type": "vuln",
                    },
                )
                result.events.append(
                    RawEventData(
                        source="snyk",
                        source_type=SourceType.CODE,
                        provider="snyk",
                        event_type="snyk_issues",
                        raw_data={
                            "endpoint": f"/rest/orgs/{org_id}/issues",
                            "org_id": org_id,
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("Snyk issues failed: %s", e)
                result.errors.append(f"issues: {e}")

            # 3. Audit Logs (v1 API)
            try:
                data = self._paginate_v1_audit(client, org_id)
                result.events.append(
                    RawEventData(
                        source="snyk",
                        source_type=SourceType.CODE,
                        provider="snyk",
                        event_type="snyk_audit_logs",
                        raw_data={
                            "endpoint": f"/v1/org/{org_id}/audit-logs/search",
                            "org_id": org_id,
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("Snyk audit logs failed: %s", e)
                result.errors.append(f"audit_logs: {e}")

        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.api+json",
            "Content-Type": "application/vnd.api+json",
        }

    def _paginate_rest(self, client, endpoint: str, params: dict) -> list:
        """Follow Snyk REST API cursor-based pagination (starting_after)."""
        all_items: list = []
        current_params = dict(params)

        while True:
            resp = client.get(endpoint, params=current_params)
            resp.raise_for_status()
            body = resp.json()

            data = body.get("data", [])
            if isinstance(data, list):
                all_items.extend(data)
            else:
                all_items.append(data)

            # Check for next page cursor
            links = body.get("links", {})
            next_url = links.get("next")
            if not next_url:
                break

            # Extract starting_after from next URL
            from urllib.parse import parse_qs, urlparse

            parsed = urlparse(next_url)
            qs = parse_qs(parsed.query)
            starting_after = qs.get("starting_after", [None])[0]
            if not starting_after:
                break
            current_params["starting_after"] = starting_after

        return all_items

    def _paginate_v1_audit(self, client, org_id: str) -> list:
        """Paginate Snyk v1 audit log search endpoint."""
        all_items: list = []
        page = 1

        while True:
            resp = client.post(
                f"/v1/org/{org_id}/audit-logs/search",
                json={"page": page, "sortOrder": "DESC"},
            )
            resp.raise_for_status()
            body = resp.json()

            results = body.get("results", [])
            if not results:
                break
            all_items.extend(results)

            total = body.get("total", 0)
            if len(all_items) >= total:
                break
            page += 1

        return all_items


# Register
registry.register("snyk", SnykConnector)
