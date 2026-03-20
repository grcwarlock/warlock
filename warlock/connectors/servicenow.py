"""ServiceNow ITSM connector — Layer 1 implementation for ITSM.

Collects change requests, incidents, problems, knowledge articles, risks,
and GRC policies from the ServiceNow Table API. Supports basic auth and OAuth.
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

# Endpoint → (table path with query params, event_type)
SNOW_ENDPOINTS: list[tuple[str, str, dict]] = [
    (
        "/api/now/table/change_request",
        "snow_change_requests",
        {
            "sysparm_query": "sys_created_on>=javascript:gs.daysAgoStart(30)",
            "sysparm_limit": "1000",
        },
    ),
    (
        "/api/now/table/incident",
        "snow_incidents",
        {
            "sysparm_query": "sys_created_on>=javascript:gs.daysAgoStart(30)",
            "sysparm_limit": "1000",
        },
    ),
    (
        "/api/now/table/problem",
        "snow_problems",
        {"sysparm_limit": "500"},
    ),
    (
        "/api/now/table/kb_knowledge",
        "snow_knowledge_articles",
        {"sysparm_limit": "500"},
    ),
    (
        "/api/now/table/risk",
        "snow_risks",
        {"sysparm_limit": "500"},
    ),
    (
        "/api/now/table/sn_grc_policy",
        "snow_policies",
        {"sysparm_limit": "500"},
    ),
]


class ServiceNowConnector(BaseConnector):
    """Collects compliance telemetry from ServiceNow Table API."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[servicenow]")

        instance = self.config.settings.get("instance")
        if not instance:
            errors.append(
                "'instance' must be set in connector settings (e.g. 'mycompany.service-now.com')"
            )

        # Require either basic auth or OAuth credentials
        has_basic = self.get_secret("WLK_SNOW_USERNAME") and self.get_secret("WLK_SNOW_PASSWORD")
        has_oauth = self.get_secret("WLK_SNOW_CLIENT_ID") and self.get_secret(
            "WLK_SNOW_CLIENT_SECRET"
        )
        if not has_basic and not has_oauth:
            errors.append(
                "ServiceNow credentials not set. Provide WLK_SNOW_USERNAME + WLK_SNOW_PASSWORD "
                "for basic auth, or WLK_SNOW_CLIENT_ID + WLK_SNOW_CLIENT_SECRET for OAuth."
            )
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            instance = self.config.settings["instance"]
            base_url = f"https://{instance}"
            headers = self._get_auth_headers()
            resp = httpx.get(
                f"{base_url}/api/now/table/sys_properties",
                params={"sysparm_limit": "1"},
                headers=headers,
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="servicenow",
            source_type=SourceType.ITSM,
            provider="servicenow",
        )

        instance = self.config.settings["instance"]
        base_url = f"https://{instance}"
        headers = self._get_auth_headers()

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in SNOW_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="servicenow",
                            source_type=SourceType.ITSM,
                            provider="servicenow",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "instance": instance,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("ServiceNow %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    # -- Auth helpers --

    def _get_auth_headers(self) -> dict[str, str]:
        """Return authorization headers, preferring OAuth if client credentials are set."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        client_id = self.get_secret("WLK_SNOW_CLIENT_ID")
        client_secret = self.get_secret("WLK_SNOW_CLIENT_SECRET")

        if client_id and client_secret:
            token = self._obtain_oauth_token(client_id, client_secret)
            headers["Authorization"] = f"Bearer {token}"
        else:
            import base64

            username = self.get_secret("WLK_SNOW_USERNAME")
            password = self.get_secret("WLK_SNOW_PASSWORD")
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"

        return headers

    def _obtain_oauth_token(self, client_id: str, client_secret: str) -> str:
        """Fetch an OAuth 2.0 bearer token from the ServiceNow token endpoint."""
        import httpx

        instance = self.config.settings["instance"]
        token_url = f"https://{instance}/oauth_token.do"

        # Use password grant if username/password are also provided, else client_credentials
        username = self.get_secret("WLK_SNOW_USERNAME")
        password = self.get_secret("WLK_SNOW_PASSWORD")

        if username and password:
            payload = {
                "grant_type": "password",
                "client_id": client_id,
                "client_secret": client_secret,
                "username": username,
                "password": password,
            }
        else:
            payload = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            }

        resp = httpx.post(token_url, data=payload, timeout=30)
        resp.raise_for_status()
        return resp.json()["access_token"]

    # -- Pagination --

    def _paginate(self, client, endpoint: str, params: dict) -> list:
        """Paginate ServiceNow Table API using sysparm_offset and X-Total-Count."""
        all_items: list = []
        limit = int(params.get("sysparm_limit", "500"))
        offset = 0
        current_params = dict(params)

        while True:
            current_params["sysparm_offset"] = str(offset)
            resp = client.get(endpoint, params=current_params)
            resp.raise_for_status()

            data = resp.json().get("result", [])
            if not data:
                break

            all_items.extend(data)

            # Check if we have fetched all records
            total_count_str = resp.headers.get("X-Total-Count")
            if total_count_str:
                total_count = int(total_count_str)
                if len(all_items) >= total_count:
                    break

            # If page returned fewer than limit, we're done
            if len(data) < limit:
                break

            offset += limit

        return all_items


# Register
registry.register("servicenow", ServiceNowConnector)
