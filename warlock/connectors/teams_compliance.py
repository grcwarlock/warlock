"""MS Teams Compliance connector — Layer 1 implementation for COLLABORATION.

Collects call records, teams inventory, and security alerts via Microsoft Graph API.
Uses Bearer token authentication.
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

TEAMS_BASE_URL = "https://graph.microsoft.com"

TEAMS_ENDPOINTS: list[tuple[str, str]] = [
    ("/v1.0/communications/callRecords", "teams_call_records"),
    ("/v1.0/teamwork/teams", "teams_inventory"),
    ("/beta/security/alerts_v2", "teams_security_alerts"),
]


class TeamsComplianceConnector(BaseConnector):
    """Collects compliance telemetry from Microsoft Teams / Graph APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("TEAMS_COMPLIANCE_TOKEN"):
            errors.append("TEAMS_COMPLIANCE_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("TEAMS_COMPLIANCE_TOKEN")
            base_url = self.config.settings.get("base_url", TEAMS_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v1.0/",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="teams_compliance",
            source_type=SourceType.COLLABORATION,
            provider="teams_compliance",
        )

        token = self.get_secret("TEAMS_COMPLIANCE_TOKEN")
        base_url = self.config.settings.get("base_url", TEAMS_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in TEAMS_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="teams_compliance",
                            source_type=SourceType.COLLABORATION,
                            provider="teams_compliance",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Teams %s failed: %s", endpoint, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow Microsoft Graph nextLink-based pagination."""
        import httpx

        all_items: list = []
        url: str | None = endpoint

        while url:
            if url.startswith("http"):
                # Absolute nextLink URL — use a raw get
                resp = httpx.get(
                    url,
                    headers=client.headers,  # type: ignore[attr-defined]
                    timeout=30,
                )
            else:
                resp = client.get(url)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()
            all_items.extend(body.get("value", []))
            url = body.get("@odata.nextLink")

        return all_items


# Register
registry.register("teams_compliance", TeamsComplianceConnector)
