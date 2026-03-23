"""Salesforce connector — Layer 1 implementation for COLLABORATION.

Collects user accounts, profiles, and login history via Salesforce REST API v58.0.
Uses OAuth access token authentication.
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

SALESFORCE_ENDPOINTS: list[tuple[str, str, str]] = [
    (
        "/services/data/v58.0/query",
        "salesforce_users",
        "SELECT Id,Username,Name,Email,IsActive,LastLoginDate,CreatedDate FROM User LIMIT 1000",
    ),
    (
        "/services/data/v58.0/query",
        "salesforce_profiles",
        "SELECT Id,Name,Description,UserType FROM Profile LIMIT 500",
    ),
    (
        "/services/data/v58.0/query",
        "salesforce_login_history",
        "SELECT Id,UserId,LoginTime,LoginType,Status,SourceIp FROM LoginHistory ORDER BY LoginTime DESC LIMIT 1000",
    ),
]

SALESFORCE_BASE_URL = "https://login.salesforce.com"


class SalesforceConnector(BaseConnector):
    """Collects compliance telemetry from Salesforce REST APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("SALESFORCE_ACCESS_TOKEN"):
            errors.append("SALESFORCE_ACCESS_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("SALESFORCE_ACCESS_TOKEN")
            base_url = self.config.settings.get("base_url", SALESFORCE_BASE_URL)
            resp = httpx.get(
                f"{base_url}/services/data/v58.0/",
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
            source="salesforce",
            source_type=SourceType.COLLABORATION,
            provider="salesforce",
        )

        token = self.get_secret("SALESFORCE_ACCESS_TOKEN")
        base_url = self.config.settings.get("base_url", SALESFORCE_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, soql in SALESFORCE_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params={"q": soql})
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="salesforce",
                            source_type=SourceType.COLLABORATION,
                            provider="salesforce",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "response": data.get("records", []),
                                "totalSize": data.get("totalSize", 0),
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Salesforce %s failed: %s", endpoint, e)
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


# Register
registry.register("salesforce", SalesforceConnector)
