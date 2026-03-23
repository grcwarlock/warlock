"""Microsoft Sentinel connector — Layer 1 implementation for SIEM.

Collects incidents, analytics rules, hunting queries, and data connector
status from the Azure Management REST API via httpx.
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

# API version for Microsoft Sentinel endpoints
API_VERSION = "2023-11-01"
MGMT_BASE = "https://management.azure.com"


class SentinelConnector(BaseConnector):
    """Collects compliance telemetry from Microsoft Sentinel via REST API."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[sentinel]")
        for key in ("subscription_id", "resource_group", "workspace_name"):
            if not self.config.settings.get(key):
                errors.append(f"Missing required setting: {key}")
        # Need at least one auth mechanism
        if not self.get_secret("AZURE_CLIENT_SECRET") and not self.get_secret("AZURE_ACCESS_TOKEN"):
            errors.append(
                "Set AZURE_CLIENT_SECRET (with AZURE_TENANT_ID and AZURE_CLIENT_ID) "
                "or AZURE_ACCESS_TOKEN env var"
            )
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self._get_token()
            url = f"{MGMT_BASE}/subscriptions/{self._sub_id}?api-version=2022-01-01"
            resp = httpx.get(url, headers=self._auth_headers(token), timeout=30)
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="sentinel",
            source_type=SourceType.SIEM,
            provider="sentinel",
        )

        token = self._get_token()
        headers = self._auth_headers(token)
        base = self._workspace_url

        checks: list[tuple[str, str]] = [
            (
                f"{base}/providers/Microsoft.SecurityInsights/incidents?api-version={API_VERSION}"
                "&$filter=properties/severity eq 'High' or properties/severity eq 'Critical'"
                "&$top=200",
                "sentinel_incidents",
            ),
            (
                f"{base}/providers/Microsoft.SecurityInsights/alertRules?api-version={API_VERSION}",
                "sentinel_analytics_rules",
            ),
            (
                f"{base}/providers/Microsoft.SecurityInsights/hunts?api-version={API_VERSION}",
                "sentinel_hunting_queries",
            ),
            (
                f"{base}/providers/Microsoft.SecurityInsights/dataConnectors?api-version={API_VERSION}",
                "sentinel_data_connectors",
            ),
        ]

        with httpx.Client(timeout=self.config.timeout_seconds) as client:
            for url, event_type in checks:
                try:
                    data = self._paginate(client, url, headers)
                    result.events.append(
                        RawEventData(
                            source="sentinel",
                            source_type=SourceType.SIEM,
                            provider="sentinel",
                            event_type=event_type,
                            raw_data={
                                "subscription_id": self._sub_id,
                                "resource_group": self._rg,
                                "workspace": self._ws,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Sentinel %s failed: %s", event_type, e)
                    result.errors.append(f"{event_type}: {e}")

        result.complete()
        return result

    # -- internal helpers --

    @property
    def _sub_id(self) -> str:
        return self.config.settings["subscription_id"]

    @property
    def _rg(self) -> str:
        return self.config.settings["resource_group"]

    @property
    def _ws(self) -> str:
        return self.config.settings["workspace_name"]

    @property
    def _workspace_url(self) -> str:
        return (
            f"{MGMT_BASE}/subscriptions/{self._sub_id}"
            f"/resourceGroups/{self._rg}"
            f"/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self._ws}"
        )

    def _get_token(self) -> str:
        """Get an Azure access token via client credentials or env var."""
        static_token = self.get_secret("AZURE_ACCESS_TOKEN")
        if static_token:
            return static_token

        import httpx

        tenant_id = self.get_secret("AZURE_TENANT_ID")
        client_id = self.get_secret("AZURE_CLIENT_ID")
        client_secret = self.get_secret("AZURE_CLIENT_SECRET")
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

        resp = httpx.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://management.azure.com/.default",
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def _paginate(self, client, url: str, headers: dict) -> list[dict]:
        """Follow nextLink pagination, return all items."""

        all_items: list[dict] = []
        while url:
            resp = client.get(url, headers=headers)
            resp.raise_for_status()
            body = resp.json()
            all_items.extend(body.get("value", []))
            url = body.get("nextLink", "")
        return all_items


# Register
registry.register("sentinel", SentinelConnector)
