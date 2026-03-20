"""Microsoft Purview DLP connector — Layer 1 implementation for DLP.

Collects DLP alerts, sensitivity labels, and DLP policies via the
Microsoft Graph Security API. Uses OAuth2 client_credentials flow with httpx.
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

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

PURVIEW_ENDPOINTS: list[tuple[str, str]] = [
    (
        "/security/alerts_v2?$filter=category eq 'DataLossPrevention'&$top=200",
        "purview_dlp_alerts",
    ),
    (
        "/security/informationProtection/sensitivityLabels",
        "purview_sensitivity_labels",
    ),
    (
        "/security/informationProtection/policy/labels",
        "purview_dlp_policies",
    ),
]


class PurviewConnector(BaseConnector):
    """Collects DLP telemetry from Microsoft Purview via Graph Security API."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install httpx")
        if not self._get_tenant_id():
            errors.append(
                "Purview tenant_id not configured "
                "(set WLK_PURVIEW_TENANT_ID or config.settings.tenant_id)"
            )
        if not self._get_client_id():
            errors.append(
                "Purview client_id not configured "
                "(set WLK_PURVIEW_CLIENT_ID or config.settings.client_id)"
            )
        if not self._get_client_secret():
            errors.append(
                "Purview client_secret not configured "
                "(set WLK_PURVIEW_CLIENT_SECRET or config.settings.client_secret)"
            )
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self._acquire_token()
            if not token:
                return False
            resp = httpx.get(
                f"{GRAPH_BASE_URL}/security/alerts_v2",
                headers=self._auth_headers(token),
                params={"$top": "1"},
                timeout=30,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="purview",
            source_type=SourceType.DLP,
            provider="purview",
        )

        token = self._acquire_token()
        if not token:
            result.errors.append("Failed to acquire OAuth2 token")
            result.complete("error")
            return result

        headers = self._auth_headers(token)
        timeout = self.config.timeout_seconds

        for endpoint, event_type in PURVIEW_ENDPOINTS:
            try:
                all_records: list[dict] = []
                url: str | None = f"{GRAPH_BASE_URL}{endpoint}"

                # OData pagination via @odata.nextLink
                while url:
                    resp = httpx.get(url, headers=headers, timeout=timeout)
                    resp.raise_for_status()
                    body = resp.json()
                    records = body.get("value", [])
                    all_records.extend(records)
                    url = body.get("@odata.nextLink")

                    if len(all_records) >= 10000:
                        log.warning("Purview %s: capped at 10k records", event_type)
                        break

                result.events.append(
                    RawEventData(
                        source="purview",
                        source_type=SourceType.DLP,
                        provider="purview",
                        event_type=event_type,
                        raw_data={
                            "endpoint": endpoint,
                            "records": all_records,
                            "total": len(all_records),
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("Purview %s failed: %s", endpoint, e)
                result.errors.append(f"{event_type}: {e}")

        result.complete()
        return result

    # -- Auth helpers --

    def _acquire_token(self) -> str:
        """Acquire OAuth2 access token using client_credentials flow."""
        try:
            import httpx

            tenant_id = self._get_tenant_id()
            token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            resp = httpx.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._get_client_id(),
                    "client_secret": self._get_client_secret(),
                    "scope": GRAPH_SCOPE,
                },
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()["access_token"]
        except Exception as e:
            log.error("Purview token acquisition error: %s", e)
            return ""

    def _get_tenant_id(self) -> str:
        return self.config.settings.get("tenant_id", "") or self.get_secret("WLK_PURVIEW_TENANT_ID")

    def _get_client_id(self) -> str:
        return self.config.settings.get("client_id", "") or self.get_secret("WLK_PURVIEW_CLIENT_ID")

    def _get_client_secret(self) -> str:
        return self.config.settings.get("client_secret", "") or self.get_secret(
            "WLK_PURVIEW_CLIENT_SECRET"
        )

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# Register
registry.register("purview", PurviewConnector)
