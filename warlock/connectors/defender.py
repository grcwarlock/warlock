"""Microsoft Defender for Endpoint connector — Layer 1 implementation for EDR.

Collects machines with risk scores, alerts, vulnerabilities, and
security recommendations via the MS Graph / Defender APIs.
Uses OAuth2 client_credentials flow with msal and httpx for HTTP calls.
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

# Defender API endpoints (relative to base_url)
DEFENDER_ENDPOINTS: list[tuple[str, str]] = [
    ("/api/machines", "defender_machines"),
    ("/api/alerts", "defender_alerts"),
    ("/api/vulnerabilities", "defender_vulnerabilities"),
    ("/api/recommendations", "defender_recommendations"),
]

GRAPH_SCOPE = "https://api.securitycenter.microsoft.com/.default"
DEFAULT_BASE_URL = "https://api.securitycenter.microsoft.com"


class DefenderConnector(BaseConnector):
    """Collects compliance telemetry from Microsoft Defender for Endpoint."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install httpx")
        try:
            import msal  # noqa: F401
        except ImportError:
            errors.append("msal not installed. Install with: pip install msal")
        if not self._get_tenant_id():
            errors.append("Defender tenant_id not configured (set DEFENDER_TENANT_ID or config.settings.tenant_id)")
        if not self._get_client_id():
            errors.append("Defender client_id not configured (set DEFENDER_CLIENT_ID or config.settings.client_id)")
        if not self._get_client_secret():
            errors.append("Defender client_secret not configured (set DEFENDER_CLIENT_SECRET or config.settings.client_secret)")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._acquire_token()
            if not token:
                return False
            import httpx
            resp = httpx.get(
                f"{self._get_base_url()}/api/machines",
                headers={"Authorization": f"Bearer {token}"},
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
            source="defender",
            source_type=SourceType.EDR,
            provider="defender",
        )

        token = self._acquire_token()
        if not token:
            result.errors.append("Failed to acquire OAuth2 token")
            result.complete("error")
            return result

        base_url = self._get_base_url()
        headers = {"Authorization": f"Bearer {token}"}
        timeout = self.config.timeout_seconds

        for endpoint, event_type in DEFENDER_ENDPOINTS:
            try:
                all_records = []
                url: str | None = f"{base_url}{endpoint}"

                # Handle OData pagination
                while url:
                    resp = httpx.get(url, headers=headers, timeout=timeout)
                    resp.raise_for_status()
                    body = resp.json()
                    records = body.get("value", [])
                    all_records.extend(records)
                    url = body.get("@odata.nextLink")

                    # Safety: cap at 10k records per endpoint
                    if len(all_records) >= 10000:
                        log.warning("Defender %s: capped at 10k records", event_type)
                        break

                result.events.append(RawEventData(
                    source="defender",
                    source_type=SourceType.EDR,
                    provider="defender",
                    event_type=event_type,
                    raw_data={
                        "endpoint": endpoint,
                        "records": all_records,
                        "total": len(all_records),
                    },
                    observed_at=datetime.now(timezone.utc),
                ))
            except Exception as e:
                log.debug("Defender %s failed: %s", endpoint, e)
                result.errors.append(f"{event_type}: {e}")

        result.complete()
        return result

    # -- Auth helpers --

    def _acquire_token(self) -> str:
        """Acquire OAuth2 access token using client_credentials flow."""
        try:
            import msal
            authority = f"https://login.microsoftonline.com/{self._get_tenant_id()}"
            app = msal.ConfidentialClientApplication(
                client_id=self._get_client_id(),
                client_credential=self._get_client_secret(),
                authority=authority,
            )
            token_resp = app.acquire_token_for_client(scopes=[GRAPH_SCOPE])
            if token_resp and "access_token" in token_resp:
                return token_resp["access_token"]
            log.error("Defender token acquisition failed: %s", token_resp.get("error_description", "unknown"))
            return ""
        except Exception as e:
            log.error("Defender token acquisition error: %s", e)
            return ""

    def _get_tenant_id(self) -> str:
        return self.config.settings.get("tenant_id", "") or self.get_secret("DEFENDER_TENANT_ID")

    def _get_client_id(self) -> str:
        return self.config.settings.get("client_id", "") or self.get_secret("DEFENDER_CLIENT_ID")

    def _get_client_secret(self) -> str:
        return self.config.settings.get("client_secret", "") or self.get_secret("DEFENDER_CLIENT_SECRET")

    def _get_base_url(self) -> str:
        return self.config.settings.get("base_url", DEFAULT_BASE_URL)


# Register
registry.register("defender", DefenderConnector)
