"""Microsoft Entra ID (Azure AD) connector — Layer 1 implementation for IAM.

Collects users, risky sign-ins, directory audit logs, conditional access
policies, service principals, and app registrations via MS Graph API.
Uses OAuth2 client credentials flow.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

# (endpoint, event_type, query_params)
ENTRA_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/v1.0/users", "entra_users", {"$top": "999", "$select": "id,displayName,userPrincipalName,accountEnabled,signInActivity,createdDateTime,assignedLicenses"}),
    ("/v1.0/identityProtection/riskyUsers", "entra_risky_users", {"$top": "999"}),
    ("/v1.0/auditLogs/signIns", "entra_sign_ins", {"$top": "999", "$filter": "status/errorCode ne 0"}),
    ("/v1.0/auditLogs/directoryAudits", "entra_directory_audits", {"$top": "999"}),
    ("/v1.0/identity/conditionalAccess/policies", "entra_conditional_access_policies", {}),
    ("/v1.0/servicePrincipals", "entra_service_principals", {"$top": "999"}),
    ("/v1.0/applications", "entra_app_registrations", {"$top": "999"}),
]


class EntraIDConnector(BaseConnector):
    """Collects compliance telemetry from Microsoft Entra ID via MS Graph API."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[entra_id]")
        if not self.get_secret("ENTRA_TENANT_ID"):
            errors.append("ENTRA_TENANT_ID env var is not set")
        if not self.get_secret("ENTRA_CLIENT_ID"):
            errors.append("ENTRA_CLIENT_ID env var is not set")
        if not self.get_secret("ENTRA_CLIENT_SECRET"):
            errors.append("ENTRA_CLIENT_SECRET env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._get_token()
            import httpx
            resp = httpx.get(
                "https://graph.microsoft.com/v1.0/organization",
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="entra_id",
            source_type=SourceType.IAM,
            provider="entra_id",
        )

        try:
            token = self._get_token()
        except Exception as e:
            result.errors.append(f"OAuth2 token acquisition failed: {e}")
            result.complete("error")
            return result

        tenant_id = self.get_secret("ENTRA_TENANT_ID")

        client = httpx.Client(
            base_url="https://graph.microsoft.com",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in ENTRA_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(RawEventData(
                        source="entra_id",
                        source_type=SourceType.IAM,
                        provider="entra_id",
                        event_type=event_type,
                        raw_data={
                            "endpoint": endpoint,
                            "tenant_id": tenant_id,
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    ))
                except Exception as e:
                    log.debug("Entra ID %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _get_token(self) -> str:
        """Acquire an OAuth2 token via client credentials flow."""
        import httpx

        tenant_id = self.get_secret("ENTRA_TENANT_ID")
        client_id = self.get_secret("ENTRA_CLIENT_ID")
        client_secret = self.get_secret("ENTRA_CLIENT_SECRET")

        resp = httpx.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _paginate(self, client, endpoint: str, params: dict) -> list:
        """Follow MS Graph @odata.nextLink pagination."""
        all_items: list = []
        url = endpoint
        current_params = dict(params)

        while url:
            resp = client.get(url, params=current_params)
            resp.raise_for_status()
            body = resp.json()

            items = body.get("value", [])
            all_items.extend(items)

            next_link = body.get("@odata.nextLink", "")
            if next_link:
                # nextLink is absolute URL, strip base
                url = next_link.replace("https://graph.microsoft.com", "")
                current_params = {}
            else:
                url = None

        return all_items


# Register
registry.register("entra_id", EntraIDConnector)
