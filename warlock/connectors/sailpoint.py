"""SailPoint IdentityNow connector — Layer 1 implementation for IAM.

Collects identities, access certifications, roles, entitlements, and accounts
from SailPoint IdentityNow v3 REST API.
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

# (endpoint, event_type, query_params)
SAILPOINT_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/v3/identities", "sailpoint_identities", {"limit": "250", "count": "true"}),
    ("/v3/campaigns", "sailpoint_certifications", {"limit": "250"}),
    ("/v3/roles", "sailpoint_roles", {"limit": "250"}),
    ("/v3/entitlements", "sailpoint_entitlements", {"limit": "250"}),
    ("/v3/accounts", "sailpoint_accounts", {"limit": "250"}),
]


class SailPointConnector(BaseConnector):
    """Collects compliance telemetry from SailPoint IdentityNow v3 API."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[sailpoint]")
        if not self.config.settings.get("tenant"):
            errors.append("'tenant' must be set in connector settings (e.g. 'mycompany')")
        if not self.get_secret("SAILPOINT_CLIENT_ID"):
            errors.append("SAILPOINT_CLIENT_ID env var is not set")
        if not self.get_secret("SAILPOINT_CLIENT_SECRET"):
            errors.append("SAILPOINT_CLIENT_SECRET env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._get_token()
            import httpx

            tenant = self.config.settings["tenant"]
            resp = httpx.get(
                f"https://{tenant}.api.identitynow.com/v3/org",
                headers={"Authorization": f"Bearer {token}"},
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
            source="sailpoint",
            source_type=SourceType.IAM,
            provider="sailpoint",
        )

        tenant = self.config.settings["tenant"]
        base_url = f"https://{tenant}.api.identitynow.com"

        try:
            token = self._get_token()
        except Exception as e:
            result.errors.append(f"OAuth2 token acquisition failed: {e}")
            result.complete("error")
            return result

        client = httpx.Client(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in SAILPOINT_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="sailpoint",
                            source_type=SourceType.IAM,
                            provider="sailpoint",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "tenant": tenant,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("SailPoint %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _get_token(self) -> str:
        """Acquire an OAuth2 token via client credentials flow."""
        import httpx

        tenant = self.config.settings["tenant"]
        client_id = self.get_secret("SAILPOINT_CLIENT_ID")
        client_secret = self.get_secret("SAILPOINT_CLIENT_SECRET")

        resp = httpx.post(
            f"https://{tenant}.api.identitynow.com/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _paginate(self, client, endpoint: str, params: dict) -> list:
        """Follow SailPoint offset-based pagination."""
        all_items: list = []
        offset = 0
        limit = int(params.get("limit", "250"))
        current_params = {k: v for k, v in params.items() if k != "limit"}
        current_params["limit"] = str(limit)

        while True:
            current_params["offset"] = str(offset)
            resp = client.get(endpoint, params=current_params)
            resp.raise_for_status()
            data = resp.json()

            if isinstance(data, list):
                all_items.extend(data)
                if len(data) < limit:
                    break
                offset += len(data)
            else:
                all_items.append(data)
                break

        return all_items


# Register
registry.register("sailpoint", SailPointConnector)
