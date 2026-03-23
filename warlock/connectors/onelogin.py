"""OneLogin connector — Layer 1 implementation for IAM.

Collects users, roles, and events from OneLogin REST APIs v2.
Uses OAuth2 client credentials for authentication.
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

ONELOGIN_BASE_URL = "https://api.us.onelogin.com"

ONELOGIN_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/2/users", "onelogin_users", {"limit": "50"}),
    ("/api/2/roles", "onelogin_roles", {"limit": "50"}),
    ("/api/2/events", "onelogin_events", {"limit": "50"}),
]


class OneLoginConnector(BaseConnector):
    """Collects compliance telemetry from OneLogin REST API v2."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("ONELOGIN_CLIENT_ID"):
            errors.append("ONELOGIN_CLIENT_ID env var is not set")
        if not self.get_secret("ONELOGIN_CLIENT_SECRET"):
            errors.append("ONELOGIN_CLIENT_SECRET env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._get_token()
            if not token:
                return False
            import httpx

            base_url = self.config.settings.get("base_url", ONELOGIN_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/2/users",
                headers={"Authorization": f"bearer:{token}"},
                params={"limit": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401)
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="onelogin",
            source_type=SourceType.IAM,
            provider="onelogin",
        )

        base_url = self.config.settings.get("base_url", ONELOGIN_BASE_URL)
        token = self._get_token()

        if not token:
            result.errors.append("Failed to obtain OAuth2 access token")
            result.complete("error")
            return result

        headers = {"Authorization": f"bearer:{token}", "Content-Type": "application/json"}

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type, params in ONELOGIN_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="onelogin",
                            source_type=SourceType.IAM,
                            provider="onelogin",
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
                    log.debug("OneLogin %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _get_token(self) -> str:
        """Obtain OAuth2 client credentials token from OneLogin."""
        try:
            import httpx

            client_id = self.get_secret("ONELOGIN_CLIENT_ID")
            client_secret = self.get_secret("ONELOGIN_CLIENT_SECRET")
            base_url = self.config.settings.get("base_url", ONELOGIN_BASE_URL)
            resp = httpx.post(
                f"{base_url}/auth/oauth2/v2/token",
                data={"grant_type": "client_credentials"},
                auth=(client_id, client_secret),
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json().get("access_token", "")
        except Exception as e:
            log.debug("OneLogin token acquisition failed: %s", e)
            return ""

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow OneLogin cursor-based pagination."""
        all_items: list = []
        current_params = dict(params)

        while True:
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            if isinstance(body, list):
                all_items.extend(body)
                break
            if isinstance(body, dict):
                items = body.get("data", body.get("result", []))
                if isinstance(items, list):
                    all_items.extend(items)
                cursor = body.get("pagination", {}).get("next_link")
                if not cursor:
                    break
                endpoint = cursor
                current_params = {}
            else:
                break

        return all_items


# Register
registry.register("onelogin", OneLoginConnector)
