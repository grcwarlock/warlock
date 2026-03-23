"""Paylocity connector — Layer 1 implementation for HRIS.

Collects employees and earnings from the Paylocity API v2.
Uses OAuth2 client credentials via PAYLOCITY_CLIENT_ID and PAYLOCITY_CLIENT_SECRET.
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

PAYLOCITY_BASE_URL = "https://api.paylocity.com"
PAYLOCITY_TOKEN_URL = "https://api.paylocity.com/IdentityServer/connect/token"


class PaylocityConnector(BaseConnector):
    """Collects compliance telemetry from the Paylocity HRIS API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("PAYLOCITY_CLIENT_ID"):
            errors.append("PAYLOCITY_CLIENT_ID env var is not set")
        if not self.get_secret("PAYLOCITY_CLIENT_SECRET"):
            errors.append("PAYLOCITY_CLIENT_SECRET env var is not set")
        if not self.config.settings.get("company_id"):
            errors.append("company_id must be set in connector settings")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._get_oauth_token()
            return bool(token)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="paylocity",
            source_type=SourceType.HRIS,
            provider="paylocity",
        )

        try:
            token = self._get_oauth_token()
        except Exception as e:
            result.errors.append(f"OAuth token fetch failed: {e}")
            result.complete("error")
            return result

        import httpx

        company_id = self.config.settings.get("company_id", "")
        base_url = self.config.settings.get("base_url", PAYLOCITY_BASE_URL)
        headers = self._headers(token)

        endpoints: list[tuple[str, str]] = [
            (f"/api/v2/companies/{company_id}/employees", "paylocity_employees"),
            (f"/api/v2/companies/{company_id}/earnings", "paylocity_earnings"),
        ]

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in endpoints:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="paylocity",
                            source_type=SourceType.HRIS,
                            provider="paylocity",
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
                    log.debug("Paylocity %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _get_oauth_token(self) -> str:
        import httpx

        client_id = self.get_secret("PAYLOCITY_CLIENT_ID")
        client_secret = self.get_secret("PAYLOCITY_CLIENT_SECRET")
        token_url = self.config.settings.get("token_url", PAYLOCITY_TOKEN_URL)

        resp = httpx.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "WebLinkAPI",
            },
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json().get("access_token", "")

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow Paylocity page-based pagination."""
        all_items: list = []
        page = 1

        while True:
            resp = client.get(endpoint, params={"pagesize": 100, "pagenumber": page})  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            if isinstance(body, list):
                items = body
            else:
                items = body.get("data", [])

            all_items.extend(items)
            if len(items) < 100:
                break
            page += 1

        return all_items


# Register
registry.register("paylocity", PaylocityConnector)
