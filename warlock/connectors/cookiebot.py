"""Cookiebot connector — Layer 1 implementation for Privacy / Consent.

Collects scan results, consent records, and domain data from the Cookiebot API.
Uses Cookiebot REST API v1 via httpx with API key authentication.
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

COOKIEBOT_BASE_URL = "https://apiv2.cookiebot.com"

COOKIEBOT_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/scans", "cookiebot_scans", {"limit": "100", "page": "1"}),
    ("/api/v1/consents", "cookiebot_consents", {"limit": "100", "page": "1"}),
    ("/api/v1/domains", "cookiebot_domains", {"limit": "100", "page": "1"}),
]


class CookiebotConnector(BaseConnector):
    """Collects privacy/consent telemetry from the Cookiebot API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("COOKIEBOT_API_KEY"):
            errors.append("COOKIEBOT_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("COOKIEBOT_API_KEY")
            base_url = self.config.settings.get("base_url", COOKIEBOT_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1/domains",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="cookiebot",
            source_type=SourceType.CUSTOM,
            provider="cookiebot",
        )

        token = self.get_secret("COOKIEBOT_API_KEY")
        base_url = self.config.settings.get("base_url", COOKIEBOT_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in COOKIEBOT_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="cookiebot",
                            source_type=SourceType.CUSTOM,
                            provider="cookiebot",
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
                    log.debug("Cookiebot %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
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
registry.register("cookiebot", CookiebotConnector)
