"""Noname Security connector — Layer 1 implementation for CUSTOM (API Security).

Collects API inventory, issues, and alerts from the Noname Security platform.
Authenticates with a bearer API key.
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

NONAME_BASE_URL = "https://api.nonamesecurity.com"

NONAME_ENDPOINTS: list[tuple[str, str]] = [
    ("/api/v1/apis", "noname_apis"),
    ("/api/v1/issues", "noname_issues"),
    ("/api/v1/alerts", "noname_alerts"),
]


class NonameConnector(BaseConnector):
    """Collects API security telemetry from the Noname Security platform."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("NONAME_API_KEY"):
            errors.append("NONAME_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("NONAME_API_KEY")
            base_url = self.config.settings.get("base_url", NONAME_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1/apis",
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
            source="noname",
            source_type=SourceType.CUSTOM,
            provider="noname",
        )

        token = self.get_secret("NONAME_API_KEY")
        base_url = self.config.settings.get("base_url", NONAME_BASE_URL)
        headers = self._headers(token)
        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type in NONAME_ENDPOINTS:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    body = resp.json()
                    items = (
                        body if isinstance(body, list) else body.get("data", body.get("items", []))
                    )
                    result.events.append(
                        RawEventData(
                            source="noname",
                            source_type=SourceType.CUSTOM,
                            provider="noname",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "response": items,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Noname %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }


# Register
registry.register("noname", NonameConnector)
