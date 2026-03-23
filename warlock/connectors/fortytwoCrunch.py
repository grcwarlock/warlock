"""42Crunch connector — Layer 1 implementation for API Security.

Collects API inventory and audit findings from the 42Crunch platform.
Uses 42Crunch REST API v2 via httpx with API key authentication.
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

FORTYTWOCRUNCH_BASE_URL = "https://platform.42crunch.com"

FORTYTWOCRUNCH_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v2/apis", "fortytwocrunch_apis", {"limit": "100"}),
    ("/api/v2/audits", "fortytwocrunch_audits", {"limit": "100"}),
]


class FortyTwoCrunchConnector(BaseConnector):
    """Collects compliance telemetry from the 42Crunch API Security platform."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("FORTYTWOCRUNCH_API_KEY"):
            errors.append("FORTYTWOCRUNCH_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("FORTYTWOCRUNCH_API_KEY")
            base_url = self.config.settings.get("base_url", FORTYTWOCRUNCH_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v2/apis",
                headers=self._headers(token),
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
            source="fortytwocrunch",
            source_type=SourceType.CUSTOM,
            provider="fortytwocrunch",
        )

        token = self.get_secret("FORTYTWOCRUNCH_API_KEY")
        base_url = self.config.settings.get("base_url", FORTYTWOCRUNCH_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in FORTYTWOCRUNCH_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="fortytwocrunch",
                            source_type=SourceType.CUSTOM,
                            provider="fortytwocrunch",
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
                    log.debug("42Crunch %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "X-API-KEY": token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


# Register
registry.register("fortytwocrunch", FortyTwoCrunchConnector)
