"""Code42 Incydr connector — Layer 1 implementation for DLP.

Collects alerts, file events, and user data from the Code42 Incydr API.
Uses Code42 REST API v1 via httpx with API key authentication.
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

CODE42_BASE_URL = "https://api.us.code42.com"

CODE42_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/v1/alerts", "code42_alerts", {"pgSize": "100", "pgNum": "1"}),
    ("/v1/file-events", "code42_file_events", {"pgSize": "100", "pgNum": "1"}),
    ("/v1/users", "code42_users", {"pgSize": "100", "pgNum": "1"}),
]


class Code42Connector(BaseConnector):
    """Collects compliance telemetry from the Code42 Incydr DLP API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("CODE42_API_KEY"):
            errors.append("CODE42_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("CODE42_API_KEY")
            base_url = self.config.settings.get("base_url", CODE42_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v1/users",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="code42",
            source_type=SourceType.DLP,
            provider="code42",
        )

        token = self.get_secret("CODE42_API_KEY")
        base_url = self.config.settings.get("base_url", CODE42_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in CODE42_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="code42",
                            source_type=SourceType.DLP,
                            provider="code42",
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
                    log.debug("Code42 %s failed: %s", endpoint, e)
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
registry.register("code42", Code42Connector)
