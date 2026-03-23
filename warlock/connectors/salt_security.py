"""Salt Security connector — Layer 1 implementation for CUSTOM (API Security).

Collects API inventory, alerts, and findings from the Salt Security platform.
Authenticates with a bearer API token.
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

SALT_SECURITY_BASE_URL = "https://api.saltsecurity.com"

SALT_SECURITY_ENDPOINTS: list[tuple[str, str]] = [
    ("/v1/apis", "salt_security_apis"),
    ("/v1/alerts", "salt_security_alerts"),
    ("/v1/findings", "salt_security_findings"),
]


class SaltSecurityConnector(BaseConnector):
    """Collects API security telemetry from the Salt Security platform."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("SALT_API_TOKEN"):
            errors.append("SALT_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("SALT_API_TOKEN")
            base_url = self.config.settings.get("base_url", SALT_SECURITY_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v1/apis",
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
            source="salt_security",
            source_type=SourceType.CUSTOM,
            provider="salt_security",
        )

        token = self.get_secret("SALT_API_TOKEN")
        base_url = self.config.settings.get("base_url", SALT_SECURITY_BASE_URL)
        headers = self._headers(token)
        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type in SALT_SECURITY_ENDPOINTS:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    body = resp.json()
                    items = (
                        body if isinstance(body, list) else body.get("data", body.get("items", []))
                    )
                    result.events.append(
                        RawEventData(
                            source="salt_security",
                            source_type=SourceType.CUSTOM,
                            provider="salt_security",
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
                    log.debug("Salt Security %s failed: %s", endpoint, e)
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
registry.register("salt_security", SaltSecurityConnector)
