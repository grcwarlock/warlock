"""Chainguard connector — Layer 1 implementation for CONTAINER_SECURITY.

Collects images, policies, and vulnerabilities from the Chainguard API.
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

CHAINGUARD_BASE_URL = "https://console-api.enforce.dev"

CHAINGUARD_ENDPOINTS: list[tuple[str, str]] = [
    ("/v1/images", "chainguard_images"),
    ("/v1/policies", "chainguard_policies"),
    ("/v1/vulnerabilities", "chainguard_vulnerabilities"),
]


class ChainguardConnector(BaseConnector):
    """Collects compliance telemetry from the Chainguard API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("CHAINGUARD_API_TOKEN"):
            errors.append("CHAINGUARD_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("CHAINGUARD_API_TOKEN")
            base_url = self.config.settings.get("base_url", CHAINGUARD_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v1/images",
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
            source="chainguard",
            source_type=SourceType.CONTAINER_SECURITY,
            provider="chainguard",
        )

        token = self.get_secret("CHAINGUARD_API_TOKEN")
        base_url = self.config.settings.get("base_url", CHAINGUARD_BASE_URL)
        headers = self._headers(token)
        client = httpx.Client(base_url=base_url, headers=headers, timeout=self.config.timeout_seconds)

        try:
            for endpoint, event_type in CHAINGUARD_ENDPOINTS:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    body = resp.json()
                    items = body if isinstance(body, list) else body.get("items", body.get("data", []))
                    result.events.append(
                        RawEventData(
                            source="chainguard",
                            source_type=SourceType.CONTAINER_SECURITY,
                            provider="chainguard",
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
                    log.debug("Chainguard %s failed: %s", endpoint, e)
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
registry.register("chainguard", ChainguardConnector)
