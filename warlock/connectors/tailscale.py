"""Tailscale connector — Layer 1 implementation for Network / Zero Trust.

Collects device inventory and ACL policies from the Tailscale API.
Uses Tailscale REST API v2 via httpx with API key authentication.
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

TAILSCALE_BASE_URL = "https://api.tailscale.com"


class TailscaleConnector(BaseConnector):
    """Collects compliance telemetry from the Tailscale network API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("TAILSCALE_API_KEY"):
            errors.append("TAILSCALE_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("TAILSCALE_API_KEY")
            base_url = self.config.settings.get("base_url", TAILSCALE_BASE_URL)
            tailnet = self.config.settings.get("tailnet", "-")
            resp = httpx.get(
                f"{base_url}/api/v2/tailnet/{tailnet}/devices",
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
            source="tailscale",
            source_type=SourceType.NETWORK,
            provider="tailscale",
        )

        token = self.get_secret("TAILSCALE_API_KEY")
        base_url = self.config.settings.get("base_url", TAILSCALE_BASE_URL)
        tailnet = self.config.settings.get("tailnet", "-")
        headers = self._headers(token)

        endpoints: list[tuple[str, str]] = [
            (f"/api/v2/tailnet/{tailnet}/devices", "tailscale_devices"),
            (f"/api/v2/tailnet/{tailnet}/acl", "tailscale_acl"),
        ]

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in endpoints:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="tailscale",
                            source_type=SourceType.NETWORK,
                            provider="tailscale",
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
                    log.debug("Tailscale %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }


# Register
registry.register("tailscale", TailscaleConnector)
