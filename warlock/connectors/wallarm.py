"""Wallarm connector — Layer 1 implementation for NETWORK.

Collects attacks, vulnerabilities, and rules from the Wallarm REST API.
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

WALLARM_BASE_URL = "https://api.wallarm.com"

WALLARM_ENDPOINTS: list[tuple[str, str]] = [
    ("/v2/objects/attack", "wallarm_attacks"),
    ("/v2/objects/vuln", "wallarm_vulns"),
    ("/v2/objects/rule", "wallarm_rules"),
]


class WallarmConnector(BaseConnector):
    """Collects network security telemetry from the Wallarm REST API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("WALLARM_API_TOKEN"):
            errors.append("WALLARM_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("WALLARM_API_TOKEN")
            base_url = self.config.settings.get("base_url", WALLARM_BASE_URL)
            resp = httpx.post(
                f"{base_url}/v2/objects/attack",
                headers=self._headers(token),
                json={"filter": {}, "limit": 1, "offset": 0},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="wallarm",
            source_type=SourceType.NETWORK,
            provider="wallarm",
        )

        token = self.get_secret("WALLARM_API_TOKEN")
        base_url = self.config.settings.get("base_url", WALLARM_BASE_URL)
        headers = self._headers(token)
        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type in WALLARM_ENDPOINTS:
                try:
                    # Wallarm uses POST for object queries
                    resp = client.post(
                        endpoint,
                        json={"filter": {}, "limit": 500, "offset": 0},
                    )
                    resp.raise_for_status()
                    body = resp.json()
                    # Wallarm returns {"objects": [...], "status": "ok"}
                    items = body.get("objects", body if isinstance(body, list) else [])
                    result.events.append(
                        RawEventData(
                            source="wallarm",
                            source_type=SourceType.NETWORK,
                            provider="wallarm",
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
                    log.debug("Wallarm %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "X-WallarmApi-Token": token,
            "Content-Type": "application/json",
        }


# Register
registry.register("wallarm", WallarmConnector)
