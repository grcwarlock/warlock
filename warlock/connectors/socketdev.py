"""Socket.dev connector — Layer 1 implementation for CODE.

Collects repository and alert data from the Socket Security API.
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

SOCKETDEV_BASE_URL = "https://api.socket.dev"


class SocketdevConnector(BaseConnector):
    """Collects code security telemetry from the Socket.dev API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("SOCKETDEV_API_KEY"):
            errors.append("SOCKETDEV_API_KEY env var is not set")
        if not self.config.settings.get("org_slug"):
            errors.append("org_slug must be set in connector settings")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("SOCKETDEV_API_KEY")
            org_slug = self.config.settings.get("org_slug", "")
            base_url = self.config.settings.get("base_url", SOCKETDEV_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v0/orgs/{org_slug}/repos",
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
            source="socketdev",
            source_type=SourceType.CODE,
            provider="socketdev",
        )

        token = self.get_secret("SOCKETDEV_API_KEY")
        org_slug = self.config.settings.get("org_slug", "")
        base_url = self.config.settings.get("base_url", SOCKETDEV_BASE_URL)
        headers = self._headers(token)

        endpoints: list[tuple[str, str]] = [
            (f"/v0/orgs/{org_slug}/repos", "socketdev_repos"),
            (f"/v0/orgs/{org_slug}/alerts", "socketdev_alerts"),
        ]

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type in endpoints:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    body = resp.json()
                    items = (
                        body
                        if isinstance(body, list)
                        else body.get("results", body.get("data", []))
                    )
                    result.events.append(
                        RawEventData(
                            source="socketdev",
                            source_type=SourceType.CODE,
                            provider="socketdev",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "org_slug": org_slug,
                                "response": items,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Socket.dev %s failed: %s", endpoint, e)
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
registry.register("socketdev", SocketdevConnector)
