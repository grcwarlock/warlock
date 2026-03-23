"""Smarsh connector — Layer 1 implementation for COLLABORATION.

Collects communication archives, retention policies, and violations via Smarsh API v1.
Uses API key authentication.
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

SMARSH_BASE_URL = "https://api.smarsh.com"

SMARSH_ENDPOINTS: list[tuple[str, str]] = [
    ("/api/v1/archives", "smarsh_archives"),
    ("/api/v1/policies", "smarsh_policies"),
    ("/api/v1/violations", "smarsh_violations"),
]


class SmarshConnector(BaseConnector):
    """Collects compliance telemetry from Smarsh archiving APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("SMARSH_API_KEY"):
            errors.append("SMARSH_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("SMARSH_API_KEY")
            base_url = self.config.settings.get("base_url", SMARSH_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1/archives",
                headers=self._headers(token),
                params={"limit": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="smarsh",
            source_type=SourceType.COLLABORATION,
            provider="smarsh",
        )

        token = self.get_secret("SMARSH_API_KEY")
        base_url = self.config.settings.get("base_url", SMARSH_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in SMARSH_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="smarsh",
                            source_type=SourceType.COLLABORATION,
                            provider="smarsh",
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
                    log.debug("Smarsh %s failed: %s", endpoint, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "X-API-Key": token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow Smarsh offset-based pagination."""
        all_items: list = []
        page = 1
        limit = 100

        while True:
            resp = client.get(  # type: ignore[attr-defined]
                endpoint, params={"page": page, "limit": limit}
            )
            resp.raise_for_status()
            body = resp.json()

            items = body if isinstance(body, list) else body.get("items", body.get("data", []))
            all_items.extend(items)

            if len(items) < limit:
                break
            page += 1

        return all_items


# Register
registry.register("smarsh", SmarshConnector)
