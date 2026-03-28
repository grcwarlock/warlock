"""Claroty xDome connector — ICS/OT asset visibility and threat detection.

Collects asset inventory, alerts, and vulnerability data from the Claroty
xDome REST API. Requires API key authentication via CLAROTY_API_KEY.
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

CLAROTY_ENDPOINTS: list[tuple[str, str]] = [
    ("/api/v1/assets", "claroty_assets"),
    ("/api/v1/alerts", "claroty_alerts"),
    ("/api/v1/vulnerabilities", "claroty_vulnerabilities"),
]


class ClarotyConnector(BaseConnector):
    """Collects ICS/OT asset and threat data from Claroty xDome REST API.

    Configuration:
        CLAROTY_BASE_URL: Base URL of the Claroty xDome instance
        CLAROTY_API_KEY: API key for authentication

    The connector queries asset inventory (PLCs, RTUs, HMIs), active alerts,
    and known vulnerabilities across the OT network.
    """

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("CLAROTY_BASE_URL"):
            errors.append("CLAROTY_BASE_URL env var is not set")
        if not self.get_secret("CLAROTY_API_KEY"):
            errors.append("CLAROTY_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.get_secret("CLAROTY_BASE_URL").rstrip("/")
            api_key = self.get_secret("CLAROTY_API_KEY")
            resp = httpx.get(
                f"{base_url}/api/v1/health",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=15,
            )
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="claroty",
            source_type=SourceType.INFRASTRUCTURE,
            provider="claroty",
        )

        base_url = self.get_secret("CLAROTY_BASE_URL").rstrip("/")
        api_key = self.get_secret("CLAROTY_API_KEY")

        client = httpx.Client(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            },
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in CLAROTY_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="claroty",
                            source_type=SourceType.INFRASTRUCTURE,
                            provider="claroty",
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
                    log.debug("Claroty %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow offset-based pagination."""
        all_items: list = []
        offset = 0
        limit = 100

        while True:
            resp = client.get(  # type: ignore[attr-defined]
                endpoint, params={"offset": offset, "limit": limit}
            )
            resp.raise_for_status()
            body = resp.json()

            items = body.get("objects", body.get("data", body.get("results", [])))
            if not isinstance(items, list):
                items = []
            all_items.extend(items)

            total = body.get("total_count", body.get("total", len(all_items)))
            if len(all_items) >= total or len(items) < limit:
                break
            offset += limit

        return all_items


# Register
registry.register("claroty", ClarotyConnector)
