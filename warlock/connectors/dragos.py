"""Dragos Platform connector — OT threat detection and intelligence.

Collects threat detections, asset inventory, and vulnerability data from
the Dragos Platform API. Requires API key + secret authentication.
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

DRAGOS_ENDPOINTS: list[tuple[str, str]] = [
    ("/api/v1/detections", "dragos_detections"),
    ("/api/v1/assets", "dragos_assets"),
    ("/api/v1/vulnerabilities", "dragos_vulnerabilities"),
    ("/api/v1/zones", "dragos_zones"),
]


class DragosConnector(BaseConnector):
    """Collects OT threat data from the Dragos Platform API.

    Configuration:
        DRAGOS_BASE_URL: Base URL of the Dragos Platform instance
        DRAGOS_API_KEY: API key for authentication
        DRAGOS_API_SECRET: API secret for HMAC-signed requests

    The connector queries threat detections across ICS/SCADA networks,
    OT asset inventory, known vulnerabilities, and network zone topology.
    """

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("DRAGOS_BASE_URL"):
            errors.append("DRAGOS_BASE_URL env var is not set")
        if not self.get_secret("DRAGOS_API_KEY"):
            errors.append("DRAGOS_API_KEY env var is not set")
        if not self.get_secret("DRAGOS_API_SECRET"):
            errors.append("DRAGOS_API_SECRET env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.get_secret("DRAGOS_BASE_URL").rstrip("/")
            api_key = self.get_secret("DRAGOS_API_KEY")
            resp = httpx.get(
                f"{base_url}/api/v1/status",
                headers={"Api-Token": api_key},
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
            source="dragos",
            source_type=SourceType.INFRASTRUCTURE,
            provider="dragos",
        )

        base_url = self.get_secret("DRAGOS_BASE_URL").rstrip("/")
        api_key = self.get_secret("DRAGOS_API_KEY")

        client = httpx.Client(
            base_url=base_url,
            headers={
                "Api-Token": api_key,
                "Accept": "application/json",
            },
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in DRAGOS_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="dragos",
                            source_type=SourceType.INFRASTRUCTURE,
                            provider="dragos",
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
                    log.debug("Dragos %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow cursor-based pagination."""
        all_items: list = []
        page = 1
        per_page = 100

        while True:
            resp = client.get(  # type: ignore[attr-defined]
                endpoint, params={"page": page, "per_page": per_page}
            )
            resp.raise_for_status()
            body = resp.json()

            items = body.get("detections", body.get("data", body.get("results", [])))
            if not isinstance(items, list):
                items = []
            all_items.extend(items)

            total_pages = body.get("total_pages", body.get("pages", 1))
            if page >= total_pages or len(items) < per_page:
                break
            page += 1

        return all_items


# Register
registry.register("dragos", DragosConnector)
