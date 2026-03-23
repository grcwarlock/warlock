"""Drata connector — Layer 1 implementation for GRC.

Collects controls, monitors, and personnel from Drata public APIs.
Uses API key authentication via Bearer token.
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

DRATA_BASE_URL = "https://public-api.drata.com"

DRATA_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/public/controls", "drata_controls", {"limit": "100", "page": "1"}),
    ("/public/monitors", "drata_monitors", {"limit": "100", "page": "1"}),
    ("/public/personnel", "drata_personnel", {"limit": "100", "page": "1"}),
]


class DrataConnector(BaseConnector):
    """Collects compliance telemetry from Drata public APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("DRATA_API_KEY"):
            errors.append("DRATA_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            api_key = self.get_secret("DRATA_API_KEY")
            base_url = self.config.settings.get("base_url", DRATA_BASE_URL)
            resp = httpx.get(
                f"{base_url}/public/controls",
                headers={"Authorization": f"Bearer {api_key}"},
                params={"limit": "1", "page": "1"},
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
            source="drata",
            source_type=SourceType.GRC,
            provider="drata",
        )

        base_url = self.config.settings.get("base_url", DRATA_BASE_URL)
        api_key = self.get_secret("DRATA_API_KEY")
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type, params in DRATA_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="drata",
                            source_type=SourceType.GRC,
                            provider="drata",
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
                    log.debug("Drata %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow Drata page-based pagination."""
        all_items: list = []
        current_params = dict(params)
        page = int(current_params.get("page", 1))

        while True:
            current_params["page"] = str(page)
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            items = body.get("items", body.get("data", []))
            if not isinstance(items, list):
                items = []
            all_items.extend(items)

            total_pages = body.get("totalPages", body.get("pages", 1))
            if page >= total_pages or not items:
                break
            page += 1

        return all_items


# Register
registry.register("drata", DrataConnector)
