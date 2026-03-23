"""Vanta API connector — Layer 1 implementation for GRC (extended).

Collects monitors, tests, and vulnerabilities from Vanta REST APIs.
Distinct from the base Vanta connector: focuses on test outcomes and vulns.
Uses API token authentication via Bearer token.
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

VANTA_API_BASE_URL = "https://api.vanta.com"

VANTA_API_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/v1/monitors", "vanta_api_monitors", {"pageSize": "100"}),
    ("/v1/tests", "vanta_api_tests", {"pageSize": "100"}),
    ("/v1/vulnerabilities", "vanta_api_vulnerabilities", {"pageSize": "100"}),
]


class VantaApiConnector(BaseConnector):
    """Collects monitor, test, and vulnerability telemetry from Vanta APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("VANTA_API_TOKEN"):
            errors.append("VANTA_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("VANTA_API_TOKEN")
            base_url = self.config.settings.get("base_url", VANTA_API_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v1/monitors",
                headers={"Authorization": f"Bearer {token}"},
                params={"pageSize": "1"},
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
            source="vanta_api",
            source_type=SourceType.GRC,
            provider="vanta_api",
        )

        base_url = self.config.settings.get("base_url", VANTA_API_BASE_URL)
        token = self.get_secret("VANTA_API_TOKEN")
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type, params in VANTA_API_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="vanta_api",
                            source_type=SourceType.GRC,
                            provider="vanta_api",
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
                    log.debug("Vanta API %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow Vanta cursor-based pagination."""
        all_items: list = []
        current_params = dict(params)

        while True:
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            items = body.get("results", body.get("data", []))
            if not isinstance(items, list):
                items = []
            all_items.extend(items)

            next_cursor = body.get("pageInfo", {}).get("endCursor")
            has_next = body.get("pageInfo", {}).get("hasNextPage", False)
            if not has_next or not next_cursor:
                break
            current_params["pageCursor"] = next_cursor

        return all_items


# Register
registry.register("vanta_api", VantaApiConnector)
