"""Vantage connector — Layer 1 implementation for FINOPS.

Collects data from the Vantage API.
Uses Bearer token authentication via VANTAGE_API_KEY.
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

VANTAGE_FINOPS_BASE_URL = "https://api.vantage.sh/v2"

VANTAGE_FINOPS_ENDPOINTS: list[tuple[str, str]] = [
    ("/costs", "vantage_costs"),
    ("/cost_reports", "vantage_cost_reports"),
    ("/providers", "vantage_providers"),
]


class VantageFinOpsConnector(BaseConnector):
    """Collects compliance telemetry from the Vantage API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("VANTAGE_API_KEY"):
            errors.append("VANTAGE_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("VANTAGE_API_KEY")
            base_url = self.config.settings.get("base_url", VANTAGE_FINOPS_BASE_URL)
            resp = httpx.get(
                base_url,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
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
            source="vantage_finops",
            source_type=SourceType.FINOPS,
            provider="vantage_finops",
        )

        token = self.get_secret("VANTAGE_API_KEY")
        base_url = self.config.settings.get("base_url", VANTAGE_FINOPS_BASE_URL)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type in VANTAGE_FINOPS_ENDPOINTS:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    data = resp.json()
                    items = (
                        data
                        if isinstance(data, list)
                        else data.get("data", data.get("results", data.get("items", [data])))
                    )
                    result.events.append(
                        RawEventData(
                            source="vantage_finops",
                            source_type=SourceType.FINOPS,
                            provider="vantage_finops",
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
                    log.debug("Vantage %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result


# Register
registry.register("vantage_finops", VantageFinOpsConnector)
