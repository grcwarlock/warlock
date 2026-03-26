"""Harness connector — Layer 1 implementation for CI_CD.

Collects data from the Harness API.
Uses Bearer token authentication via HARNESS_API_KEY.
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

HARNESS_BASE_URL = "https://app.harness.io/gateway/api"

HARNESS_ENDPOINTS: list[tuple[str, str]] = [
    ("/pipelines", "harness_pipelines"),
    ("/executions", "harness_executions"),
    ("/connectors", "harness_connectors"),
]


class HarnessConnector(BaseConnector):
    """Collects compliance telemetry from the Harness API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("HARNESS_API_KEY"):
            errors.append("HARNESS_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("HARNESS_API_KEY")
            base_url = self.config.settings.get("base_url", HARNESS_BASE_URL)
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
            source="harness",
            source_type=SourceType.CI_CD,
            provider="harness",
        )

        token = self.get_secret("HARNESS_API_KEY")
        base_url = self.config.settings.get("base_url", HARNESS_BASE_URL)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type in HARNESS_ENDPOINTS:
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
                            source="harness",
                            source_type=SourceType.CI_CD,
                            provider="harness",
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
                    log.debug("Harness %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result


# Register
registry.register("harness", HarnessConnector)
