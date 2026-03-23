"""Kubecost connector — Layer 1 implementation for OBSERVABILITY.

Collects allocation, assets, and savings data from the Kubecost API.
Uses API key authentication via KUBECOST_API_KEY.
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

KUBECOST_BASE_URL = "http://localhost:9090"

KUBECOST_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/model/allocation", "kubecost_allocation", {"window": "1d", "aggregate": "namespace"}),
    ("/model/assets", "kubecost_assets", {"window": "1d"}),
    ("/model/savings", "kubecost_savings", {}),
]


class KubecostConnector(BaseConnector):
    """Collects compliance telemetry from the Kubecost Cost Monitoring API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("KUBECOST_API_KEY"):
            errors.append("KUBECOST_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            api_key = self.get_secret("KUBECOST_API_KEY")
            base_url = self.config.settings.get("base_url", KUBECOST_BASE_URL)
            resp = httpx.get(
                f"{base_url}/healthz",
                headers=self._headers(api_key),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="kubecost",
            source_type=SourceType.OBSERVABILITY,
            provider="kubecost",
        )

        api_key = self.get_secret("KUBECOST_API_KEY")
        base_url = self.config.settings.get("base_url", KUBECOST_BASE_URL)
        headers = self._headers(api_key)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in KUBECOST_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    body = resp.json()
                    # Kubecost wraps data in a "data" key
                    data = body.get("data", body)
                    result.events.append(
                        RawEventData(
                            source="kubecost",
                            source_type=SourceType.OBSERVABILITY,
                            provider="kubecost",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "response": data if isinstance(data, list) else [data],
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Kubecost %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, api_key: str) -> dict[str, str]:
        return {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        }


# Register
registry.register("kubecost", KubecostConnector)
