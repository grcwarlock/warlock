"""CloudHealth connector — Layer 1 implementation for FINOPS.

Collects data from the CloudHealth API.
Uses Bearer token authentication via CLOUDHEALTH_API_KEY.
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

CLOUDHEALTH_BASE_URL = "https://chapi.cloudhealthtech.com/v1"

CLOUDHEALTH_ENDPOINTS: list[tuple[str, str]] = [
    ("/aws_accounts", "cloudhealth_accounts"),
    ("/reports/cost/current", "cloudhealth_cost"),
    ("/olap_reports/cost/current", "cloudhealth_olap"),
]


class CloudHealthConnector(BaseConnector):
    """Collects compliance telemetry from the CloudHealth API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("CLOUDHEALTH_API_KEY"):
            errors.append("CLOUDHEALTH_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("CLOUDHEALTH_API_KEY")
            base_url = self.config.settings.get("base_url", CLOUDHEALTH_BASE_URL)
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
            source="cloudhealth",
            source_type=SourceType.FINOPS,
            provider="cloudhealth",
        )

        token = self.get_secret("CLOUDHEALTH_API_KEY")
        base_url = self.config.settings.get("base_url", CLOUDHEALTH_BASE_URL)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type in CLOUDHEALTH_ENDPOINTS:
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
                            source="cloudhealth",
                            source_type=SourceType.FINOPS,
                            provider="cloudhealth",
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
                    log.debug("CloudHealth %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result


# Register
registry.register("cloudhealth", CloudHealthConnector)
