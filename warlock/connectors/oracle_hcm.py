"""Oracle HCM connector — Layer 1 implementation for HRIS.

Collects data from the Oracle HCM API.
Uses Bearer token authentication via ORACLE_HCM_API_KEY.
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

ORACLE_HCM_BASE_URL = "https://{host}/hcmRestApi/resources"

ORACLE_HCM_ENDPOINTS: list[tuple[str, str]] = [
    ("/workers", "oracle_hcm_workers"),
    ("/departments", "oracle_hcm_departments"),
    ("/absences", "oracle_hcm_absences"),
]


class OracleHCMConnector(BaseConnector):
    """Collects compliance telemetry from the Oracle HCM API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("ORACLE_HCM_API_KEY"):
            errors.append("ORACLE_HCM_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("ORACLE_HCM_API_KEY")
            base_url = self.config.settings.get("base_url", ORACLE_HCM_BASE_URL)
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
            source="oracle_hcm",
            source_type=SourceType.HRIS,
            provider="oracle_hcm",
        )

        token = self.get_secret("ORACLE_HCM_API_KEY")
        base_url = self.config.settings.get("base_url", ORACLE_HCM_BASE_URL)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type in ORACLE_HCM_ENDPOINTS:
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
                            source="oracle_hcm",
                            source_type=SourceType.HRIS,
                            provider="oracle_hcm",
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
                    log.debug("Oracle HCM %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result


# Register
registry.register("oracle_hcm", OracleHCMConnector)
