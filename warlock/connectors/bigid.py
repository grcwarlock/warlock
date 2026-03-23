"""BigID connector — Layer 1 implementation for Data Governance.

Collects data catalog, policies, and scan results from the BigID API.
Uses BigID REST API v1 via httpx with API token authentication.
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

BIGID_BASE_URL = "https://api.bigid.com"

BIGID_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/data-catalog", "bigid_data_catalog", {"limit": "100", "skip": "0"}),
    ("/api/v1/policies", "bigid_policies", {"limit": "100", "skip": "0"}),
    ("/api/v1/scans", "bigid_scans", {"limit": "100", "skip": "0"}),
]


class BigIDConnector(BaseConnector):
    """Collects compliance telemetry from the BigID Data Governance API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("BIGID_API_TOKEN"):
            errors.append("BIGID_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("BIGID_API_TOKEN")
            base_url = self.config.settings.get("base_url", BIGID_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1/scans",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="bigid",
            source_type=SourceType.DATA_GOVERNANCE,
            provider="bigid",
        )

        token = self.get_secret("BIGID_API_TOKEN")
        base_url = self.config.settings.get("base_url", BIGID_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in BIGID_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="bigid",
                            source_type=SourceType.DATA_GOVERNANCE,
                            provider="bigid",
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
                    log.debug("BigID %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


# Register
registry.register("bigid", BigIDConnector)
