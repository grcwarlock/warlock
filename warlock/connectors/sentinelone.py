"""SentinelOne connector — Layer 1 implementation for EDR.

Collects agents, threats, installed applications, and policies
via the SentinelOne REST API using httpx.
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

# SentinelOne API endpoints → event_type
S1_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/web/api/v2.1/agents", "s1_agents", {}),
    ("/web/api/v2.1/threats", "s1_threats", {}),
    ("/web/api/v2.1/installed-applications", "s1_applications", {}),
    ("/web/api/v2.1/policies", "s1_policies", {}),
]


class SentinelOneConnector(BaseConnector):
    """Collects compliance telemetry from SentinelOne Management Console."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install httpx")
        if not self._get_api_token():
            errors.append("SentinelOne API token not configured (set SENTINELONE_API_TOKEN or config.settings.api_token)")
        if not self._get_base_url():
            errors.append("SentinelOne base_url not configured (set config.settings.base_url)")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx
            resp = httpx.get(
                f"{self._get_base_url()}/web/api/v2.1/system/status",
                headers=self._auth_headers(),
                timeout=30,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="sentinelone",
            source_type=SourceType.EDR,
            provider="sentinelone",
        )

        base_url = self._get_base_url()
        headers = self._auth_headers()
        timeout = self.config.timeout_seconds

        for endpoint, event_type, params in S1_ENDPOINTS:
            try:
                all_records = []
                url: str | None = f"{base_url}{endpoint}"
                request_params = {**params, "limit": 1000}

                # Handle cursor-based pagination
                while url:
                    resp = httpx.get(url, headers=headers, params=request_params, timeout=timeout)
                    resp.raise_for_status()
                    body = resp.json()
                    records = body.get("data", [])
                    all_records.extend(records)

                    # SentinelOne uses cursor pagination
                    cursor = body.get("pagination", {}).get("nextCursor")
                    if cursor:
                        request_params = {**params, "limit": 1000, "cursor": cursor}
                    else:
                        url = None

                    # Safety: cap at 10k records per endpoint
                    if len(all_records) >= 10000:
                        log.warning("SentinelOne %s: capped at 10k records", event_type)
                        break

                result.events.append(RawEventData(
                    source="sentinelone",
                    source_type=SourceType.EDR,
                    provider="sentinelone",
                    event_type=event_type,
                    raw_data={
                        "endpoint": endpoint,
                        "records": all_records,
                        "total": len(all_records),
                    },
                    observed_at=datetime.now(timezone.utc),
                ))
            except Exception as e:
                log.debug("SentinelOne %s failed: %s", endpoint, e)
                result.errors.append(f"{event_type}: {e}")

        result.complete()
        return result

    # -- Auth helpers --

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"APIToken {self._get_api_token()}",
            "Content-Type": "application/json",
        }

    def _get_api_token(self) -> str:
        return self.config.settings.get("api_token", "") or self.get_secret("SENTINELONE_API_TOKEN")

    def _get_base_url(self) -> str:
        return self.config.settings.get("base_url", "") or self.get_secret("SENTINELONE_BASE_URL")


# Register
registry.register("sentinelone", SentinelOneConnector)
