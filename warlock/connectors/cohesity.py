"""Cohesity connector — Layer 1 implementation for Backup.

Collects protection job and protection run data from the Cohesity API.
Uses Cohesity Iris Services API v1 via httpx with API key authentication.
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

COHESITY_BASE_URL = "https://api.cohesity.com"

COHESITY_ENDPOINTS: list[tuple[str, str, dict]] = [
    (
        "/irisservices/api/v1/public/protectionJobs",
        "cohesity_protection_jobs",
        {"includeLastRunAndStats": "true"},
    ),
    (
        "/irisservices/api/v1/public/protectionRuns",
        "cohesity_protection_runs",
        {"numRuns": "100"},
    ),
]


class CohesityConnector(BaseConnector):
    """Collects backup compliance telemetry from the Cohesity API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("COHESITY_API_KEY"):
            errors.append("COHESITY_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("COHESITY_API_KEY")
            base_url = self.config.settings.get("base_url", COHESITY_BASE_URL)
            resp = httpx.get(
                f"{base_url}/irisservices/api/v1/public/protectionJobs",
                headers=self._headers(token),
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
            source="cohesity",
            source_type=SourceType.BACKUP,
            provider="cohesity",
        )

        token = self.get_secret("COHESITY_API_KEY")
        base_url = self.config.settings.get("base_url", COHESITY_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in COHESITY_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="cohesity",
                            source_type=SourceType.BACKUP,
                            provider="cohesity",
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
                    log.debug("Cohesity %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "apiKey": token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


# Register
registry.register("cohesity", CohesityConnector)
