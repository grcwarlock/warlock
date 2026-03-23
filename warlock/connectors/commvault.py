"""Commvault connector — Layer 1 implementation for Backup.

Collects client inventory, backup jobs, and backup set data from the Commvault API.
Uses Commvault REST API v4 via httpx with API token authentication.
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

COMMVAULT_BASE_URL = "https://api.commvault.com"

COMMVAULT_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v4/clients", "commvault_clients", {"limit": "100", "offset": "0"}),
    ("/api/v4/jobs", "commvault_jobs", {"limit": "100", "offset": "0"}),
    ("/api/v4/backupsets", "commvault_backupsets", {"limit": "100", "offset": "0"}),
]


class CommvaultConnector(BaseConnector):
    """Collects backup compliance telemetry from the Commvault API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("COMMVAULT_API_TOKEN"):
            errors.append("COMMVAULT_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("COMMVAULT_API_TOKEN")
            base_url = self.config.settings.get("base_url", COMMVAULT_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v4/clients",
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
            source="commvault",
            source_type=SourceType.BACKUP,
            provider="commvault",
        )

        token = self.get_secret("COMMVAULT_API_TOKEN")
        base_url = self.config.settings.get("base_url", COMMVAULT_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in COMMVAULT_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="commvault",
                            source_type=SourceType.BACKUP,
                            provider="commvault",
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
                    log.debug("Commvault %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authtoken": token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


# Register
registry.register("commvault", CommvaultConnector)
