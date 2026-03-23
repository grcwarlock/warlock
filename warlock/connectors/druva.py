"""Druva connector — Layer 1 implementation for Backup.

Collects endpoint, backup set, and restore data from the Druva inSync API.
Uses Druva REST API v1 via httpx with API key authentication.
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

DRUVA_BASE_URL = "https://apis.druva.com"

DRUVA_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/insync/endpoints", "druva_endpoints", {"pageSize": "100", "pageToken": ""}),
    ("/api/v1/insync/backupsets", "druva_backupsets", {"pageSize": "100", "pageToken": ""}),
    ("/api/v1/insync/restores", "druva_restores", {"pageSize": "100", "pageToken": ""}),
]


class DruvaConnector(BaseConnector):
    """Collects backup compliance telemetry from the Druva inSync API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("DRUVA_API_KEY"):
            errors.append("DRUVA_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("DRUVA_API_KEY")
            base_url = self.config.settings.get("base_url", DRUVA_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1/insync/endpoints",
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
            source="druva",
            source_type=SourceType.BACKUP,
            provider="druva",
        )

        token = self.get_secret("DRUVA_API_KEY")
        base_url = self.config.settings.get("base_url", DRUVA_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in DRUVA_ENDPOINTS:
                try:
                    # Remove empty pageToken to avoid API rejection
                    clean_params = {k: v for k, v in params.items() if v}
                    resp = client.get(endpoint, params=clean_params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="druva",
                            source_type=SourceType.BACKUP,
                            provider="druva",
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
                    log.debug("Druva %s failed: %s", endpoint, e)
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
registry.register("druva", DruvaConnector)
