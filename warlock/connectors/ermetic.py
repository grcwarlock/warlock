"""Ermetic (Tenable CIEM) connector — Layer 1 implementation for CSPM.

Collects identity, permission, and finding data from the Ermetic API.
Uses Ermetic REST API v1 via httpx with API key authentication.
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

ERMETIC_BASE_URL = "https://api.ermetic.com"

ERMETIC_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/identities", "ermetic_identities", {"limit": "100", "offset": "0"}),
    ("/api/v1/permissions", "ermetic_permissions", {"limit": "100", "offset": "0"}),
    ("/api/v1/findings", "ermetic_findings", {"limit": "100", "offset": "0"}),
]


class ErmeticConnector(BaseConnector):
    """Collects CSPM/CIEM telemetry from the Ermetic API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("ERMETIC_API_KEY"):
            errors.append("ERMETIC_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("ERMETIC_API_KEY")
            base_url = self.config.settings.get("base_url", ERMETIC_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1/findings",
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
            source="ermetic",
            source_type=SourceType.CSPM,
            provider="ermetic",
        )

        token = self.get_secret("ERMETIC_API_KEY")
        base_url = self.config.settings.get("base_url", ERMETIC_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in ERMETIC_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="ermetic",
                            source_type=SourceType.CSPM,
                            provider="ermetic",
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
                    log.debug("Ermetic %s failed: %s", endpoint, e)
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
registry.register("ermetic", ErmeticConnector)
