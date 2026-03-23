"""Cobalt connector — Layer 1 implementation for Pentest-as-a-Service.

Collects asset, pentest, and finding data from the Cobalt API.
Uses Cobalt REST API v2 via httpx with API token authentication.
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

COBALT_BASE_URL = "https://api.us.cobalt.io"

COBALT_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/v2/assets", "cobalt_assets", {"limit": "100", "cursor": ""}),
    ("/v2/pentests", "cobalt_pentests", {"limit": "100", "cursor": ""}),
    ("/v2/findings", "cobalt_findings", {"limit": "100", "cursor": ""}),
]


class CobaltConnector(BaseConnector):
    """Collects pentest telemetry from the Cobalt PtaaS API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("COBALT_API_TOKEN"):
            errors.append("COBALT_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("COBALT_API_TOKEN")
            base_url = self.config.settings.get("base_url", COBALT_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v2/assets",
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
            source="cobalt",
            source_type=SourceType.CUSTOM,
            provider="cobalt",
        )

        token = self.get_secret("COBALT_API_TOKEN")
        base_url = self.config.settings.get("base_url", COBALT_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in COBALT_ENDPOINTS:
                try:
                    clean_params = {k: v for k, v in params.items() if v}
                    resp = client.get(endpoint, params=clean_params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="cobalt",
                            source_type=SourceType.CUSTOM,
                            provider="cobalt",
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
                    log.debug("Cobalt %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.cobalt.v2+json",
            "Content-Type": "application/json",
        }


# Register
registry.register("cobalt", CobaltConnector)
