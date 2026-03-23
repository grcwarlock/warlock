"""runZero connector — Layer 1 implementation for CUSTOM network asset discovery.

Collects network assets, services, and wireless endpoints.
Uses runZero REST API v1.0 via httpx with Bearer token authentication.
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

# Endpoint → (event_type, params) mapping
RUNZERO_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1.0/org/assets", "runzero_assets", {"_limit": "1000"}),
    ("/api/v1.0/org/services", "runzero_services", {"_limit": "1000"}),
    ("/api/v1.0/org/wireless", "runzero_wireless", {"_limit": "1000"}),
]

RUNZERO_BASE_URL = "https://console.runzero.com"


class RunZeroConnector(BaseConnector):
    """Collects network asset discovery data from runZero REST APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("RUNZERO_API_TOKEN"):
            errors.append("RUNZERO_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("RUNZERO_API_TOKEN")
            base_url = self.config.settings.get("base_url", RUNZERO_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1.0/account/orgs",
                headers=self._headers(token),
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
            source="runzero",
            source_type=SourceType.CUSTOM,
            provider="runzero",
        )

        token = self.get_secret("RUNZERO_API_TOKEN")
        base_url = self.config.settings.get("base_url", RUNZERO_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in RUNZERO_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="runzero",
                            source_type=SourceType.CUSTOM,
                            provider="runzero",
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
                    log.debug("runZero %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """runZero returns all results in a single JSON array; no pagination needed."""
        resp = client.get(endpoint, params=params)  # type: ignore[attr-defined]
        resp.raise_for_status()
        body = resp.json()
        if isinstance(body, list):
            return body
        return body.get("data", body.get("results", [body]))


# Register
registry.register("runzero", RunZeroConnector)
