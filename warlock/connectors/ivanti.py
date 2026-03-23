"""Ivanti Patch connector — Layer 1 implementation for MDM.

Collects machine inventory, patch catalog, and patch deployment status
from the Ivanti Patch Management REST API using API key authentication.
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

IVANTI_BASE_URL = "https://ivanti.example.com"

ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/patch/machines", "ivanti_machines", {"limit": "100", "offset": "0"}),
    ("/api/patch/patches", "ivanti_patches", {"limit": "100", "offset": "0"}),
    ("/api/patch/deployments", "ivanti_deployments", {"limit": "100", "offset": "0"}),
]


class IvantiConnector(BaseConnector):
    """Collects patch management telemetry from Ivanti REST API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("IVANTI_API_KEY"):
            errors.append("IVANTI_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("IVANTI_API_KEY")
            base_url = self.config.settings.get("base_url", IVANTI_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/patch/machines",
                headers=self._headers(token),
                params={"limit": "1", "offset": "0"},
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
            source="ivanti",
            source_type=SourceType.MDM,
            provider="ivanti",
        )

        token = self.get_secret("IVANTI_API_KEY")
        base_url = self.config.settings.get("base_url", IVANTI_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params, event_type)
                    result.events.append(
                        RawEventData(
                            source="ivanti",
                            source_type=SourceType.MDM,
                            provider="ivanti",
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
                    log.debug("Ivanti %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str, params: dict, event_type: str) -> list:
        """Follow Ivanti offset-based pagination."""
        all_items: list = []
        limit = int(params.get("limit", 100))
        offset = 0
        current_params = dict(params)

        while True:
            current_params["offset"] = str(offset)
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            # Ivanti may return a list directly or wrap in {"data": [...]}
            if isinstance(body, list):
                items = body
            else:
                items = body.get("data", body.get("items", body.get("results", [])))

            all_items.extend(items)

            if len(items) < limit:
                break
            offset += limit

        return all_items


# Register
registry.register("ivanti", IvantiConnector)
