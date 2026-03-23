"""Secureframe connector — Layer 1 implementation for GRC.

Collects controls, tests, and personnel from Secureframe REST APIs.
Uses API key authentication via Bearer token.
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

SECUREFRAME_BASE_URL = "https://api.secureframe.com"

SECUREFRAME_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/controls", "secureframe_controls", {"per_page": "100", "page": "1"}),
    ("/api/v1/tests", "secureframe_tests", {"per_page": "100", "page": "1"}),
    ("/api/v1/personnel", "secureframe_personnel", {"per_page": "100", "page": "1"}),
]


class SecureframeConnector(BaseConnector):
    """Collects compliance telemetry from Secureframe REST APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("SECUREFRAME_API_KEY"):
            errors.append("SECUREFRAME_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            api_key = self.get_secret("SECUREFRAME_API_KEY")
            base_url = self.config.settings.get("base_url", SECUREFRAME_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/v1/controls",
                headers={"Authorization": f"Bearer {api_key}"},
                params={"per_page": "1", "page": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="secureframe",
            source_type=SourceType.GRC,
            provider="secureframe",
        )

        base_url = self.config.settings.get("base_url", SECUREFRAME_BASE_URL)
        api_key = self.get_secret("SECUREFRAME_API_KEY")
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type, params in SECUREFRAME_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="secureframe",
                            source_type=SourceType.GRC,
                            provider="secureframe",
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
                    log.debug("Secureframe %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow Secureframe page-based pagination."""
        all_items: list = []
        current_params = dict(params)
        page = int(current_params.get("page", 1))

        while True:
            current_params["page"] = str(page)
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            items = body.get("data", body.get("items", []))
            if not isinstance(items, list):
                items = []
            all_items.extend(items)

            meta = body.get("meta", {})
            total_pages = meta.get("total_pages", meta.get("pages", 1))
            if page >= total_pages or not items:
                break
            page += 1

        return all_items


# Register
registry.register("secureframe", SecureframeConnector)
