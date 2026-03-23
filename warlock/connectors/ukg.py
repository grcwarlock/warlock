"""UKG connector — Layer 1 implementation for HRIS.

Collects employee records and employment records via UKG Pro Personnel API v1.
Uses API key authentication.
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

UKG_BASE_URL = "https://api.ultipro.com"

UKG_ENDPOINTS: list[tuple[str, str]] = [
    ("/personnel/v1/employees", "ukg_employees"),
    ("/personnel/v1/employment-records", "ukg_employment_records"),
]


class UKGConnector(BaseConnector):
    """Collects compliance telemetry from UKG Pro HR APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("UKG_API_KEY"):
            errors.append("UKG_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("UKG_API_KEY")
            base_url = self.config.settings.get("base_url", UKG_BASE_URL)
            resp = httpx.get(
                f"{base_url}/personnel/v1/employees",
                headers=self._headers(token),
                params={"per_page": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="ukg",
            source_type=SourceType.HRIS,
            provider="ukg",
        )

        token = self.get_secret("UKG_API_KEY")
        base_url = self.config.settings.get("base_url", UKG_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in UKG_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="ukg",
                            source_type=SourceType.HRIS,
                            provider="ukg",
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
                    log.debug("UKG %s failed: %s", endpoint, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "US-Customer-Api-Key": token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow UKG page-based pagination."""
        all_items: list = []
        page = 1
        per_page = 200

        while True:
            resp = client.get(  # type: ignore[attr-defined]
                endpoint, params={"page": page, "per_page": per_page}
            )
            resp.raise_for_status()
            body = resp.json()

            items = (
                body if isinstance(body, list) else body.get("employees", body.get("records", []))
            )
            all_items.extend(items)

            if len(items) < per_page:
                break
            page += 1

        return all_items


# Register
registry.register("ukg", UKGConnector)
