"""Orca Security connector — collects cloud alerts, assets, and compliance findings."""

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

ORCA_BASE_URL = "https://api.orcasecurity.io"

ORCA_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/alerts", "orca_alerts", {"limit": "100"}),
    ("/api/assets", "orca_assets", {"limit": "100"}),
    ("/api/compliance", "orca_compliance", {"limit": "100"}),
]


class OrcaConnector(BaseConnector):
    """Collects CSPM findings from Orca Security REST API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("ORCA_API_TOKEN"):
            errors.append("ORCA_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("ORCA_API_TOKEN")
            base_url = self.config.settings.get("base_url", ORCA_BASE_URL)
            resp = httpx.get(
                f"{base_url}/api/assets",
                headers=self._headers(token),
                params={"limit": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="orca",
            source_type=SourceType.CSPM,
            provider="orca",
        )

        token = self.get_secret("ORCA_API_TOKEN")
        base_url = self.config.settings.get("base_url", ORCA_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in ORCA_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params, event_type)
                    result.events.append(
                        RawEventData(
                            source="orca",
                            source_type=SourceType.CSPM,
                            provider="orca",
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
                    log.debug("Orca %s failed: %s", endpoint, e)
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
        """Paginate Orca cursor-based responses."""
        all_items: list = []
        current_params = dict(params)

        _key_map = {
            "orca_alerts": "data",
            "orca_assets": "data",
            "orca_compliance": "data",
        }
        data_key = _key_map.get(event_type, "data")

        while True:
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()
            items = body.get(data_key, [])
            all_items.extend(items)
            next_page = body.get("next_page_token") or body.get("nextPageToken")
            if not next_page or not items:
                break
            current_params["page_token"] = next_page

        return all_items


registry.register("orca", OrcaConnector)
