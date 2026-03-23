"""Rapid7 InsightVM connector — collects assets, vulnerabilities, and scan metadata."""

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

RAPID7_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/3/assets", "rapid7_assets", {"size": "500"}),
    ("/api/3/vulnerabilities", "rapid7_vulnerabilities", {"size": "500"}),
    ("/api/3/scans", "rapid7_scans", {"size": "500"}),
]


class Rapid7Connector(BaseConnector):
    """Collects vulnerability and asset data from Rapid7 InsightVM REST API v3."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("RAPID7_API_KEY"):
            errors.append("RAPID7_API_KEY env var is not set")
        if not self.config.settings.get("base_url"):
            errors.append("settings.base_url is required (e.g. https://myhost:3780)")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            api_key = self.get_secret("RAPID7_API_KEY")
            base_url = self.config.settings.get("base_url", "")
            resp = httpx.get(
                f"{base_url}/api/3/administration/info",
                headers=self._headers(api_key),
                timeout=self.config.timeout_seconds,
                verify=self.config.settings.get("verify_ssl", True),
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="rapid7",
            source_type=SourceType.SCANNER,
            provider="rapid7",
        )

        api_key = self.get_secret("RAPID7_API_KEY")
        base_url = self.config.settings.get("base_url", "")
        verify_ssl = self.config.settings.get("verify_ssl", True)
        headers = self._headers(api_key)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
            verify=verify_ssl,
        )

        try:
            for endpoint, event_type, params in RAPID7_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="rapid7",
                            source_type=SourceType.SCANNER,
                            provider="rapid7",
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
                    log.debug("Rapid7 %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, api_key: str) -> dict[str, str]:
        return {
            "X-Api-Key": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Paginate Rapid7 InsightVM page-based responses."""
        all_items: list = []
        page = 0
        size = int(params.get("size", 500))
        current_params = dict(params)

        while True:
            current_params["page"] = str(page)
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()
            resources = body.get("resources", [])
            all_items.extend(resources)

            page_info = body.get("page", {})
            total_pages = page_info.get("totalPages", 1)
            if page + 1 >= total_pages or len(resources) < size:
                break
            page += 1

        return all_items


registry.register("rapid7", Rapid7Connector)
