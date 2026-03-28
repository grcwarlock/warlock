"""Nozomi Networks connector — OT/IoT network monitoring and visibility.

Collects asset inventory, alerts, and vulnerability data from the Nozomi
Networks Guardian/Vantage REST API.
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

NOZOMI_ENDPOINTS: list[tuple[str, str]] = [
    ("/api/v1/assets", "nozomi_assets"),
    ("/api/v1/alerts", "nozomi_alerts"),
    ("/api/v1/vulnerabilities", "nozomi_vulnerabilities"),
    ("/api/v1/links", "nozomi_network_links"),
]


class NozomiConnector(BaseConnector):
    """Collects OT/IoT network data from Nozomi Networks Guardian/Vantage API.

    Configuration:
        NOZOMI_BASE_URL: Base URL of the Nozomi Guardian or Vantage instance
        NOZOMI_API_TOKEN: API token for authentication

    The connector queries OT/IoT asset inventory, network anomaly alerts,
    known vulnerabilities, and network communication links.
    """

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("NOZOMI_BASE_URL"):
            errors.append("NOZOMI_BASE_URL env var is not set")
        if not self.get_secret("NOZOMI_API_TOKEN"):
            errors.append("NOZOMI_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.get_secret("NOZOMI_BASE_URL").rstrip("/")
            token = self.get_secret("NOZOMI_API_TOKEN")
            resp = httpx.get(
                f"{base_url}/api/v1/health",
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="nozomi",
            source_type=SourceType.INFRASTRUCTURE,
            provider="nozomi",
        )

        base_url = self.get_secret("NOZOMI_BASE_URL").rstrip("/")
        token = self.get_secret("NOZOMI_API_TOKEN")

        client = httpx.Client(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in NOZOMI_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="nozomi",
                            source_type=SourceType.INFRASTRUCTURE,
                            provider="nozomi",
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
                    log.debug("Nozomi %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow offset-based pagination."""
        all_items: list = []
        offset = 0
        limit = 100

        while True:
            resp = client.get(  # type: ignore[attr-defined]
                endpoint, params={"offset": offset, "limit": limit}
            )
            resp.raise_for_status()
            body = resp.json()

            items = body.get("result", body.get("data", []))
            if not isinstance(items, list):
                items = []
            all_items.extend(items)

            total = body.get("count", body.get("total", len(all_items)))
            if len(all_items) >= total or len(items) < limit:
                break
            offset += limit

        return all_items


# Register
registry.register("nozomi", NozomiConnector)
