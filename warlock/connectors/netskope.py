"""Netskope connector — Layer 1 implementation for CASB / cloud security.

Collects alerts (DLP, anomaly, compromised credential), events
(application, page, network), and client status via Netskope REST API v2.
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

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


class NetskopeConnector(BaseConnector):
    """Collects compliance telemetry from Netskope REST API v2."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[netskope]")
        if not self.get_secret("WLK_NETSKOPE_TENANT_URL"):
            errors.append("WLK_NETSKOPE_TENANT_URL not set")
        if not self.get_secret("WLK_NETSKOPE_API_TOKEN"):
            errors.append("WLK_NETSKOPE_API_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            tenant_url = self.get_secret("WLK_NETSKOPE_TENANT_URL").rstrip("/")
            resp = client.get(f"{tenant_url}/api/v2/events/data/alert", params={"limit": 1})
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="netskope",
            source_type=SourceType.DLP,
            provider="netskope",
        )

        client = self._client()
        tenant_url = self.get_secret("WLK_NETSKOPE_TENANT_URL").rstrip("/")

        self._collect_alerts(client, tenant_url, result)
        self._collect_events(client, tenant_url, result)
        self._collect_clients(client, tenant_url, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _client(self) -> httpx.Client:
        """Build an httpx client with Netskope v2 token auth."""
        token = self.get_secret("WLK_NETSKOPE_API_TOKEN")
        headers = {
            "Content-Type": "application/json",
            "Netskope-Api-Token": token,
        }
        return httpx.Client(headers=headers, timeout=self.config.timeout_seconds)

    # -- Pagination --

    def _paginate(
        self,
        client: httpx.Client,
        url: str,
        result_key: str = "data",
    ) -> list:
        """Offset-based pagination for Netskope API v2."""
        max_pages = self.config.settings.get("max_pages", 20)
        per_page = self.config.settings.get("per_page", 100)
        all_items: list = []
        skip = 0

        for _ in range(max_pages):
            resp = client.get(url, params={"limit": per_page, "skip": skip})
            resp.raise_for_status()
            body = resp.json()

            items = body.get(result_key, [])
            if not items:
                break

            all_items.extend(items)
            skip += len(items)

            total = body.get("total", 0)
            if total and skip >= total:
                break

        return all_items

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="netskope",
            source_type=SourceType.DLP,
            provider="netskope",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_alerts(
        self, client: httpx.Client, tenant_url: str, result: ConnectorResult
    ) -> None:
        """Collect alerts (DLP, anomaly, compromised credential, malware)."""
        try:
            url = f"{tenant_url}/api/v2/events/data/alert"
            alerts = self._paginate(client, url, result_key="data")
            result.events.append(
                self._raw_event(
                    "netskope_alerts",
                    {"alerts": alerts},
                )
            )
        except Exception as e:
            log.debug("Netskope alerts collection failed: %s", e)
            result.errors.append(f"netskope_alerts: {e}")

    def _collect_events(
        self, client: httpx.Client, tenant_url: str, result: ConnectorResult
    ) -> None:
        """Collect application/page/network events."""
        try:
            url = f"{tenant_url}/api/v2/events/data/application"
            events = self._paginate(client, url, result_key="data")
            result.events.append(
                self._raw_event(
                    "netskope_events",
                    {"events": events},
                )
            )
        except Exception as e:
            log.debug("Netskope events collection failed: %s", e)
            result.errors.append(f"netskope_events: {e}")

    def _collect_clients(
        self, client: httpx.Client, tenant_url: str, result: ConnectorResult
    ) -> None:
        """Collect Netskope client (agent) status."""
        try:
            url = f"{tenant_url}/api/v2/steering/clients"
            clients = self._paginate(client, url, result_key="data")
            result.events.append(
                self._raw_event(
                    "netskope_clients",
                    {"clients": clients},
                )
            )
        except Exception as e:
            log.debug("Netskope clients collection failed: %s", e)
            result.errors.append(f"netskope_clients: {e}")


# Register
registry.register("netskope", NetskopeConnector)
