"""Datadog connector — Layer 1 implementation for observability platforms.

Collects monitors, security signals, SLOs, and host inventory
via Datadog API v1/v2.
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


class DatadogConnector(BaseConnector):
    """Collects compliance telemetry from Datadog API v1/v2."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[datadog]")
        if not self.get_secret("WLK_DATADOG_API_KEY"):
            errors.append("WLK_DATADOG_API_KEY not set")
        if not self.get_secret("WLK_DATADOG_APP_KEY"):
            errors.append("WLK_DATADOG_APP_KEY not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self._base_url()}/api/v1/validate")
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="datadog",
            source_type=SourceType.OBSERVABILITY,
            provider="datadog",
        )

        client = self._client()

        self._collect_monitors(client, result)
        self._collect_security_signals(client, result)
        self._collect_slos(client, result)
        self._collect_hosts(client, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _base_url(self) -> str:
        site = self.get_secret("WLK_DATADOG_SITE") or self.config.settings.get(
            "site", "datadoghq.com"
        )
        return f"https://api.{site}"

    def _client(self) -> httpx.Client:
        """Build an httpx client with Datadog auth headers."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "DD-API-KEY": self.get_secret("WLK_DATADOG_API_KEY"),
            "DD-APPLICATION-KEY": self.get_secret("WLK_DATADOG_APP_KEY"),
        }
        return httpx.Client(headers=headers, timeout=self.config.timeout_seconds)

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="datadog",
            source_type=SourceType.OBSERVABILITY,
            provider="datadog",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_monitors(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect all monitors with their status."""
        try:
            url = f"{self._base_url()}/api/v1/monitor"
            monitors: list[dict] = []
            page = 0
            page_size = 100

            while True:
                resp = client.get(url, params={"page": page, "page_size": page_size})
                resp.raise_for_status()
                batch = resp.json()
                if not isinstance(batch, list) or len(batch) == 0:
                    break
                monitors.extend(batch)
                if len(batch) < page_size:
                    break
                page += 1

            result.events.append(self._raw_event("datadog_monitors", {"monitors": monitors}))
        except Exception as e:
            log.debug("Datadog monitors collection failed: %s", e)
            result.errors.append(f"datadog_monitors: {e}")

    def _collect_security_signals(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect recent security signals via v2 API."""
        try:
            url = f"{self._base_url()}/api/v2/security_monitoring/signals"
            resp = client.get(url, params={"page[limit]": 100})
            resp.raise_for_status()
            body = resp.json()
            signals = body.get("data", [])
            result.events.append(self._raw_event("datadog_security_signals", {"signals": signals}))
        except Exception as e:
            log.debug("Datadog security signals collection failed: %s", e)
            result.errors.append(f"datadog_security_signals: {e}")

    def _collect_slos(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect SLO definitions and status."""
        try:
            url = f"{self._base_url()}/api/v1/slo"
            resp = client.get(url)
            resp.raise_for_status()
            body = resp.json()
            slos = body.get("data", [])
            result.events.append(self._raw_event("datadog_slos", {"slos": slos}))
        except Exception as e:
            log.debug("Datadog SLOs collection failed: %s", e)
            result.errors.append(f"datadog_slos: {e}")

    def _collect_hosts(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect host inventory."""
        try:
            url = f"{self._base_url()}/api/v1/hosts"
            hosts: list[dict] = []
            start = 0
            count = 100

            while True:
                resp = client.get(url, params={"start": start, "count": count})
                resp.raise_for_status()
                body = resp.json()
                batch = body.get("host_list", [])
                hosts.extend(batch)
                total = body.get("total_returned", 0)
                if total < count:
                    break
                start += count

            result.events.append(self._raw_event("datadog_hosts", {"hosts": hosts}))
        except Exception as e:
            log.debug("Datadog hosts collection failed: %s", e)
            result.errors.append(f"datadog_hosts: {e}")


# Register
registry.register("datadog", DatadogConnector)
