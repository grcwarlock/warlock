"""Fortinet FortiGate connector — Layer 1 implementation for network security.

Collects firewall policies, IPS threat logs, system status, VPN tunnel status,
and antivirus events via FortiGate REST API.
"""

from __future__ import annotations

import logging
import os
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


class FortinetConnector(BaseConnector):
    """Collects compliance telemetry from Fortinet FortiGate REST API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[fortinet]")
        if not self.get_secret("WLK_FORTINET_API_KEY"):
            errors.append("WLK_FORTINET_API_KEY not set")
        if not os.environ.get("WLK_FORTINET_BASE_URL", ""):
            errors.append("WLK_FORTINET_BASE_URL not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self._base_url()}/api/v2/monitor/system/status")
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="fortinet",
            source_type=SourceType.NETWORK,
            provider="fortinet",
        )

        client = self._client()

        self._collect_firewall_policies(client, result)
        self._collect_threat_logs(client, result)
        self._collect_system_status(client, result)
        self._collect_vpn_tunnels(client, result)
        self._collect_antivirus(client, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _base_url(self) -> str:
        return os.environ.get("WLK_FORTINET_BASE_URL", "").rstrip("/")

    def _client(self) -> httpx.Client:
        api_key = self.get_secret("WLK_FORTINET_API_KEY")
        return httpx.Client(
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            timeout=self.config.timeout_seconds,
            verify=True,
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="fortinet",
            source_type=SourceType.NETWORK,
            provider="fortinet",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_firewall_policies(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect firewall policies from FortiGate."""
        try:
            url = f"{self._base_url()}/api/v2/cmdb/firewall/policy"
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()
            policies = data.get("results", [])
            result.events.append(self._raw_event("forti_firewall_policies", {"policies": policies}))
        except Exception as e:
            log.debug("FortiGate firewall policies collection failed: %s", e)
            result.errors.append(f"forti_firewall_policies: {e}")

    def _collect_threat_logs(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect IPS threat logs."""
        try:
            url = f"{self._base_url()}/api/v2/log/disk/ips"
            resp = client.get(url, params={"rows": 500})
            resp.raise_for_status()
            data = resp.json()
            logs = data.get("results", [])
            result.events.append(self._raw_event("forti_threat_logs", {"logs": logs}))
        except Exception as e:
            log.debug("FortiGate IPS threat logs collection failed: %s", e)
            result.errors.append(f"forti_threat_logs: {e}")

    def _collect_system_status(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect system status information."""
        try:
            url = f"{self._base_url()}/api/v2/monitor/system/status"
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()
            status = data.get("results", data)
            result.events.append(self._raw_event("forti_system_status", {"status": status}))
        except Exception as e:
            log.debug("FortiGate system status collection failed: %s", e)
            result.errors.append(f"forti_system_status: {e}")

    def _collect_vpn_tunnels(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect IPsec VPN tunnel status."""
        try:
            url = f"{self._base_url()}/api/v2/monitor/vpn/ipsec"
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()
            tunnels = data.get("results", [])
            result.events.append(self._raw_event("forti_vpn_tunnels", {"tunnels": tunnels}))
        except Exception as e:
            log.debug("FortiGate VPN tunnels collection failed: %s", e)
            result.errors.append(f"forti_vpn_tunnels: {e}")

    def _collect_antivirus(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect antivirus event logs."""
        try:
            url = f"{self._base_url()}/api/v2/log/disk/virus"
            resp = client.get(url, params={"rows": 500})
            resp.raise_for_status()
            data = resp.json()
            events = data.get("results", [])
            result.events.append(self._raw_event("forti_antivirus", {"events": events}))
        except Exception as e:
            log.debug("FortiGate antivirus logs collection failed: %s", e)
            result.errors.append(f"forti_antivirus: {e}")


# Register
registry.register("fortinet", FortinetConnector)
