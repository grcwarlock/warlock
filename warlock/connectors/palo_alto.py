"""Palo Alto Networks connector — Layer 1 implementation for network security.

Collects security policies/rules, threat logs, traffic summaries, system info,
and GlobalProtect status via PAN-OS REST API.
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


class PaloAltoConnector(BaseConnector):
    """Collects compliance telemetry from Palo Alto Networks PAN-OS REST API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[palo_alto]")
        if not self.get_secret("WLK_PALO_ALTO_API_KEY"):
            errors.append("WLK_PALO_ALTO_API_KEY not set")
        if not os.environ.get("WLK_PALO_ALTO_BASE_URL", ""):
            errors.append("WLK_PALO_ALTO_BASE_URL not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self._base_url()}/api/?type=op&cmd=<show><system><info></info></system></show>")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="palo_alto",
            source_type=SourceType.NETWORK,
            provider="palo_alto",
        )

        client = self._client()

        self._collect_security_rules(client, result)
        self._collect_threat_logs(client, result)
        self._collect_traffic_summary(client, result)
        self._collect_system_info(client, result)
        self._collect_globalprotect(client, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _base_url(self) -> str:
        return os.environ.get("WLK_PALO_ALTO_BASE_URL", "").rstrip("/")

    def _client(self) -> httpx.Client:
        api_key = self.get_secret("WLK_PALO_ALTO_API_KEY")
        return httpx.Client(
            headers={"X-PAN-KEY": api_key, "Content-Type": "application/json"},
            timeout=self.config.timeout_seconds,
            verify=True,
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="palo_alto",
            source_type=SourceType.NETWORK,
            provider="palo_alto",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_security_rules(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect security policy rules via REST API."""
        try:
            url = f"{self._base_url()}/restapi/v10.2/Policies/SecurityRules"
            resp = client.get(url, params={"location": "vsys", "vsys": "vsys1"})
            resp.raise_for_status()
            data = resp.json()
            rules = data.get("result", {}).get("entry", [])
            result.events.append(
                self._raw_event("pan_security_rules", {"rules": rules})
            )
        except Exception as e:
            log.debug("PAN security rules collection failed: %s", e)
            result.errors.append(f"pan_security_rules: {e}")

    def _collect_threat_logs(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect threat log entries."""
        try:
            url = f"{self._base_url()}/api/"
            params = {
                "type": "log",
                "log-type": "threat",
                "nlogs": "500",
            }
            resp = client.get(url, params=params)
            resp.raise_for_status()
            # PAN-OS returns XML by default; parse what we get
            result.events.append(
                self._raw_event("pan_threat_logs", {"raw_response": resp.text})
            )
        except Exception as e:
            log.debug("PAN threat logs collection failed: %s", e)
            result.errors.append(f"pan_threat_logs: {e}")

    def _collect_traffic_summary(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect traffic log summary."""
        try:
            url = f"{self._base_url()}/api/"
            params = {
                "type": "log",
                "log-type": "traffic",
                "nlogs": "100",
            }
            resp = client.get(url, params=params)
            resp.raise_for_status()
            result.events.append(
                self._raw_event("pan_traffic_summary", {"raw_response": resp.text})
            )
        except Exception as e:
            log.debug("PAN traffic summary collection failed: %s", e)
            result.errors.append(f"pan_traffic_summary: {e}")

    def _collect_system_info(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect system information via operational command."""
        try:
            url = f"{self._base_url()}/api/"
            params = {
                "type": "op",
                "cmd": "<show><system><info></info></system></show>",
            }
            resp = client.get(url, params=params)
            resp.raise_for_status()
            result.events.append(
                self._raw_event("pan_system_info", {"raw_response": resp.text})
            )
        except Exception as e:
            log.debug("PAN system info collection failed: %s", e)
            result.errors.append(f"pan_system_info: {e}")

    def _collect_globalprotect(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect GlobalProtect gateway and user status."""
        try:
            url = f"{self._base_url()}/api/"
            params = {
                "type": "op",
                "cmd": "<show><global-protect-gateway><current-user></current-user></global-protect-gateway></show>",
            }
            resp = client.get(url, params=params)
            resp.raise_for_status()
            result.events.append(
                self._raw_event("pan_globalprotect", {"raw_response": resp.text})
            )
        except Exception as e:
            log.debug("PAN GlobalProtect collection failed: %s", e)
            result.errors.append(f"pan_globalprotect: {e}")


# Register
registry.register("palo_alto", PaloAltoConnector)
