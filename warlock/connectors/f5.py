"""F5 BIG-IP connector — Layer 1 implementation for NETWORK.

Collects virtual servers, performance metrics, and firewall policies from
the F5 BIG-IP iControl REST API. Supports Basic auth via F5_USERNAME/F5_PASSWORD
or Bearer token via F5_API_TOKEN.
"""

from __future__ import annotations

import base64
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

F5_BASE_URL = "https://localhost"

F5_ENDPOINTS: list[tuple[str, str]] = [
    ("/mgmt/tm/ltm/virtual", "f5_virtual_servers"),
    ("/mgmt/tm/sys/performance/all-stats", "f5_performance"),
    ("/mgmt/tm/security/firewall/policy", "f5_firewall_policies"),
]


class F5Connector(BaseConnector):
    """Collects compliance telemetry from the F5 BIG-IP iControl REST API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        token = self.get_secret("F5_API_TOKEN")
        username = self.get_secret("F5_USERNAME")
        password = self.get_secret("F5_PASSWORD")
        if not token and not (username and password):
            errors.append("Either F5_API_TOKEN or both F5_USERNAME and F5_PASSWORD must be set")
        if not self.config.settings.get("base_url"):
            errors.append(
                "F5 base_url must be set in connector settings (e.g. https://bigip.example.com)"
            )
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.config.settings.get("base_url", F5_BASE_URL)
            resp = httpx.get(
                f"{base_url}/mgmt/tm/sys/version",
                headers=self._headers(),
                verify=self.config.settings.get("verify_tls", True),
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
            source="f5",
            source_type=SourceType.NETWORK,
            provider="f5",
        )

        base_url = self.config.settings.get("base_url", F5_BASE_URL)
        headers = self._headers()

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            verify=self.config.settings.get("verify_tls", True),
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in F5_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params={"$top": 100})
                    resp.raise_for_status()
                    body = resp.json()
                    items = body.get("items", [body])
                    result.events.append(
                        RawEventData(
                            source="f5",
                            source_type=SourceType.NETWORK,
                            provider="f5",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "response": items,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("F5 %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self) -> dict[str, str]:
        token = self.get_secret("F5_API_TOKEN")
        if token:
            return {
                "X-F5-Auth-Token": token,
                "Content-Type": "application/json",
            }
        username = self.get_secret("F5_USERNAME")
        password = self.get_secret("F5_PASSWORD")
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
        }


# Register
registry.register("f5", F5Connector)
