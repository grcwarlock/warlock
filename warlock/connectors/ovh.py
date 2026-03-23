"""OVHcloud connector — Layer 1 implementation for cloud infrastructure.

Collects cloud projects, instances, users, networks, storage containers,
Kubernetes clusters, and SSL certificates from the OVHcloud REST API.
Uses OVH custom signature authentication via httpx.
"""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)


class OVHConnector(BaseConnector):
    """Collects compliance telemetry from OVHcloud REST APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[ovh]")
        if not self.get_secret("WLK_OVH_APP_KEY"):
            errors.append("WLK_OVH_APP_KEY env var is not set")
        if not self.get_secret("WLK_OVH_APP_SECRET"):
            errors.append("WLK_OVH_APP_SECRET env var is not set")
        if not self.get_secret("WLK_OVH_CONSUMER_KEY"):
            errors.append("WLK_OVH_CONSUMER_KEY env var is not set")
        if not self.config.settings.get("service_name"):
            errors.append("'service_name' (project ID) must be set in connector settings")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self._base_url()
            url = f"{base_url}/auth/time"
            resp = httpx.get(url, timeout=self.config.timeout_seconds)
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="ovh",
            source_type=SourceType.CLOUD,
            provider="ovh",
        )

        service_name = self.config.settings["service_name"]
        base_url = self._base_url()
        app_key = self.get_secret("WLK_OVH_APP_KEY")
        app_secret = self.get_secret("WLK_OVH_APP_SECRET")
        consumer_key = self.get_secret("WLK_OVH_CONSUMER_KEY")

        # Get server time delta for signature
        try:
            time_delta = self._get_time_delta(base_url)
        except Exception as e:
            log.debug("OVH time sync failed: %s", e)
            time_delta = 0

        collectors: list[tuple[str, str]] = [
            ("ovh_projects", "/cloud/project"),
            ("ovh_instances", f"/cloud/project/{service_name}/instance"),
            ("ovh_cloud_users", f"/cloud/project/{service_name}/user"),
            ("ovh_networks", f"/cloud/project/{service_name}/network/private"),
            ("ovh_storage", f"/cloud/project/{service_name}/storage"),
            ("ovh_kubernetes", f"/cloud/project/{service_name}/kube"),
            ("ovh_certificates", "/ssl"),
        ]

        client = httpx.Client(timeout=self.config.timeout_seconds)

        try:
            for event_type, endpoint in collectors:
                try:
                    url = f"{base_url}/1.0{endpoint}"
                    headers = self._sign_request(
                        app_key,
                        app_secret,
                        consumer_key,
                        "GET",
                        url,
                        "",
                        time_delta,
                    )
                    resp = client.get(url, headers=headers)
                    resp.raise_for_status()
                    data = resp.json()

                    result.events.append(
                        RawEventData(
                            source="ovh",
                            source_type=SourceType.CLOUD,
                            provider="ovh",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "service_name": service_name,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("OVH %s failed: %s", event_type, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    # -- Internal helpers --

    def _base_url(self) -> str:
        endpoint = self.config.settings.get("endpoint", "eu.api.ovh.com")
        return f"https://{endpoint}"

    def _get_time_delta(self, base_url: str) -> int:
        import httpx

        resp = httpx.get(f"{base_url}/1.0/auth/time", timeout=10)
        resp.raise_for_status()
        server_time = int(resp.text)
        return server_time - int(time.time())

    def _sign_request(
        self,
        app_key: str,
        app_secret: str,
        consumer_key: str,
        method: str,
        url: str,
        body: str,
        time_delta: int,
    ) -> dict[str, str]:
        """Build OVH API authentication headers with signature."""
        timestamp = str(int(time.time()) + time_delta)
        to_sign = "+".join(
            [
                app_secret,
                consumer_key,
                method.upper(),
                url,
                body,
                timestamp,
            ]
        )
        signature = "$1$" + hashlib.sha1(to_sign.encode("utf-8")).hexdigest()

        return {
            "X-Ovh-Application": app_key,
            "X-Ovh-Consumer": consumer_key,
            "X-Ovh-Timestamp": timestamp,
            "X-Ovh-Signature": signature,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


# Register
registry.register("ovh", OVHConnector)
