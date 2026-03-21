"""Aqua Security connector — Layer 1 implementation for container security.

Collects images (vulnerability scan results), runtime policies,
compliance (CIS benchmarks), and secrets via the Aqua CSP API v2.
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


class AquaConnector(BaseConnector):
    """Collects compliance telemetry from Aqua CSP API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[aqua]")
        if not self.get_secret("WLK_AQUA_URL"):
            errors.append("WLK_AQUA_URL not set")
        if not self.get_secret("WLK_AQUA_USER"):
            errors.append("WLK_AQUA_USER not set")
        if not self.get_secret("WLK_AQUA_PASSWORD"):
            errors.append("WLK_AQUA_PASSWORD not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self._base_url()}/api/v1/dashboard")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aqua",
            source_type=SourceType.CONTAINER_SECURITY,
            provider="aqua",
        )

        client = self._client()

        self._collect_images(client, result)
        self._collect_runtime_policies(client, result)
        self._collect_compliance(client, result)
        self._collect_secrets(client, result)

        result.complete()
        return result

    # -- HTTP client --

    def _base_url(self) -> str:
        url = self.get_secret("WLK_AQUA_URL").rstrip("/")
        return url

    def _client(self) -> httpx.Client:
        """Authenticate and return an httpx client with bearer token."""
        base = self._base_url()
        tmp = httpx.Client(timeout=self.config.timeout_seconds)

        # Aqua CSP token-based auth
        auth_resp = tmp.post(
            f"{base}/api/v1/login",
            json={
                "id": self.get_secret("WLK_AQUA_USER"),
                "password": self.get_secret("WLK_AQUA_PASSWORD"),
            },
        )
        auth_resp.raise_for_status()
        token = auth_resp.json().get("token", "")
        tmp.close()

        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="aqua",
            source_type=SourceType.CONTAINER_SECURITY,
            provider="aqua",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_images(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect container image scan results with vulnerability details."""
        try:
            resp = client.get(
                f"{self._base_url()}/api/v2/images",
                params={"page": "1", "pagesize": "100", "order_by": "-scan_date"},
            )
            resp.raise_for_status()
            images = resp.json().get("result", resp.json().get("data", []))
            result.events.append(self._raw_event("aqua_images", {"images": images}))
        except Exception as e:
            log.debug("Aqua images collection failed: %s", e)
            result.errors.append(f"aqua_images: {e}")

    def _collect_runtime_policies(
        self, client: httpx.Client, result: ConnectorResult
    ) -> None:
        """Collect runtime protection policies and enforcement status."""
        try:
            resp = client.get(
                f"{self._base_url()}/api/v2/runtime_policies",
                params={"page": "1", "pagesize": "100"},
            )
            resp.raise_for_status()
            policies = resp.json().get("result", resp.json().get("data", []))
            result.events.append(
                self._raw_event("aqua_runtime_policies", {"policies": policies})
            )
        except Exception as e:
            log.debug("Aqua runtime policies collection failed: %s", e)
            result.errors.append(f"aqua_runtime_policies: {e}")

    def _collect_compliance(
        self, client: httpx.Client, result: ConnectorResult
    ) -> None:
        """Collect CIS benchmark compliance results."""
        try:
            resp = client.get(
                f"{self._base_url()}/api/v2/risks/bench",
                params={"page": "1", "pagesize": "100"},
            )
            resp.raise_for_status()
            benchmarks = resp.json().get("result", resp.json().get("data", []))
            result.events.append(
                self._raw_event("aqua_compliance", {"benchmarks": benchmarks})
            )
        except Exception as e:
            log.debug("Aqua compliance collection failed: %s", e)
            result.errors.append(f"aqua_compliance: {e}")

    def _collect_secrets(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect exposed secrets detected in container images."""
        try:
            resp = client.get(
                f"{self._base_url()}/api/v2/risks/secrets",
                params={"page": "1", "pagesize": "100"},
            )
            resp.raise_for_status()
            secrets = resp.json().get("result", resp.json().get("data", []))
            result.events.append(self._raw_event("aqua_secrets", {"secrets": secrets}))
        except Exception as e:
            log.debug("Aqua secrets collection failed: %s", e)
            result.errors.append(f"aqua_secrets: {e}")


# Register
registry.register("aqua", AquaConnector)
