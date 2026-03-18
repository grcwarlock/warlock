"""Prisma Cloud connector — Layer 1 implementation for CSPM.

Collects alerts (open), compliance posture, asset inventory, and policies
via Prisma Cloud REST API.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorConfig,
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


class PrismaConnector(BaseConnector):
    """Collects compliance telemetry from Prisma Cloud APIs."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[prisma]")
        if not self.get_secret("PRISMA_ACCESS_KEY"):
            errors.append("PRISMA_ACCESS_KEY env var not set")
        if not self.get_secret("PRISMA_SECRET_KEY"):
            errors.append("PRISMA_SECRET_KEY env var not set")
        if not self.config.settings.get("api_url"):
            errors.append("settings.api_url not set (e.g. https://api.prismacloud.io)")
        return errors

    def health_check(self) -> bool:
        try:
            token = self._authenticate()
            return bool(token)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="prisma",
            source_type=SourceType.CSPM,
            provider="prisma",
        )

        token = self._authenticate()
        client = self._client(token)

        self._collect_alerts(client, result)
        self._collect_compliance(client, result)
        self._collect_assets(client, result)
        self._collect_policies(client, result)

        result.complete()
        return result

    @property
    def _api_url(self) -> str:
        return self.config.settings.get("api_url", "https://api.prismacloud.io").rstrip("/")

    def _authenticate(self) -> str:
        """Authenticate with access_key + secret_key to get JWT token."""
        resp = httpx.post(
            f"{self._api_url}/login",
            json={
                "username": self.get_secret("PRISMA_ACCESS_KEY"),
                "password": self.get_secret("PRISMA_SECRET_KEY"),
            },
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("token", "")

    def _client(self, token: str) -> httpx.Client:
        return httpx.Client(
            headers={
                "x-redlock-auth": token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=self.config.timeout_seconds,
        )

    def _collect_alerts(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect open alerts."""
        try:
            page_size = self.config.settings.get("page_size", 100)
            all_alerts: list = []
            next_token = None

            for _ in range(self.config.settings.get("max_pages", 20)):
                body: dict = {
                    "limit": page_size,
                    "filters": [
                        {"name": "alert.status", "operator": "=", "value": "open"},
                    ],
                    "sortBy": ["alertTime:desc"],
                }
                if next_token:
                    body["pageToken"] = next_token

                resp = client.post(f"{self._api_url}/v2/alert", json=body)
                resp.raise_for_status()
                data = resp.json()
                items = data.get("items", [])
                all_alerts.extend(items)

                next_token = data.get("nextPageToken")
                if not next_token or not items:
                    break

            result.events.append(RawEventData(
                source="prisma",
                source_type=SourceType.CSPM,
                provider="prisma",
                event_type="prisma_alerts",
                raw_data={"alerts": all_alerts},
                observed_at=datetime.now(timezone.utc),
            ))
        except Exception as e:
            log.debug("Prisma alerts collection failed: %s", e)
            result.errors.append(f"prisma_alerts: {e}")

    def _collect_compliance(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect compliance posture summary."""
        try:
            resp = client.get(f"{self._api_url}/compliance/posture", params={
                "timeType": "relative",
                "timeAmount": 24,
                "timeUnit": "hour",
            })
            resp.raise_for_status()
            posture = resp.json()

            result.events.append(RawEventData(
                source="prisma",
                source_type=SourceType.CSPM,
                provider="prisma",
                event_type="prisma_compliance",
                raw_data={"compliance": posture},
                observed_at=datetime.now(timezone.utc),
            ))
        except Exception as e:
            log.debug("Prisma compliance collection failed: %s", e)
            result.errors.append(f"prisma_compliance: {e}")

    def _collect_assets(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect asset inventory."""
        try:
            resp = client.post(f"{self._api_url}/v2/inventory", json={
                "timeType": "relative",
                "timeAmount": 24,
                "timeUnit": "hour",
            })
            resp.raise_for_status()
            inventory = resp.json()

            result.events.append(RawEventData(
                source="prisma",
                source_type=SourceType.CSPM,
                provider="prisma",
                event_type="prisma_assets",
                raw_data={"inventory": inventory},
                observed_at=datetime.now(timezone.utc),
            ))
        except Exception as e:
            log.debug("Prisma asset inventory failed: %s", e)
            result.errors.append(f"prisma_assets: {e}")

    def _collect_policies(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect enabled policies."""
        try:
            resp = client.get(f"{self._api_url}/v2/policy", params={
                "policy.enabled": "true",
            })
            resp.raise_for_status()
            policies = resp.json()
            if isinstance(policies, list):
                policy_list = policies
            else:
                policy_list = policies.get("items", policies.get("value", []))

            result.events.append(RawEventData(
                source="prisma",
                source_type=SourceType.CSPM,
                provider="prisma",
                event_type="prisma_policies",
                raw_data={"policies": policy_list},
                observed_at=datetime.now(timezone.utc),
            ))
        except Exception as e:
            log.debug("Prisma policies collection failed: %s", e)
            result.errors.append(f"prisma_policies: {e}")


# Register
registry.register("prisma", PrismaConnector)
