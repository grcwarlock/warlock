"""Spot.io connector — Layer 1 implementation for CLOUD.

Collects EC2 groups, Ocean clusters, and Elastigroups from the Spot.io API.
Uses Bearer token authentication via SPOTIO_API_TOKEN.
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

SPOTIO_BASE_URL = "https://api.spotinst.io"

SPOTIO_ENDPOINTS: list[tuple[str, str]] = [
    ("/aws/ec2/group", "spotio_ec2_groups"),
    ("/ocean/aws/k8s/cluster", "spotio_ocean_clusters"),
    ("/aws/ec2/group", "spotio_elastigroups"),  # elastigroups use same ec2/group endpoint
]


class SpotioConnector(BaseConnector):
    """Collects compliance telemetry from the Spot.io (Spot by NetApp) API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("SPOTIO_API_TOKEN"):
            errors.append("SPOTIO_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("SPOTIO_API_TOKEN")
            base_url = self.config.settings.get("base_url", SPOTIO_BASE_URL)
            resp = httpx.get(
                f"{base_url}/aws/ec2/group",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 403)  # 403 = auth ok, scope issue
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="spotio",
            source_type=SourceType.CLOUD,
            provider="spotio",
        )

        token = self.get_secret("SPOTIO_API_TOKEN")
        base_url = self.config.settings.get("base_url", SPOTIO_BASE_URL)
        headers = self._headers(token)
        account_id = self.config.settings.get("account_id", "")

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        # Deduplicate endpoints — elastigroups = ec2 groups
        seen: set[str] = set()
        endpoints: list[tuple[str, str]] = []
        for endpoint, event_type in SPOTIO_ENDPOINTS:
            key = f"{endpoint}:{event_type}"
            if key not in seen:
                seen.add(key)
                endpoints.append((endpoint, event_type))

        # Use distinct endpoints for ec2 groups and ocean
        unique_endpoints: list[tuple[str, str]] = [
            ("/aws/ec2/group", "spotio_ec2_groups"),
            ("/ocean/aws/k8s/cluster", "spotio_ocean_clusters"),
        ]

        try:
            for endpoint, event_type in unique_endpoints:
                try:
                    params = {}
                    if account_id:
                        params["accountId"] = account_id
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    body = resp.json()
                    items = body.get("response", {}).get("items", [])
                    result.events.append(
                        RawEventData(
                            source="spotio",
                            source_type=SourceType.CLOUD,
                            provider="spotio",
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
                    log.debug("Spot.io %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }


# Register
registry.register("spotio", SpotioConnector)
