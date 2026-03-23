"""Opsgenie connector — Layer 1 implementation for ITSM.

Collects alerts, incidents, on-call schedules, and escalation policies.
Uses Opsgenie REST API v2 via httpx with GenieKey authentication.
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

# Endpoint → (event_type, params) mapping
OPSGENIE_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/v2/alerts", "opsgenie_alerts", {"limit": "100", "order": "desc"}),
    ("/v2/incidents", "opsgenie_incidents", {"limit": "100"}),
    ("/v2/schedules", "opsgenie_schedules", {"limit": "100"}),
    ("/v2/escalations", "opsgenie_escalations", {"limit": "100"}),
]

OPSGENIE_BASE_URL = "https://api.opsgenie.com"


class OpsgenieConnector(BaseConnector):
    """Collects compliance telemetry from Opsgenie REST APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("OPSGENIE_API_KEY"):
            errors.append("OPSGENIE_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("OPSGENIE_API_KEY")
            base_url = self.config.settings.get("base_url", OPSGENIE_BASE_URL)
            resp = httpx.get(
                f"{base_url}/v2/heartbeats",
                headers=self._headers(token),
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
            source="opsgenie",
            source_type=SourceType.ITSM,
            provider="opsgenie",
        )

        token = self.get_secret("OPSGENIE_API_KEY")
        base_url = self.config.settings.get("base_url", OPSGENIE_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in OPSGENIE_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(
                        RawEventData(
                            source="opsgenie",
                            source_type=SourceType.ITSM,
                            provider="opsgenie",
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
                    log.debug("Opsgenie %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"GenieKey {token}",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str, params: dict) -> list:
        """Follow Opsgenie cursor-based pagination."""
        all_items: list = []
        current_params = dict(params)

        while True:
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            data = body.get("data", [])
            if isinstance(data, list):
                all_items.extend(data)
            elif isinstance(data, dict):
                all_items.append(data)

            # Opsgenie uses cursor-based pagination via paging block
            paging = body.get("paging", {})
            next_url = paging.get("next")
            if not next_url:
                break

            # Extract offset/cursor from next URL query string
            from urllib.parse import parse_qs, urlparse

            parsed = urlparse(next_url)
            qs = parse_qs(parsed.query)
            current_params = {k: v[0] for k, v in qs.items()}

        return all_items


# Register
registry.register("opsgenie", OpsgenieConnector)
