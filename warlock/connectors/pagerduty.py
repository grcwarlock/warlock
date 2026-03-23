"""PagerDuty connector — Layer 1 implementation for ITSM.

Collects incidents, services, on-call schedules, and escalation policies.
Uses PagerDuty REST API v2 via httpx with API token authentication.
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
PAGERDUTY_ENDPOINTS: list[tuple[str, str, dict]] = [
    (
        "/incidents",
        "pagerduty_incidents",
        {"limit": "100", "statuses[]": ["triggered", "acknowledged", "resolved"]},
    ),
    ("/services", "pagerduty_services", {"limit": "100"}),
    ("/oncalls", "pagerduty_oncalls", {"limit": "100"}),
    ("/escalation_policies", "pagerduty_escalation_policies", {"limit": "100"}),
]

PAGERDUTY_BASE_URL = "https://api.pagerduty.com"


class PagerDutyConnector(BaseConnector):
    """Collects compliance telemetry from PagerDuty REST APIs."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("PAGERDUTY_API_KEY"):
            errors.append("PAGERDUTY_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("PAGERDUTY_API_KEY")
            base_url = self.config.settings.get("base_url", PAGERDUTY_BASE_URL)
            resp = httpx.get(
                f"{base_url}/abilities",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="pagerduty",
            source_type=SourceType.ITSM,
            provider="pagerduty",
        )

        token = self.get_secret("PAGERDUTY_API_KEY")
        base_url = self.config.settings.get("base_url", PAGERDUTY_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, params in PAGERDUTY_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params, event_type)
                    result.events.append(
                        RawEventData(
                            source="pagerduty",
                            source_type=SourceType.ITSM,
                            provider="pagerduty",
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
                    log.debug("PagerDuty %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Token token={token}",
            "Accept": "application/vnd.pagerduty+json;version=2",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, endpoint: str, params: dict, event_type: str) -> list:
        """Follow PagerDuty offset-based pagination."""

        all_items: list = []
        offset = 0
        limit = int(params.get("limit", 100))
        current_params = dict(params)

        # Map event_type to the key in the response body
        _key_map = {
            "pagerduty_incidents": "incidents",
            "pagerduty_services": "services",
            "pagerduty_oncalls": "oncalls",
            "pagerduty_escalation_policies": "escalation_policies",
        }
        response_key = _key_map.get(event_type, "response")

        while True:
            current_params["offset"] = str(offset)
            resp = client.get(endpoint, params=current_params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            items = body.get(response_key, [])
            all_items.extend(items)

            if not body.get("more", False) or len(items) < limit:
                break
            offset += limit

        return all_items


# Register
registry.register("pagerduty", PagerDutyConnector)
