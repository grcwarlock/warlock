"""Proofpoint TAP connector — extended threat analysis (GAP-085).

Extends the base Proofpoint connector with additional TAP API endpoints
for click permits, URL decode, and campaign data.
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

PROOFPOINT_TAP_BASE = "https://tap-api-v2.proofpoint.com"

TAP_ENDPOINTS: list[tuple[str, str, str, dict]] = [
    (
        "/v2/siem/clicks/permitted",
        "proofpoint_tap_clicks_permitted",
        "clicksPermitted",
        {"sinceSeconds": "86400", "format": "json"},
    ),
    (
        "/v2/siem/messages/blocked",
        "proofpoint_tap_messages_blocked",
        "messagesBlocked",
        {"sinceSeconds": "86400", "format": "json"},
    ),
    (
        "/v2/siem/messages/delivered",
        "proofpoint_tap_messages_delivered",
        "messagesDelivered",
        {"sinceSeconds": "86400", "format": "json"},
    ),
    (
        "/v2/siem/issues",
        "proofpoint_tap_issues",
        "issues",
        {"sinceSeconds": "86400", "format": "json"},
    ),
]


class ProofpointTAPConnector(BaseConnector):
    """Collects extended threat telemetry from Proofpoint TAP SIEM API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install httpx")
        if not self.get_secret("WLK_PROOFPOINT_SERVICE_PRINCIPAL"):
            errors.append("WLK_PROOFPOINT_SERVICE_PRINCIPAL not set")
        if not self.get_secret("WLK_PROOFPOINT_SECRET"):
            errors.append("WLK_PROOFPOINT_SECRET not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            resp = httpx.get(
                f"{PROOFPOINT_TAP_BASE}/v2/siem/messages/blocked",
                params={"sinceSeconds": "3600", "format": "json"},
                auth=(
                    self.get_secret("WLK_PROOFPOINT_SERVICE_PRINCIPAL"),
                    self.get_secret("WLK_PROOFPOINT_SECRET"),
                ),
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
            source="proofpoint_tap",
            source_type=SourceType.EMAIL_SECURITY,
            provider="proofpoint_tap",
        )

        auth = (
            self.get_secret("WLK_PROOFPOINT_SERVICE_PRINCIPAL"),
            self.get_secret("WLK_PROOFPOINT_SECRET"),
        )

        client = httpx.Client(
            base_url=PROOFPOINT_TAP_BASE,
            auth=auth,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, response_key, params in TAP_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    body = resp.json()
                    data = body.get(response_key, [])

                    result.events.append(
                        RawEventData(
                            source="proofpoint_tap",
                            source_type=SourceType.EMAIL_SECURITY,
                            provider="proofpoint_tap",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Proofpoint TAP %s failed: %s", endpoint, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result


registry.register("proofpoint_tap", ProofpointTAPConnector)
