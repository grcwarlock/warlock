"""Proofpoint TAP connector — Layer 1 implementation for email security.

Collects blocked messages, delivered threats, and blocked clicks from
the Proofpoint Targeted Attack Protection (TAP) SIEM API.
Uses Basic auth with service principal and secret.
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

PROOFPOINT_BASE_URL = "https://tap-api-v2.proofpoint.com"

# (endpoint, event_type, response_key)
PROOFPOINT_ENDPOINTS: list[tuple[str, str, str, dict]] = [
    (
        "/v2/siem/messages/blocked",
        "proofpoint_blocked_messages",
        "messagesBlocked",
        {"sinceSeconds": "86400", "format": "json"},
    ),
    (
        "/v2/siem/messages/delivered",
        "proofpoint_delivered_threats",
        "messagesDelivered",
        {"sinceSeconds": "86400", "format": "json"},
    ),
    (
        "/v2/siem/clicks/blocked",
        "proofpoint_clicks_blocked",
        "clicksBlocked",
        {"sinceSeconds": "86400", "format": "json"},
    ),
]


class ProofpointConnector(BaseConnector):
    """Collects email security telemetry from Proofpoint TAP SIEM API."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[proofpoint]")
        if not self.get_secret("WLK_PROOFPOINT_SERVICE_PRINCIPAL"):
            errors.append("WLK_PROOFPOINT_SERVICE_PRINCIPAL env var is not set")
        if not self.get_secret("WLK_PROOFPOINT_SECRET"):
            errors.append("WLK_PROOFPOINT_SECRET env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            resp = httpx.get(
                f"{PROOFPOINT_BASE_URL}/v2/siem/messages/blocked",
                params={"sinceSeconds": "3600", "format": "json"},
                auth=(
                    self.get_secret("WLK_PROOFPOINT_SERVICE_PRINCIPAL"),
                    self.get_secret("WLK_PROOFPOINT_SECRET"),
                ),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="proofpoint",
            source_type=SourceType.EMAIL,
            provider="proofpoint",
        )

        auth = (
            self.get_secret("WLK_PROOFPOINT_SERVICE_PRINCIPAL"),
            self.get_secret("WLK_PROOFPOINT_SECRET"),
        )

        client = httpx.Client(
            base_url=PROOFPOINT_BASE_URL,
            auth=auth,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type, response_key, params in PROOFPOINT_ENDPOINTS:
                try:
                    resp = client.get(endpoint, params=params)
                    resp.raise_for_status()
                    body = resp.json()
                    data = body.get(response_key, [])

                    result.events.append(RawEventData(
                        source="proofpoint",
                        source_type=SourceType.EMAIL,
                        provider="proofpoint",
                        event_type=event_type,
                        raw_data={
                            "endpoint": endpoint,
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    ))
                except Exception as e:
                    log.debug("Proofpoint %s failed: %s", endpoint, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result


# Register
registry.register("proofpoint", ProofpointConnector)
