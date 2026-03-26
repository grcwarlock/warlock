"""Twilio connector — Layer 1 implementation for COMMUNICATION.

Collects data from the Twilio API.
Uses Bearer token authentication via TWILIO_AUTH_TOKEN.
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

TWILIO_BASE_URL = "https://api.twilio.com/2010-04-01"

TWILIO_ENDPOINTS: list[tuple[str, str]] = [
    ("/Accounts/{sid}/Calls.json", "twilio_calls"),
    ("/Accounts/{sid}/Messages.json", "twilio_messages"),
    ("/Accounts/{sid}/Keys.json", "twilio_api_keys"),
]


class TwilioConnector(BaseConnector):
    """Collects compliance telemetry from the Twilio API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("TWILIO_AUTH_TOKEN"):
            errors.append("TWILIO_AUTH_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("TWILIO_AUTH_TOKEN")
            base_url = self.config.settings.get("base_url", TWILIO_BASE_URL)
            resp = httpx.get(
                base_url,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 401, 403)
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="twilio",
            source_type=SourceType.COMMUNICATION,
            provider="twilio",
        )

        token = self.get_secret("TWILIO_AUTH_TOKEN")
        base_url = self.config.settings.get("base_url", TWILIO_BASE_URL)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        client = httpx.Client(
            base_url=base_url, headers=headers, timeout=self.config.timeout_seconds
        )

        try:
            for endpoint, event_type in TWILIO_ENDPOINTS:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    data = resp.json()
                    items = (
                        data
                        if isinstance(data, list)
                        else data.get("data", data.get("results", data.get("items", [data])))
                    )
                    result.events.append(
                        RawEventData(
                            source="twilio",
                            source_type=SourceType.COMMUNICATION,
                            provider="twilio",
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
                    log.debug("Twilio %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result


# Register
registry.register("twilio", TwilioConnector)
