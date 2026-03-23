"""LogRhythm connector — Layer 1 implementation for SIEM.

Collects hosts, alarms, and log sources from the LogRhythm Admin API.
Uses Bearer token authentication via LOGRHYTHM_API_KEY.
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

LOGRHYTHM_BASE_URL = "https://api.logrhythm.com"

LOGRHYTHM_ENDPOINTS: list[tuple[str, str]] = [
    ("/lr-admin-api/hosts", "logrhythm_hosts"),
    ("/lr-admin-api/alarms", "logrhythm_alarms"),
    ("/lr-admin-api/log-sources", "logrhythm_log_sources"),
]


class LogRhythmConnector(BaseConnector):
    """Collects compliance telemetry from the LogRhythm Admin API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("LOGRHYTHM_API_KEY"):
            errors.append("LOGRHYTHM_API_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("LOGRHYTHM_API_KEY")
            base_url = self.config.settings.get("base_url", LOGRHYTHM_BASE_URL)
            resp = httpx.get(
                f"{base_url}/lr-admin-api/hosts",
                headers=self._headers(token),
                params={"count": 1},
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
            source="logrhythm",
            source_type=SourceType.SIEM,
            provider="logrhythm",
        )

        token = self.get_secret("LOGRHYTHM_API_KEY")
        base_url = self.config.settings.get("base_url", LOGRHYTHM_BASE_URL)
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in LOGRHYTHM_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint)
                    result.events.append(
                        RawEventData(
                            source="logrhythm",
                            source_type=SourceType.SIEM,
                            provider="logrhythm",
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
                    log.debug("LogRhythm %s failed: %s", endpoint, e)
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

    def _paginate(self, client: object, endpoint: str) -> list:
        """Follow LogRhythm offset-based pagination."""
        all_items: list = []
        offset = 0
        count = 100

        while True:
            resp = client.get(endpoint, params={"offset": offset, "count": count})  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            # LogRhythm returns a list directly or a dict with data key
            if isinstance(body, list):
                items = body
            else:
                items = body.get("data", body.get("items", []))

            all_items.extend(items)
            if len(items) < count:
                break
            offset += count

        return all_items


# Register
registry.register("logrhythm", LogRhythmConnector)
