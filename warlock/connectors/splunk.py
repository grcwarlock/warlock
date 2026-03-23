"""Splunk connector — Layer 1 implementation for SIEM.

Collects notable events, saved searches, correlation rules, and index
health from the Splunk REST API via httpx.
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


class SplunkConnector(BaseConnector):
    """Collects compliance telemetry from Splunk via REST API."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[splunk]")
        if not self.config.settings.get("base_url"):
            errors.append("Missing required setting: base_url (e.g. https://splunk:8089)")
        if not self.get_secret("SPLUNK_TOKEN") and not self.get_secret("SPLUNK_PASSWORD"):
            errors.append("Set SPLUNK_TOKEN or SPLUNK_PASSWORD (with SPLUNK_USERNAME) env var")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            url = f"{self._base_url}/services/server/info"
            resp = httpx.get(
                url,
                headers=self._auth_headers(),
                params={"output_mode": "json"},
                verify=self._verify_ssl,
                timeout=30,
            )
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="splunk",
            source_type=SourceType.SIEM,
            provider="splunk",
        )

        headers = self._auth_headers()

        checks: list[tuple[str, dict[str, str], str]] = [
            # Notable events (ES) — last 24h
            (
                f"{self._base_url}/services/search/jobs/export",
                {
                    "search": "| search `notable` | head 500",
                    "earliest_time": "-24h",
                    "latest_time": "now",
                    "output_mode": "json",
                },
                "splunk_notable_events",
            ),
            # Saved searches
            (
                f"{self._base_url}/services/saved/searches",
                {"output_mode": "json", "count": "0"},
                "splunk_saved_searches",
            ),
            # Correlation searches (ES)
            (
                f"{self._base_url}/services/saved/searches",
                {
                    "output_mode": "json",
                    "count": "0",
                    "search": "action.correlationsearch.enabled=1",
                },
                "splunk_correlation_rules",
            ),
            # Index health
            (
                f"{self._base_url}/services/data/indexes",
                {"output_mode": "json", "count": "0"},
                "splunk_index_health",
            ),
        ]

        with httpx.Client(timeout=self.config.timeout_seconds, verify=self._verify_ssl) as client:
            for url, params, event_type in checks:
                try:
                    data = self._fetch(client, url, headers, params, event_type)
                    result.events.append(
                        RawEventData(
                            source="splunk",
                            source_type=SourceType.SIEM,
                            provider="splunk",
                            event_type=event_type,
                            raw_data={
                                "base_url": self._base_url,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Splunk %s failed: %s", event_type, e)
                    result.errors.append(f"{event_type}: {e}")

        result.complete()
        return result

    # -- internal helpers --

    @property
    def _base_url(self) -> str:
        return self.config.settings["base_url"].rstrip("/")

    @property
    def _verify_ssl(self) -> bool:
        return self.config.settings.get("verify_ssl", True)

    def _auth_headers(self) -> dict[str, str]:
        token = self.get_secret("SPLUNK_TOKEN")
        if token:
            return {"Authorization": f"Bearer {token}"}
        username = self.get_secret("SPLUNK_USERNAME")
        password = self.get_secret("SPLUNK_PASSWORD")
        import base64

        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    def _fetch(
        self,
        client,
        url: str,
        headers: dict,
        params: dict,
        event_type: str,
    ) -> list[dict] | dict:
        """Fetch data from Splunk REST API. Handle search export vs normal endpoints."""
        if event_type == "splunk_notable_events":
            # Search export returns newline-delimited JSON
            resp = client.post(url, headers=headers, data=params)
            resp.raise_for_status()
            import json

            results = []
            for line in resp.text.strip().split("\n"):
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return results
        else:
            resp = client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            body = resp.json()
            return body.get("entry", body)


# Register
registry.register("splunk", SplunkConnector)
