"""GitGuardian connector — Layer 1 implementation for secret detection.

Collects incidents (secret leaks), members, and sources (repos)
via the GitGuardian API v1 with Bearer token auth.
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


class GitGuardianConnector(BaseConnector):
    """Collects compliance telemetry from GitGuardian API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[gitguardian]")
        if not self.get_secret("WLK_GITGUARDIAN_TOKEN"):
            errors.append("WLK_GITGUARDIAN_TOKEN not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get("/health")
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="gitguardian",
            source_type=SourceType.CODE,
            provider="gitguardian",
        )

        client = self._client()

        self._collect_incidents(client, result)
        self._collect_members(client, result)
        self._collect_sources(client, result)

        result.complete()
        return result

    # -- Client helper --

    def _client(self) -> httpx.Client:
        token = self.get_secret("WLK_GITGUARDIAN_TOKEN")
        return httpx.Client(
            base_url="https://api.gitguardian.com/v1",
            headers={
                "Authorization": f"Token {token}",
                "Accept": "application/json",
            },
            timeout=self.config.timeout_seconds,
        )

    # -- Event helper --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="gitguardian",
            source_type=SourceType.CODE,
            provider="gitguardian",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_incidents(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect secret leak incidents."""
        try:
            resp = client.get(
                "/incidents",
                params={"per_page": 100, "page": 1},
            )
            resp.raise_for_status()
            incidents = resp.json()
            # API returns a list directly
            if isinstance(incidents, dict):
                incidents = incidents.get("results", incidents.get("incidents", []))
            result.events.append(self._raw_event("gitguardian_incidents", {"incidents": incidents}))
        except Exception as e:
            log.debug("GitGuardian incidents collection failed: %s", e)
            result.errors.append(f"gitguardian_incidents: {e}")

    def _collect_members(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect organization members."""
        try:
            resp = client.get(
                "/members",
                params={"per_page": 100, "page": 1},
            )
            resp.raise_for_status()
            members = resp.json()
            if isinstance(members, dict):
                members = members.get("results", members.get("members", []))
            result.events.append(self._raw_event("gitguardian_members", {"members": members}))
        except Exception as e:
            log.debug("GitGuardian members collection failed: %s", e)
            result.errors.append(f"gitguardian_members: {e}")

    def _collect_sources(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect monitored sources (repos)."""
        try:
            resp = client.get(
                "/sources",
                params={"per_page": 100, "page": 1},
            )
            resp.raise_for_status()
            sources = resp.json()
            if isinstance(sources, dict):
                sources = sources.get("results", sources.get("sources", []))
            result.events.append(self._raw_event("gitguardian_sources", {"sources": sources}))
        except Exception as e:
            log.debug("GitGuardian sources collection failed: %s", e)
            result.errors.append(f"gitguardian_sources: {e}")


# Register
registry.register("gitguardian", GitGuardianConnector)
