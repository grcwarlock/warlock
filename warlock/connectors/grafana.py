"""Grafana connector — Layer 1 implementation for observability.

Collects alert rules (firing/pending), dashboards, data sources,
and users/teams via the Grafana HTTP API.
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


class GrafanaConnector(BaseConnector):
    """Collects compliance telemetry from Grafana HTTP API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[grafana]")
        if not self.get_secret("WLK_GRAFANA_URL"):
            errors.append("WLK_GRAFANA_URL not set")
        # Accept either token or user/password auth
        has_token = bool(self.get_secret("WLK_GRAFANA_TOKEN"))
        has_basic = bool(
            self.get_secret("WLK_GRAFANA_USER")
            and self.get_secret("WLK_GRAFANA_PASSWORD")
        )
        if not has_token and not has_basic:
            errors.append(
                "Either WLK_GRAFANA_TOKEN or both WLK_GRAFANA_USER and WLK_GRAFANA_PASSWORD must be set"
            )
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self._base_url()}/api/health")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="grafana",
            source_type=SourceType.OBSERVABILITY,
            provider="grafana",
        )

        client = self._client()

        self._collect_alerts(client, result)
        self._collect_dashboards(client, result)
        self._collect_datasources(client, result)
        self._collect_users(client, result)

        result.complete()
        return result

    # -- HTTP client --

    def _base_url(self) -> str:
        return self.get_secret("WLK_GRAFANA_URL").rstrip("/")

    def _client(self) -> httpx.Client:
        headers: dict[str, str] = {"Content-Type": "application/json"}

        token = self.get_secret("WLK_GRAFANA_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
            return httpx.Client(
                timeout=self.config.timeout_seconds,
                headers=headers,
            )

        # Fall back to basic auth
        user = self.get_secret("WLK_GRAFANA_USER")
        password = self.get_secret("WLK_GRAFANA_PASSWORD")
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers=headers,
            auth=(user, password),
        )

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="grafana",
            source_type=SourceType.OBSERVABILITY,
            provider="grafana",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_alerts(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect alert rules with current state (firing/pending/normal)."""
        try:
            resp = client.get(f"{self._base_url()}/api/v1/provisioning/alert-rules")
            resp.raise_for_status()
            alert_rules = resp.json() if isinstance(resp.json(), list) else resp.json().get("data", [])

            # Also fetch current alert instances for state
            try:
                state_resp = client.get(f"{self._base_url()}/api/alertmanager/grafana/api/v2/alerts")
                state_resp.raise_for_status()
                alert_instances = state_resp.json() if isinstance(state_resp.json(), list) else []
            except Exception:
                alert_instances = []

            result.events.append(
                self._raw_event(
                    "grafana_alerts",
                    {"alert_rules": alert_rules, "alert_instances": alert_instances},
                )
            )
        except Exception as e:
            log.debug("Grafana alerts collection failed: %s", e)
            result.errors.append(f"grafana_alerts: {e}")

    def _collect_dashboards(
        self, client: httpx.Client, result: ConnectorResult
    ) -> None:
        """Collect dashboards with metadata."""
        try:
            resp = client.get(
                f"{self._base_url()}/api/search",
                params={"type": "dash-db", "limit": "200"},
            )
            resp.raise_for_status()
            dashboards = resp.json() if isinstance(resp.json(), list) else []
            result.events.append(
                self._raw_event("grafana_dashboards", {"dashboards": dashboards})
            )
        except Exception as e:
            log.debug("Grafana dashboards collection failed: %s", e)
            result.errors.append(f"grafana_dashboards: {e}")

    def _collect_datasources(
        self, client: httpx.Client, result: ConnectorResult
    ) -> None:
        """Collect data sources with access configuration."""
        try:
            resp = client.get(f"{self._base_url()}/api/datasources")
            resp.raise_for_status()
            datasources = resp.json() if isinstance(resp.json(), list) else []
            result.events.append(
                self._raw_event("grafana_datasources", {"datasources": datasources})
            )
        except Exception as e:
            log.debug("Grafana datasources collection failed: %s", e)
            result.errors.append(f"grafana_datasources: {e}")

    def _collect_users(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect org users and teams."""
        try:
            resp = client.get(
                f"{self._base_url()}/api/org/users",
                params={"perpage": "500"},
            )
            resp.raise_for_status()
            users = resp.json() if isinstance(resp.json(), list) else []

            # Also fetch teams
            teams = []
            try:
                teams_resp = client.get(f"{self._base_url()}/api/teams/search", params={"perpage": "100"})
                teams_resp.raise_for_status()
                teams = teams_resp.json().get("teams", []) if isinstance(teams_resp.json(), dict) else []
            except Exception:
                pass

            result.events.append(
                self._raw_event("grafana_users", {"users": users, "teams": teams})
            )
        except Exception as e:
            log.debug("Grafana users collection failed: %s", e)
            result.errors.append(f"grafana_users: {e}")


# Register
registry.register("grafana", GrafanaConnector)
