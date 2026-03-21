"""New Relic connector — Layer 1 implementation for observability platforms.

Collects alert conditions, entity health, and open violations
via NerdGraph (GraphQL) API and REST v2.
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

NERDGRAPH_URL = "https://api.newrelic.com/graphql"
REST_BASE_URL = "https://api.newrelic.com/v2"


class NewRelicConnector(BaseConnector):
    """Collects compliance telemetry from New Relic NerdGraph + REST v2."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[newrelic]")
        if not self.get_secret("WLK_NEWRELIC_API_KEY"):
            errors.append("WLK_NEWRELIC_API_KEY not set")
        if not self.get_secret("WLK_NEWRELIC_ACCOUNT_ID"):
            errors.append("WLK_NEWRELIC_ACCOUNT_ID not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._nerdgraph_client()
            query = "{ actor { user { name } } }"
            resp = client.post(NERDGRAPH_URL, json={"query": query})
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="newrelic",
            source_type=SourceType.OBSERVABILITY,
            provider="newrelic",
        )

        account_id = self.get_secret("WLK_NEWRELIC_ACCOUNT_ID")

        self._collect_alerts(account_id, result)
        self._collect_entities(account_id, result)
        self._collect_violations(account_id, result)

        result.complete()
        return result

    # -- Auth & Clients --

    def _nerdgraph_client(self) -> httpx.Client:
        """Build an httpx client for NerdGraph API."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "API-Key": self.get_secret("WLK_NEWRELIC_API_KEY"),
        }
        return httpx.Client(headers=headers, timeout=self.config.timeout_seconds)

    def _rest_client(self) -> httpx.Client:
        """Build an httpx client for REST v2 API."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Api-Key": self.get_secret("WLK_NEWRELIC_API_KEY"),
        }
        return httpx.Client(headers=headers, timeout=self.config.timeout_seconds)

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="newrelic",
            source_type=SourceType.OBSERVABILITY,
            provider="newrelic",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_alerts(self, account_id: str, result: ConnectorResult) -> None:
        """Collect NRQL alert conditions via NerdGraph."""
        try:
            client = self._nerdgraph_client()
            query = (
                """
            {
              actor {
                account(id: %s) {
                  alerts {
                    nrqlConditionsSearch {
                      nrqlConditions {
                        id
                        name
                        enabled
                        type
                        signal {
                          aggregationWindow
                        }
                        terms {
                          operator
                          priority
                          threshold
                          thresholdDuration
                          thresholdOccurrences
                        }
                        nrql {
                          query
                        }
                        policyId
                      }
                      totalCount
                    }
                  }
                }
              }
            }
            """
                % account_id
            )

            resp = client.post(NERDGRAPH_URL, json={"query": query})
            resp.raise_for_status()
            body = resp.json()

            conditions = (
                body.get("data", {})
                .get("actor", {})
                .get("account", {})
                .get("alerts", {})
                .get("nrqlConditionsSearch", {})
                .get("nrqlConditions", [])
            )

            result.events.append(
                self._raw_event(
                    "newrelic_alerts",
                    {"account_id": account_id, "conditions": conditions},
                )
            )
        except Exception as e:
            log.debug("New Relic alerts collection failed: %s", e)
            result.errors.append(f"newrelic_alerts: {e}")

    def _collect_entities(self, account_id: str, result: ConnectorResult) -> None:
        """Collect entity health via NerdGraph."""
        try:
            client = self._nerdgraph_client()
            query = """
            {
              actor {
                entitySearch(queryBuilder: {type: APPLICATION}) {
                  results {
                    entities {
                      guid
                      name
                      type
                      domain
                      entityType
                      reporting
                      alertSeverity
                      tags {
                        key
                        values
                      }
                    }
                    nextCursor
                  }
                  count
                }
              }
            }
            """

            resp = client.post(NERDGRAPH_URL, json={"query": query})
            resp.raise_for_status()
            body = resp.json()

            entities = (
                body.get("data", {})
                .get("actor", {})
                .get("entitySearch", {})
                .get("results", {})
                .get("entities", [])
            )

            result.events.append(
                self._raw_event(
                    "newrelic_entities",
                    {"account_id": account_id, "entities": entities},
                )
            )
        except Exception as e:
            log.debug("New Relic entities collection failed: %s", e)
            result.errors.append(f"newrelic_entities: {e}")

    def _collect_violations(self, account_id: str, result: ConnectorResult) -> None:
        """Collect open violations via REST v2 API."""
        try:
            client = self._rest_client()
            violations: list[dict] = []
            page = 1

            while True:
                resp = client.get(
                    f"{REST_BASE_URL}/alerts_violations.json",
                    params={"only_open": "true", "page": page},
                )
                resp.raise_for_status()
                body = resp.json()
                batch = body.get("violations", [])
                violations.extend(batch)
                if len(batch) == 0:
                    break
                page += 1

            result.events.append(
                self._raw_event(
                    "newrelic_violations",
                    {"account_id": account_id, "violations": violations},
                )
            )
        except Exception as e:
            log.debug("New Relic violations collection failed: %s", e)
            result.errors.append(f"newrelic_violations: {e}")


# Register
registry.register("newrelic", NewRelicConnector)
