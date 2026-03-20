"""Verkada connector — Layer 1 implementation for physical security.

Collects access events, doors, and card holders from the Verkada API.
Uses x-api-key header authentication.
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

VERKADA_BASE_URL = "https://api.verkada.com"


class VerkadaConnector(BaseConnector):
    """Collects physical security telemetry from Verkada APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[verkada]")
        if not self.get_secret("WLK_VERKADA_API_KEY"):
            errors.append("WLK_VERKADA_API_KEY env var is not set")
        if not self.config.settings.get("org_id"):
            errors.append("'org_id' must be set in connector settings")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            org_id = self.config.settings["org_id"]
            resp = httpx.get(
                f"{VERKADA_BASE_URL}/access/v1/doors",
                params={"org_id": org_id},
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="verkada",
            source_type=SourceType.PHYSICAL,
            provider="verkada",
        )

        org_id = self.config.settings["org_id"]
        headers = self._headers()

        client = httpx.Client(
            base_url=VERKADA_BASE_URL,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            # Collect access events
            self._collect_endpoint(
                client,
                result,
                endpoint="/access/v1/access_events",
                params={"org_id": org_id, "page_size": "100"},
                event_type="verkada_access_events",
                paginated=True,
            )

            # Collect doors
            self._collect_endpoint(
                client,
                result,
                endpoint="/access/v1/doors",
                params={"org_id": org_id},
                event_type="verkada_doors",
            )

            # Collect card holders / users
            self._collect_endpoint(
                client,
                result,
                endpoint="/access/v1/card_holders",
                params={"org_id": org_id, "page_size": "100"},
                event_type="verkada_users",
                paginated=True,
            )
        finally:
            client.close()

        result.complete()
        return result

    def _collect_endpoint(
        self,
        client,
        result: ConnectorResult,
        endpoint: str,
        params: dict,
        event_type: str,
        paginated: bool = False,
    ) -> None:
        try:
            if paginated:
                data = self._paginate(client, endpoint, params)
            else:
                resp = client.get(endpoint, params=params)
                resp.raise_for_status()
                data = resp.json()

            result.events.append(
                RawEventData(
                    source="verkada",
                    source_type=SourceType.PHYSICAL,
                    provider="verkada",
                    event_type=event_type,
                    raw_data={"response": data if isinstance(data, list) else data},
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("Verkada %s failed: %s", endpoint, e)
            result.errors.append(f"{event_type}: {e}")

    def _paginate(self, client, endpoint: str, params: dict) -> list:
        """Paginate Verkada API using next_page_token."""
        all_items: list = []
        current_params = dict(params)

        while True:
            resp = client.get(endpoint, params=current_params)
            resp.raise_for_status()
            body = resp.json()

            items = (
                body
                if isinstance(body, list)
                else body.get("access_events", body.get("card_holders", body.get("results", [])))
            )
            if isinstance(items, list):
                all_items.extend(items)
            else:
                all_items.append(items)

            next_token = body.get("next_page_token") if isinstance(body, dict) else None
            if not next_token:
                break
            current_params["page_token"] = next_token

        return all_items

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self.get_secret("WLK_VERKADA_API_KEY"),
            "Accept": "application/json",
        }


# Register
registry.register("verkada", VerkadaConnector)
