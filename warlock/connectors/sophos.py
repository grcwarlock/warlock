"""Sophos Central connector — Layer 1 implementation for endpoint/firewall security.

Collects endpoint health and protection status, alerts (threats, policy violations),
and firewall group/rule configuration via Sophos Central API.
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

AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token"
WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"


class SophosConnector(BaseConnector):
    """Collects compliance telemetry from Sophos Central API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[sophos]")
        if not self.get_secret("WLK_SOPHOS_CLIENT_ID"):
            errors.append("WLK_SOPHOS_CLIENT_ID not set")
        if not self.get_secret("WLK_SOPHOS_CLIENT_SECRET"):
            errors.append("WLK_SOPHOS_CLIENT_SECRET not set")
        return errors

    def health_check(self) -> bool:
        try:
            token, _, _ = self._authenticate()
            return bool(token)
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sophos",
            source_type=SourceType.EDR,
            provider="sophos",
        )

        try:
            access_token, tenant_id, data_region_url = self._authenticate()
        except Exception as e:
            log.debug("Sophos authentication failed: %s", e)
            result.errors.append(f"sophos_auth: {e}")
            result.complete()
            return result

        client = self._client(access_token, tenant_id)

        self._collect_endpoints(client, data_region_url, result)
        self._collect_alerts(client, data_region_url, result)
        self._collect_firewall_groups(client, data_region_url, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _authenticate(self) -> tuple[str, str, str]:
        """OAuth2 client credentials flow, then whoami for tenant details.

        Returns (access_token, tenant_id, data_region_url).
        """
        client_id = self.get_secret("WLK_SOPHOS_CLIENT_ID")
        client_secret = self.get_secret("WLK_SOPHOS_CLIENT_SECRET")

        with httpx.Client(timeout=self.config.timeout_seconds) as client:
            # Get access token
            token_resp = client.post(
                AUTH_URL,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "token",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            token_resp.raise_for_status()
            access_token = token_resp.json()["access_token"]

            # Get tenant info
            whoami_resp = client.get(
                WHOAMI_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            whoami_resp.raise_for_status()
            whoami = whoami_resp.json()
            tenant_id = whoami.get("id", "")
            data_region_url = whoami.get("apiHosts", {}).get("dataRegion", "")

        return access_token, tenant_id, data_region_url

    def _client(self, access_token: str, tenant_id: str) -> httpx.Client:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-Tenant-ID": tenant_id,
            "Content-Type": "application/json",
        }
        return httpx.Client(headers=headers, timeout=self.config.timeout_seconds)

    # -- Pagination --

    def _paginate(
        self,
        client: httpx.Client,
        url: str,
        items_key: str = "items",
    ) -> list:
        """Key-based pagination via pages.nextKey."""
        max_pages = self.config.settings.get("max_pages", 20)
        page_size = self.config.settings.get("page_size", 100)
        all_items: list = []
        params: dict = {"pageSize": page_size}

        for _ in range(max_pages):
            resp = client.get(url, params=params)
            resp.raise_for_status()
            body = resp.json()
            items = body.get(items_key, [])
            if isinstance(items, list):
                all_items.extend(items)
            else:
                return [items] if items else []

            # Sophos uses pages.nextKey for pagination
            pages = body.get("pages", {})
            next_key = pages.get("nextKey", "")
            if not next_key:
                break
            params["pageFromKey"] = next_key

        return all_items

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="sophos",
            source_type=SourceType.EDR,
            provider="sophos",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_endpoints(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect endpoint inventory with health and protection status."""
        try:
            url = f"{base_url}/endpoint/v1/endpoints"
            endpoints = self._paginate(client, url)
            result.events.append(self._raw_event("sophos_endpoints", {"endpoints": endpoints}))
        except Exception as e:
            log.debug("Sophos endpoints collection failed: %s", e)
            result.errors.append(f"sophos_endpoints: {e}")

    def _collect_alerts(self, client: httpx.Client, base_url: str, result: ConnectorResult) -> None:
        """Collect alerts (threats, policy violations, etc.)."""
        try:
            url = f"{base_url}/common/v1/alerts"
            alerts = self._paginate(client, url)
            result.events.append(self._raw_event("sophos_alerts", {"alerts": alerts}))
        except Exception as e:
            log.debug("Sophos alerts collection failed: %s", e)
            result.errors.append(f"sophos_alerts: {e}")

    def _collect_firewall_groups(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect firewall groups and their rules."""
        try:
            url = f"{base_url}/firewall/v1/firewall-groups"
            groups = self._paginate(client, url)

            # Enrich each group with its rules
            for group in groups:
                group_id = group.get("id", "")
                if group_id:
                    try:
                        rules_url = f"{base_url}/firewall/v1/firewall-groups/{group_id}/rules"
                        rules = self._paginate(client, rules_url)
                        group["rules"] = rules
                    except Exception as e:
                        log.debug(
                            "Sophos firewall rules failed for group %s: %s",
                            group_id,
                            e,
                        )
                        group["rules"] = []

            result.events.append(self._raw_event("sophos_firewall_groups", {"groups": groups}))
        except Exception as e:
            log.debug("Sophos firewall groups collection failed: %s", e)
            result.errors.append(f"sophos_firewall_groups: {e}")


# Register
registry.register("sophos", SophosConnector)
