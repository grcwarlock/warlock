"""Cloudflare connector — Layer 1 implementation for infrastructure protection.

Collects WAF events, DNS records, Zero Trust policies, gateway rules,
SSL/TLS settings, Page Shield data, and audit logs via Cloudflare API v4.
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

BASE_URL = "https://api.cloudflare.com/client/v4"


class CloudflareConnector(BaseConnector):
    """Collects compliance telemetry from Cloudflare API v4."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[cloudflare]")
        # Need either API token or API key + email
        has_token = bool(self.get_secret("WLK_CLOUDFLARE_API_TOKEN"))
        has_key = bool(self.get_secret("WLK_CLOUDFLARE_API_KEY")) and bool(
            self.get_secret("WLK_CLOUDFLARE_EMAIL")
        )
        if not has_token and not has_key:
            errors.append(
                "Auth not configured. Set WLK_CLOUDFLARE_API_TOKEN, "
                "or both WLK_CLOUDFLARE_API_KEY and WLK_CLOUDFLARE_EMAIL"
            )
        if not self.config.settings.get("account_id"):
            errors.append("settings.account_id not set")
        if not self.config.settings.get("zone_ids"):
            errors.append("settings.zone_ids not set (list of zone IDs)")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{BASE_URL}/user/tokens/verify")
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="cloudflare",
            source_type=SourceType.CLOUD,
            provider="cloudflare",
        )

        client = self._client()
        account_id = self.config.settings["account_id"]
        zone_ids: list[str] = self.config.settings["zone_ids"]

        # Per-zone collections
        for zone_id in zone_ids:
            self._collect_waf_rules(client, zone_id, result)
            self._collect_dns_records(client, zone_id, result)
            self._collect_ssl_settings(client, zone_id, result)
            self._collect_page_shield(client, zone_id, result)

        # Account-level collections
        self._collect_access_apps(client, account_id, result)
        self._collect_gateway_rules(client, account_id, result)
        self._collect_audit_logs(client, account_id, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _client(self) -> httpx.Client:
        """Build an httpx client with appropriate auth headers."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        token = self.get_secret("WLK_CLOUDFLARE_API_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        else:
            headers["X-Auth-Key"] = self.get_secret("WLK_CLOUDFLARE_API_KEY")
            headers["X-Auth-Email"] = self.get_secret("WLK_CLOUDFLARE_EMAIL")
        return httpx.Client(headers=headers, timeout=self.config.timeout_seconds)

    # -- Pagination --

    def _paginate(
        self,
        client: httpx.Client,
        url: str,
        result_key: str = "result",
    ) -> list:
        """Cursor-based pagination via result_info.cursors."""
        max_pages = self.config.settings.get("max_pages", 20)
        per_page = self.config.settings.get("per_page", 100)
        all_items: list = []
        params: dict = {"per_page": per_page}

        for _ in range(max_pages):
            resp = client.get(url, params=params)
            resp.raise_for_status()
            body = resp.json()
            items = body.get(result_key, [])
            if isinstance(items, list):
                all_items.extend(items)
            else:
                # Single-object result (e.g. SSL settings)
                return [items] if items else []

            # Cursor-based pagination
            result_info = body.get("result_info", {})
            cursors = result_info.get("cursors", {})
            after = cursors.get("after", "")
            if not after:
                # Fall back to page-based pagination
                total_pages = result_info.get("total_pages", 1)
                current_page = result_info.get("page", 1)
                if current_page >= total_pages:
                    break
                params["page"] = current_page + 1
            else:
                params["cursor"] = after

        return all_items

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="cloudflare",
            source_type=SourceType.CLOUD,
            provider="cloudflare",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Per-zone collectors --

    def _collect_waf_rules(
        self, client: httpx.Client, zone_id: str, result: ConnectorResult
    ) -> None:
        """Collect WAF / firewall access rules for a zone."""
        try:
            url = f"{BASE_URL}/zones/{zone_id}/firewall/access_rules/rules"
            rules = self._paginate(client, url)
            result.events.append(
                self._raw_event(
                    "cf_waf_rules",
                    {"zone_id": zone_id, "rules": rules},
                )
            )
        except Exception as e:
            log.debug("Cloudflare WAF rules collection failed for zone %s: %s", zone_id, e)
            result.errors.append(f"cf_waf_rules[{zone_id}]: {e}")

    def _collect_dns_records(
        self, client: httpx.Client, zone_id: str, result: ConnectorResult
    ) -> None:
        """Collect DNS records for a zone."""
        try:
            url = f"{BASE_URL}/zones/{zone_id}/dns_records"
            records = self._paginate(client, url)
            result.events.append(
                self._raw_event(
                    "cf_dns_records",
                    {"zone_id": zone_id, "records": records},
                )
            )
        except Exception as e:
            log.debug("Cloudflare DNS records collection failed for zone %s: %s", zone_id, e)
            result.errors.append(f"cf_dns_records[{zone_id}]: {e}")

    def _collect_ssl_settings(
        self, client: httpx.Client, zone_id: str, result: ConnectorResult
    ) -> None:
        """Collect SSL/TLS settings: ssl mode, min TLS version, always-use-https."""
        try:
            ssl_resp = client.get(f"{BASE_URL}/zones/{zone_id}/settings/ssl")
            ssl_resp.raise_for_status()
            ssl_data = ssl_resp.json().get("result", {})

            tls_resp = client.get(f"{BASE_URL}/zones/{zone_id}/settings/min_tls_version")
            tls_resp.raise_for_status()
            tls_data = tls_resp.json().get("result", {})

            https_resp = client.get(f"{BASE_URL}/zones/{zone_id}/settings/always_use_https")
            https_resp.raise_for_status()
            https_data = https_resp.json().get("result", {})

            result.events.append(
                self._raw_event(
                    "cf_ssl_settings",
                    {
                        "zone_id": zone_id,
                        "ssl": ssl_data,
                        "min_tls_version": tls_data,
                        "always_use_https": https_data,
                    },
                )
            )
        except Exception as e:
            log.debug("Cloudflare SSL settings collection failed for zone %s: %s", zone_id, e)
            result.errors.append(f"cf_ssl_settings[{zone_id}]: {e}")

    def _collect_page_shield(
        self, client: httpx.Client, zone_id: str, result: ConnectorResult
    ) -> None:
        """Collect Page Shield scripts for a zone."""
        try:
            url = f"{BASE_URL}/zones/{zone_id}/page_shield/scripts"
            scripts = self._paginate(client, url)
            result.events.append(
                self._raw_event(
                    "cf_page_shield",
                    {"zone_id": zone_id, "scripts": scripts},
                )
            )
        except Exception as e:
            log.debug("Cloudflare Page Shield collection failed for zone %s: %s", zone_id, e)
            result.errors.append(f"cf_page_shield[{zone_id}]: {e}")

    # -- Account-level collectors --

    def _collect_access_apps(
        self, client: httpx.Client, account_id: str, result: ConnectorResult
    ) -> None:
        """Collect Zero Trust Access applications."""
        try:
            url = f"{BASE_URL}/accounts/{account_id}/access/apps"
            apps = self._paginate(client, url)
            result.events.append(
                self._raw_event(
                    "cf_access_apps",
                    {"account_id": account_id, "apps": apps},
                )
            )
        except Exception as e:
            log.debug("Cloudflare Access apps collection failed: %s", e)
            result.errors.append(f"cf_access_apps: {e}")

    def _collect_gateway_rules(
        self, client: httpx.Client, account_id: str, result: ConnectorResult
    ) -> None:
        """Collect Zero Trust Gateway rules."""
        try:
            url = f"{BASE_URL}/accounts/{account_id}/gateway/rules"
            rules = self._paginate(client, url)
            result.events.append(
                self._raw_event(
                    "cf_gateway_rules",
                    {"account_id": account_id, "rules": rules},
                )
            )
        except Exception as e:
            log.debug("Cloudflare Gateway rules collection failed: %s", e)
            result.errors.append(f"cf_gateway_rules: {e}")

    def _collect_audit_logs(
        self, client: httpx.Client, account_id: str, result: ConnectorResult
    ) -> None:
        """Collect account audit logs."""
        try:
            url = f"{BASE_URL}/accounts/{account_id}/audit_logs"
            logs = self._paginate(client, url)
            result.events.append(
                self._raw_event(
                    "cf_audit_logs",
                    {"account_id": account_id, "logs": logs},
                )
            )
        except Exception as e:
            log.debug("Cloudflare audit logs collection failed: %s", e)
            result.errors.append(f"cf_audit_logs: {e}")


# Register
registry.register("cloudflare", CloudflareConnector)
