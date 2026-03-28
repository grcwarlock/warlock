"""Zscaler connector — Layer 1 implementation for network security.

Collects web security policies, DLP policies, firewall rules, URL filtering rules,
and sandbox submissions via Zscaler Internet Access (ZIA) API.
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


class ZscalerConnector(BaseConnector):
    """Collects compliance telemetry from Zscaler Internet Access (ZIA) API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[zscaler]")
        if not self.get_secret("WLK_ZSCALER_API_KEY"):
            errors.append("WLK_ZSCALER_API_KEY not set")
        if not self.get_secret("WLK_ZSCALER_CLOUD"):
            errors.append("WLK_ZSCALER_CLOUD not set (e.g. zscloud.net)")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            session_token = self._authenticate(client)
            if session_token:
                self._deauthenticate(client, session_token)
                return True
            return False
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="zscaler",
            source_type=SourceType.NETWORK,
            provider="zscaler",
        )

        client = self._client()

        # Session-based auth: authenticate first
        session_token = None
        try:
            session_token = self._authenticate(client)
            if not session_token:
                result.errors.append("zscaler_auth: Failed to obtain session token")
                result.complete()
                return result
        except Exception as e:
            result.errors.append(f"zscaler_auth: {e}")
            result.complete()
            return result

        # Set session cookie for subsequent requests
        client.cookies.set("JSESSIONID", session_token)

        try:
            self._collect_web_policies(client, result)
            self._collect_dlp_policies(client, result)
            self._collect_firewall_rules(client, result)
            self._collect_url_filter(client, result)
            self._collect_sandbox(client, result)
        finally:
            # Always deauthenticate
            try:
                self._deauthenticate(client, session_token)
            except Exception as e:
                log.debug("Zscaler deauthentication failed: %s", e)

        result.complete()
        return result

    # -- Auth & Client --

    def _zscaler_base_url(self) -> str:
        cloud = self.get_secret("WLK_ZSCALER_CLOUD") or "zscloud.net"
        return f"https://zsapi.{cloud.strip()}"

    def _client(self) -> httpx.Client:
        return httpx.Client(
            headers={"Content-Type": "application/json"},
            timeout=self.config.timeout_seconds,
            verify=True,
        )

    def _authenticate(self, client: httpx.Client) -> str | None:
        """Authenticate and return session token (JSESSIONID)."""
        url = f"{self._zscaler_base_url()}/api/v1/authenticatedSession"
        api_key = self.get_secret("WLK_ZSCALER_API_KEY")
        resp = client.post(url, json={"apiKey": api_key})
        resp.raise_for_status()
        # Session token is in the JSESSIONID cookie
        return resp.cookies.get("JSESSIONID", "")

    def _deauthenticate(self, client: httpx.Client, session_token: str) -> None:
        """End the authenticated session."""
        url = f"{self._zscaler_base_url()}/api/v1/authenticatedSession"
        client.delete(url)

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="zscaler",
            source_type=SourceType.NETWORK,
            provider="zscaler",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_web_policies(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect web application security policies."""
        try:
            url = f"{self._zscaler_base_url()}/api/v1/webApplicationRules"
            resp = client.get(url)
            resp.raise_for_status()
            policies = resp.json()
            if not isinstance(policies, list):
                policies = policies.get("rules", policies.get("result", []))
            result.events.append(self._raw_event("zscaler_web_policies", {"policies": policies}))
        except Exception as e:
            log.debug("Zscaler web policies collection failed: %s", e)
            result.errors.append(f"zscaler_web_policies: {e}")

    def _collect_dlp_policies(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect DLP policy rules."""
        try:
            url = f"{self._zscaler_base_url()}/api/v1/dlpDictionaries"
            resp = client.get(url)
            resp.raise_for_status()
            policies = resp.json()
            if not isinstance(policies, list):
                policies = policies.get("rules", policies.get("result", []))
            result.events.append(self._raw_event("zscaler_dlp_policies", {"policies": policies}))
        except Exception as e:
            log.debug("Zscaler DLP policies collection failed: %s", e)
            result.errors.append(f"zscaler_dlp_policies: {e}")

    def _collect_firewall_rules(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect cloud firewall rules."""
        try:
            url = f"{self._zscaler_base_url()}/api/v1/firewallRules"
            resp = client.get(url)
            resp.raise_for_status()
            rules = resp.json()
            if not isinstance(rules, list):
                rules = rules.get("rules", rules.get("result", []))
            result.events.append(self._raw_event("zscaler_firewall_rules", {"rules": rules}))
        except Exception as e:
            log.debug("Zscaler firewall rules collection failed: %s", e)
            result.errors.append(f"zscaler_firewall_rules: {e}")

    def _collect_url_filter(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect URL filtering rules."""
        try:
            url = f"{self._zscaler_base_url()}/api/v1/urlFilteringRules"
            resp = client.get(url)
            resp.raise_for_status()
            rules = resp.json()
            if not isinstance(rules, list):
                rules = rules.get("rules", rules.get("result", []))
            result.events.append(self._raw_event("zscaler_url_filter", {"rules": rules}))
        except Exception as e:
            log.debug("Zscaler URL filtering collection failed: %s", e)
            result.errors.append(f"zscaler_url_filter: {e}")

    def _collect_sandbox(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect sandbox submission results."""
        try:
            url = f"{self._zscaler_base_url()}/api/v1/sandbox/report"
            resp = client.get(url)
            resp.raise_for_status()
            submissions = resp.json()
            if not isinstance(submissions, list):
                submissions = submissions.get("submissions", submissions.get("result", []))
            result.events.append(self._raw_event("zscaler_sandbox", {"submissions": submissions}))
        except Exception as e:
            log.debug("Zscaler sandbox collection failed: %s", e)
            result.errors.append(f"zscaler_sandbox: {e}")


# Register
registry.register("zscaler", ZscalerConnector)
