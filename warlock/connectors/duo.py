"""Duo Security connector — Layer 1 implementation for MFA / IAM.

Collects users (MFA enrollment), auth logs, devices, and policies
via the Duo Admin API with HMAC-SHA1 signed requests.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import urllib.parse
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


class DuoConnector(BaseConnector):
    """Collects compliance telemetry from Duo Admin API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[duo]")
        if not self.get_secret("WLK_DUO_INTEGRATION_KEY"):
            errors.append("WLK_DUO_INTEGRATION_KEY not set")
        if not self.get_secret("WLK_DUO_SECRET_KEY"):
            errors.append("WLK_DUO_SECRET_KEY not set")
        if not self.get_secret("WLK_DUO_API_HOST"):
            errors.append("WLK_DUO_API_HOST not set")
        return errors

    def health_check(self) -> bool:
        try:
            api_host = self.get_secret("WLK_DUO_API_HOST")
            resp = self._signed_request("GET", "/admin/v1/info/summary", api_host)
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="duo",
            source_type=SourceType.IAM,
            provider="duo",
        )

        api_host = self.get_secret("WLK_DUO_API_HOST")

        self._collect_users(api_host, result)
        self._collect_auth_logs(api_host, result)
        self._collect_devices(api_host, result)
        self._collect_policies(api_host, result)

        result.complete()
        return result

    # -- HMAC-SHA1 Signed Requests --

    def _sign(self, method: str, host: str, path: str, params: str, date: str) -> str:
        """Generate Duo HMAC-SHA1 signature."""
        canon = "\n".join([date, method.upper(), host.lower(), path, params])
        secret_key = self.get_secret("WLK_DUO_SECRET_KEY")
        sig = hmac.new(
            secret_key.encode("utf-8"),
            canon.encode("utf-8"),
            hashlib.sha1,
        ).hexdigest()
        return sig

    def _signed_request(
        self,
        method: str,
        path: str,
        api_host: str,
        params: dict | None = None,
    ) -> httpx.Response:
        """Make an HMAC-SHA1 signed request to the Duo Admin API."""
        now = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %z").strip()
        params = params or {}

        # Sort and encode params for signature
        sorted_params = urllib.parse.urlencode(sorted(params.items()))

        sig = self._sign(method, api_host, path, sorted_params, now)
        ikey = self.get_secret("WLK_DUO_INTEGRATION_KEY")

        import base64

        auth = base64.b64encode(f"{ikey}:{sig}".encode()).decode()

        headers = {
            "Date": now,
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        url = f"https://{api_host}{path}"
        client = httpx.Client(timeout=self.config.timeout_seconds)

        if method.upper() == "GET":
            return client.get(url, params=params, headers=headers)
        return client.post(url, data=params, headers=headers)

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="duo",
            source_type=SourceType.IAM,
            provider="duo",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_users(self, api_host: str, result: ConnectorResult) -> None:
        """Collect Duo users with MFA enrollment status."""
        try:
            resp = self._signed_request("GET", "/admin/v1/users", api_host, {"limit": "300"})
            resp.raise_for_status()
            users = resp.json().get("response", [])
            result.events.append(self._raw_event("duo_users", {"users": users}))
        except Exception as e:
            log.debug("Duo users collection failed: %s", e)
            result.errors.append(f"duo_users: {e}")

    def _collect_auth_logs(self, api_host: str, result: ConnectorResult) -> None:
        """Collect authentication logs (failed/fraud attempts)."""
        try:
            # Fetch last 24h of auth logs
            mintime = str(int((datetime.now(timezone.utc).timestamp() - 86400) * 1000))
            resp = self._signed_request(
                "GET",
                "/admin/v2/logs/authentication",
                api_host,
                {"mintime": mintime, "limit": "1000"},
            )
            resp.raise_for_status()
            body = resp.json()
            logs = body.get("response", {}).get("authlogs", body.get("response", []))
            result.events.append(self._raw_event("duo_auth_logs", {"logs": logs}))
        except Exception as e:
            log.debug("Duo auth logs collection failed: %s", e)
            result.errors.append(f"duo_auth_logs: {e}")

    def _collect_devices(self, api_host: str, result: ConnectorResult) -> None:
        """Collect endpoint devices and their security health."""
        try:
            resp = self._signed_request("GET", "/admin/v1/endpoints", api_host, {"limit": "300"})
            resp.raise_for_status()
            devices = resp.json().get("response", [])
            result.events.append(self._raw_event("duo_devices", {"devices": devices}))
        except Exception as e:
            log.debug("Duo devices collection failed: %s", e)
            result.errors.append(f"duo_devices: {e}")

    def _collect_policies(self, api_host: str, result: ConnectorResult) -> None:
        """Collect Duo policies."""
        try:
            resp = self._signed_request("GET", "/admin/v2/policies", api_host)
            resp.raise_for_status()
            policies = resp.json().get("response", [])
            result.events.append(self._raw_event("duo_policies", {"policies": policies}))
        except Exception as e:
            log.debug("Duo policies collection failed: %s", e)
            result.errors.append(f"duo_policies: {e}")


# Register
registry.register("duo", DuoConnector)
