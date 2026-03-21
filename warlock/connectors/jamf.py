"""Jamf connector — Layer 1 implementation for MDM (macOS device management).

Collects managed devices, policies, configuration profiles, and patch reports
via the Jamf Pro REST API.
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


class JamfConnector(BaseConnector):
    """Collects compliance telemetry from Jamf Pro REST API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[jamf]")
        if not self.get_secret("WLK_JAMF_BASE_URL"):
            errors.append("WLK_JAMF_BASE_URL not set")
        if not self.get_secret("WLK_JAMF_CLIENT_ID"):
            errors.append("WLK_JAMF_CLIENT_ID not set")
        if not self.get_secret("WLK_JAMF_CLIENT_SECRET"):
            errors.append("WLK_JAMF_CLIENT_SECRET not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            base_url = self.get_secret("WLK_JAMF_BASE_URL").rstrip("/")
            resp = client.get(f"{base_url}/api/v1/jamf-pro-version")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="jamf",
            source_type=SourceType.MDM,
            provider="jamf",
        )

        client = self._client()
        base_url = self.get_secret("WLK_JAMF_BASE_URL").rstrip("/")

        self._collect_devices(client, base_url, result)
        self._collect_policies(client, base_url, result)
        self._collect_config_profiles(client, base_url, result)
        self._collect_patch_reports(client, base_url, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _get_bearer_token(self) -> str:
        """OAuth2 client credentials flow to obtain a Bearer token."""
        base_url = self.get_secret("WLK_JAMF_BASE_URL").rstrip("/")
        client_id = self.get_secret("WLK_JAMF_CLIENT_ID")
        client_secret = self.get_secret("WLK_JAMF_CLIENT_SECRET")

        resp = httpx.post(
            f"{base_url}/api/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _client(self) -> httpx.Client:
        """Build an httpx client with Bearer token auth."""
        token = self._get_bearer_token()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        return httpx.Client(headers=headers, timeout=self.config.timeout_seconds)

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="jamf",
            source_type=SourceType.MDM,
            provider="jamf",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_devices(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect managed devices (computers) with compliance details."""
        try:
            resp = client.get(f"{base_url}/api/v1/computers-inventory", params={"page-size": 200})
            resp.raise_for_status()
            devices = resp.json().get("results", [])
            result.events.append(self._raw_event("jamf_devices", {"devices": devices}))
        except Exception as e:
            log.debug("Jamf devices collection failed: %s", e)
            result.errors.append(f"jamf_devices: {e}")

    def _collect_policies(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect Jamf policies."""
        try:
            resp = client.get(
                f"{base_url}/JSSResource/policies", headers={"Accept": "application/json"}
            )
            resp.raise_for_status()
            policies = resp.json().get("policies", [])
            result.events.append(self._raw_event("jamf_policies", {"policies": policies}))
        except Exception as e:
            log.debug("Jamf policies collection failed: %s", e)
            result.errors.append(f"jamf_policies: {e}")

    def _collect_config_profiles(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect macOS configuration profiles."""
        try:
            resp = client.get(
                f"{base_url}/JSSResource/osxconfigurationprofiles",
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            profiles = resp.json().get("os_x_configuration_profiles", [])
            result.events.append(self._raw_event("jamf_config_profiles", {"profiles": profiles}))
        except Exception as e:
            log.debug("Jamf configuration profiles collection failed: %s", e)
            result.errors.append(f"jamf_config_profiles: {e}")

    def _collect_patch_reports(
        self, client: httpx.Client, base_url: str, result: ConnectorResult
    ) -> None:
        """Collect patch management reports."""
        try:
            resp = client.get(f"{base_url}/api/v2/patch-software-title-configurations")
            resp.raise_for_status()
            reports = resp.json().get("results", resp.json().get("records", []))
            result.events.append(self._raw_event("jamf_patch_reports", {"reports": reports}))
        except Exception as e:
            log.debug("Jamf patch reports collection failed: %s", e)
            result.errors.append(f"jamf_patch_reports: {e}")


# Register
registry.register("jamf", JamfConnector)
