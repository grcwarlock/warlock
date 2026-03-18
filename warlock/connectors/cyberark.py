"""CyberArk PAM connector — Layer 1 implementation for IAM.

Collects privileged accounts, safes, platforms, session recordings metadata,
and password compliance from CyberArk REST API.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

# (endpoint, event_type, query_params)
CYBERARK_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/PasswordVault/api/Accounts", "cyberark_accounts", {"limit": "1000"}),
    ("/PasswordVault/api/Safes", "cyberark_safes", {}),
    ("/PasswordVault/api/Platforms", "cyberark_platforms", {}),
    ("/PasswordVault/api/recordings", "cyberark_recordings", {"limit": "1000"}),
]


class CyberArkConnector(BaseConnector):
    """Collects compliance telemetry from CyberArk PAM REST API."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[cyberark]")
        if not self.config.settings.get("base_url"):
            errors.append("'base_url' must be set in connector settings (e.g. 'https://pvwa.company.com')")
        if not self.get_secret("CYBERARK_USERNAME"):
            errors.append("CYBERARK_USERNAME env var is not set")
        if not self.get_secret("CYBERARK_PASSWORD"):
            errors.append("CYBERARK_PASSWORD env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.config.settings["base_url"]
            resp = httpx.get(
                f"{base_url}/PasswordVault/api/Server",
                timeout=self.config.timeout_seconds,
                verify=self.config.settings.get("verify_ssl", True),
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="cyberark",
            source_type=SourceType.IAM,
            provider="cyberark",
        )

        base_url = self.config.settings["base_url"]
        verify_ssl = self.config.settings.get("verify_ssl", True)

        # Authenticate to get session token
        try:
            token = self._authenticate(base_url, verify_ssl)
        except Exception as e:
            result.errors.append(f"CyberArk authentication failed: {e}")
            result.complete("error")
            return result

        headers = {
            "Authorization": token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
            verify=verify_ssl,
        )

        try:
            for endpoint, event_type, params in CYBERARK_ENDPOINTS:
                try:
                    data = self._paginate(client, endpoint, params)
                    result.events.append(RawEventData(
                        source="cyberark",
                        source_type=SourceType.IAM,
                        provider="cyberark",
                        event_type=event_type,
                        raw_data={
                            "endpoint": endpoint,
                            "base_url": base_url,
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    ))
                except Exception as e:
                    log.debug("CyberArk %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")

            # Password compliance check — accounts with overdue rotation
            try:
                resp = client.get(
                    "/PasswordVault/api/Accounts",
                    params={"filter": "PasswordChangeInProcess eq false", "limit": "1000"},
                )
                resp.raise_for_status()
                body = resp.json()
                accounts = body.get("value", body.get("accounts", []))
                result.events.append(RawEventData(
                    source="cyberark",
                    source_type=SourceType.IAM,
                    provider="cyberark",
                    event_type="cyberark_password_compliance",
                    raw_data={
                        "endpoint": "/PasswordVault/api/Accounts (password compliance)",
                        "base_url": base_url,
                        "response": accounts,
                    },
                    observed_at=datetime.now(timezone.utc),
                ))
            except Exception as e:
                log.debug("CyberArk password compliance check failed: %s", e)
                result.errors.append(f"password_compliance: {e}")

        finally:
            # Log off
            try:
                client.post("/PasswordVault/api/Auth/Logoff")
            except Exception:
                pass
            client.close()

        result.complete()
        return result

    def _authenticate(self, base_url: str, verify_ssl: bool) -> str:
        """Authenticate and return session token."""
        import httpx

        username = self.get_secret("CYBERARK_USERNAME")
        password = self.get_secret("CYBERARK_PASSWORD")
        auth_type = self.config.settings.get("auth_type", "CyberArk")

        resp = httpx.post(
            f"{base_url}/PasswordVault/api/Auth/{auth_type}/Logon",
            json={"username": username, "password": password},
            timeout=30,
            verify=verify_ssl,
        )
        resp.raise_for_status()
        return resp.json() if isinstance(resp.json(), str) else resp.text.strip('"')

    def _paginate(self, client, endpoint: str, params: dict) -> list:
        """Follow CyberArk offset-based pagination."""
        all_items: list = []
        offset = 0
        limit = int(params.get("limit", "1000"))
        current_params = {k: v for k, v in params.items() if k != "limit"}
        current_params["limit"] = str(limit)

        while True:
            current_params["offset"] = str(offset)
            resp = client.get(endpoint, params=current_params)
            resp.raise_for_status()
            body = resp.json()

            # CyberArk wraps results in "value" or specific keys
            items = body.get("value", body.get("accounts", body.get("Safes", [])))
            if isinstance(items, list):
                all_items.extend(items)
            else:
                all_items.append(body)
                break

            total = body.get("count", body.get("Total", 0))
            offset += len(items)
            if not items or offset >= total:
                break

        return all_items


# Register
registry.register("cyberark", CyberArkConnector)
