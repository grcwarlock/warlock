"""HashiCorp Vault connector — Layer 1 implementation for secrets management.

Collects secret engines, auth methods, policies, audit devices, seal status,
and health from the Vault HTTP API. Supports token and AppRole authentication.
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

VAULT_ENDPOINTS: list[tuple[str, str]] = [
    ("/v1/sys/mounts", "vault_secret_engines"),
    ("/v1/sys/auth", "vault_auth_methods"),
    ("/v1/sys/policies/acl", "vault_policies"),
    ("/v1/sys/audit", "vault_audit_devices"),
    ("/v1/sys/seal-status", "vault_seal_status"),
    ("/v1/sys/health", "vault_health"),
]


class VaultConnector(BaseConnector):
    """Collects security telemetry from HashiCorp Vault HTTP API."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[vault]")
        if not self.get_secret("WLK_VAULT_ADDR"):
            errors.append("WLK_VAULT_ADDR env var is not set")
        # Require either direct token or AppRole credentials
        has_token = bool(self.get_secret("WLK_VAULT_TOKEN"))
        has_approle = bool(
            self.get_secret("WLK_VAULT_ROLE_ID")
            and self.get_secret("WLK_VAULT_SECRET_ID")
        )
        if not has_token and not has_approle:
            errors.append(
                "Either WLK_VAULT_TOKEN or both WLK_VAULT_ROLE_ID and "
                "WLK_VAULT_SECRET_ID must be set"
            )
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.get_secret("WLK_VAULT_ADDR").rstrip("/")
            token = self._resolve_token()
            resp = httpx.get(
                f"{base_url}/v1/sys/health",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            # Vault returns 200 (active), 429 (standby), 472 (perf standby),
            # 501 (not initialized), 503 (sealed) — all are "reachable"
            return resp.status_code in (200, 429, 472, 473)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="vault",
            source_type=SourceType.IAM,
            provider="vault",
        )

        base_url = self.get_secret("WLK_VAULT_ADDR").rstrip("/")
        token = self._resolve_token()
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for endpoint, event_type in VAULT_ENDPOINTS:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(RawEventData(
                        source="vault",
                        source_type=SourceType.IAM,
                        provider="vault",
                        event_type=event_type,
                        raw_data={
                            "endpoint": endpoint,
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    ))
                except Exception as e:
                    log.debug("Vault %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _resolve_token(self) -> str:
        """Return a Vault token, performing AppRole login if needed."""
        token = self.get_secret("WLK_VAULT_TOKEN")
        if token:
            return token

        import httpx

        base_url = self.get_secret("WLK_VAULT_ADDR").rstrip("/")
        role_id = self.get_secret("WLK_VAULT_ROLE_ID")
        secret_id = self.get_secret("WLK_VAULT_SECRET_ID")

        resp = httpx.post(
            f"{base_url}/v1/auth/approle/login",
            json={"role_id": role_id, "secret_id": secret_id},
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()["auth"]["client_token"]

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "X-Vault-Token": token,
            "Accept": "application/json",
        }


# Register
registry.register("vault", VaultConnector)
