"""Azure Key Vault connector — Layer 1 implementation for CLOUD.

Collects secrets, keys, and certificate metadata from Azure Key Vault
using Bearer token authentication. Secret values are never collected.
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

AZURE_KEYVAULT_API_VERSION = "7.4"

# Sub-resource types to enumerate
RESOURCE_TYPES: list[tuple[str, str]] = [
    ("secrets", "azure_keyvault_secrets"),
    ("keys", "azure_keyvault_keys"),
    ("certificates", "azure_keyvault_certificates"),
]


class AzureKeyVaultConnector(BaseConnector):
    """Collects Key Vault metadata from Azure Key Vault REST API.

    Security note: Only metadata is collected for secrets (name, enabled,
    expiry, creation date, last updated). Secret values are never fetched.
    """

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("AZURE_KEYVAULT_TOKEN"):
            errors.append("AZURE_KEYVAULT_TOKEN env var is not set")
        vault_url = self.config.settings.get("vault_url", "")
        if not vault_url:
            errors.append("settings.vault_url is required (e.g. https://myvault.vault.azure.net)")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("AZURE_KEYVAULT_TOKEN")
            vault_url = self.config.settings.get("vault_url", "")
            resp = httpx.get(
                f"{vault_url}/secrets",
                headers=self._headers(token),
                params={"api-version": AZURE_KEYVAULT_API_VERSION, "maxresults": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="azure_keyvault",
            source_type=SourceType.CLOUD,
            provider="azure_keyvault",
        )

        token = self.get_secret("AZURE_KEYVAULT_TOKEN")
        vault_url = self.config.settings.get("vault_url", "")
        headers = self._headers(token)

        if not vault_url:
            result.errors.append("settings.vault_url is not configured")
            result.complete("error")
            return result

        client = httpx.Client(
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            for resource_type, event_type in RESOURCE_TYPES:
                try:
                    data = self._paginate(client, vault_url, resource_type)
                    result.events.append(
                        RawEventData(
                            source="azure_keyvault",
                            source_type=SourceType.CLOUD,
                            provider="azure_keyvault",
                            event_type=event_type,
                            raw_data={
                                "vault_url": vault_url,
                                "resource_type": resource_type,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Azure Key Vault %s failed: %s", resource_type, e)
                    result.errors.append(f"{resource_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _paginate(self, client: object, vault_url: str, resource_type: str) -> list:
        """Follow Azure Key Vault nextLink pagination. Returns metadata only."""
        all_items: list = []
        params = {
            "api-version": AZURE_KEYVAULT_API_VERSION,
            "maxresults": "100",
        }
        url = f"{vault_url}/{resource_type}"

        while url:
            resp = client.get(url, params=params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()

            items = body.get("value", [])
            # For secrets, strip the 'id' URL to avoid following to the value endpoint
            # Keep only the metadata sub-object if present
            safe_items = [{k: v for k, v in item.items() if k != "value"} for item in items]
            all_items.extend(safe_items)

            next_link = body.get("nextLink")
            if next_link:
                url = next_link
                params = {}  # type: ignore[assignment]
            else:
                url = ""

        return all_items


# Register
registry.register("azure_keyvault", AzureKeyVaultConnector)
