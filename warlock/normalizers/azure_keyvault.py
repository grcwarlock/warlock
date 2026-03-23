"""Azure Key Vault normalizer — transforms raw Key Vault metadata into Findings.

Normalizes secrets (misconfiguration if rotation overdue >90 days or disabled,
otherwise inventory), keys (inventory), and certificates (misconfiguration if
expired/expiring, inventory if valid). Secret values are never present in findings.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_ROTATION_OVERDUE_DAYS = 90
_EXPIRY_HIGH_DAYS = 30


def _days_since(timestamp: str | int | float | None) -> int | None:
    """Return days since a Unix timestamp or ISO-8601 string. None if absent."""
    if timestamp is None:
        return None
    try:
        if isinstance(timestamp, (int, float)):
            dt = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
        else:
            dt = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError, OSError):
        return None


def _days_until(timestamp: str | int | float | None) -> int | None:
    """Return days until a Unix timestamp or ISO-8601 string. Negative = expired."""
    if timestamp is None:
        return None
    try:
        if isinstance(timestamp, (int, float)):
            dt = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
        else:
            dt = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except (ValueError, TypeError, OSError):
        return None


class AzureKeyVaultNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "azure_keyvault_secrets": "_normalize_secrets",
        "azure_keyvault_keys": "_normalize_keys",
        "azure_keyvault_certificates": "_normalize_certificates",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return (
            raw_event.source == "azure_keyvault" and raw_event.event_type in self.HANDLERS
        )

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "azure_keyvault",
            "source_type": SourceType.CLOUD,
            "provider": "azure_keyvault",
            "account_id": raw.raw_data.get("vault_url", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Secrets --

    def _normalize_secrets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for secret in items:
            # 'id' is the secret metadata URL, not the value
            secret_id = secret.get("id", "").rsplit("/", 1)[-1]
            full_id = secret.get("id", "")
            name = full_id.rsplit("/", 2)[-2] if "/secrets/" in full_id else secret_id
            attrs = secret.get("attributes", {}) or {}
            enabled = attrs.get("enabled", True)
            expires = attrs.get("expires")  # Unix timestamp
            created = attrs.get("created")
            updated = attrs.get("updated")

            days_since_updated = _days_since(updated or created)
            days_until_expiry = _days_until(expires)

            if not enabled:
                obs_type = "misconfiguration"
                severity = "medium"
                title = f"Azure Key Vault secret disabled: {name}"
            elif days_since_updated is not None and days_since_updated > _ROTATION_OVERDUE_DAYS:
                obs_type = "misconfiguration"
                severity = "medium"
                title = f"Azure Key Vault secret rotation overdue ({days_since_updated}d): {name}"
            elif days_until_expiry is not None and days_until_expiry <= 0:
                obs_type = "misconfiguration"
                severity = "high"
                title = f"Azure Key Vault secret expired: {name}"
            else:
                obs_type = "inventory"
                severity = "info"
                title = f"Azure Key Vault secret: {name}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "secret_id": secret_id,
                        "name": name,
                        "enabled": enabled,
                        "days_since_updated": days_since_updated,
                        "days_until_expiry": days_until_expiry,
                    },
                    resource_id=secret_id,
                    resource_type="azure_keyvault_secret",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    # -- Keys --

    def _normalize_keys(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for key in items:
            full_id = key.get("kid", key.get("id", ""))
            key_id = full_id.rsplit("/", 1)[-1]
            name = full_id.rsplit("/", 2)[-2] if "/keys/" in full_id else key_id
            attrs = key.get("attributes", {}) or {}
            enabled = attrs.get("enabled", True)
            expires = attrs.get("expires")
            key_type = key.get("kty", "")
            key_ops = key.get("key_ops", [])

            days_until_expiry = _days_until(expires)

            if not enabled:
                obs_type = "misconfiguration"
                severity = "medium"
                title = f"Azure Key Vault key disabled: {name}"
            elif days_until_expiry is not None and days_until_expiry <= 0:
                obs_type = "misconfiguration"
                severity = "high"
                title = f"Azure Key Vault key expired: {name}"
            elif days_until_expiry is not None and days_until_expiry <= _EXPIRY_HIGH_DAYS:
                obs_type = "misconfiguration"
                severity = "medium"
                title = f"Azure Key Vault key expiring soon ({days_until_expiry}d): {name}"
            else:
                obs_type = "inventory"
                severity = "info"
                title = f"Azure Key Vault key: {name}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "key_id": key_id,
                        "name": name,
                        "enabled": enabled,
                        "key_type": key_type,
                        "key_ops": key_ops if isinstance(key_ops, list) else [key_ops],
                        "days_until_expiry": days_until_expiry,
                    },
                    resource_id=key_id,
                    resource_type="azure_keyvault_key",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    # -- Certificates --

    def _normalize_certificates(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for cert in items:
            full_id = cert.get("id", "")
            cert_id = full_id.rsplit("/", 1)[-1]
            name = full_id.rsplit("/", 2)[-2] if "/certificates/" in full_id else cert_id
            attrs = cert.get("attributes", {}) or {}
            enabled = attrs.get("enabled", True)
            expires = attrs.get("expires")

            days_until_expiry = _days_until(expires)

            if not enabled or (days_until_expiry is not None and days_until_expiry <= 0):
                obs_type = "misconfiguration"
                severity = "high"
                title = f"Azure Key Vault certificate expired/disabled: {name}"
            elif days_until_expiry is not None and days_until_expiry <= _EXPIRY_HIGH_DAYS:
                obs_type = "misconfiguration"
                severity = "medium"
                title = f"Azure Key Vault certificate expiring soon ({days_until_expiry}d): {name}"
            else:
                obs_type = "inventory"
                severity = "info"
                title = f"Azure Key Vault certificate: {name}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "cert_id": cert_id,
                        "name": name,
                        "enabled": enabled,
                        "days_until_expiry": days_until_expiry,
                    },
                    resource_id=cert_id,
                    resource_type="azure_keyvault_certificate",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AzureKeyVaultNormalizer())
