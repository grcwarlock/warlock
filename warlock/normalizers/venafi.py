"""Venafi normalizer — transforms raw Venafi API responses into Findings.

Normalizes certificates as misconfiguration (expired or expiring soon) or
inventory (valid). Config endpoint produces inventory findings.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_EXPIRY_CRITICAL_DAYS = 0   # Already expired
_EXPIRY_HIGH_DAYS = 30      # Expires within 30 days


def _days_until_expiry(not_after: str) -> int | None:
    """Return days until certificate expiry. Negative means already expired."""
    if not not_after:
        return None
    try:
        expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        delta = expiry - datetime.now(timezone.utc)
        return delta.days
    except (ValueError, TypeError):
        return None


class VenafiNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "venafi_certificates": "_normalize_certificates",
        "venafi_config": "_normalize_config",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "venafi" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "venafi",
            "source_type": SourceType.CUSTOM,
            "provider": "venafi",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Certificates --

    def _normalize_certificates(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for cert in items:
            cert_id = str(cert.get("Guid", cert.get("id", "")))
            cn = cert.get("CN", cert.get("CommonName", cert.get("Subject", "unknown")))
            not_after = cert.get("ValidTo", cert.get("NotAfter", ""))
            issuer = cert.get("Issuer", cert.get("IssuerDN", ""))
            subject_alt = cert.get("SubjectAltNames", [])
            key_algorithm = cert.get("KeyAlgorithm", "")
            key_size = cert.get("KeySize", "")

            days = _days_until_expiry(not_after)

            if days is not None and days <= _EXPIRY_CRITICAL_DAYS:
                obs_type = "misconfiguration"
                severity = "high"
                title = f"Venafi certificate expired: {cn}"
            elif days is not None and days <= _EXPIRY_HIGH_DAYS:
                obs_type = "misconfiguration"
                severity = "medium"
                title = f"Venafi certificate expiring soon ({days}d): {cn}"
            else:
                obs_type = "inventory"
                severity = "info"
                title = f"Venafi certificate: {cn}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "cert_id": cert_id,
                        "common_name": cn,
                        "not_after": not_after,
                        "days_until_expiry": days,
                        "issuer": issuer,
                        "subject_alt_names": subject_alt
                        if isinstance(subject_alt, list)
                        else [subject_alt],
                        "key_algorithm": key_algorithm,
                        "key_size": key_size,
                    },
                    resource_id=cert_id,
                    resource_type="venafi_certificate",
                    resource_name=cn,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    # -- Config --

    def _normalize_config(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for config_item in items:
            if not isinstance(config_item, dict):
                continue
            config_id = str(config_item.get("DN", config_item.get("id", "")))
            name = config_item.get("Name", config_item.get("name", "unknown"))
            object_class = config_item.get("ObjectClass", config_item.get("Class", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Venafi config object: {name}",
                    detail={
                        "config_id": config_id,
                        "name": name,
                        "object_class": object_class,
                    },
                    resource_id=config_id,
                    resource_type="venafi_config",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(VenafiNormalizer())
