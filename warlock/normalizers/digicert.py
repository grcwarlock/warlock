"""DigiCert normalizer — transforms raw DigiCert API responses into Findings.

Normalizes certificate orders and certificates as misconfiguration (expired
or expiring soon) or inventory (valid). Severity is high for expired,
medium for <30 days.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_EXPIRY_HIGH_DAYS = 30


def _days_until_expiry(valid_till: str | None) -> int | None:
    """Return days until certificate expiry. Negative means already expired."""
    if not valid_till:
        return None
    try:
        expiry = datetime.fromisoformat(str(valid_till).replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        delta = expiry - datetime.now(timezone.utc)
        return delta.days
    except (ValueError, TypeError):
        return None


class DigiCertNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "digicert_orders": "_normalize_orders",
        "digicert_certificates": "_normalize_certificates",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "digicert" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "digicert",
            "source_type": SourceType.CUSTOM,
            "provider": "digicert",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Orders --

    def _normalize_orders(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for order in items:
            order_id = str(order.get("id", ""))
            status = order.get("status", "unknown")
            product = order.get("product", {})
            product_name = product.get("name", "unknown") if isinstance(product, dict) else str(product)
            cert = order.get("certificate", {}) or {}
            cn = cert.get("common_name", "unknown")
            valid_till = cert.get("valid_till", "")

            days = _days_until_expiry(valid_till)

            if status == "expired" or (days is not None and days <= 0):
                obs_type = "misconfiguration"
                severity = "high"
                title = f"DigiCert order expired: {cn}"
            elif days is not None and days <= _EXPIRY_HIGH_DAYS:
                obs_type = "misconfiguration"
                severity = "medium"
                title = f"DigiCert order expiring soon ({days}d): {cn}"
            else:
                obs_type = "inventory"
                severity = "info"
                title = f"DigiCert certificate order: {cn}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "order_id": order_id,
                        "status": status,
                        "product": product_name,
                        "common_name": cn,
                        "valid_till": valid_till,
                        "days_until_expiry": days,
                    },
                    resource_id=order_id,
                    resource_type="digicert_order",
                    resource_name=cn,
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
            cert_id = str(cert.get("id", cert.get("serial_number", "")))
            cn = cert.get("common_name", cert.get("cn", "unknown"))
            status = cert.get("status", "unknown")
            valid_till = cert.get("valid_till", cert.get("expires_at", ""))
            issuer_org = cert.get("org", {})
            org_name = issuer_org.get("name", "") if isinstance(issuer_org, dict) else str(issuer_org)
            sans = cert.get("dns_names", [])

            days = _days_until_expiry(valid_till)

            if status == "revoked" or (days is not None and days <= 0):
                obs_type = "misconfiguration"
                severity = "high"
                title = f"DigiCert certificate expired/revoked: {cn}"
            elif days is not None and days <= _EXPIRY_HIGH_DAYS:
                obs_type = "misconfiguration"
                severity = "medium"
                title = f"DigiCert certificate expiring soon ({days}d): {cn}"
            else:
                obs_type = "inventory"
                severity = "info"
                title = f"DigiCert certificate: {cn}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "cert_id": cert_id,
                        "common_name": cn,
                        "status": status,
                        "valid_till": valid_till,
                        "days_until_expiry": days,
                        "org": org_name,
                        "sans": sans if isinstance(sans, list) else [sans],
                    },
                    resource_id=cert_id,
                    resource_type="digicert_certificate",
                    resource_name=cn,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(DigiCertNormalizer())
