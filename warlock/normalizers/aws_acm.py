"""AWS ACM normalizer — transforms raw ACM API responses into Findings.

Normalizes certificates as misconfiguration (expired or expiring soon) or
inventory (valid). Severity is high for expired, medium for <30 days.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_EXPIRY_HIGH_DAYS = 30  # Medium severity threshold


def _days_until_expiry(not_after: str | None) -> int | None:
    """Return days until certificate expiry. Negative means already expired."""
    if not not_after:
        return None
    try:
        expiry = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        delta = expiry - datetime.now(timezone.utc)
        return delta.days
    except (ValueError, TypeError):
        return None


class AwsAcmNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "aws_acm_certificates": "_normalize_certificates",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "aws_acm" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "aws_acm",
            "source_type": SourceType.CLOUD,
            "provider": "aws_acm",
            "account_id": "",
            "region": raw.raw_data.get("region", ""),
            "observed_at": raw.observed_at,
        }

    # -- Certificates --

    def _normalize_certificates(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for cert in items:
            cert_arn = cert.get("CertificateArn", cert.get("CertificateArn", ""))
            domain = cert.get(
                "DomainName",
                cert.get("SubjectAlternativeNames", ["unknown"])[0]
                if cert.get("SubjectAlternativeNames")
                else "unknown",
            )
            status = cert.get("Status", "UNKNOWN")
            not_after = cert.get("NotAfter", "")
            key_algorithm = cert.get("KeyAlgorithm", "")
            issuer = cert.get("Issuer", "")
            renewal_eligibility = cert.get("RenewalEligibility", "")
            cert_type = cert.get("Type", "AMAZON_ISSUED")

            # Extract short ID from ARN
            cert_id = cert_arn.split("/")[-1] if "/" in cert_arn else cert_arn

            days = _days_until_expiry(not_after)

            if status in ("EXPIRED",) or (days is not None and days <= 0):
                obs_type = "misconfiguration"
                severity = "high"
                title = f"AWS ACM certificate expired: {domain}"
            elif days is not None and days <= _EXPIRY_HIGH_DAYS:
                obs_type = "misconfiguration"
                severity = "medium"
                title = f"AWS ACM certificate expiring soon ({days}d): {domain}"
            elif status in ("FAILED", "REVOKED", "INACTIVE"):
                obs_type = "misconfiguration"
                severity = "medium"
                title = f"AWS ACM certificate {status.lower()}: {domain}"
            else:
                obs_type = "inventory"
                severity = "info"
                title = f"AWS ACM certificate: {domain}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "certificate_arn": cert_arn,
                        "domain": domain,
                        "status": status,
                        "not_after": str(not_after) if not_after else "",
                        "days_until_expiry": days,
                        "key_algorithm": key_algorithm,
                        "issuer": issuer,
                        "renewal_eligibility": renewal_eligibility,
                        "type": cert_type,
                    },
                    resource_id=cert_id,
                    resource_type="aws_acm_certificate",
                    resource_name=domain,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AwsAcmNormalizer())
