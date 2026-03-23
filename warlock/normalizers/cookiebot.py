"""Cookiebot normalizer — transforms raw Cookiebot API responses into Findings.

Normalizes scan results, consent records, and domain data as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class CookiebotNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Cookiebot privacy findings."""

    HANDLERS: dict[str, str] = {
        "cookiebot_scans": "_normalize_scans",
        "cookiebot_consents": "_normalize_consents",
        "cookiebot_domains": "_normalize_domains",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "cookiebot" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "cookiebot",
            "source_type": SourceType.CUSTOM,
            "provider": "cookiebot",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_scans(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("scans", response.get("data", []))

        for scan in items:
            scan_id = str(scan.get("id", scan.get("scanId", "")))
            domain = scan.get("domain", scan.get("url", "unknown"))
            cookies_found = scan.get("cookiesFound", scan.get("cookieCount", 0))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Cookiebot scan: {domain}",
                    detail={
                        "scan_id": scan_id,
                        "domain": domain,
                        "cookies_found": cookies_found,
                        "scan_date": scan.get("scanDate", scan.get("date", "")),
                        "status": scan.get("status", ""),
                        "categories": scan.get("categories", {}),
                    },
                    resource_id=scan_id,
                    resource_type="cookiebot_scan",
                    resource_name=domain,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_consents(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("consents", response.get("data", []))

        for consent in items:
            consent_id = str(consent.get("id", consent.get("consentId", "")))
            user_key = consent.get("userKey", consent.get("userId", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Cookiebot consent: {user_key}",
                    detail={
                        "consent_id": consent_id,
                        "user_key": user_key,
                        "accepted": consent.get("accepted", False),
                        "necessary": consent.get("necessary", False),
                        "preferences": consent.get("preferences", False),
                        "statistics": consent.get("statistics", False),
                        "marketing": consent.get("marketing", False),
                        "method": consent.get("method", ""),
                        "timestamp": consent.get("timestamp", ""),
                    },
                    resource_id=consent_id,
                    resource_type="cookiebot_consent",
                    resource_name=user_key,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_domains(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("domains", response.get("data", []))

        for domain in items:
            domain_id = str(domain.get("id", domain.get("domainId", "")))
            name = domain.get("name", domain.get("domain", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Cookiebot domain: {name}",
                    detail={
                        "domain_id": domain_id,
                        "name": name,
                        "enabled": domain.get("enabled", True),
                        "language": domain.get("language", ""),
                        "created_at": domain.get("createdAt", ""),
                        "cookie_count": domain.get("cookieCount", 0),
                    },
                    resource_id=domain_id,
                    resource_type="cookiebot_domain",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(CookiebotNormalizer())
