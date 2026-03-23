"""TrustArc normalizer — transforms raw TrustArc API responses into Findings.

Normalizes assessments, data inventory, and cookie consent records
as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class TrustArcNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for TrustArc privacy findings."""

    HANDLERS: dict[str, str] = {
        "trustarc_assessments": "_normalize_assessments",
        "trustarc_data_inventory": "_normalize_data_inventory",
        "trustarc_cookie_consent": "_normalize_cookie_consent",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "trustarc" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "trustarc",
            "source_type": SourceType.GRC,
            "provider": "trustarc",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_assessments(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("assessments", response.get("data", []))

        for assessment in items:
            assessment_id = str(assessment.get("id", assessment.get("assessmentId", "")))
            name = assessment.get("name", assessment.get("title", "unknown"))
            status = assessment.get("status", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"TrustArc assessment: {name}",
                    detail={
                        "assessment_id": assessment_id,
                        "name": name,
                        "status": status,
                        "type": assessment.get("type", ""),
                        "assigned_to": assessment.get("assignedTo", ""),
                        "due_date": assessment.get("dueDate", ""),
                        "completed_at": assessment.get("completedAt", ""),
                        "risk_score": assessment.get("riskScore", 0),
                    },
                    resource_id=assessment_id,
                    resource_type="trustarc_assessment",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_data_inventory(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("dataInventory", response.get("data", []))
        )

        for item in items:
            item_id = str(item.get("id", ""))
            name = item.get("name", item.get("dataElement", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"TrustArc data inventory: {name}",
                    detail={
                        "item_id": item_id,
                        "name": name,
                        "category": item.get("category", ""),
                        "data_type": item.get("dataType", ""),
                        "processing_purpose": item.get("processingPurpose", ""),
                        "legal_basis": item.get("legalBasis", ""),
                        "retention_period": item.get("retentionPeriod", ""),
                    },
                    resource_id=item_id,
                    resource_type="trustarc_data_item",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_cookie_consent(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("consents", response.get("data", []))

        for consent in items:
            consent_id = str(consent.get("id", ""))
            domain = consent.get("domain", consent.get("website", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"TrustArc cookie consent: {domain}",
                    detail={
                        "consent_id": consent_id,
                        "domain": domain,
                        "status": consent.get("status", ""),
                        "consent_rate": consent.get("consentRate", 0),
                        "opt_out_rate": consent.get("optOutRate", 0),
                        "categories": consent.get("categories", []),
                        "last_scan": consent.get("lastScan", ""),
                    },
                    resource_id=consent_id,
                    resource_type="trustarc_cookie_consent",
                    resource_name=domain,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(TrustArcNormalizer())
