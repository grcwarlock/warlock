"""Osano normalizer — transforms raw Osano API responses into Findings.

Normalizes consent records, data maps, and vendor assessments as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class OsanoNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Osano privacy findings."""

    HANDLERS: dict[str, str] = {
        "osano_consent_records": "_normalize_consent_records",
        "osano_data_maps": "_normalize_data_maps",
        "osano_vendor_assessments": "_normalize_vendor_assessments",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "osano" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "osano",
            "source_type": SourceType.CUSTOM,
            "provider": "osano",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_consent_records(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("consentRecords", response.get("data", []))
        )

        for record in items:
            record_id = str(record.get("id", record.get("consentId", "")))
            subject = record.get("subject", record.get("userId", record.get("email", "unknown")))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Osano consent record: {subject}",
                    detail={
                        "record_id": record_id,
                        "subject": subject,
                        "consent_type": record.get("consentType", ""),
                        "status": record.get("status", ""),
                        "purpose": record.get("purpose", ""),
                        "timestamp": record.get("timestamp", record.get("createdAt", "")),
                        "jurisdiction": record.get("jurisdiction", ""),
                    },
                    resource_id=record_id,
                    resource_type="osano_consent_record",
                    resource_name=subject,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_data_maps(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("dataMaps", response.get("data", []))

        for data_map in items:
            map_id = str(data_map.get("id", ""))
            name = data_map.get("name", data_map.get("title", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Osano data map: {name}",
                    detail={
                        "map_id": map_id,
                        "name": name,
                        "description": data_map.get("description", ""),
                        "data_categories": data_map.get("dataCategories", []),
                        "processing_activities": data_map.get("processingActivities", []),
                        "created_at": data_map.get("createdAt", ""),
                        "updated_at": data_map.get("updatedAt", ""),
                    },
                    resource_id=map_id,
                    resource_type="osano_data_map",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_vendor_assessments(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("vendorAssessments", response.get("data", []))
        )

        for assessment in items:
            assessment_id = str(assessment.get("id", ""))
            vendor_name = assessment.get("vendorName", assessment.get("name", "unknown"))
            score = assessment.get("score", assessment.get("privacyScore", 100))

            # Low score vendors are a risk
            severity = "medium" if isinstance(score, (int, float)) and score < 60 else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Osano vendor assessment: {vendor_name}",
                    detail={
                        "assessment_id": assessment_id,
                        "vendor_name": vendor_name,
                        "score": score,
                        "status": assessment.get("status", ""),
                        "risk_level": assessment.get("riskLevel", ""),
                        "data_categories": assessment.get("dataCategories", []),
                        "last_assessed": assessment.get("lastAssessed", ""),
                    },
                    resource_id=assessment_id,
                    resource_type="osano_vendor_assessment",
                    resource_name=vendor_name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(OsanoNormalizer())
