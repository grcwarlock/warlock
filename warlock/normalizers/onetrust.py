"""OneTrust normalizer — transforms raw OneTrust API responses into Findings.

Normalizes assessments (incomplete PIA detection), data maps, DSAR requests
(overdue detection), and consent records into inventory and policy violation findings.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# DSAR overdue threshold in days
DSAR_OVERDUE_DAYS = 30


class OneTrustNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "onetrust_assessments": "_normalize_assessments",
        "onetrust_data_maps": "_normalize_data_maps",
        "onetrust_dsar_requests": "_normalize_dsar_requests",
        "onetrust_consent_records": "_normalize_consent_records",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "onetrust" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all OneTrust findings."""
        return {
            "raw_event_id": raw.id,
            "source": "onetrust",
            "source_type": SourceType.GRC,
            "provider": "onetrust",
            "observed_at": raw.observed_at,
        }

    # -- Assessments --

    def _normalize_assessments(self, raw: RawEventData) -> list[FindingData]:
        """One inventory finding per assessment; policy violation for incomplete PIAs."""
        findings = []
        assessments = raw.raw_data.get("response", [])

        for assessment in assessments:
            assessment_id = str(assessment.get("assessmentId", assessment.get("id", "")))
            name = assessment.get("name", assessment.get("assessmentName", "Unnamed Assessment"))
            status = assessment.get("status", "")
            assessment_type = assessment.get("type", assessment.get("assessmentType", ""))
            created_date = assessment.get("createdDt", assessment.get("createdDate", ""))
            org_group = assessment.get("orgGroup", {}).get("name", "")

            # Inventory finding
            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Privacy assessment: {name}",
                detail={
                    "assessment_id": assessment_id,
                    "name": name,
                    "status": status,
                    "type": assessment_type,
                    "created_date": created_date,
                    "org_group": org_group,
                },
                resource_id=f"onetrust:assessment:{assessment_id}",
                resource_type="privacy_assessment",
                resource_name=name,
                severity="info",
            ))

            # Incomplete PIA detection
            is_pia = assessment_type.lower() in ("pia", "privacy impact assessment", "dpia") if assessment_type else False
            is_incomplete = status.lower() not in ("complete", "completed", "approved") if status else True

            if is_pia and is_incomplete:
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="policy_violation",
                    title=f"Incomplete PIA: {name} (status: {status})",
                    detail={
                        "assessment_id": assessment_id,
                        "name": name,
                        "status": status,
                        "type": assessment_type,
                        "issue": "incomplete_pia",
                    },
                    resource_id=f"onetrust:assessment:{assessment_id}",
                    resource_type="privacy_assessment",
                    resource_name=name,
                    severity="medium",
                ))

        return findings

    # -- Data Maps --

    def _normalize_data_maps(self, raw: RawEventData) -> list[FindingData]:
        """One inventory finding per data map."""
        findings = []
        data_maps = raw.raw_data.get("response", [])

        for dm in data_maps:
            dm_id = str(dm.get("id", dm.get("dataMapId", "")))
            name = dm.get("name", "Unnamed Data Map")
            description = dm.get("description", "")
            org_group = dm.get("orgGroup", {}).get("name", "") if isinstance(dm.get("orgGroup"), dict) else ""

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Data map: {name}",
                detail={
                    "data_map_id": dm_id,
                    "name": name,
                    "description": description,
                    "org_group": org_group,
                },
                resource_id=f"onetrust:data_map:{dm_id}",
                resource_type="privacy_data_map",
                resource_name=name,
                severity="info",
            ))

        return findings

    # -- DSAR Requests --

    def _normalize_dsar_requests(self, raw: RawEventData) -> list[FindingData]:
        """Policy violation for overdue DSARs (>30 days open)."""
        findings = []
        requests = raw.raw_data.get("response", [])
        now = datetime.now(timezone.utc)
        overdue_threshold = now - timedelta(days=DSAR_OVERDUE_DAYS)

        for req in requests:
            req_id = str(req.get("requestId", req.get("id", "")))
            subject_name = req.get("subjectName", req.get("name", "Unknown"))
            status = req.get("status", req.get("requestStatus", ""))
            request_type = req.get("type", req.get("requestType", ""))
            created_date_str = req.get("createdDate", req.get("createdDt", ""))
            deadline_str = req.get("deadline", req.get("dueDate", ""))

            created_date = self._parse_dt(created_date_str)

            # Check if overdue: open request created more than 30 days ago
            is_open = status.lower() not in ("completed", "closed", "fulfilled", "denied") if status else True
            is_overdue = created_date is not None and created_date < overdue_threshold and is_open

            if is_overdue:
                days_overdue = (now - created_date).days - DSAR_OVERDUE_DAYS
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="policy_violation",
                    title=f"Overdue DSAR: {subject_name} ({days_overdue} days past deadline)",
                    detail={
                        "request_id": req_id,
                        "subject_name": subject_name,
                        "status": status,
                        "type": request_type,
                        "created_date": created_date_str,
                        "deadline": deadline_str,
                        "days_overdue": days_overdue,
                        "issue": "overdue_dsar",
                    },
                    resource_id=f"onetrust:dsar:{req_id}",
                    resource_type="privacy_dsar",
                    resource_name=f"DSAR-{req_id}",
                    severity="high",
                ))

        return findings

    # -- Consent Records --

    def _normalize_consent_records(self, raw: RawEventData) -> list[FindingData]:
        """One inventory finding per consent record."""
        findings = []
        records = raw.raw_data.get("response", [])

        for record in records:
            record_id = str(record.get("consentReceiptId", record.get("id", "")))
            purpose = record.get("purpose", record.get("purposeName", ""))
            status = record.get("status", record.get("consentStatus", ""))
            collection_point = record.get("collectionPoint", record.get("collectionPointName", ""))

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Consent record: {purpose}" if purpose else f"Consent record: {record_id}",
                detail={
                    "record_id": record_id,
                    "purpose": purpose,
                    "status": status,
                    "collection_point": collection_point,
                },
                resource_id=f"onetrust:consent:{record_id}",
                resource_type="privacy_consent",
                resource_name=f"consent-{record_id}",
                severity="info",
            ))

        return findings

    @staticmethod
    def _parse_dt(dt_str: str) -> datetime | None:
        """Parse an ISO 8601 datetime string."""
        if not dt_str:
            return None
        try:
            cleaned = str(dt_str).replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned)
        except (ValueError, TypeError):
            return None


# Register
registry.register(OneTrustNormalizer())
