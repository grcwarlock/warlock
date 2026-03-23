"""ADP normalizer — transforms raw ADP HR API responses into Findings.

Normalizes worker records (as inventory) and work assignments (as inventory
for active workers; as access_anomaly for terminated workers with active
system access still indicated by the record being present).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ADPNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "adp_workers": "_normalize_workers",
        "adp_work_assignments": "_normalize_work_assignments",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "adp" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "adp",
            "source_type": SourceType.HRIS,
            "provider": "adp",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_workers(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for worker in items:
            associate_oid = str(worker.get("associateOID", ""))
            person = worker.get("person", {})
            legal_name = person.get("legalName", {}) if isinstance(person, dict) else {}
            full_name = (
                legal_name.get("formattedName", "unknown")
                if isinstance(legal_name, dict)
                else "unknown"
            )

            worker_status = worker.get("workerStatus", {})
            status_code = ""
            if isinstance(worker_status, dict):
                status_code = worker_status.get("statusCode", {}).get("codeValue", "")

            is_terminated = status_code.lower() in ("terminated", "inactive", "separated")
            obs_type = "access_anomaly" if is_terminated else "inventory"
            severity = "medium" if is_terminated else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"ADP worker: {full_name}",
                    detail={
                        "associate_oid": associate_oid,
                        "full_name": full_name,
                        "worker_status": status_code,
                        "is_terminated": is_terminated,
                        "hire_date": worker.get("hireDate", ""),
                        "termination_date": worker.get("terminationDate", ""),
                    },
                    resource_id=associate_oid,
                    resource_type="adp_worker",
                    resource_name=full_name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_work_assignments(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for assignment in items:
            assignment_id = str(assignment.get("itemID", assignment.get("id", "")))
            worker_oid = str(assignment.get("associateOID", ""))
            job_title = assignment.get("jobTitle", "unknown")
            department = assignment.get("homeOrganizationalUnits", [{}])
            dept_name = ""
            if isinstance(department, list) and department:
                dept_name = (
                    department[0].get("nameCode", {}).get("shortName", "")
                    if isinstance(department[0], dict)
                    else ""
                )

            assignment_status = assignment.get("assignmentStatus", {})
            status_code = ""
            if isinstance(assignment_status, dict):
                status_code = assignment_status.get("statusCode", {}).get("codeValue", "")

            is_terminated = status_code.lower() in ("terminated", "inactive")
            obs_type = "access_anomaly" if is_terminated else "inventory"
            severity = "medium" if is_terminated else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"ADP work assignment: {job_title}",
                    detail={
                        "assignment_id": assignment_id,
                        "worker_oid": worker_oid,
                        "job_title": job_title,
                        "department": dept_name,
                        "assignment_status": status_code,
                        "is_terminated": is_terminated,
                        "primary_indicator": assignment.get("primaryIndicator", False),
                    },
                    resource_id=assignment_id,
                    resource_type="adp_work_assignment",
                    resource_name=job_title,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ADPNormalizer())
