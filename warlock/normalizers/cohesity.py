"""Cohesity normalizer — transforms raw Cohesity API responses into Findings.

Normalizes protection jobs as inventory findings,
failed protection runs as high-severity misconfiguration findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_FAILED_RUN_STATUSES = {"kFailed", "kCanceled", "Failed", "Canceled"}


class CohesityNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Cohesity backup findings."""

    HANDLERS: dict[str, str] = {
        "cohesity_protection_jobs": "_normalize_protection_jobs",
        "cohesity_protection_runs": "_normalize_protection_runs",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "cohesity" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "cohesity",
            "source_type": SourceType.BACKUP,
            "provider": "cohesity",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_protection_jobs(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else []

        for job in items:
            job_id = str(job.get("id", ""))
            name = job.get("name", "unknown")
            status = job.get("lastRunStatus", "unknown")
            env = job.get("environment", "")

            is_failed = status in _FAILED_RUN_STATUSES
            severity = "high" if is_failed else "info"
            obs_type = "misconfiguration" if is_failed else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Cohesity protection job: {name}",
                    detail={
                        "job_id": job_id,
                        "name": name,
                        "environment": env,
                        "last_run_status": status,
                        "policy_id": str(job.get("policyId", "")),
                        "is_active": job.get("isActive", True),
                        "is_deleted": job.get("isDeleted", False),
                    },
                    resource_id=job_id,
                    resource_type="cohesity_protection_job",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_protection_runs(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else []

        for run in items:
            job_id = str(run.get("jobId", ""))
            job_name = run.get("jobName", "unknown")
            run_id = str(run.get("backupRun", {}).get("base", {}).get("jobRunId", run.get("id", "")))
            status = (
                run.get("backupRun", {}).get("base", {}).get("publicStatus", run.get("status", "unknown"))
            )

            is_failed = status in _FAILED_RUN_STATUSES
            severity = "high" if is_failed else "info"
            obs_type = "misconfiguration" if is_failed else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Cohesity run {status}: {job_name}",
                    detail={
                        "run_id": run_id,
                        "job_id": job_id,
                        "job_name": job_name,
                        "status": status,
                        "start_time": run.get("backupRun", {}).get("base", {}).get("startTimeUsecs", ""),
                        "end_time": run.get("backupRun", {}).get("base", {}).get("endTimeUsecs", ""),
                    },
                    resource_id=run_id or job_id,
                    resource_type="cohesity_protection_run",
                    resource_name=job_name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(CohesityNormalizer())
