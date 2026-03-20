"""Veeam normalizer — transforms raw Veeam API responses into Findings.

Handles backup jobs, sessions (with RPO checks), and restore points.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

RPO_THRESHOLD_HOURS = 24


class VeeamNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Veeam backup data."""

    HANDLERS: dict[str, str] = {
        "veeam_backup_jobs": "_normalize_backup_jobs",
        "veeam_backup_sessions": "_normalize_backup_sessions",
        "veeam_restore_points": "_normalize_restore_points",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "veeam" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Veeam findings."""
        return {
            "raw_event_id": raw.id,
            "source": "veeam",
            "source_type": SourceType.BACKUP,
            "provider": "veeam",
            "observed_at": raw.observed_at,
        }

    # -- Backup Jobs --

    def _normalize_backup_jobs(self, raw: RawEventData) -> list[FindingData]:
        """Job inventory — disabled jobs become misconfigurations."""
        findings = []
        jobs = raw.raw_data.get("records", [])

        for job in jobs:
            job_id = job.get("id", "")
            name = job.get("name", "unknown")
            job_type = job.get("type", "")
            is_disabled = job.get("isDisabled", False)
            schedule_enabled = job.get("scheduleEnabled", True)
            description = job.get("description", "")

            if is_disabled or not schedule_enabled:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Backup job disabled: {name}",
                        detail={
                            "job_id": job_id,
                            "name": name,
                            "type": job_type,
                            "is_disabled": is_disabled,
                            "schedule_enabled": schedule_enabled,
                            "description": description,
                            "issue": "backup_job_disabled",
                        },
                        resource_id=job_id,
                        resource_type="backup_job",
                        resource_name=name,
                        severity="high",
                    )
                )
            else:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="inventory",
                        title=f"Backup job: {name}",
                        detail={
                            "job_id": job_id,
                            "name": name,
                            "type": job_type,
                            "is_disabled": is_disabled,
                            "schedule_enabled": schedule_enabled,
                            "description": description,
                        },
                        resource_id=job_id,
                        resource_type="backup_job",
                        resource_name=name,
                        severity="info",
                    )
                )

        return findings

    # -- Backup Sessions --

    def _normalize_backup_sessions(self, raw: RawEventData) -> list[FindingData]:
        """Failed sessions become alerts. RPO checks for stale backups."""
        findings = []
        sessions = raw.raw_data.get("records", [])
        now = datetime.now(timezone.utc)
        rpo_cutoff = now - timedelta(hours=RPO_THRESHOLD_HOURS)

        # Track the most recent successful session per job
        latest_success_by_job: dict[str, datetime] = {}

        for session in sessions:
            session_id = session.get("id", "")
            name = session.get("name", "unknown")
            job_id = session.get("jobId", session.get("parentSessionId", ""))
            status = session.get("result", session.get("status", "")).lower()
            end_time_str = session.get("endTime", "")
            session_type = session.get("type", "")

            end_time = self._parse_time(end_time_str)

            # Track latest successful backup per job
            if status in ("success", "succeeded", "warning"):
                if job_id and (
                    job_id not in latest_success_by_job
                    or (end_time and end_time > latest_success_by_job[job_id])
                ):
                    if end_time:
                        latest_success_by_job[job_id] = end_time

            # Failed sessions -> alert
            if status in ("failed", "failure"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Backup session failed: {name}",
                        detail={
                            "session_id": session_id,
                            "name": name,
                            "job_id": job_id,
                            "status": status,
                            "end_time": end_time_str,
                            "type": session_type,
                            "issue": "backup_session_failed",
                        },
                        resource_id=session_id,
                        resource_type="backup_session",
                        resource_name=name,
                        severity="high",
                    )
                )

        # RPO check: flag jobs whose last success is older than threshold
        for job_id, last_success in latest_success_by_job.items():
            if last_success < rpo_cutoff:
                hours_since = (now - last_success).total_seconds() / 3600
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"RPO exceeded: last successful backup {hours_since:.0f}h ago (job {job_id})",
                        detail={
                            "job_id": job_id,
                            "last_successful_backup": last_success.isoformat(),
                            "hours_since_last_backup": round(hours_since, 1),
                            "rpo_threshold_hours": RPO_THRESHOLD_HOURS,
                            "issue": "rpo_exceeded",
                        },
                        resource_id=job_id,
                        resource_type="backup_session",
                        resource_name=f"job-{job_id}",
                        severity="critical",
                    )
                )

        return findings

    # -- Restore Points --

    def _normalize_restore_points(self, raw: RawEventData) -> list[FindingData]:
        """Restore point inventory. No recent restore points -> misconfiguration."""
        findings = []
        points = raw.raw_data.get("records", [])
        now = datetime.now(timezone.utc)
        recent_cutoff = now - timedelta(hours=RPO_THRESHOLD_HOURS)

        has_recent = False

        for point in points:
            point_id = point.get("id", "")
            name = point.get("name", point.get("platformName", "unknown"))
            creation_time_str = point.get("creationTime", point.get("createdDate", ""))
            backup_id = point.get("backupId", "")

            creation_time = self._parse_time(creation_time_str)
            if creation_time and creation_time >= recent_cutoff:
                has_recent = True

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Restore point: {name}",
                    detail={
                        "restore_point_id": point_id,
                        "name": name,
                        "creation_time": creation_time_str,
                        "backup_id": backup_id,
                    },
                    resource_id=point_id,
                    resource_type="backup_restore_point",
                    resource_name=name,
                    severity="info",
                )
            )

        # Flag if no restore points exist in the last 24h
        if points and not has_recent:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="No restore points created in the last 24 hours",
                    detail={
                        "total_restore_points": len(points),
                        "threshold_hours": RPO_THRESHOLD_HOURS,
                        "issue": "no_recent_restore_points",
                    },
                    resource_id="veeam-restore-points",
                    resource_type="backup_restore_point",
                    resource_name="restore-point-recency",
                    severity="high",
                )
            )

        return findings

    # -- Helpers --

    @staticmethod
    def _parse_time(time_str: str) -> datetime | None:
        """Best-effort parse of ISO-8601 timestamps from Veeam."""
        if not time_str:
            return None
        try:
            # Handle both Z suffix and +00:00 offset
            cleaned = time_str.replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned)
        except (ValueError, TypeError):
            return None


# Register
registry.register(VeeamNormalizer())
