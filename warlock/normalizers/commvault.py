"""Commvault normalizer — transforms raw Commvault API responses into Findings.

Normalizes client inventory as inventory findings, failed backup jobs
as high-severity misconfiguration findings, and backup sets as inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_FAILED_JOB_STATUSES = {"Failed", "Killed", "Waiting", "Suspended", "failed", "killed"}


class CommvaultNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Commvault backup findings."""

    HANDLERS: dict[str, str] = {
        "commvault_clients": "_normalize_clients",
        "commvault_jobs": "_normalize_jobs",
        "commvault_backupsets": "_normalize_backupsets",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "commvault" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "commvault",
            "source_type": SourceType.BACKUP,
            "provider": "commvault",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_clients(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("clientProperties", response.get("clients", []))
        )

        for client in items:
            client_obj = client.get("client", client) if isinstance(client, dict) else client
            client_id = str(client_obj.get("clientId", client_obj.get("id", "")))
            name = client_obj.get("clientName", client_obj.get("name", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Commvault client: {name}",
                    detail={
                        "client_id": client_id,
                        "name": name,
                        "hostname": client_obj.get("hostName", ""),
                        "os_type": client_obj.get("osType", ""),
                        "version": client_obj.get("version", ""),
                    },
                    resource_id=client_id,
                    resource_type="commvault_client",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_jobs(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("jobs", response.get("data", []))
        )

        for job in items:
            job_id = str(job.get("jobId", job.get("id", "")))
            status = job.get("status", job.get("jobStatus", "unknown"))
            job_type = job.get("jobType", job.get("type", "Backup"))
            client_name = job.get("clientName", job.get("client", "unknown"))

            is_failed = status in _FAILED_JOB_STATUSES
            severity = "high" if is_failed else "info"
            obs_type = "misconfiguration" if is_failed else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Commvault backup job {status}: {client_name}",
                    detail={
                        "job_id": job_id,
                        "status": status,
                        "job_type": job_type,
                        "client_name": client_name,
                        "subclient": job.get("subclientName", ""),
                        "start_time": job.get("jobStartTime", ""),
                        "end_time": job.get("jobEndTime", ""),
                        "failure_reason": job.get("failureReason", ""),
                    },
                    resource_id=job_id,
                    resource_type="commvault_job",
                    resource_name=f"{job_type} on {client_name}",
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_backupsets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("backupSetProperties", response.get("backupsets", []))
        )

        for bset in items:
            bset_obj = bset.get("backupSet", bset) if isinstance(bset, dict) else bset
            bset_id = str(bset_obj.get("backupsetId", bset_obj.get("id", "")))
            name = bset_obj.get("backupsetName", bset_obj.get("name", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Commvault backup set: {name}",
                    detail={
                        "backupset_id": bset_id,
                        "name": name,
                        "client": bset_obj.get("clientName", ""),
                        "agent": bset_obj.get("agentName", ""),
                        "is_default": bset_obj.get("defaultBackupSet", False),
                    },
                    resource_id=bset_id,
                    resource_type="commvault_backupset",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(CommvaultNormalizer())
