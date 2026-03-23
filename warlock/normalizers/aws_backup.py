"""AWS Backup normalizer — transforms backup plans, vaults, and job data into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_JOB_STATUS_SEVERITY: dict[str, str] = {
    "FAILED": "high",
    "ABORTED": "medium",
    "EXPIRED": "medium",
    "PARTIAL": "low",
    "COMPLETED": "info",
    "RUNNING": "info",
    "PENDING": "info",
    "CREATED": "info",
}


class AWSBackupNormalizer(BaseNormalizer):
    """Dispatches AWS Backup event types to type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "aws_backup_plans": "_normalize_plans",
        "aws_backup_vaults": "_normalize_vaults",
        "aws_backup_jobs": "_normalize_jobs",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "aws_backup" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "aws_backup",
            "source_type": SourceType.BACKUP,
            "provider": "aws_backup",
            "account_id": "",
            "region": raw.raw_data.get("region", ""),
            "observed_at": raw.observed_at,
        }

    def _normalize_plans(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for plan in raw.raw_data.get("response", []):
            plan_id = str(plan.get("BackupPlanId", ""))
            name = plan.get("BackupPlanName", "unknown")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"AWS Backup plan: {name}",
                    detail={
                        "plan_id": plan_id,
                        "name": name,
                        "version_id": plan.get("VersionId", ""),
                        "creation_date": str(plan.get("CreationDate", "")),
                        "last_execution_date": str(plan.get("LastExecutionDate", "")),
                        "arn": plan.get("BackupPlanArn", ""),
                    },
                    resource_id=plan_id,
                    resource_type="aws_backup_plan",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_vaults(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for vault in raw.raw_data.get("response", []):
            vault_name = str(vault.get("BackupVaultName", "unknown"))
            arn = vault.get("BackupVaultArn", "")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"AWS Backup vault: {vault_name}",
                    detail={
                        "vault_name": vault_name,
                        "arn": arn,
                        "creation_date": str(vault.get("CreationDate", "")),
                        "number_of_recovery_points": vault.get("NumberOfRecoveryPoints", 0),
                        "encryption_key_arn": vault.get("EncryptionKeyArn", ""),
                    },
                    resource_id=arn or vault_name,
                    resource_type="aws_backup_vault",
                    resource_name=vault_name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_jobs(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for job in raw.raw_data.get("response", []):
            job_id = str(job.get("BackupJobId", ""))
            status = job.get("State", "UNKNOWN").upper()
            resource_arn = job.get("ResourceArn", "")
            resource_type = job.get("ResourceType", "")
            severity = _JOB_STATUS_SEVERITY.get(status, "info")

            # Failed jobs become misconfiguration findings
            obs_type = "misconfiguration" if status in ("FAILED", "ABORTED") else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"AWS Backup job {status}: {resource_arn}",
                    detail={
                        "job_id": job_id,
                        "state": status,
                        "resource_arn": resource_arn,
                        "resource_type": resource_type,
                        "backup_vault_name": job.get("BackupVaultName", ""),
                        "creation_date": str(job.get("CreationDate", "")),
                        "completion_date": str(job.get("CompletionDate", "")),
                        "status_message": job.get("StatusMessage", ""),
                        "percent_done": job.get("PercentDone", ""),
                    },
                    resource_id=job_id,
                    resource_type="aws_backup_job",
                    resource_name=job_id,
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings


registry.register(AWSBackupNormalizer())
