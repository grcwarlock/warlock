"""Terraform Cloud normalizer — transforms raw TFC API responses into Findings.

Handles workspaces, runs, policy checks, and state versions.
Flags: workspaces with drift, failed policy checks, runs without approval,
workspaces without VCS connection.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class TerraformCloudNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "tfc_workspaces": "_normalize_workspaces",
        "tfc_runs": "_normalize_runs",
        "tfc_policy_checks": "_normalize_policy_checks",
        "tfc_state_versions": "_normalize_state_versions",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "terraform_cloud" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Terraform Cloud findings."""
        return {
            "raw_event_id": raw.id,
            "source": "terraform_cloud",
            "source_type": SourceType.INFRASTRUCTURE,
            "provider": "hashicorp",
            "observed_at": raw.observed_at,
        }

    # -- Workspaces --

    def _normalize_workspaces(self, raw: RawEventData) -> list[FindingData]:
        """Inventory workspaces; flag drift and missing VCS."""
        findings = []
        workspaces = raw.raw_data.get("workspaces", [])

        for ws in workspaces:
            ws_id = ws.get("id", "")
            attrs = ws.get("attributes", {})
            ws_name = attrs.get("name", "")
            vcs_repo = attrs.get("vcs-repo")
            resource_count = attrs.get("resource-count", 0)
            terraform_version = attrs.get("terraform-version", "")
            locked = attrs.get("locked", False)
            execution_mode = attrs.get("execution-mode", "")
            drift_detection = attrs.get("setting-overwrites", {}).get(
                "drift-detection", attrs.get("drift-detection", False)
            )

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"TFC workspace: {ws_name}",
                    detail={
                        "workspace_id": ws_id,
                        "workspace_name": ws_name,
                        "has_vcs": vcs_repo is not None,
                        "resource_count": resource_count,
                        "terraform_version": terraform_version,
                        "locked": locked,
                        "execution_mode": execution_mode,
                        "drift_detection": drift_detection,
                    },
                    resource_id=ws_id,
                    resource_type="tfc_workspace",
                    resource_name=ws_name,
                    severity="info",
                )
            )

            # Flag workspaces without VCS connection
            if vcs_repo is None:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Workspace without VCS connection: {ws_name}",
                        detail={
                            "workspace_id": ws_id,
                            "workspace_name": ws_name,
                            "has_vcs": False,
                            "issue": "Workspace has no VCS connection — infrastructure changes are not tracked in version control",
                        },
                        resource_id=ws_id,
                        resource_type="tfc_workspace",
                        resource_name=ws_name,
                        severity="high",
                    )
                )

            # Flag workspaces with drift detected
            if drift_detection and attrs.get("current-run"):
                run_attrs = attrs.get("current-run", {})
                if isinstance(run_attrs, dict) and run_attrs.get("status") == "planned_and_finished":
                    has_changes = run_attrs.get("has-changes", False)
                    if has_changes:
                        findings.append(
                            FindingData(
                                **self._base(raw),
                                observation_type="alert",
                                title=f"Infrastructure drift detected: {ws_name}",
                                detail={
                                    "workspace_id": ws_id,
                                    "workspace_name": ws_name,
                                    "resource_count": resource_count,
                                    "issue": "Drift detection found changes between state and actual infrastructure",
                                },
                                resource_id=ws_id,
                                resource_type="tfc_workspace",
                                resource_name=ws_name,
                                severity="high",
                            )
                        )

        return findings

    # -- Runs --

    def _normalize_runs(self, raw: RawEventData) -> list[FindingData]:
        """Flag failed runs and runs without approval."""
        findings = []
        runs = raw.raw_data.get("runs", [])

        for run in runs:
            run_id = run.get("id", "")
            attrs = run.get("attributes", {})
            status = attrs.get("status", "")
            source = attrs.get("source", "")
            is_destroy = attrs.get("is-destroy", False)
            auto_apply = attrs.get("auto-apply", False)
            message = attrs.get("message", "")
            created_at = attrs.get("created-at", "")

            ws_data = (
                run.get("relationships", {})
                .get("workspace", {})
                .get("data", {})
            )
            ws_id = ws_data.get("id", "") if isinstance(ws_data, dict) else ""

            # Flag errored runs
            if status == "errored":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"TFC run failed: {run_id}",
                        detail={
                            "run_id": run_id,
                            "status": status,
                            "source": source,
                            "message": message,
                            "workspace_id": ws_id,
                            "created_at": created_at,
                            "issue": "Terraform run ended in error state — infrastructure may be in inconsistent state",
                        },
                        resource_id=run_id,
                        resource_type="tfc_run",
                        resource_name=f"run:{run_id}",
                        severity="high",
                    )
                )

            # Flag auto-applied destroy runs
            if is_destroy and auto_apply:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Auto-applied destroy run: {run_id}",
                        detail={
                            "run_id": run_id,
                            "status": status,
                            "is_destroy": True,
                            "auto_apply": True,
                            "workspace_id": ws_id,
                            "created_at": created_at,
                            "issue": "Destroy run was auto-applied without manual approval — infrastructure deletion without human review",
                        },
                        resource_id=run_id,
                        resource_type="tfc_run",
                        resource_name=f"run:{run_id}",
                        severity="critical",
                    )
                )

        return findings

    # -- Policy Checks --

    def _normalize_policy_checks(self, raw: RawEventData) -> list[FindingData]:
        """Flag failed Sentinel policy checks."""
        findings = []
        policy_checks = raw.raw_data.get("policy_checks", [])

        for check in policy_checks:
            check_id = check.get("id", "")
            attrs = check.get("attributes", {})
            status = attrs.get("status", "")
            scope = attrs.get("scope", "")
            run_id = check.get("_run_id", "")
            workspace_id = check.get("_workspace", "")
            result_obj = attrs.get("result", {})

            # Flag hard-failed policy checks
            if status in ("hard_failed", "soft_failed"):
                sev = "critical" if status == "hard_failed" else "medium"
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Sentinel policy check {status}: {check_id}",
                        detail={
                            "check_id": check_id,
                            "status": status,
                            "scope": scope,
                            "run_id": run_id,
                            "workspace_id": workspace_id,
                            "result": result_obj if isinstance(result_obj, dict) else {},
                            "issue": f"Sentinel policy check {status} — governance policy violated",
                        },
                        resource_id=check_id,
                        resource_type="tfc_policy_check",
                        resource_name=f"policy-check:{check_id}",
                        severity=sev,
                    )
                )

        return findings

    # -- State Versions --

    def _normalize_state_versions(self, raw: RawEventData) -> list[FindingData]:
        """Inventory state versions."""
        findings = []
        state_versions = raw.raw_data.get("state_versions", [])

        for sv in state_versions:
            sv_id = sv.get("id", "")
            attrs = sv.get("attributes", {})
            serial = attrs.get("serial", 0)
            created_at = attrs.get("created-at", "")
            resource_count = attrs.get("resources-processed", 0)
            ws_name = sv.get("_workspace_name", "")
            ws_id = sv.get("_workspace_id", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"TFC state version: {ws_name} serial {serial}",
                    detail={
                        "state_version_id": sv_id,
                        "workspace_name": ws_name,
                        "workspace_id": ws_id,
                        "serial": serial,
                        "resource_count": resource_count,
                        "created_at": created_at,
                    },
                    resource_id=sv_id,
                    resource_type="tfc_state_version",
                    resource_name=f"{ws_name}:v{serial}",
                    severity="info",
                )
            )

        return findings


# Register
registry.register(TerraformCloudNormalizer())
