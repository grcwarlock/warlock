"""W&B normalizer — transforms raw Weights & Biases API responses into Findings.

Normalizes projects and runs as inventory, artifacts as inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class WandbNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for W&B telemetry."""

    HANDLERS: dict[str, str] = {
        "wandb_projects": "_normalize_projects",
        "wandb_runs": "_normalize_runs",
        "wandb_artifacts": "_normalize_artifacts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "wandb" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        return getattr(self, handler_name)(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "wandb",
            "source_type": SourceType.AI_ML,
            "provider": "wandb",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_projects(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for project in raw.raw_data.get("response", []):
            project_id = str(project.get("id", project.get("name", "")))
            name = project.get("name", "unknown")
            entity = project.get("entity", "")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"W&B project: {entity}/{name}",
                    detail={
                        "project_id": project_id,
                        "name": name,
                        "entity": entity,
                        "description": project.get("description", ""),
                        "visibility": project.get("access", "private"),
                    },
                    resource_id=project_id,
                    resource_type="wandb_project",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_runs(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for run in raw.raw_data.get("response", []):
            run_id = str(run.get("name", run.get("id", "")))
            display_name = run.get("displayName", run_id)
            state = run.get("state", "unknown")
            project = run.get("project", {})
            project_name = project.get("name", "") if isinstance(project, dict) else str(project)
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"W&B run: {display_name}",
                    detail={
                        "run_id": run_id,
                        "display_name": display_name,
                        "state": state,
                        "project": project_name,
                        "created_at": run.get("createdAt", ""),
                        "tags": run.get("tags", []),
                    },
                    resource_id=run_id,
                    resource_type="wandb_run",
                    resource_name=display_name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_artifacts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for artifact in raw.raw_data.get("response", []):
            artifact_id = str(artifact.get("id", ""))
            name = artifact.get("name", "unknown")
            artifact_type = artifact.get("type", "unknown")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"W&B artifact: {name} ({artifact_type})",
                    detail={
                        "artifact_id": artifact_id,
                        "name": name,
                        "type": artifact_type,
                        "size_bytes": artifact.get("size", 0),
                        "created_at": artifact.get("createdAt", ""),
                        "digest": artifact.get("digest", ""),
                    },
                    resource_id=artifact_id,
                    resource_type="wandb_artifact",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings


# Register
registry.register(WandbNormalizer())
