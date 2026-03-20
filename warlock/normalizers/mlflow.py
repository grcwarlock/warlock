"""MLflow normalizer — transforms raw MLflow API responses into Findings.

Normalizes registered models (missing description detection), experiments,
and model versions (production models without description) into inventory
and misconfiguration findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class MLflowNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "mlflow_registered_models": "_normalize_registered_models",
        "mlflow_experiments": "_normalize_experiments",
        "mlflow_model_versions": "_normalize_model_versions",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "mlflow" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all MLflow findings."""
        return {
            "raw_event_id": raw.id,
            "source": "mlflow",
            "source_type": SourceType.CUSTOM,
            "provider": "mlflow",
            "observed_at": raw.observed_at,
        }

    # -- Registered Models --

    def _normalize_registered_models(self, raw: RawEventData) -> list[FindingData]:
        """One inventory finding per model; misconfiguration for models without description."""
        findings = []
        models = raw.raw_data.get("response", [])

        for model in models:
            model_name = model.get("name", "unknown")
            description = model.get("description", "")
            creation_timestamp = model.get("creation_timestamp", "")
            last_updated = model.get("last_updated_timestamp", "")
            tags = model.get("tags", [])

            # Inventory finding
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Registered model: {model_name}",
                    detail={
                        "model_name": model_name,
                        "description": description,
                        "creation_timestamp": creation_timestamp,
                        "last_updated_timestamp": last_updated,
                        "tags": tags,
                    },
                    resource_id=f"mlflow:model:{model_name}",
                    resource_type="ai_model",
                    resource_name=model_name,
                    severity="info",
                )
            )

            # Models without description
            if not description or not description.strip():
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Model without description: {model_name}",
                        detail={
                            "model_name": model_name,
                            "issue": "no_description",
                        },
                        resource_id=f"mlflow:model:{model_name}",
                        resource_type="ai_model",
                        resource_name=model_name,
                        severity="low",
                    )
                )

        return findings

    # -- Experiments --

    def _normalize_experiments(self, raw: RawEventData) -> list[FindingData]:
        """One inventory finding per experiment."""
        findings = []
        experiments = raw.raw_data.get("response", [])

        for exp in experiments:
            exp_id = str(exp.get("experiment_id", ""))
            name = exp.get("name", "unknown")
            lifecycle_stage = exp.get("lifecycle_stage", "")
            artifact_location = exp.get("artifact_location", "")
            creation_time = exp.get("creation_time", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Experiment: {name}",
                    detail={
                        "experiment_id": exp_id,
                        "name": name,
                        "lifecycle_stage": lifecycle_stage,
                        "artifact_location": artifact_location,
                        "creation_time": creation_time,
                    },
                    resource_id=f"mlflow:experiment:{exp_id}",
                    resource_type="ai_experiment",
                    resource_name=name,
                    severity="info",
                )
            )

        return findings

    # -- Model Versions --

    def _normalize_model_versions(self, raw: RawEventData) -> list[FindingData]:
        """One inventory finding per model version; misconfiguration for production models without description."""
        findings = []
        versions = raw.raw_data.get("response", [])

        for ver in versions:
            model_name = ver.get("name", "unknown")
            version_num = str(ver.get("version", ""))
            stage = ver.get("current_stage", "")
            description = ver.get("description", "")
            status = ver.get("status", "")
            creation_timestamp = ver.get("creation_timestamp", "")
            run_id = ver.get("run_id", "")

            # Inventory finding
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Model version: {model_name} v{version_num} ({stage})",
                    detail={
                        "model_name": model_name,
                        "version": version_num,
                        "stage": stage,
                        "description": description,
                        "status": status,
                        "creation_timestamp": creation_timestamp,
                        "run_id": run_id,
                    },
                    resource_id=f"mlflow:model_version:{model_name}:{version_num}",
                    resource_type="ai_model_version",
                    resource_name=f"{model_name} v{version_num}",
                    severity="info",
                )
            )

            # Production models without description
            if stage.lower() == "production" and (not description or not description.strip()):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Production model without description: {model_name} v{version_num}",
                        detail={
                            "model_name": model_name,
                            "version": version_num,
                            "stage": stage,
                            "issue": "production_no_description",
                        },
                        resource_id=f"mlflow:model_version:{model_name}:{version_num}",
                        resource_type="ai_model_version",
                        resource_name=f"{model_name} v{version_num}",
                        severity="medium",
                    )
                )

        return findings


# Register
registry.register(MLflowNormalizer())
