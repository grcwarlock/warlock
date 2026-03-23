"""Vertex AI normalizer — transforms raw Vertex AI API responses into Findings.

Normalizes models, endpoints, and datasets as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class VertexAINormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Vertex AI telemetry."""

    HANDLERS: dict[str, str] = {
        "vertex_ai_models": "_normalize_models",
        "vertex_ai_endpoints": "_normalize_endpoints",
        "vertex_ai_datasets": "_normalize_datasets",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "vertex_ai" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        return getattr(self, handler_name)(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "vertex_ai",
            "source_type": SourceType.AI_ML,
            "provider": "vertex_ai",
            "account_id": raw.raw_data.get("project_id", ""),
            "region": raw.raw_data.get("location", ""),
            "observed_at": raw.observed_at,
        }

    def _normalize_models(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for model in raw.raw_data.get("response", []):
            model_id = model.get("name", "").split("/")[-1]
            display_name = model.get("displayName", model_id)
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Vertex AI model: {display_name}",
                    detail={
                        "model_id": model_id,
                        "display_name": display_name,
                        "resource_name": model.get("name", ""),
                        "create_time": model.get("createTime", ""),
                        "update_time": model.get("updateTime", ""),
                        "version_id": model.get("versionId", ""),
                    },
                    resource_id=model_id,
                    resource_type="vertex_ai_model",
                    resource_name=display_name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_endpoints(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for endpoint in raw.raw_data.get("response", []):
            endpoint_id = endpoint.get("name", "").split("/")[-1]
            display_name = endpoint.get("displayName", endpoint_id)
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Vertex AI endpoint: {display_name}",
                    detail={
                        "endpoint_id": endpoint_id,
                        "display_name": display_name,
                        "resource_name": endpoint.get("name", ""),
                        "create_time": endpoint.get("createTime", ""),
                        "deployed_models": len(endpoint.get("deployedModels", [])),
                    },
                    resource_id=endpoint_id,
                    resource_type="vertex_ai_endpoint",
                    resource_name=display_name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_datasets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for dataset in raw.raw_data.get("response", []):
            dataset_id = dataset.get("name", "").split("/")[-1]
            display_name = dataset.get("displayName", dataset_id)
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Vertex AI dataset: {display_name}",
                    detail={
                        "dataset_id": dataset_id,
                        "display_name": display_name,
                        "resource_name": dataset.get("name", ""),
                        "create_time": dataset.get("createTime", ""),
                        "metadata_schema_uri": dataset.get("metadataSchemaUri", ""),
                    },
                    resource_id=dataset_id,
                    resource_type="vertex_ai_dataset",
                    resource_name=display_name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings


# Register
registry.register(VertexAINormalizer())
