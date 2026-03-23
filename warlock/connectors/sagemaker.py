"""SageMaker connector — Layer 1 implementation for AI/ML governance.

Collects models (registry), endpoints (deployed), training jobs, and
notebook instances via AWS SageMaker API (boto3).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

try:
    import boto3
except ImportError:
    boto3 = None  # type: ignore[assignment]


class SageMakerConnector(BaseConnector):
    """Collects compliance telemetry from AWS SageMaker."""

    def validate(self) -> list[str]:
        errors = []
        if boto3 is None:
            errors.append("boto3 not installed. Install with: pip install warlock[sagemaker]")
        # AWS credentials can come from env vars, instance role, or config file
        # Only require explicit keys if no default credential chain is available
        return errors

    def health_check(self) -> bool:
        try:
            client = self._boto_client()
            client.list_models(MaxResults=1)
            return True
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sagemaker",
            source_type=SourceType.AI_ML,
            provider="aws",
        )

        self._collect_models(result)
        self._collect_endpoints(result)
        self._collect_training_jobs(result)
        self._collect_notebooks(result)

        result.complete()
        return result

    # -- Client --

    def _boto_client(self):
        """Create a boto3 SageMaker client."""
        kwargs = {}
        access_key = self.get_secret("WLK_AWS_ACCESS_KEY_ID")
        secret_key = self.get_secret("WLK_AWS_SECRET_ACCESS_KEY")
        region = self.get_secret("WLK_AWS_REGION")

        if access_key and secret_key:
            kwargs["aws_access_key_id"] = access_key
            kwargs["aws_secret_access_key"] = secret_key
        if region:
            kwargs["region_name"] = region

        return boto3.client("sagemaker", **kwargs)

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="sagemaker",
            source_type=SourceType.AI_ML,
            provider="aws",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_models(self, result: ConnectorResult) -> None:
        """Collect SageMaker model registry entries."""
        try:
            client = self._boto_client()
            paginator = client.get_paginator("list_models")
            models = []
            for page in paginator.paginate(PaginationConfig={"MaxItems": 500}):
                for model in page.get("Models", []):
                    # Get model details
                    try:
                        detail = client.describe_model(ModelName=model["ModelName"])
                        detail.pop("ResponseMetadata", None)
                        models.append(detail)
                    except Exception:
                        models.append(model)
            result.events.append(self._raw_event("sagemaker_models", {"models": models}))
        except Exception as e:
            log.debug("SageMaker models collection failed: %s", e)
            result.errors.append(f"sagemaker_models: {e}")

    def _collect_endpoints(self, result: ConnectorResult) -> None:
        """Collect deployed SageMaker endpoints."""
        try:
            client = self._boto_client()
            paginator = client.get_paginator("list_endpoints")
            endpoints = []
            for page in paginator.paginate(PaginationConfig={"MaxItems": 200}):
                for ep in page.get("Endpoints", []):
                    try:
                        detail = client.describe_endpoint(EndpointName=ep["EndpointName"])
                        detail.pop("ResponseMetadata", None)
                        endpoints.append(detail)
                    except Exception:
                        endpoints.append(ep)
            result.events.append(self._raw_event("sagemaker_endpoints", {"endpoints": endpoints}))
        except Exception as e:
            log.debug("SageMaker endpoints collection failed: %s", e)
            result.errors.append(f"sagemaker_endpoints: {e}")

    def _collect_training_jobs(self, result: ConnectorResult) -> None:
        """Collect SageMaker training jobs."""
        try:
            client = self._boto_client()
            paginator = client.get_paginator("list_training_jobs")
            jobs = []
            for page in paginator.paginate(PaginationConfig={"MaxItems": 200}):
                for job in page.get("TrainingJobSummaries", []):
                    try:
                        detail = client.describe_training_job(
                            TrainingJobName=job["TrainingJobName"]
                        )
                        detail.pop("ResponseMetadata", None)
                        jobs.append(detail)
                    except Exception:
                        jobs.append(job)
            result.events.append(self._raw_event("sagemaker_training_jobs", {"jobs": jobs}))
        except Exception as e:
            log.debug("SageMaker training jobs collection failed: %s", e)
            result.errors.append(f"sagemaker_training_jobs: {e}")

    def _collect_notebooks(self, result: ConnectorResult) -> None:
        """Collect SageMaker notebook instances."""
        try:
            client = self._boto_client()
            paginator = client.get_paginator("list_notebook_instances")
            notebooks = []
            for page in paginator.paginate(PaginationConfig={"MaxItems": 200}):
                for nb in page.get("NotebookInstances", []):
                    try:
                        detail = client.describe_notebook_instance(
                            NotebookInstanceName=nb["NotebookInstanceName"]
                        )
                        detail.pop("ResponseMetadata", None)
                        notebooks.append(detail)
                    except Exception:
                        notebooks.append(nb)
            result.events.append(self._raw_event("sagemaker_notebooks", {"notebooks": notebooks}))
        except Exception as e:
            log.debug("SageMaker notebooks collection failed: %s", e)
            result.errors.append(f"sagemaker_notebooks: {e}")


# Register
registry.register("sagemaker", SageMakerConnector)
