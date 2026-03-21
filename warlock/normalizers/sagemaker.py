"""SageMaker normalizer — transforms raw AWS SageMaker API responses into Findings.

Handles models, endpoints, training jobs, and notebook instances.
Flags: unencrypted endpoints, public notebook instances, models without approval,
long-running training jobs.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SageMakerNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "sagemaker_models": "_normalize_models",
        "sagemaker_endpoints": "_normalize_endpoints",
        "sagemaker_training_jobs": "_normalize_training_jobs",
        "sagemaker_notebooks": "_normalize_notebooks",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sagemaker" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all SageMaker findings."""
        return {
            "raw_event_id": raw.id,
            "source": "sagemaker",
            "source_type": SourceType.AI_ML,
            "provider": "aws",
            "observed_at": raw.observed_at,
        }

    # -- Models --

    def _normalize_models(self, raw: RawEventData) -> list[FindingData]:
        """Inventory models; flag models without approval status."""
        findings = []
        models = raw.raw_data.get("models", [])

        for model in models:
            model_name = model.get("ModelName", "")
            model_arn = model.get("ModelArn", "")
            creation_time = str(model.get("CreationTime", ""))
            vpc_config = model.get("VpcConfig", None)
            containers = model.get("Containers", model.get("PrimaryContainer", []))
            enable_network_isolation = model.get("EnableNetworkIsolation", False)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"SageMaker model: {model_name}",
                    detail={
                        "model_name": model_name,
                        "model_arn": model_arn,
                        "creation_time": creation_time,
                        "has_vpc_config": vpc_config is not None,
                        "network_isolation": enable_network_isolation,
                        "container_count": len(containers) if isinstance(containers, list) else 1,
                    },
                    resource_id=model_arn or model_name,
                    resource_type="sagemaker_model",
                    resource_name=model_name,
                    severity="info",
                )
            )

            # Flag models without network isolation
            if not enable_network_isolation:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Model without network isolation: {model_name}",
                        detail={
                            "model_name": model_name,
                            "model_arn": model_arn,
                            "network_isolation": False,
                            "issue": "Model does not have network isolation enabled — containers can make outbound calls, risking data exfiltration",
                        },
                        resource_id=model_arn or model_name,
                        resource_type="sagemaker_model",
                        resource_name=model_name,
                        severity="medium",
                    )
                )

            # Flag models without VPC config
            if vpc_config is None:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Model without VPC config: {model_name}",
                        detail={
                            "model_name": model_name,
                            "model_arn": model_arn,
                            "has_vpc_config": False,
                            "issue": "Model is not deployed in a VPC — traffic flows over public network, not private endpoints",
                        },
                        resource_id=model_arn or model_name,
                        resource_type="sagemaker_model",
                        resource_name=model_name,
                        severity="medium",
                    )
                )

        return findings

    # -- Endpoints --

    def _normalize_endpoints(self, raw: RawEventData) -> list[FindingData]:
        """Inventory endpoints; flag unencrypted endpoints."""
        findings = []
        endpoints = raw.raw_data.get("endpoints", [])

        for ep in endpoints:
            ep_name = ep.get("EndpointName", "")
            ep_arn = ep.get("EndpointArn", "")
            status = ep.get("EndpointStatus", "")
            creation_time = str(ep.get("CreationTime", ""))
            kms_key = ep.get("KmsKeyId", ep.get("DataCaptureConfig", {}).get("KmsKeyId", ""))
            config_name = ep.get("EndpointConfigName", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"SageMaker endpoint: {ep_name} ({status})",
                    detail={
                        "endpoint_name": ep_name,
                        "endpoint_arn": ep_arn,
                        "status": status,
                        "creation_time": creation_time,
                        "kms_key_present": bool(kms_key),
                        "config_name": config_name,
                    },
                    resource_id=ep_arn or ep_name,
                    resource_type="sagemaker_endpoint",
                    resource_name=ep_name,
                    severity="info",
                )
            )

            # Flag unencrypted endpoints (no KMS key)
            if not kms_key and status == "InService":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Unencrypted SageMaker endpoint: {ep_name}",
                        detail={
                            "endpoint_name": ep_name,
                            "endpoint_arn": ep_arn,
                            "status": status,
                            "kms_key_present": False,
                            "issue": "Endpoint does not have a KMS key configured — data in transit and at rest may not be encrypted with customer-managed keys",
                        },
                        resource_id=ep_arn or ep_name,
                        resource_type="sagemaker_endpoint",
                        resource_name=ep_name,
                        severity="high",
                    )
                )

        return findings

    # -- Training Jobs --

    def _normalize_training_jobs(self, raw: RawEventData) -> list[FindingData]:
        """Inventory training jobs; flag long-running jobs."""
        findings = []
        jobs = raw.raw_data.get("jobs", [])

        for job in jobs:
            job_name = job.get("TrainingJobName", "")
            job_arn = job.get("TrainingJobArn", "")
            status = job.get("TrainingJobStatus", "")
            creation_time = str(job.get("CreationTime", ""))
            training_time = job.get("TrainingTimeInSeconds", 0)
            billable_time = job.get("BillableTimeInSeconds", 0)
            vpc_config = job.get("VpcConfig", None)
            enable_network_isolation = job.get("EnableNetworkIsolation", False)
            output_kms = job.get("OutputDataConfig", {}).get("KmsKeyId", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"SageMaker training job: {job_name} ({status})",
                    detail={
                        "job_name": job_name,
                        "job_arn": job_arn,
                        "status": status,
                        "creation_time": creation_time,
                        "training_time_seconds": training_time,
                        "billable_time_seconds": billable_time,
                        "has_vpc_config": vpc_config is not None,
                        "network_isolation": enable_network_isolation,
                    },
                    resource_id=job_arn or job_name,
                    resource_type="sagemaker_training_job",
                    resource_name=job_name,
                    severity="info",
                )
            )

            # Flag long-running training jobs (>24 hours)
            if status == "InProgress" and training_time > 86400:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Long-running training job: {job_name} ({training_time // 3600}h)",
                        detail={
                            "job_name": job_name,
                            "job_arn": job_arn,
                            "status": status,
                            "training_time_seconds": training_time,
                            "training_time_hours": training_time // 3600,
                            "issue": "Training job has been running for over 24 hours — review for stuck jobs or cost overruns",
                        },
                        resource_id=job_arn or job_name,
                        resource_type="sagemaker_training_job",
                        resource_name=job_name,
                        severity="medium",
                    )
                )

            # Flag training output without encryption
            if not output_kms and status in ("Completed", "InProgress"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Training job output not encrypted: {job_name}",
                        detail={
                            "job_name": job_name,
                            "job_arn": job_arn,
                            "output_kms_present": False,
                            "issue": "Training job output data is not encrypted with a customer-managed KMS key",
                        },
                        resource_id=job_arn or job_name,
                        resource_type="sagemaker_training_job",
                        resource_name=job_name,
                        severity="medium",
                    )
                )

        return findings

    # -- Notebooks --

    def _normalize_notebooks(self, raw: RawEventData) -> list[FindingData]:
        """Inventory notebooks; flag public and unencrypted instances."""
        findings = []
        notebooks = raw.raw_data.get("notebooks", [])

        for nb in notebooks:
            nb_name = nb.get("NotebookInstanceName", "")
            nb_arn = nb.get("NotebookInstanceArn", "")
            status = nb.get("NotebookInstanceStatus", "")
            instance_type = nb.get("InstanceType", "")
            direct_internet = nb.get("DirectInternetAccess", "")
            root_access = nb.get("RootAccess", "")
            kms_key = nb.get("KmsKeyId", "")
            subnet_id = nb.get("SubnetId", "")
            nb.get("Url", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"SageMaker notebook: {nb_name} ({status})",
                    detail={
                        "notebook_name": nb_name,
                        "notebook_arn": nb_arn,
                        "status": status,
                        "instance_type": instance_type,
                        "direct_internet_access": direct_internet,
                        "root_access": root_access,
                        "kms_key_present": bool(kms_key),
                        "subnet_id": subnet_id,
                    },
                    resource_id=nb_arn or nb_name,
                    resource_type="sagemaker_notebook",
                    resource_name=nb_name,
                    severity="info",
                )
            )

            # Flag public notebook instances (direct internet access enabled)
            if direct_internet == "Enabled" and status == "InService":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Public notebook instance: {nb_name}",
                        detail={
                            "notebook_name": nb_name,
                            "notebook_arn": nb_arn,
                            "direct_internet_access": "Enabled",
                            "issue": "Notebook instance has direct internet access enabled — data exfiltration and unauthorized access risk",
                        },
                        resource_id=nb_arn or nb_name,
                        resource_type="sagemaker_notebook",
                        resource_name=nb_name,
                        severity="high",
                    )
                )

            # Flag root access enabled
            if root_access == "Enabled" and status == "InService":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Notebook with root access: {nb_name}",
                        detail={
                            "notebook_name": nb_name,
                            "notebook_arn": nb_arn,
                            "root_access": "Enabled",
                            "issue": "Notebook instance has root access enabled — users can install arbitrary software and modify system configuration",
                        },
                        resource_id=nb_arn or nb_name,
                        resource_type="sagemaker_notebook",
                        resource_name=nb_name,
                        severity="medium",
                    )
                )

            # Flag unencrypted notebooks
            if not kms_key and status == "InService":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Unencrypted notebook instance: {nb_name}",
                        detail={
                            "notebook_name": nb_name,
                            "notebook_arn": nb_arn,
                            "kms_key_present": False,
                            "issue": "Notebook instance volume is not encrypted with a customer-managed KMS key",
                        },
                        resource_id=nb_arn or nb_name,
                        resource_type="sagemaker_notebook",
                        resource_name=nb_name,
                        severity="high",
                    )
                )

        return findings


# Register
registry.register(SageMakerNormalizer())
