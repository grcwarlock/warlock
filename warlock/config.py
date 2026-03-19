"""Pipeline configuration. Environment variables override everything."""

from __future__ import annotations

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    model_config = {"env_prefix": "WLK_"}

    # Database
    database_url: str = "sqlite:///warlock.db"

    # Pipeline
    pipeline_batch_size: int = 500
    pipeline_timeout_seconds: int = 300

    # Cloud providers — disabled by default, enabled by setting credentials
    aws_enabled: bool = False
    aws_regions: list[str] = Field(default_factory=lambda: ["us-east-1"])
    aws_assume_role_arn: str = ""

    azure_enabled: bool = False
    azure_subscription_id: str = ""
    azure_tenant_id: str = ""

    gcp_enabled: bool = False
    gcp_project_id: str = ""

    # EDR — CrowdStrike Falcon
    crowdstrike_enabled: bool = False
    crowdstrike_client_id: str = ""      # or set CROWDSTRIKE_CLIENT_ID
    crowdstrike_client_secret: str = ""  # or set CROWDSTRIKE_CLIENT_SECRET

    # EDR — Microsoft Defender for Endpoint
    defender_enabled: bool = False
    defender_tenant_id: str = ""
    defender_client_id: str = ""
    defender_client_secret: str = ""

    # EDR — SentinelOne
    sentinelone_enabled: bool = False
    sentinelone_base_url: str = ""
    sentinelone_api_token: str = ""

    # IAM — Okta
    okta_enabled: bool = False
    okta_domain: str = ""
    okta_api_token: str = ""

    # IAM — Entra ID (Azure AD)
    entra_id_enabled: bool = False
    entra_id_tenant_id: str = ""
    entra_id_client_id: str = ""
    entra_id_client_secret: str = ""

    # IAM — CyberArk
    cyberark_enabled: bool = False
    cyberark_base_url: str = ""

    # IAM — SailPoint
    sailpoint_enabled: bool = False
    sailpoint_base_url: str = ""

    # Scanner — Tenable
    tenable_enabled: bool = False

    # Scanner — Qualys
    qualys_enabled: bool = False
    qualys_base_url: str = ""

    # Scanner — Wiz
    wiz_enabled: bool = False

    # CSPM — Prisma Cloud
    prisma_enabled: bool = False
    prisma_base_url: str = ""

    # SIEM — Microsoft Sentinel
    sentinel_enabled: bool = False
    sentinel_subscription_id: str = ""
    sentinel_resource_group: str = ""
    sentinel_workspace_name: str = ""

    # SIEM — Splunk
    splunk_enabled: bool = False
    splunk_base_url: str = ""

    # SIEM — Elastic
    elastic_enabled: bool = False
    elastic_base_url: str = ""

    # Cloud — Oracle Cloud (OCI)
    oci_enabled: bool = False
    oci_region: str = "us-ashburn-1"
    oci_compartment_id: str = ""
    oci_tenancy_id: str = ""

    # Cloud — IBM Cloud
    ibm_cloud_enabled: bool = False
    ibm_cloud_region: str = "us-south"
    ibm_cloud_account_id: str = ""

    # Cloud — Alibaba Cloud
    alibaba_enabled: bool = False
    alibaba_region: str = "cn-hangzhou"

    # Cloud — DigitalOcean
    digitalocean_enabled: bool = False

    # Cloud — Huawei Cloud
    huawei_enabled: bool = False
    huawei_region: str = "cn-north-4"
    huawei_project_id: str = ""

    # Cloud — OVHcloud
    ovh_enabled: bool = False
    ovh_service_name: str = ""
    ovh_endpoint: str = "eu.api.ovh.com"

    # Cloud — Cloudflare
    cloudflare_enabled: bool = False
    cloudflare_account_id: str = ""
    cloudflare_zone_ids: list[str] = Field(default_factory=list)

    # HRIS — Workday
    workday_enabled: bool = False
    workday_tenant: str = ""

    # ITSM — ServiceNow
    servicenow_enabled: bool = False
    servicenow_instance: str = ""

    # Training — KnowBe4
    knowbe4_enabled: bool = False
    knowbe4_region: str = "us"

    # Code Security — Snyk
    snyk_enabled: bool = False
    snyk_org_id: str = ""

    # DLP — Microsoft Purview
    purview_enabled: bool = False
    purview_tenant_id: str = ""
    purview_client_id: str = ""
    purview_client_secret: str = ""

    # Backup — Veeam
    veeam_enabled: bool = False
    veeam_base_url: str = ""

    # MDM — Microsoft Intune
    intune_enabled: bool = False
    intune_tenant_id: str = ""
    intune_client_id: str = ""
    intune_client_secret: str = ""

    # GRC — Confluence
    confluence_enabled: bool = False
    confluence_url: str = ""
    confluence_space_keys: list[str] = Field(default_factory=list)

    # Physical Security — Verkada
    verkada_enabled: bool = False
    verkada_org_id: str = ""

    # Privacy — OneTrust
    onetrust_enabled: bool = False
    onetrust_host: str = ""

    # Email Security — Proofpoint
    proofpoint_enabled: bool = False

    # AI Tracking — MLflow
    mlflow_enabled: bool = False

    # Secrets Management — HashiCorp Vault
    vault_enabled: bool = False
    vault_addr: str = ""

    # Container Security — Kubernetes
    kubernetes_enabled: bool = False
    kubernetes_api_url: str = ""

    # CI/CD — GitHub
    github_enabled: bool = False
    github_org: str = ""

    # Third-Party Risk — SecurityScorecard
    securityscorecard_enabled: bool = False

    # AI reasoning — optional
    ai_provider: str = ""  # "anthropic", "openai", "gemini", "ollama"
    ai_api_key: str = ""
    ai_model: str = ""
    ai_base_url: str = ""  # for ollama / vllm
    ai_confidence_floor: float = 0.7  # minimum AI confidence to accept assessment
    ai_temperature: float = 0.0  # LLM temperature (0.0 for reproducibility)

    # Field encryption
    encryption_key: str = ""  # key for field-level encryption (crypto.py)

    # JWT authentication
    jwt_secret: str = ""  # REQUIRED in production — min 32 chars
    jwt_expire_minutes: int = 60  # token lifetime

    # API server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_reload: bool = False

    # Queue backend
    queue_backend: str = "memory"  # "memory", "redis", "kafka", "sqs"
    queue_url: str = ""  # redis://localhost:6379, kafka broker, SQS region
    queue_prefix: str = "warlock"  # stream/topic prefix
    queue_consumer_group: str = "warlock-pipeline"
    queue_max_retries: int = 3
    queue_batch_size: int = 100

    # Scheduler
    scheduler_interval_minutes: int = 60  # pipeline collection interval
    snapshot_interval_minutes: int = 1440  # posture snapshot interval (daily)
    cadence_check_interval_minutes: int = 60  # cadence check interval

    # OPA policy enforcement
    opa_url: str = ""  # OPA decision endpoint URL
    opa_fail_mode: str = "open"  # "open" (allow if OPA down) or "closed" (deny)

    # Change event retention
    change_event_retention_days: int = 90  # auto-purge change events older than this

    # CORS
    cors_origins: list[str] = Field(default_factory=list)  # allowed origins, empty = no CORS

    # Environment mode
    env: str = "development"  # "development", "staging", "production"

    # Logging
    log_level: str = "INFO"
    log_format: str = "text"  # "text" or "json" for structured logging


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
