"""Pipeline configuration. Environment variables override everything."""

from __future__ import annotations

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    model_config = {"env_prefix": "WLK_", "env_file": ".env", "env_file_encoding": "utf-8"}

    # Database
    database_url: str = "sqlite:///warlock.db"
    database_read_url: str = ""  # Read replica URL; falls back to database_url when empty
    pgbouncer_mode: bool = False  # When True: pool_size=1, max_overflow=0, no prepared stmts

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
    crowdstrike_client_id: str = ""  # or set CROWDSTRIKE_CLIENT_ID
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

    # Cloud — AWS GuardDuty
    guardduty_enabled: bool = False
    guardduty_detector_id: str = ""

    # Observability — Datadog
    datadog_enabled: bool = False
    datadog_site: str = "datadoghq.com"

    # Observability — New Relic
    newrelic_enabled: bool = False
    newrelic_account_id: str = ""

    # Cloud — Cloudflare
    cloudflare_enabled: bool = False
    cloudflare_account_id: str = ""
    cloudflare_zone_ids: list[str] = Field(default_factory=list)

    # Network Security — Palo Alto Networks
    palo_alto_enabled: bool = False
    palo_alto_base_url: str = ""

    # Network Security — Fortinet FortiGate
    fortinet_enabled: bool = False
    fortinet_base_url: str = ""

    # Network Security — Zscaler
    zscaler_enabled: bool = False
    zscaler_cloud: str = ""  # e.g. zscloud.net

    # HRIS — Workday
    workday_enabled: bool = False
    workday_tenant: str = ""

    # ITSM — ServiceNow
    servicenow_enabled: bool = False
    servicenow_instance: str = ""

    # Training — KnowBe4
    knowbe4_enabled: bool = False
    knowbe4_region: str = "us"

    # Code Security — Checkmarx
    checkmarx_enabled: bool = False
    checkmarx_base_url: str = ""
    checkmarx_client_id: str = ""

    # Code Security — SonarQube
    sonarqube_enabled: bool = False
    sonarqube_base_url: str = ""

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

    # Email Security — Abnormal Security
    abnormal_security_enabled: bool = False

    # CASB — Netskope
    netskope_enabled: bool = False
    netskope_tenant_url: str = ""

    # Scanner — Nessus (standalone)
    nessus_enabled: bool = False
    nessus_base_url: str = ""

    # HRIS — BambooHR
    bamboohr_enabled: bool = False
    bamboohr_subdomain: str = ""

    # EDR — Sophos
    sophos_enabled: bool = False

    # MDM — Jamf
    jamf_enabled: bool = False
    jamf_base_url: str = ""
    jamf_client_id: str = ""
    jamf_client_secret: str = ""

    # IAM — Duo Security
    duo_enabled: bool = False
    duo_api_host: str = ""

    # IAM — 1Password
    onepassword_enabled: bool = False
    onepassword_domain: str = ""

    # IAM — Bitwarden
    bitwarden_enabled: bool = False
    bitwarden_base_url: str = ""

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

    # AI reasoning — configured via .env file or environment variables
    # The demo script (scripts/demo.sh) writes .env with user's chosen provider/key/model
    ai_provider: str = ""  # "anthropic", "openai", "gemini", "ollama"
    ai_api_key: str = ""  # set via WLK_AI_API_KEY or .env
    ai_model: str = ""  # e.g. claude-sonnet-4-20250514, gpt-4o, qwen3-coder:30b
    ai_base_url: str = ""  # for ollama / vllm
    ai_confidence_floor: float = 0.7  # minimum AI confidence to accept assessment
    ai_temperature: float = 0.0  # LLM temperature (0.0 for reproducibility)
    ai_enabled: bool = False  # AI is opt-in. Set to true via .env or WLK_AI_ENABLED=true
    ai_enhanced_features: list[str] = Field(default_factory=list)  # Empty = all features enabled
    ai_max_tokens: int = 1024
    ai_timeout: float = 60.0
    ai_batch_concurrency: int = 10
    ai_audit_enabled: bool = True

    # Vector / RAG embeddings
    embedding_provider: str = ""  # "openai", "ollama" — empty = disabled
    embedding_api_key: str = ""  # defaults to ai_api_key if empty
    embedding_model: str = ""  # defaults per provider
    embedding_base_url: str = ""  # defaults to ai_base_url if empty
    embedding_min_similarity: float = 0.6  # minimum cosine similarity for semantic matches

    # Field encryption
    encryption_key: str = ""  # key for field-level encryption (crypto.py)

    # JWT authentication
    jwt_secret: str = ""  # REQUIRED in production — min 32 chars
    jwt_expire_minutes: int = 60  # token lifetime

    # H-29: Legacy SHA-256 password hash migration deadline (days from deployment).
    # After this many days, SHA-256 hashes are rejected and users must reset.
    password_hash_legacy_deadline_days: int = 90

    # API server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_reload: bool = False

    # Shared cache (multi-worker state)
    cache_url: str = ""  # redis://localhost:6379 for multi-worker; empty = in-memory

    # Queue backend
    queue_backend: str = "memory"  # "memory", "redis", "kafka", "sqs"
    queue_url: str = ""  # redis://localhost:6379, kafka broker, SQS region
    queue_prefix: str = "warlock"  # stream/topic prefix
    queue_consumer_group: str = "warlock-pipeline"
    queue_max_retries: int = 3
    queue_batch_size: int = 100

    # Outbound — Slack
    slack_webhook_url: str = ""
    slack_channel: str = ""
    slack_min_severity: str = "medium"

    # Outbound — PagerDuty
    pagerduty_routing_key: str = ""
    pagerduty_min_severity: str = "high"

    # Outbound — Jira
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_project_key: str = "GRC"
    jira_issue_type: str = "Bug"
    jira_min_severity: str = "high"

    # Outbound — ServiceNow
    servicenow_outbound_instance: str = ""
    servicenow_outbound_username: str = ""
    servicenow_outbound_password: str = ""
    servicenow_min_severity: str = "high"
    servicenow_assignment_group: str = ""

    # Scheduler
    scheduler_interval_minutes: int = 60  # pipeline collection interval
    snapshot_interval_minutes: int = 1440  # posture snapshot interval (daily)
    cadence_check_interval_minutes: int = 60  # cadence check interval

    # OPA policy enforcement (API gate)
    opa_url: str = ""  # OPA decision endpoint URL
    opa_fail_mode: str = "closed"  # S-2: "closed" (deny if OPA down) or "open" (allow)

    # OPA compliance evaluation engine
    opa_compliance_enabled: bool = False
    opa_compliance_url: str = ""  # e.g. http://localhost:8181/v1/data
    opa_compliance_timeout: float = 30.0
    opa_compliance_fail_mode: str = "open"  # "open" (skip if OPA down) or "closed"
    opa_bundle_path: str = "policies/"
    opa_frameworks: list[str] = Field(default_factory=list)  # empty = all available

    # GDPR HMAC secret for deterministic anonymization (H-22)
    # Must be 32+ chars in production. Empty = error when GDPR features are invoked.
    gdpr_hmac_secret: str = ""

    # Trust portal
    trust_portal_secret: str = ""  # HMAC secret for download token signing

    # Change event retention
    change_event_retention_days: int = 90  # auto-purge change events older than this

    # CORS
    cors_origins: list[str] = Field(default_factory=list)  # allowed origins, empty = no CORS

    # Environment mode
    env: str = "development"  # "development", "staging", "production"

    # Event-type schema validation (OPS-7)
    schema_validation_enabled: bool = False  # Log warnings for unregistered event_types

    # Continuous Control Monitoring
    ccm_enabled: bool = False
    ccm_stale_threshold_hours: int = 24
    ccm_reassess_on_finding: bool = True

    # Logging
    log_level: str = "INFO"
    log_format: str = "text"  # "text" or "json" for structured logging

    # --- SMTP Email (AUT-2) ---
    smtp_host: str = ""  # SMTP server hostname
    smtp_port: int = 587  # 587 for STARTTLS, 465 for SSL, 25 for plain
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_tls: bool = True  # use STARTTLS
    smtp_from: str = "warlock@localhost"  # From address

    # --- SSO/OIDC (INT-1) ---
    sso_enabled: bool = False
    sso_provider: str = ""  # okta, azure_ad, google, generic_oidc
    sso_issuer_url: str = ""  # e.g. https://accounts.google.com
    sso_client_id: str = ""
    sso_client_secret: str = ""
    sso_callback_url: str = "/api/v1/auth/sso/callback"
    sso_auto_create_users: bool = True  # auto-create user on first SSO login
    sso_default_role: str = "viewer"  # role for auto-created SSO users

    # --- IP Allowlist (SAC-1) ---
    ip_allowlist_enabled: bool = False  # enforce IP allowlist from DB

    # --- Session Management (SAC-2) ---
    session_timeout_minutes: int = 480  # 8 hours default
    max_concurrent_sessions: int = 5  # per user

    # --- Escalation (AUT-4) ---
    escalation_enabled: bool = False
    escalation_check_interval_minutes: int = 60  # how often to scan for overdue items

    # --- Data Lake ---
    lake_enabled: bool = False
    lake_path: str = "lake"  # Local filesystem path or object store prefix
    lake_catalog_type: str = "sqlite"  # "sqlite" (dev) or "rest" (cloud)
    lake_catalog_url: str = ""  # REST catalog URL (cloud only)
    lake_storage_backend: str = "local"  # "local", "s3", "azure"
    lake_storage_url: str = ""  # S3 bucket URL or Azure container URL
    lake_storage_region: str = ""  # For S3-compatible stores
    lake_reads: bool = False  # Master switch for lake reads (requires lake_enabled too)
    lake_read_overrides: str = "{}"  # JSON dict of per-query overrides {"method_name": false}
    retention_purge_frozen: bool = False  # Freeze automated OLTP retention purging during Phase 2
    ai_inline_disabled: bool = (
        False  # Phase 3: disable AI in pipeline Stage 4, use lake batch assessor instead
    )
    lake_oltp_thin: bool = False  # Phase 3: thin OLTP after lake writes confirmed

    def lake_reads_enabled(self, query_name: str = "") -> bool:
        """Check if lake reads are enabled for a specific query.

        Returns True only if:
        1. lake_enabled is True (lake infrastructure exists)
        2. lake_reads is True (master read switch)
        3. No per-query override disables this specific query
        """
        if not self.lake_enabled or not self.lake_reads:
            return False
        if query_name and self.lake_read_overrides != "{}":
            import json

            try:
                overrides = json.loads(self.lake_read_overrides)
                if query_name in overrides:
                    return bool(overrides[query_name])
            except (json.JSONDecodeError, TypeError):
                pass
        return True


_settings: Settings | None = None


def validate_production_config(settings: Settings) -> None:
    """Raise RuntimeError if production-critical settings are missing.

    Call this from your ASGI lifespan or CLI startup hook *before*
    the application begins serving traffic.
    """
    if settings.env != "production":
        return

    errors: list[str] = []

    if not settings.jwt_secret:
        errors.append("WLK_JWT_SECRET must be set in production (min 32 chars)")

    # Encryption key is required when field-level crypto features are active.
    # An empty key with encryption_key="" means Fernet encrypt/decrypt will
    # crash at runtime — catch it at startup instead.
    crypto_features_enabled = settings.encryption_key != ""
    if not crypto_features_enabled:
        errors.append("WLK_ENCRYPTION_KEY must be set in production for field-level encryption")

    if errors:
        raise RuntimeError(
            "Production configuration validation failed:\n  - " + "\n  - ".join(errors)
        )


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


# Risk appetite defaults — importable by warlock.assessors.risk_appetite
# to avoid circular imports, defined here alongside other pipeline config.
risk_appetite_defaults: dict[str, dict[str, float]] = {
    "nist_800_53": {"max_ale": 2_000_000.0, "max_var95": 5_000_000.0, "max_high_findings": 10},
    "soc2": {"max_ale": 1_500_000.0, "max_var95": 3_500_000.0, "max_high_findings": 5},
    "iso_27001": {"max_ale": 1_500_000.0, "max_var95": 4_000_000.0, "max_high_findings": 8},
    "fedramp": {"max_ale": 1_000_000.0, "max_var95": 3_000_000.0, "max_high_findings": 3},
    "hipaa": {"max_ale": 1_000_000.0, "max_var95": 3_000_000.0, "max_high_findings": 5},
    "cmmc_l2": {"max_ale": 1_500_000.0, "max_var95": 4_000_000.0, "max_high_findings": 5},
    "gdpr": {"max_ale": 2_000_000.0, "max_var95": 5_000_000.0, "max_high_findings": 5},
    "ucf": {"max_ale": 1_500_000.0, "max_var95": 4_000_000.0, "max_high_findings": 8},
    "iso_27701": {"max_ale": 1_500_000.0, "max_var95": 4_000_000.0, "max_high_findings": 5},
    "iso_42001": {"max_ale": 1_500_000.0, "max_var95": 4_000_000.0, "max_high_findings": 5},
}
