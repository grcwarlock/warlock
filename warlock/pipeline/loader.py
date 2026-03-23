"""Pipeline bootstrap — loads connectors, normalizers, assertions, framework
configs, and assembles a ready-to-run ``Pipeline`` instance.

This module replaces the ad-hoc ``_build_pipeline`` / ``_load_*`` helpers
that previously lived in ``warlock.cli``.
"""

from __future__ import annotations

import functools
import importlib
import logging
import os
from pathlib import Path
from typing import Any

import yaml

from warlock.connectors.base import (
    ConnectorConfig,
    ConnectorRegistry,
    SourceType,
    registry as type_registry,
)
from warlock.normalizers.base import registry as norm_registry
from warlock.mappers.control_mapper import ControlMapper
from warlock.assessors.engine import Assessor, engine as assertion_engine
from warlock.pipeline.bus import EventBus
from warlock.pipeline.orchestrator import Pipeline
from warlock.config import get_settings

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module lists — every connector / normalizer / assertion module that should
# be imported so its top-level ``registry.register(...)`` call fires.
# ---------------------------------------------------------------------------

_CONNECTOR_MODULES = [
    "warlock.connectors.aws",
    "warlock.connectors.azure",
    "warlock.connectors.gcp",
    "warlock.connectors.oci",
    "warlock.connectors.ibm_cloud",
    "warlock.connectors.alibaba",
    "warlock.connectors.digitalocean",
    "warlock.connectors.huawei",
    "warlock.connectors.ovh",
    "warlock.connectors.cloudflare",
    "warlock.connectors.crowdstrike",
    "warlock.connectors.defender",
    "warlock.connectors.sentinelone",
    "warlock.connectors.okta",
    "warlock.connectors.entra_id",
    "warlock.connectors.cyberark",
    "warlock.connectors.sailpoint",
    "warlock.connectors.tenable",
    "warlock.connectors.qualys",
    "warlock.connectors.wiz",
    "warlock.connectors.prisma",
    "warlock.connectors.sentinel",
    "warlock.connectors.splunk",
    "warlock.connectors.elastic",
    "warlock.connectors.workday",
    "warlock.connectors.servicenow",
    "warlock.connectors.knowbe4",
    "warlock.connectors.snyk",
    "warlock.connectors.purview",
    "warlock.connectors.veeam",
    "warlock.connectors.intune",
    "warlock.connectors.confluence",
    "warlock.connectors.verkada",
    "warlock.connectors.onetrust",
    "warlock.connectors.proofpoint",
    "warlock.connectors.mlflow",
    "warlock.connectors.vault",
    "warlock.connectors.kubernetes",
    "warlock.connectors.github",
    "warlock.connectors.securityscorecard",
    "warlock.connectors.palo_alto",
    "warlock.connectors.fortinet",
    "warlock.connectors.zscaler",
    "warlock.connectors.guardduty",
    "warlock.connectors.datadog",
    "warlock.connectors.newrelic",
    "warlock.connectors.checkmarx",
    "warlock.connectors.sonarqube",
    "warlock.connectors.abnormal_security",
    "warlock.connectors.netskope",
    "warlock.connectors.nessus",
    "warlock.connectors.bamboohr",
    "warlock.connectors.sophos",
    "warlock.connectors.jamf",
    "warlock.connectors.duo",
    "warlock.connectors.onepassword",
    "warlock.connectors.bitwarden",
    "warlock.connectors.jumpcloud",
    "warlock.connectors.auth0",
    "warlock.connectors.semgrep",
    "warlock.connectors.trivy",
    "warlock.connectors.gitguardian",
    "warlock.connectors.veracode",
    "warlock.connectors.terraform_cloud",
    "warlock.connectors.aqua",
    "warlock.connectors.kandji",
    "warlock.connectors.grafana",
    "warlock.connectors.gitlab",
    "warlock.connectors.jira",
    "warlock.connectors.slack",
    "warlock.connectors.google_workspace",
    "warlock.connectors.bitsight",
    "warlock.connectors.gusto",
    "warlock.connectors.rippling",
    "warlock.connectors.sagemaker",
    "warlock.connectors.databricks",
    "warlock.connectors.exchange_online",
    "warlock.connectors.jenkins",
    "warlock.connectors.github_actions",
    "warlock.connectors.gitlab_ci",
    "warlock.connectors.circleci",
    "warlock.connectors.pagerduty",
    "warlock.connectors.opsgenie",
    "warlock.connectors.axonius",
    "warlock.connectors.servicenow_cmdb",
    "warlock.connectors.runzero",
    "warlock.connectors.patch_mgmt_microsoft",
    "warlock.connectors.ivanti",
    "warlock.connectors.venafi",
    "warlock.connectors.aws_acm",
    "warlock.connectors.digicert",
    "warlock.connectors.aws_secrets",
    "warlock.connectors.azure_keyvault",
    "warlock.connectors.gcp_secrets",
    "warlock.connectors.servicenow_grc",
    "warlock.connectors.nightfall",
    "warlock.connectors.aws_backup",
    "warlock.connectors.orca",
    "warlock.connectors.lacework",
    "warlock.connectors.rapid7",
    "warlock.connectors.crowdstrike_spotlight",
    # Batch 2A — IAM, MDM, SIEM, Network, GRC
    "warlock.connectors.ping_identity",
    "warlock.connectors.onelogin",
    "warlock.connectors.workspace_one",
    "warlock.connectors.sumo_logic",
    "warlock.connectors.cisco_umbrella",
    "warlock.connectors.drata",
    "warlock.connectors.vanta",
    "warlock.connectors.archer",
    "warlock.connectors.drata_api",
    "warlock.connectors.vanta_api",
    "warlock.connectors.secureframe",
    # Batch 2B — Collaboration, Infrastructure, HRIS
    "warlock.connectors.salesforce",
    "warlock.connectors.teams_compliance",
    "warlock.connectors.zoom",
    "warlock.connectors.smarsh",
    "warlock.connectors.ansible",
    "warlock.connectors.adp",
    "warlock.connectors.ukg",
    "warlock.connectors.sap_successfactors",
    # Batch 2C — AI/ML, Email Security, Supply Chain, API Security
    "warlock.connectors.wandb",
    "warlock.connectors.vertex_ai",
    "warlock.connectors.mimecast",
    "warlock.connectors.chainguard",
    "warlock.connectors.syft_grype",
    "warlock.connectors.fossa",
    "warlock.connectors.snyk_container",
    "warlock.connectors.socketdev",
    "warlock.connectors.salt_security",
    "warlock.connectors.noname",
    "warlock.connectors.wallarm",
    # Batch 2D — Zero Trust, DLP, Backup, CSPM, Privacy, Vuln, Endpoint, Pentest
    "warlock.connectors.fortytwoCrunch",
    "warlock.connectors.tailscale",
    "warlock.connectors.twingate",
    "warlock.connectors.banyan",
    "warlock.connectors.code42",
    "warlock.connectors.varonis",
    "warlock.connectors.bigid",
    "warlock.connectors.rubrik_security",
    "warlock.connectors.commvault",
    "warlock.connectors.rubrik",
    "warlock.connectors.cohesity",
    "warlock.connectors.druva",
    "warlock.connectors.ermetic",
    "warlock.connectors.trustarc",
    "warlock.connectors.cookiebot",
    "warlock.connectors.osano",
    "warlock.connectors.vulcan",
    "warlock.connectors.tanium",
    "warlock.connectors.automox",
    "warlock.connectors.fleet",
    "warlock.connectors.cobalt",
    "warlock.connectors.hackerone",
    # Batch 3 — Tier 3
    "warlock.connectors.linode",
    "warlock.connectors.hetzner",
    "warlock.connectors.logrhythm",
    "warlock.connectors.barracuda",
    "warlock.connectors.f5",
    "warlock.connectors.paylocity",
    "warlock.connectors.kubecost",
    "warlock.connectors.infracost",
    "warlock.connectors.spotio",
    "warlock.connectors.manageengine",
    "warlock.connectors.ivanti_patch",
    "warlock.connectors.plextrac",
]

_NORMALIZER_MODULES = [
    "warlock.normalizers.aws",
    "warlock.normalizers.azure",
    "warlock.normalizers.gcp",
    "warlock.normalizers.oci",
    "warlock.normalizers.ibm_cloud",
    "warlock.normalizers.alibaba",
    "warlock.normalizers.digitalocean",
    "warlock.normalizers.huawei",
    "warlock.normalizers.ovh",
    "warlock.normalizers.cloudflare",
    "warlock.normalizers.crowdstrike",
    "warlock.normalizers.defender",
    "warlock.normalizers.sentinelone",
    "warlock.normalizers.okta",
    "warlock.normalizers.entra_id",
    "warlock.normalizers.cyberark",
    "warlock.normalizers.sailpoint",
    "warlock.normalizers.tenable",
    "warlock.normalizers.qualys",
    "warlock.normalizers.wiz",
    "warlock.normalizers.prisma",
    "warlock.normalizers.sentinel",
    "warlock.normalizers.splunk",
    "warlock.normalizers.elastic",
    "warlock.normalizers.workday",
    "warlock.normalizers.servicenow",
    "warlock.normalizers.knowbe4",
    "warlock.normalizers.snyk",
    "warlock.normalizers.purview",
    "warlock.normalizers.veeam",
    "warlock.normalizers.intune",
    "warlock.normalizers.confluence",
    "warlock.normalizers.verkada",
    "warlock.normalizers.onetrust",
    "warlock.normalizers.proofpoint",
    "warlock.normalizers.mlflow",
    "warlock.normalizers.vault",
    "warlock.normalizers.kubernetes",
    "warlock.normalizers.github",
    "warlock.normalizers.securityscorecard",
    "warlock.normalizers.palo_alto",
    "warlock.normalizers.fortinet",
    "warlock.normalizers.zscaler",
    "warlock.normalizers.guardduty",
    "warlock.normalizers.datadog",
    "warlock.normalizers.newrelic",
    "warlock.normalizers.checkmarx",
    "warlock.normalizers.sonarqube",
    "warlock.normalizers.abnormal_security",
    "warlock.normalizers.netskope",
    "warlock.normalizers.nessus",
    "warlock.normalizers.bamboohr",
    "warlock.normalizers.sophos",
    "warlock.normalizers.jamf",
    "warlock.normalizers.duo",
    "warlock.normalizers.onepassword",
    "warlock.normalizers.bitwarden",
    "warlock.normalizers.jumpcloud",
    "warlock.normalizers.auth0",
    "warlock.normalizers.semgrep",
    "warlock.normalizers.trivy",
    "warlock.normalizers.gitguardian",
    "warlock.normalizers.veracode",
    "warlock.normalizers.terraform_cloud",
    "warlock.normalizers.aqua",
    "warlock.normalizers.kandji",
    "warlock.normalizers.grafana",
    "warlock.normalizers.gitlab",
    "warlock.normalizers.jira",
    "warlock.normalizers.slack",
    "warlock.normalizers.google_workspace",
    "warlock.normalizers.bitsight",
    "warlock.normalizers.gusto",
    "warlock.normalizers.rippling",
    "warlock.normalizers.sagemaker",
    "warlock.normalizers.databricks",
    "warlock.normalizers.exchange_online",
    "warlock.normalizers.jenkins",
    "warlock.normalizers.github_actions",
    "warlock.normalizers.gitlab_ci",
    "warlock.normalizers.circleci",
    "warlock.normalizers.pagerduty",
    "warlock.normalizers.opsgenie",
    "warlock.normalizers.axonius",
    "warlock.normalizers.servicenow_cmdb",
    "warlock.normalizers.runzero",
    "warlock.normalizers.patch_mgmt_microsoft",
    "warlock.normalizers.ivanti",
    "warlock.normalizers.venafi",
    "warlock.normalizers.aws_acm",
    "warlock.normalizers.digicert",
    "warlock.normalizers.aws_secrets",
    "warlock.normalizers.azure_keyvault",
    "warlock.normalizers.gcp_secrets",
    "warlock.normalizers.servicenow_grc",
    "warlock.normalizers.nightfall",
    "warlock.normalizers.aws_backup",
    "warlock.normalizers.orca",
    "warlock.normalizers.lacework",
    "warlock.normalizers.rapid7",
    "warlock.normalizers.crowdstrike_spotlight",
    # Batch 2A — IAM, MDM, SIEM, Network, GRC
    "warlock.normalizers.ping_identity",
    "warlock.normalizers.onelogin",
    "warlock.normalizers.workspace_one",
    "warlock.normalizers.sumo_logic",
    "warlock.normalizers.cisco_umbrella",
    "warlock.normalizers.drata",
    "warlock.normalizers.vanta",
    "warlock.normalizers.archer",
    "warlock.normalizers.drata_api",
    "warlock.normalizers.vanta_api",
    "warlock.normalizers.secureframe",
    # Batch 2B — Collaboration, Infrastructure, HRIS
    "warlock.normalizers.salesforce",
    "warlock.normalizers.teams_compliance",
    "warlock.normalizers.zoom",
    "warlock.normalizers.smarsh",
    "warlock.normalizers.ansible",
    "warlock.normalizers.adp",
    "warlock.normalizers.ukg",
    "warlock.normalizers.sap_successfactors",
    # Batch 2C — AI/ML, Email Security, Supply Chain, API Security
    "warlock.normalizers.wandb",
    "warlock.normalizers.vertex_ai",
    "warlock.normalizers.mimecast",
    "warlock.normalizers.chainguard",
    "warlock.normalizers.syft_grype",
    "warlock.normalizers.fossa",
    "warlock.normalizers.snyk_container",
    "warlock.normalizers.socketdev",
    "warlock.normalizers.salt_security",
    "warlock.normalizers.noname",
    "warlock.normalizers.wallarm",
    # Batch 2D — Zero Trust, DLP, Backup, CSPM, Privacy, Vuln, Endpoint, Pentest
    "warlock.normalizers.fortytwoCrunch",
    "warlock.normalizers.tailscale",
    "warlock.normalizers.twingate",
    "warlock.normalizers.banyan",
    "warlock.normalizers.code42",
    "warlock.normalizers.varonis",
    "warlock.normalizers.bigid",
    "warlock.normalizers.rubrik_security",
    "warlock.normalizers.commvault",
    "warlock.normalizers.rubrik",
    "warlock.normalizers.cohesity",
    "warlock.normalizers.druva",
    "warlock.normalizers.ermetic",
    "warlock.normalizers.trustarc",
    "warlock.normalizers.cookiebot",
    "warlock.normalizers.osano",
    "warlock.normalizers.vulcan",
    "warlock.normalizers.tanium",
    "warlock.normalizers.automox",
    "warlock.normalizers.fleet",
    "warlock.normalizers.cobalt",
    "warlock.normalizers.hackerone",
    # Batch 3 — Tier 3
    "warlock.normalizers.linode",
    "warlock.normalizers.hetzner",
    "warlock.normalizers.logrhythm",
    "warlock.normalizers.barracuda",
    "warlock.normalizers.f5",
    "warlock.normalizers.paylocity",
    "warlock.normalizers.kubecost",
    "warlock.normalizers.infracost",
    "warlock.normalizers.spotio",
    "warlock.normalizers.manageengine",
    "warlock.normalizers.ivanti_patch",
    "warlock.normalizers.plextrac",
    # Generic / fallback normalizer — must be last so it doesn't shadow others.
    "warlock.normalizers.generic",
]

_ASSERTION_MODULES: list[str] = [
    "warlock.assessors.assertions",
]


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def _import_modules(modules: list[str], label: str) -> None:
    """Import each module, silently skipping ImportErrors."""
    for mod in modules:
        try:
            importlib.import_module(mod)
        except ImportError:
            log.debug("Could not import %s module: %s", label, mod)


def load_all_connectors() -> None:
    """Import every connector module to trigger registration."""
    _import_modules(_CONNECTOR_MODULES, "connector")


def load_all_normalizers() -> None:
    """Import every normalizer module to trigger registration."""
    _import_modules(_NORMALIZER_MODULES, "normalizer")


def load_assertions() -> None:
    """Import assertion modules to trigger registration."""
    _import_modules(_ASSERTION_MODULES, "assertion")


@functools.lru_cache(maxsize=None)
def _load_yaml_file(path: str) -> dict[str, Any]:
    """Parse a single YAML file and return the resulting dict.

    Results are cached by absolute path so repeated calls to
    ``load_framework_configs`` (e.g. once per API request) pay the
    file-system and YAML-parse cost only once per process lifetime.
    """
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def load_framework_configs(config_dir: str, mapper: ControlMapper) -> None:
    """Read all YAML files from *config_dir* and feed them into *mapper*.

    Files whose name starts with ``crosswalk`` are loaded via
    ``mapper.load_crosswalk_yaml()``; all others are loaded as framework
    configs via ``mapper.load_framework_yaml()``.

    Individual file parses are cached by ``_load_yaml_file`` so that
    large framework YAMLs are not re-parsed on every pipeline bootstrap.
    """
    config_path = Path(config_dir)
    if not config_path.is_dir():
        log.debug("Framework config dir does not exist: %s", config_dir)
        return

    for yaml_file in sorted(config_path.glob("*.yaml")):
        try:
            data: dict[str, Any] = _load_yaml_file(str(yaml_file))
        except Exception:
            log.exception("Failed to parse framework YAML: %s", yaml_file)
            continue

        filename = yaml_file.stem  # e.g. "nist_800_53" or "crosswalk_nist_iso"

        if filename.startswith("crosswalk"):
            crosswalks = data.get("crosswalks", data.get("mappings", []))
            if isinstance(crosswalks, list):
                mapper.load_crosswalk_yaml(crosswalks)
                log.info("Loaded crosswalk config: %s (%d edges)", yaml_file.name, len(crosswalks))
        else:
            framework_id = data.get("framework_id", filename)
            mapper.load_framework_yaml(framework_id, data)
            log.info("Loaded framework config: %s (id=%s)", yaml_file.name, framework_id)

    # Also check for *.yml files (common alternative extension).
    for yml_file in sorted(config_path.glob("*.yml")):
        try:
            data = _load_yaml_file(str(yml_file))
        except Exception:
            log.exception("Failed to parse framework YAML: %s", yml_file)
            continue

        filename = yml_file.stem
        if filename.startswith("crosswalk"):
            crosswalks = data.get("crosswalks", data.get("mappings", []))
            if isinstance(crosswalks, list):
                mapper.load_crosswalk_yaml(crosswalks)
                log.info("Loaded crosswalk config: %s (%d edges)", yml_file.name, len(crosswalks))
        else:
            framework_id = data.get("framework_id", filename)
            mapper.load_framework_yaml(framework_id, data)
            log.info("Loaded framework config: %s (id=%s)", yml_file.name, framework_id)


# ---------------------------------------------------------------------------
# Source → ConnectorConfig mapping driven by Settings
# ---------------------------------------------------------------------------

# (settings_prefix, provider_name, source_type)
_SOURCE_DEFS: list[tuple[str, str, SourceType]] = [
    ("aws", "aws", SourceType.CLOUD),
    ("azure", "azure", SourceType.CLOUD),
    ("gcp", "gcp", SourceType.CLOUD),
    ("oci", "oci", SourceType.CLOUD),
    ("ibm_cloud", "ibm_cloud", SourceType.CLOUD),
    ("alibaba", "alibaba", SourceType.CLOUD),
    ("digitalocean", "digitalocean", SourceType.CLOUD),
    ("huawei", "huawei", SourceType.CLOUD),
    ("ovh", "ovh", SourceType.CLOUD),
    ("cloudflare", "cloudflare", SourceType.CLOUD),
    ("crowdstrike", "crowdstrike", SourceType.EDR),
    ("defender", "defender", SourceType.EDR),
    ("sentinelone", "sentinelone", SourceType.EDR),
    ("okta", "okta", SourceType.IAM),
    ("entra_id", "entra_id", SourceType.IAM),
    ("cyberark", "cyberark", SourceType.IAM),
    ("sailpoint", "sailpoint", SourceType.IAM),
    ("tenable", "tenable", SourceType.SCANNER),
    ("qualys", "qualys", SourceType.SCANNER),
    ("wiz", "wiz", SourceType.SCANNER),
    ("prisma", "prisma", SourceType.CSPM),
    ("sentinel", "sentinel", SourceType.SIEM),
    ("splunk", "splunk", SourceType.SIEM),
    ("elastic", "elastic", SourceType.SIEM),
    ("workday", "workday", SourceType.HRIS),
    ("servicenow", "servicenow", SourceType.ITSM),
    ("knowbe4", "knowbe4", SourceType.TRAINING),
    ("snyk", "snyk", SourceType.CODE),
    ("purview", "purview", SourceType.DLP),
    ("veeam", "veeam", SourceType.BACKUP),
    ("intune", "intune", SourceType.MDM),
    ("confluence", "confluence", SourceType.GRC),
    ("verkada", "verkada", SourceType.PHYSICAL),
    ("onetrust", "onetrust", SourceType.GRC),
    ("proofpoint", "proofpoint", SourceType.EMAIL),
    ("mlflow", "mlflow", SourceType.CUSTOM),
    ("vault", "vault", SourceType.IAM),
    ("kubernetes", "kubernetes", SourceType.CLOUD),
    ("github", "github", SourceType.CODE),
    ("securityscorecard", "securityscorecard", SourceType.GRC),
    ("palo_alto", "palo_alto", SourceType.NETWORK),
    ("fortinet", "fortinet", SourceType.NETWORK),
    ("zscaler", "zscaler", SourceType.NETWORK),
    ("guardduty", "guardduty", SourceType.CLOUD),
    ("datadog", "datadog", SourceType.OBSERVABILITY),
    ("newrelic", "newrelic", SourceType.OBSERVABILITY),
    ("checkmarx", "checkmarx", SourceType.CODE),
    ("sonarqube", "sonarqube", SourceType.CODE),
    ("abnormal_security", "abnormal_security", SourceType.EMAIL),
    ("netskope", "netskope", SourceType.DLP),
    ("nessus", "nessus", SourceType.SCANNER),
    ("bamboohr", "bamboohr", SourceType.HRIS),
    ("sophos", "sophos", SourceType.EDR),
    ("jamf", "jamf", SourceType.MDM),
    ("duo", "duo", SourceType.IAM),
    ("onepassword", "onepassword", SourceType.IAM),
    ("bitwarden", "bitwarden", SourceType.IAM),
    ("semgrep", "semgrep", SourceType.CODE),
    ("trivy", "trivy", SourceType.SCANNER),
    ("gitguardian", "gitguardian", SourceType.CODE),
    ("veracode", "veracode", SourceType.CODE),
]


def _is_source_enabled(settings: Any, prefix: str) -> bool:
    """Check ``<prefix>_enabled`` on the settings object."""
    return bool(getattr(settings, f"{prefix}_enabled", False))


# ---------------------------------------------------------------------------
# Full assembly
# ---------------------------------------------------------------------------


def build_pipeline(
    bus: EventBus,
    sources: tuple[str, ...] | None = None,
) -> Pipeline:
    """Bootstrap the full pipeline: load registries, create connectors for
    enabled sources, load framework YAML, and return a ready ``Pipeline``.

    Parameters
    ----------
    bus:
        The event bus instance for pipeline events.
    sources:
        Optional filter — only enable these providers.  ``None`` means
        "use whatever is enabled in settings".
    """
    settings = get_settings()

    framework_dir = os.environ.get(
        "WLK_FRAMEWORK_CONFIG_DIR",
        str(Path(__file__).resolve().parent.parent / "frameworks"),
    )

    # 1. Load connector types, normalizers, assertions
    load_all_connectors()
    load_all_normalizers()
    load_assertions()

    # Load assertion propagation (crosswalks + enhancement inheritance)
    try:
        from warlock.assessors.propagation import AssertionPropagator

        propagator = AssertionPropagator(assertion_engine, framework_dir)
        propagator.propagate_all()
        log.info("Assertion propagation complete")
    except Exception:
        log.warning("Assertion propagation failed — running with direct bindings only")

    # Register family-level default assertions
    try:
        from warlock.assessors.family_assertions import register_family_assertions

        register_family_assertions(assertion_engine)
        log.info("Family-level default assertions registered")
    except Exception:
        log.warning("Family assertion registration failed")

    # 2. Build connector registry with enabled sources
    connectors = ConnectorRegistry()
    connectors._types = type_registry._types  # share registered types

    for prefix, provider, source_type in _SOURCE_DEFS:
        if not _is_source_enabled(settings, prefix):
            continue
        if sources is not None and provider not in sources:
            continue
        # Only attempt to create if the type is registered
        if provider not in type_registry.list_types():
            log.debug("Provider %s enabled but no connector registered — skipping", provider)
            continue
        try:
            cfg = ConnectorConfig(
                name=provider,
                source_type=source_type,
                provider=provider,
            )
            connectors.create(cfg)
            log.info("Activated connector: %s", provider)
        except Exception:
            log.exception("Failed to create connector for %s", provider)

    # 3. Build mapper and load framework YAML configs
    mapper = ControlMapper()
    load_framework_configs(framework_dir, mapper)

    # 3b. Attach semantic mapper if embedding provider is configured
    if settings.embedding_provider:
        try:
            from warlock.ai.embeddings import EmbeddingProvider
            from warlock.ai.rag import SemanticMapper, VectorStore
            from warlock.db.engine import get_session_factory

            emb_provider = EmbeddingProvider(
                provider=settings.embedding_provider,
                api_key=settings.embedding_api_key or settings.ai_api_key,
                model=settings.embedding_model,
                base_url=settings.embedding_base_url or settings.ai_base_url,
            )

            session_factory = get_session_factory()
            vector_store = VectorStore(
                session_factory=session_factory,
                embedding_provider=emb_provider,
            )
            semantic_mapper = SemanticMapper(
                vector_store=vector_store,
                min_similarity=settings.embedding_min_similarity,
            )
            mapper.set_semantic_mapper(semantic_mapper)
            log.info(
                "Semantic control mapping enabled: %s/%s",
                settings.embedding_provider,
                emb_provider.model,
            )
        except Exception:
            log.warning(
                "Embedding provider configured but failed to initialize "
                "— running without semantic mapping"
            )

    # 4. Build assessor (with AI reasoning if configured)
    ai_reasoner = None
    if settings.ai_provider and settings.ai_api_key:
        try:
            from warlock.assessors.ai_reasoning import create_reasoner

            ai_reasoner = create_reasoner(
                provider=settings.ai_provider,
                api_key=settings.ai_api_key,
                model=settings.ai_model,
                base_url=getattr(settings, "ai_base_url", ""),
            )
            log.info("AI reasoning enabled: %s/%s", settings.ai_provider, settings.ai_model)
        except Exception:
            log.warning(
                "AI reasoning configured but failed to initialize — running deterministic only"
            )

    assessor = Assessor(engine=assertion_engine, ai_reasoner=ai_reasoner)

    # 5. Build OPA compliance evaluator (if configured)
    opa_evaluator = None
    if settings.opa_compliance_enabled and settings.opa_compliance_url:
        try:
            from warlock.assessors.opa_evaluator import OPAComplianceEvaluator

            opa_evaluator = OPAComplianceEvaluator(
                base_url=settings.opa_compliance_url,
                timeout=settings.opa_compliance_timeout,
                fail_mode=settings.opa_compliance_fail_mode,
            )
            log.info(
                "OPA compliance evaluation enabled: %s (fail_mode=%s)",
                settings.opa_compliance_url,
                settings.opa_compliance_fail_mode,
            )
        except Exception:
            log.warning("OPA compliance evaluation configured but failed to initialize")

    return Pipeline(
        connectors=connectors,
        normalizers=norm_registry,
        mapper=mapper,
        assessor=assessor,
        bus=bus,
        opa_evaluator=opa_evaluator,
    )


# ---------------------------------------------------------------------------
# Lake writer registration
# ---------------------------------------------------------------------------


def register_lake_writer(bus: EventBus) -> Any:
    """Register the lake writer if lake is enabled.

    Returns the ``LakeWriter`` instance, or ``None`` if the lake is disabled.
    The writer subscribes to all bus events and accumulates payload IDs.
    Call ``writer.flush(run_id, session)`` after ``pipeline.run()`` succeeds.
    """
    settings = get_settings()
    if not settings.lake_enabled:
        return None

    from warlock.lake.writer import LakeWriter

    writer = LakeWriter(settings.lake_path)
    bus.subscribe_all(writer.handle_event)
    log.info("Lake writer registered (lake_path=%s)", settings.lake_path)
    return writer
