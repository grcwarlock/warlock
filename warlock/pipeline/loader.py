"""Pipeline bootstrap — loads connectors, normalizers, assertions, framework
configs, and assembles a ready-to-run ``Pipeline`` instance.

This module replaces the ad-hoc ``_build_pipeline`` / ``_load_*`` helpers
that previously lived in ``warlock.cli``.
"""

from __future__ import annotations

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
from warlock.normalizers.base import NormalizerRegistry, registry as norm_registry
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


def load_framework_configs(config_dir: str, mapper: ControlMapper) -> None:
    """Read all YAML files from *config_dir* and feed them into *mapper*.

    Files whose name starts with ``crosswalk`` are loaded via
    ``mapper.load_crosswalk_yaml()``; all others are loaded as framework
    configs via ``mapper.load_framework_yaml()``.
    """
    config_path = Path(config_dir)
    if not config_path.is_dir():
        log.debug("Framework config dir does not exist: %s", config_dir)
        return

    for yaml_file in sorted(config_path.glob("*.yaml")):
        try:
            with open(yaml_file) as fh:
                data: dict[str, Any] = yaml.safe_load(fh) or {}
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
            with open(yml_file) as fh:
                data = yaml.safe_load(fh) or {}
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

    # 1. Load connector types, normalizers, assertions
    load_all_connectors()
    load_all_normalizers()
    load_assertions()

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
    framework_dir = os.environ.get(
        "WLK_FRAMEWORK_CONFIG_DIR",
        str(Path(__file__).resolve().parent.parent / "frameworks"),
    )
    load_framework_configs(framework_dir, mapper)

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
            log.warning("AI reasoning configured but failed to initialize — running deterministic only")

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
