"""Layer 1 — Data Collection.

BaseConnector defines the contract every source must implement.
ConnectorRegistry manages registration and discovery.
"""

from __future__ import annotations

import concurrent.futures
import functools
import hashlib
import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Source taxonomy — matches your architecture diagram's Layer 1 categories
# ---------------------------------------------------------------------------


class SourceType(str, Enum):
    CLOUD = "cloud"  # AWS, Azure, GCP, Prisma Cloud
    EDR = "edr"  # CrowdStrike, MS Defender, SentinelOne
    IAM = "iam"  # Okta, Entra ID, CyberArk, SailPoint
    SCANNER = "scanner"  # Tenable, Qualys, Wiz
    SIEM = "siem"  # Sentinel, Splunk, Elastic
    CSPM = "cspm"  # Prisma Cloud (also fits here)
    HRIS = "hris"  # Workday, BambooHR
    ITSM = "itsm"  # ServiceNow, Jira
    TRAINING = "training"  # KnowBe4
    PHYSICAL = "physical"  # Verkada, Brivo
    CODE = "code"  # Snyk, GitHub Advanced Security
    DLP = "dlp"  # Microsoft Purview
    BACKUP = "backup"  # Veeam, AWS Backup
    MDM = "mdm"  # Intune, Jamf
    GRC = "grc"  # OneTrust, Drata, Confluence
    EMAIL = "email"  # Proofpoint, Mimecast
    OBSERVABILITY = "observability"  # Datadog, New Relic
    NETWORK = "network"  # Palo Alto, Fortinet, Zscaler
    COLLABORATION = "collaboration"  # Slack, Google Workspace
    INFRASTRUCTURE = "infrastructure"  # Terraform Cloud, Pulumi
    CONTAINER_SECURITY = "container_security"  # Aqua, Twistlock
    THIRD_PARTY_RISK = "third_party_risk"  # BitSight, SecurityScorecard
    AI_ML = "ai_ml"  # SageMaker, Vertex AI
    DATA_GOVERNANCE = "data_governance"  # Databricks, Snowflake
    EMAIL_SECURITY = "email_security"  # Exchange Online, Proofpoint
    CI_CD = "ci_cd"  # Jenkins, GitHub Actions, GitLab CI, CircleCI
    CUSTOM = "custom"


# ---------------------------------------------------------------------------
# Connector configuration
# ---------------------------------------------------------------------------


@dataclass
class ConnectorConfig:
    name: str
    source_type: SourceType
    provider: str  # "aws", "crowdstrike", "okta"
    enabled: bool = True
    poll_interval_minutes: int = 60
    timeout_seconds: int = 300
    settings: dict[str, Any] = field(default_factory=dict)
    secret_env_vars: list[str] = field(default_factory=list)  # env var NAMES, not values


# ---------------------------------------------------------------------------
# Raw event — what a connector produces. Immutable once created.
# ---------------------------------------------------------------------------


@dataclass
class RawEventData:
    source: str
    source_type: SourceType
    provider: str
    event_type: str  # "iam_credential_report", "ec2_security_groups", "falcon_detections"
    raw_data: dict[str, Any]
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: str(uuid4()))

    @functools.cached_property
    def sha256(self) -> str:
        content = json.dumps(self.raw_data, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Connector result — outcome of a collection run
# ---------------------------------------------------------------------------


@dataclass
class ConnectorResult:
    connector_name: str
    source: str
    source_type: SourceType
    provider: str
    status: str = "running"  # running, success, partial, error
    events: list[RawEventData] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    id: str = field(default_factory=lambda: str(uuid4()))

    @property
    def event_count(self) -> int:
        return len(self.events)

    def complete(self, status: str | None = None) -> None:
        self.completed_at = datetime.now(timezone.utc)
        if status:
            self.status = status
        elif self.errors and self.events:
            self.status = "partial"
        elif self.errors:
            self.status = "error"
        else:
            self.status = "success"

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()


# ---------------------------------------------------------------------------
# Base connector — the contract
# ---------------------------------------------------------------------------


class BaseConnector(ABC):
    """Every data source implements this. Nothing else required."""

    def __init__(self, config: ConnectorConfig) -> None:
        self.config = config

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def source(self) -> str:
        return self.config.provider

    @property
    def source_type(self) -> SourceType:
        return self.config.source_type

    @property
    def provider(self) -> str:
        return self.config.provider

    @abstractmethod
    def validate(self) -> list[str]:
        """Return list of error messages. Empty = valid."""
        ...

    @abstractmethod
    def collect(self) -> ConnectorResult:
        """Fetch data from the source. Return raw events."""
        ...

    @abstractmethod
    def health_check(self) -> bool:
        """Can we reach the source?"""
        ...

    def get_secret(self, env_var: str) -> str:
        """Retrieve a secret from the environment. Never log the value."""
        value = os.environ.get(env_var, "")
        if not value:
            log.warning("Secret env var %s is not set for connector %s", env_var, self.name)
        return value


# ---------------------------------------------------------------------------
# Connector registry
# ---------------------------------------------------------------------------


class ConnectorRegistry:
    """Register connector types, instantiate and manage active connectors."""

    def __init__(self) -> None:
        self._types: dict[str, type[BaseConnector]] = {}
        self._active: dict[str, BaseConnector] = {}

    def register(self, provider: str, connector_class: type[BaseConnector]) -> None:
        self._types[provider] = connector_class

    def create(self, config: ConnectorConfig) -> BaseConnector:
        cls = self._types.get(config.provider)
        if cls is None:
            raise ValueError(f"No connector registered for provider: {config.provider}")
        connector = cls(config)
        errors = connector.validate()
        if errors:
            raise ValueError(f"Connector {config.name} validation failed: {errors}")
        self._active[config.name] = connector
        return connector

    def get(self, name: str) -> BaseConnector | None:
        return self._active.get(name)

    def list_types(self) -> list[str]:
        return list(self._types.keys())

    def list_active(self) -> list[str]:
        return list(self._active.keys())

    def collect_all(self, max_workers: int | None = None) -> list[ConnectorResult]:
        active_connectors = [
            (name, connector)
            for name, connector in self._active.items()
            if connector.config.enabled
        ]
        if not active_connectors:
            return []

        effective_workers = (
            max_workers if max_workers is not None else min(32, len(active_connectors))
        )

        def _collect_one(name: str, connector: BaseConnector) -> ConnectorResult:
            log.info("Collecting from %s", name)
            try:
                return connector.collect()
            except Exception as e:
                log.exception("Connector %s failed", name)
                result = ConnectorResult(
                    connector_name=name,
                    source=connector.source,
                    source_type=connector.source_type,
                    provider=connector.provider,
                )
                result.errors.append(str(e))
                result.complete("error")
                return result

        results: list[ConnectorResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=effective_workers) as executor:
            futures = {
                executor.submit(_collect_one, name, connector): name
                for name, connector in active_connectors
            }
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        return results


# Singleton registry
registry = ConnectorRegistry()
