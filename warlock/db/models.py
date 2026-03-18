"""Core pipeline schema. Four tables that everything flows through."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Index,
    String,
    Text,
    Boolean,
    ForeignKey,
)
from sqlalchemy.dialects.sqlite import JSON as SQLiteJSON
from sqlalchemy.orm import DeclarativeBase, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid4())


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Stage 0: Connector runs — tracks each collection execution
# ---------------------------------------------------------------------------

class ConnectorRun(Base):
    __tablename__ = "connector_runs"

    id = Column(String(36), primary_key=True, default=_uuid)
    connector_name = Column(String(100), nullable=False)
    source = Column(String(50), nullable=False)
    source_type = Column(String(20), nullable=False)
    provider = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False, default="running")  # running, success, partial, error
    event_count = Column(Float, default=0)
    error_count = Column(Float, default=0)
    errors = Column(SQLiteJSON, default=list)
    started_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Float)

    raw_events = relationship("RawEvent", back_populates="connector_run")


# ---------------------------------------------------------------------------
# Stage 1: Raw events — verbatim data from sources. Never mutated.
# ---------------------------------------------------------------------------

class RawEvent(Base):
    __tablename__ = "raw_events"

    id = Column(String(36), primary_key=True, default=_uuid)
    connector_run_id = Column(String(36), ForeignKey("connector_runs.id"), nullable=False)
    source = Column(String(50), nullable=False)          # "aws", "crowdstrike", "tenable"
    source_type = Column(String(20), nullable=False)      # cloud, edr, scanner, siem, iam
    provider = Column(String(50), nullable=False)         # specific product
    event_type = Column(String(100), nullable=False)      # "iam_credential_report", "ec2_security_groups"
    raw_data = Column(SQLiteJSON, nullable=False)
    sha256 = Column(String(64), nullable=False)
    ingested_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    connector_run = relationship("ConnectorRun", back_populates="raw_events")
    findings = relationship("Finding", back_populates="raw_event")

    __table_args__ = (
        Index("idx_raw_source", "source", "provider"),
        Index("idx_raw_ingested", "ingested_at"),
        Index("idx_raw_sha256", "sha256"),
    )


# ---------------------------------------------------------------------------
# Stage 2: Findings — normalized observations. The universal unit.
# ---------------------------------------------------------------------------

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=_uuid)
    raw_event_id = Column(String(36), ForeignKey("raw_events.id"), nullable=False)

    # What was observed
    observation_type = Column(String(50), nullable=False)  # misconfiguration, vulnerability, alert, policy_violation, access_anomaly, inventory
    title = Column(Text, nullable=False)
    detail = Column(SQLiteJSON, nullable=False)

    # What resource
    resource_id = Column(Text)                  # ARN, Azure resource ID, hostname
    resource_type = Column(String(100))         # ec2_instance, iam_user, okta_user
    resource_name = Column(Text)
    account_id = Column(String(100))
    region = Column(String(50))

    # Source lineage
    source = Column(String(50), nullable=False)
    source_type = Column(String(20), nullable=False)
    provider = Column(String(50), nullable=False)

    # Severity as reported by source
    severity = Column(String(20), nullable=False)   # critical, high, medium, low, info
    confidence = Column(Float, default=1.0)

    # Time
    observed_at = Column(DateTime(timezone=True), nullable=False)
    ingested_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    # Integrity
    sha256 = Column(String(64), nullable=False)

    raw_event = relationship("RawEvent", back_populates="findings")
    control_mappings = relationship("ControlMapping", back_populates="finding")

    __table_args__ = (
        Index("idx_finding_resource", "resource_type", "resource_id"),
        Index("idx_finding_severity", "severity"),
        Index("idx_finding_observed", "observed_at"),
        Index("idx_finding_source", "source", "provider"),
        Index("idx_finding_type", "observation_type"),
    )


# ---------------------------------------------------------------------------
# Stage 3: Control mappings — finding ↔ framework controls (many-to-many)
# ---------------------------------------------------------------------------

class ControlMapping(Base):
    __tablename__ = "control_mappings"

    id = Column(String(36), primary_key=True, default=_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False)
    framework = Column(String(50), nullable=False)        # nist_800_53, soc2, iso_27001
    control_id = Column(String(50), nullable=False)       # AC-2, CC6.1, A.9.2.1
    control_family = Column(String(50))
    mapping_method = Column(String(30), nullable=False)   # explicit, resource_rule, keyword, crosswalk
    confidence = Column(Float, nullable=False)
    crosswalk_path = Column(SQLiteJSON)                   # for transitive: ["nist:AC-2", "soc2:CC6.1"]
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    finding = relationship("Finding", back_populates="control_mappings")
    control_results = relationship("ControlResult", back_populates="control_mapping")

    __table_args__ = (
        Index("idx_mapping_finding", "finding_id"),
        Index("idx_mapping_control", "framework", "control_id"),
    )


# ---------------------------------------------------------------------------
# Stage 4: Control results — compliance determination per finding per control
# ---------------------------------------------------------------------------

class ControlResult(Base):
    __tablename__ = "control_results"

    id = Column(String(36), primary_key=True, default=_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False)
    control_mapping_id = Column(String(36), ForeignKey("control_mappings.id"), nullable=False)
    framework = Column(String(50), nullable=False)
    control_id = Column(String(50), nullable=False)

    # Determination
    status = Column(String(20), nullable=False)         # compliant, non_compliant, partial, not_assessed, not_applicable
    severity = Column(String(20), nullable=False)

    # Tier 1: deterministic assertion
    assertion_name = Column(String(100))
    assertion_passed = Column(Boolean)
    assertion_findings = Column(SQLiteJSON)              # specific failure reasons

    # Tier 2: AI reasoning (nullable)
    ai_assessment = Column(Text)
    ai_confidence = Column(Float)
    ai_model = Column(String(50))

    # Remediation
    remediation_summary = Column(Text)
    remediation_steps = Column(SQLiteJSON)
    console_path = Column(Text)

    # Lineage
    evidence_ids = Column(SQLiteJSON)                    # [raw_event UUIDs] that informed this
    assessed_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    assessor = Column(String(100), nullable=False)       # "assertion:mfa_check" or "ai:claude"

    control_mapping = relationship("ControlMapping", back_populates="control_results")

    __table_args__ = (
        Index("idx_result_control", "framework", "control_id"),
        Index("idx_result_status", "status"),
        Index("idx_result_assessed", "assessed_at"),
        Index("idx_result_finding", "finding_id"),
    )
