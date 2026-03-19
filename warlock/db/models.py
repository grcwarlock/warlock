"""Core pipeline schema. Four tables that everything flows through."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Index,
    Integer,
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
    event_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
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


# ---------------------------------------------------------------------------
# Immutable Audit Trail — append-only evidence chain
# ---------------------------------------------------------------------------

class AuditEntry(Base):
    """Append-only audit log with hash chaining for tamper evidence.

    Each entry's hash includes the previous entry's hash, creating a
    verifiable chain. If any entry is modified or deleted, the chain breaks.
    """
    __tablename__ = "audit_entries"

    id = Column(String(36), primary_key=True, default=_uuid)
    sequence = Column(Integer, nullable=False)  # monotonically increasing
    previous_hash = Column(String(64), nullable=False, default="genesis")
    entry_hash = Column(String(64), nullable=False)

    # What happened
    action = Column(String(50), nullable=False)  # evidence_collected, finding_created, control_assessed, etc.
    entity_type = Column(String(50), nullable=False)  # raw_event, finding, control_result, etc.
    entity_id = Column(String(36), nullable=False)

    # Who/what did it
    actor = Column(String(100), nullable=False)  # "pipeline", "api:user@example.com", "system"

    # Evidence integrity
    evidence_sha256 = Column(String(64))  # SHA256 of the evidence payload

    # Context
    extra = Column("metadata", SQLiteJSON, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("idx_audit_sequence", "sequence"),
        Index("idx_audit_entity", "entity_type", "entity_id"),
        Index("idx_audit_created", "created_at"),
        Index("idx_audit_action", "action"),
    )


# ---------------------------------------------------------------------------
# Posture Snapshots — periodic control-level rollups
# ---------------------------------------------------------------------------

class PostureSnapshot(Base):
    """Point-in-time compliance posture per control per framework.

    Created periodically (daily/weekly) to enable trend analysis,
    historical queries, and drift detection without scanning all findings.
    """
    __tablename__ = "posture_snapshots"

    id = Column(String(36), primary_key=True, default=_uuid)
    snapshot_date = Column(DateTime(timezone=True), nullable=False)
    framework = Column(String(50), nullable=False)
    control_id = Column(String(50), nullable=False)

    # Aggregated posture
    status = Column(String(20), nullable=False)  # compliant, non_compliant, partial, not_assessed
    posture_score = Column(Float, nullable=False, default=0.0)  # 0.0-100.0

    # Evidence metrics
    total_findings = Column(Integer, default=0)
    compliant_findings = Column(Integer, default=0)
    non_compliant_findings = Column(Integer, default=0)
    partial_findings = Column(Integer, default=0)
    not_assessed_findings = Column(Integer, default=0)

    # Evidence sources
    evidence_sources = Column(SQLiteJSON, default=list)  # ["aws", "okta", "crowdstrike"]
    evidence_freshness_hours = Column(Float)  # hours since newest evidence

    # Sufficiency
    sufficiency_score = Column(Float, default=0.0)  # 0.0-100.0
    sufficiency_details = Column(SQLiteJSON, default=dict)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("idx_posture_date", "snapshot_date"),
        Index("idx_posture_framework", "framework", "control_id"),
        Index("idx_posture_status", "status"),
    )


# ---------------------------------------------------------------------------
# Users & RBAC
# ---------------------------------------------------------------------------

class User(Base):
    """Platform user with role-based access control."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=_uuid)
    email = Column(String(255), nullable=False, unique=True)
    name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="viewer")  # admin, auditor, owner, viewer
    is_active = Column(Boolean, default=True)

    # Scoping — for 'owner' role, which system boundaries they can see
    allowed_frameworks = Column(SQLiteJSON, default=list)  # empty = all
    allowed_sources = Column(SQLiteJSON, default=list)  # empty = all

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    last_login = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("idx_user_email", "email"),
        Index("idx_user_role", "role"),
    )


class APIKey(Base):
    """API keys for programmatic access."""
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    key_hash = Column(String(64), nullable=False)  # SHA256 of the actual key
    name = Column(String(100), nullable=False)
    scopes = Column(SQLiteJSON, default=list)  # ["read", "write", "admin"]
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    last_used = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("idx_apikey_hash", "key_hash"),
        Index("idx_apikey_user", "user_id"),
    )


# ---------------------------------------------------------------------------
# Audit Engagements — scoped audit periods
# ---------------------------------------------------------------------------

class RiskAnalysis(Base):
    """FAIR Monte Carlo risk quantification results."""
    __tablename__ = "risk_analyses"

    id = Column(String(36), primary_key=True, default=_uuid)
    framework = Column(String(50), nullable=False)
    scenario_name = Column(String(255), nullable=False)
    mean_ale = Column(Float, nullable=False)
    var_95 = Column(Float, nullable=False)
    var_99 = Column(Float, nullable=False)
    control_effectiveness = Column(Float)
    iterations = Column(Integer, default=10000)
    details = Column(SQLiteJSON, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("idx_risk_framework", "framework"),
        Index("idx_risk_created", "created_at"),
    )


class AuditEngagement(Base):
    """Represents a scoped audit period for evidence packaging.

    e.g., "SOC 2 Type II 2025" covering Jan 1 - Dec 31 2025 for SOC 2 framework.
    """
    __tablename__ = "audit_engagements"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)  # "SOC 2 Type II 2025"
    framework = Column(String(50), nullable=False)
    period_start = Column(DateTime(timezone=True), nullable=False)
    period_end = Column(DateTime(timezone=True), nullable=False)
    status = Column(String(20), nullable=False, default="active")  # active, completed, archived

    # Scoping
    in_scope_controls = Column(SQLiteJSON, default=list)  # empty = all controls in framework
    excluded_controls = Column(SQLiteJSON, default=list)

    # Auditor info
    auditor_name = Column(String(255))
    auditor_firm = Column(String(255))

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    completed_at = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("idx_engagement_framework", "framework"),
        Index("idx_engagement_period", "period_start", "period_end"),
        Index("idx_engagement_status", "status"),
    )


# ---------------------------------------------------------------------------
# Issue Tracking & Remediation
# ---------------------------------------------------------------------------


class Issue(Base):
    """Tracks remediation of non-compliant findings through their lifecycle."""
    __tablename__ = "issues"

    id = Column(String(36), primary_key=True, default=_uuid)
    title = Column(Text, nullable=False)
    description = Column(Text)

    # Linked to compliance data
    finding_id = Column(String(36), ForeignKey("findings.id"))
    control_result_id = Column(String(36), ForeignKey("control_results.id"))
    framework = Column(String(50))
    control_id = Column(String(50))

    # Lifecycle
    status = Column(String(20), nullable=False, default="open")
    # open -> assigned -> in_progress -> remediated -> verified -> closed
    # open -> risk_accepted (alternative path)
    priority = Column(String(20), nullable=False, default="medium")  # critical, high, medium, low

    # Assignment
    assigned_to = Column(String(255))  # email or name
    assigned_by = Column(String(255))
    assigned_at = Column(DateTime(timezone=True))

    # Dates
    due_date = Column(DateTime(timezone=True))
    remediated_at = Column(DateTime(timezone=True))
    verified_at = Column(DateTime(timezone=True))
    closed_at = Column(DateTime(timezone=True))

    # Risk acceptance (if applicable)
    risk_accepted = Column(Boolean, default=False)
    risk_acceptance_owner = Column(String(255))
    risk_acceptance_expiry = Column(DateTime(timezone=True))
    risk_acceptance_justification = Column(Text)

    # Remediation details
    remediation_plan = Column(Text)
    remediation_evidence = Column(SQLiteJSON, default=list)  # [{description, url, uploaded_at}]
    verification_notes = Column(Text)

    # Metadata
    source = Column(String(50))  # "pipeline", "manual", "import"
    tags = Column(SQLiteJSON, default=list)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    created_by = Column(String(255))

    __table_args__ = (
        Index("idx_issue_status", "status"),
        Index("idx_issue_priority", "priority"),
        Index("idx_issue_framework", "framework", "control_id"),
        Index("idx_issue_assigned", "assigned_to"),
        Index("idx_issue_due", "due_date"),
    )


class IssueComment(Base):
    """Comments on issues for collaboration."""
    __tablename__ = "issue_comments"

    id = Column(String(36), primary_key=True, default=_uuid)
    issue_id = Column(String(36), ForeignKey("issues.id"), nullable=False)
    author = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    comment_type = Column(String(20), default="comment")  # comment, status_change, assignment, evidence
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("idx_comment_issue", "issue_id"),
    )


# ---------------------------------------------------------------------------
# Attestation & Audit Collaboration
# ---------------------------------------------------------------------------


class Attestation(Base):
    """Sign-off workflow for control assessments."""
    __tablename__ = "attestations"

    id = Column(String(36), primary_key=True, default=_uuid)
    engagement_id = Column(String(36), ForeignKey("audit_engagements.id"))
    framework = Column(String(50), nullable=False)
    control_id = Column(String(50))  # null = framework-level attestation

    # Workflow: draft -> submitted -> reviewed -> approved -> rejected
    status = Column(String(20), nullable=False, default="draft")

    # Content
    statement = Column(Text, nullable=False)  # "Management asserts that..."
    evidence_references = Column(SQLiteJSON, default=list)  # [{finding_id, description}]

    # Actors (separation of duties: preparer != reviewer != approver)
    prepared_by = Column(String(255))
    prepared_at = Column(DateTime(timezone=True))
    submitted_by = Column(String(255))
    submitted_at = Column(DateTime(timezone=True))
    reviewed_by = Column(String(255))
    reviewed_at = Column(DateTime(timezone=True))
    review_notes = Column(Text)
    approved_by = Column(String(255))
    approved_at = Column(DateTime(timezone=True))
    rejected_by = Column(String(255))
    rejected_at = Column(DateTime(timezone=True))
    rejection_reason = Column(Text)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("idx_attest_engagement", "engagement_id"),
        Index("idx_attest_framework", "framework", "control_id"),
        Index("idx_attest_status", "status"),
    )


class AuditComment(Base):
    """Auditor-practitioner collaboration comments."""
    __tablename__ = "audit_comments"

    id = Column(String(36), primary_key=True, default=_uuid)
    engagement_id = Column(String(36), ForeignKey("audit_engagements.id"), nullable=False)

    # What the comment is about
    target_type = Column(String(30), nullable=False)  # "control", "finding", "attestation", "engagement"
    target_id = Column(String(50), nullable=False)  # control_id, finding_id, attestation_id, or engagement_id

    # Content
    author = Column(String(255), nullable=False)
    author_role = Column(String(20))  # "auditor", "practitioner", "management"
    content = Column(Text, nullable=False)

    # Thread support
    parent_id = Column(String(36))  # null = top-level comment
    resolved = Column(Boolean, default=False)
    resolved_by = Column(String(255))
    resolved_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("idx_auditcomment_engagement", "engagement_id"),
        Index("idx_auditcomment_target", "target_type", "target_id"),
    )


# ---------------------------------------------------------------------------
# System Profile & Authorization Boundary
# ---------------------------------------------------------------------------


class SystemProfile(Base):
    """Defines an authorization boundary / system for assessment scoping."""
    __tablename__ = "system_profiles"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)
    acronym = Column(String(50))
    description = Column(Text)

    # Security categorization (FIPS 199)
    confidentiality_impact = Column(String(10), default="moderate")  # low, moderate, high
    integrity_impact = Column(String(10), default="moderate")
    availability_impact = Column(String(10), default="moderate")
    overall_impact = Column(String(10), default="moderate")

    # Boundary definition
    cloud_accounts = Column(SQLiteJSON, default=list)  # [{provider, account_id, regions}]
    network_boundaries = Column(SQLiteJSON, default=list)  # [{cidr, description}]
    interconnections = Column(SQLiteJSON, default=list)  # [{system_name, direction, data_types}]

    # Applicable connectors — which connectors feed this system
    connector_scope = Column(SQLiteJSON, default=list)  # ["aws", "okta", "crowdstrike"]

    # Applicable frameworks
    frameworks = Column(SQLiteJSON, default=list)  # ["nist_800_53", "soc2"]

    # Responsible parties
    system_owner = Column(String(255))
    system_owner_email = Column(String(255))
    isso = Column(String(255))  # Information System Security Officer
    isso_email = Column(String(255))
    issm = Column(String(255))  # Information System Security Manager
    issm_email = Column(String(255))
    authorizing_official = Column(String(255))
    ao_email = Column(String(255))

    # Authorization
    authorization_status = Column(String(30), default="not_authorized")
    # not_authorized, in_process, authorized, denied, revoked
    authorization_date = Column(DateTime(timezone=True))
    authorization_expiry = Column(DateTime(timezone=True))
    continuous_monitoring_plan = Column(Text)

    # Deployment
    deployment_model = Column(String(30))  # cloud, on-premise, hybrid
    service_model = Column(String(20))  # IaaS, PaaS, SaaS

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("idx_system_name", "name"),
        Index("idx_system_status", "authorization_status"),
    )
