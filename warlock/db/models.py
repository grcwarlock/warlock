"""Core pipeline schema. Four tables that everything flows through.

PostgreSQL production note: JSON columns defined here with SQLiteJSON map to
native JSON in SQLite and JSON in PostgreSQL. For production PostgreSQL
deployments, these should be migrated to JSONB to enable GIN index support
for efficient JSONB containment queries (@>) and full-text search. This is a
PostgreSQL-specific migration that should be applied separately from this
schema -- do not change the column type here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    BigInteger,
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
from sqlalchemy import (
    JSON as SQLiteJSON,
)  # Generic JSON: maps to JSONB on PostgreSQL, JSON on SQLite
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, relationship

# High-volume columns: JSONB on PostgreSQL (GIN-indexable, faster operators), JSON on SQLite (dev)
JSONType = JSON().with_variant(JSONB(), "postgresql")


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
    status = Column(
        String(20), nullable=False, default="running"
    )  # running, success, partial, error
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
    connector_run_id = Column(
        String(36), ForeignKey("connector_runs.id", ondelete="CASCADE"), nullable=False
    )
    source = Column(String(50), nullable=False)  # "aws", "crowdstrike", "tenable"
    source_type = Column(String(20), nullable=False)  # cloud, edr, scanner, siem, iam
    provider = Column(String(50), nullable=False)  # specific product
    event_type = Column(
        String(100), nullable=False
    )  # "iam_credential_report", "ec2_security_groups"
    raw_data = Column(JSONType, nullable=False)
    sha256 = Column(String(64), nullable=False)
    ingested_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    connector_run = relationship("ConnectorRun", back_populates="raw_events")
    findings = relationship("Finding", back_populates="raw_event")

    __table_args__ = (
        Index("idx_raw_source", "source", "provider"),
        Index("idx_raw_ingested", "ingested_at"),
        Index("idx_raw_sha256", "sha256"),
        Index("idx_raw_connector_run_id", "connector_run_id"),  # #20: FK index
    )


# ---------------------------------------------------------------------------
# Stage 2: Findings — normalized observations. The universal unit.
# ---------------------------------------------------------------------------


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=_uuid)
    raw_event_id = Column(
        String(36), ForeignKey("raw_events.id", ondelete="CASCADE"), nullable=False
    )

    # What was observed
    observation_type = Column(
        String(50), nullable=False
    )  # misconfiguration, vulnerability, alert, policy_violation, access_anomaly, inventory
    title = Column(Text, nullable=False)
    detail = Column(JSONType, nullable=False)

    # What resource
    resource_id = Column(Text)  # ARN, Azure resource ID, hostname
    resource_type = Column(String(100))  # ec2_instance, iam_user, okta_user
    resource_name = Column(Text)
    account_id = Column(String(100))
    region = Column(String(50))
    system_profile_id = Column(
        String(36), ForeignKey("system_profiles.id", ondelete="SET NULL")
    )  # Phase 3: multi-system scoping

    # Source lineage
    source = Column(String(50), nullable=False)
    source_type = Column(String(20), nullable=False)
    provider = Column(String(50), nullable=False)

    # Severity as reported by source
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
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
        Index("idx_finding_raw_event_id", "raw_event_id"),  # #20: FK index
        Index("idx_finding_system_profile", "system_profile_id"),
    )


# ---------------------------------------------------------------------------
# Stage 3: Control mappings — finding ↔ framework controls (many-to-many)
# ---------------------------------------------------------------------------


class ControlMapping(Base):
    __tablename__ = "control_mappings"

    id = Column(String(36), primary_key=True, default=_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    framework = Column(String(50), nullable=False)  # nist_800_53, soc2, iso_27001
    control_id = Column(String(50), nullable=False)  # AC-2, CC6.1, A.9.2.1
    control_family = Column(String(50))
    mapping_method = Column(
        String(30), nullable=False
    )  # explicit, resource_rule, keyword, crosswalk
    confidence = Column(Float, nullable=False)
    crosswalk_path = Column(JSONType)  # for transitive: ["nist:AC-2", "soc2:CC6.1"]
    monitoring_frequency = Column(String(20))  # daily, weekly, monthly, quarterly, annual
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
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    control_mapping_id = Column(
        String(36), ForeignKey("control_mappings.id", ondelete="CASCADE"), nullable=False
    )
    framework = Column(String(50), nullable=False)
    control_id = Column(String(50), nullable=False)

    system_profile_id = Column(
        String(36), ForeignKey("system_profiles.id", ondelete="SET NULL")
    )  # Phase 3

    # Determination
    status = Column(
        String(20), nullable=False
    )  # compliant, non_compliant, partial, not_assessed, not_applicable, risk_accepted, inherited_compliant, inherited_at_risk
    severity = Column(String(20), nullable=False)

    # Tier 1: deterministic assertion
    assertion_name = Column(String(255))
    assertion_passed = Column(Boolean)
    assertion_findings = Column(JSONType)  # specific failure reasons

    # Tier 2: AI reasoning (nullable)
    ai_assessment = Column(Text)
    ai_confidence = Column(Float)
    ai_model = Column(String(50))

    # Remediation
    remediation_summary = Column(Text)
    remediation_steps = Column(JSONType)
    console_path = Column(Text)

    # Lineage
    evidence_ids = Column(JSONType)  # [raw_event UUIDs] that informed this
    assessed_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    assessor = Column(String(255), nullable=False)  # "assertion:mfa_check" or "ai:claude"

    # Phase 5b: Auditor examination
    examined_at = Column(DateTime(timezone=True))
    examined_by = Column(String(255))

    control_mapping = relationship("ControlMapping", back_populates="control_results")

    __table_args__ = (
        Index("idx_result_control", "framework", "control_id"),
        Index("idx_result_status", "status"),
        Index("idx_result_assessed", "assessed_at"),
        Index("idx_result_finding", "finding_id"),
        Index("idx_result_mapping", "control_mapping_id"),
        Index("idx_result_system_profile", "system_profile_id"),
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
    sequence = Column(BigInteger, nullable=False)  # monotonically increasing
    previous_hash = Column(String(64), nullable=False, default="genesis")
    entry_hash = Column(String(64), nullable=False)

    # What happened
    action = Column(
        String(50), nullable=False
    )  # evidence_collected, finding_created, control_assessed, etc.
    entity_type = Column(String(50), nullable=False)  # raw_event, finding, control_result, etc.
    entity_id = Column(String(36), nullable=False)

    # Who/what did it
    actor = Column(String(100), nullable=False)  # "pipeline", "api:user@example.com", "system"

    # Evidence integrity
    evidence_sha256 = Column(String(64))  # SHA256 of the evidence payload

    # Context
    extra = Column("extra", SQLiteJSON, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("idx_audit_sequence", "sequence", unique=True),
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
    evidence_sources = Column(JSONType, default=list)  # ["aws", "okta", "crowdstrike"]
    evidence_freshness_hours = Column(Float)  # hours since newest evidence

    # Sufficiency
    sufficiency_score = Column(Float, default=0.0)  # 0.0-100.0
    sufficiency_details = Column(SQLiteJSON, default=dict)

    # Phase 3: multi-system scoping
    system_profile_id = Column(String(36), ForeignKey("system_profiles.id", ondelete="SET NULL"))

    # Phase 4: effectiveness scoring
    uptime_pct = Column(Float)  # % of time compliant over trailing window
    mttr_hours = Column(Float)  # mean time to remediate
    drift_count = Column(Integer)  # number of status changes in window

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("idx_posture_date", "snapshot_date"),
        Index("idx_posture_framework", "framework", "control_id"),
        Index("idx_posture_status", "status"),
        Index("idx_posture_system", "system_profile_id"),
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
    allowed_control_families = Column(SQLiteJSON, default=list)  # Phase 5a: ABAC — empty = all
    allowed_actions = Column(SQLiteJSON, default=list)  # Phase 5a: overrides role defaults

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    last_login = Column(DateTime(timezone=True))
    failed_login_count = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True))  # null = not locked
    token_valid_after = Column(DateTime(timezone=True))  # tokens issued before this are rejected

    # MFA/TOTP fields (#21)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(64), nullable=True)  # TOTP secret (encrypted)
    mfa_backup_codes = Column(JSON, nullable=True)  # hashed backup codes
    mfa_verified_at = Column(DateTime(timezone=True), nullable=True)

    # Refresh token (#58)
    refresh_token_hash = Column(String(64), nullable=True)

    __table_args__ = (Index("idx_user_role", "role"),)


class APIKey(Base):
    """API keys for programmatic access."""

    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
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
# POA&M — Plan of Action & Milestones
# ---------------------------------------------------------------------------


class POAM(Base):
    """First-class POA&M entity for tracking remediation plans."""

    __tablename__ = "poams"

    id = Column(String(36), primary_key=True, default=_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"))
    control_result_id = Column(String(36), ForeignKey("control_results.id", ondelete="SET NULL"))
    framework = Column(String(50), nullable=False)
    control_id = Column(String(50), nullable=False)
    system_profile_id = Column(String(36), ForeignKey("system_profiles.id", ondelete="SET NULL"))

    weakness_description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    risk_level = Column(String(20), default="moderate")

    # Lifecycle: draft -> open -> in_progress -> completed -> verified -> closed
    status = Column(String(20), nullable=False, default="draft")

    milestones = Column(
        SQLiteJSON, default=list
    )  # [{description, due_date, completed_date, status}]
    scheduled_completion = Column(DateTime(timezone=True))
    actual_completion = Column(DateTime(timezone=True))
    delay_count = Column(Integer, default=0)
    delay_justifications = Column(SQLiteJSON, default=list)  # [{date, justification, approved_by}]
    resources_required = Column(Text)

    created_by = Column(String(255))
    updated_by = Column(String(255))
    approved_by = Column(String(255))
    approved_at = Column(DateTime(timezone=True))
    vendor_dependency = Column(String(255))

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("idx_poam_framework", "framework", "control_id"),
        Index("idx_poam_status", "status"),
        Index("idx_poam_completion", "scheduled_completion"),
        Index("idx_poam_system", "system_profile_id"),
        Index("idx_poam_finding", "finding_id"),
        Index("idx_poam_control_result", "control_result_id"),
    )


# ---------------------------------------------------------------------------
# Compensating Controls
# ---------------------------------------------------------------------------


class CompensatingControl(Base):
    """Documents alternative controls when primary control is non-compliant."""

    __tablename__ = "compensating_controls"

    id = Column(String(36), primary_key=True, default=_uuid)
    original_framework = Column(String(50), nullable=False)
    original_control_id = Column(String(50), nullable=False)
    poam_id = Column(String(36), ForeignKey("poams.id", ondelete="SET NULL"))
    system_profile_id = Column(String(36), ForeignKey("system_profiles.id", ondelete="SET NULL"))

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    implementation_details = Column(Text)
    evidence_references = Column(SQLiteJSON, default=list)  # [{type, description, url, finding_id}]

    # Lifecycle: proposed -> approved -> active -> expired | revoked
    status = Column(String(20), nullable=False, default="proposed")

    approved_by = Column(String(255))
    approved_at = Column(DateTime(timezone=True))
    expiry_date = Column(DateTime(timezone=True))
    review_frequency = Column(String(20), default="quarterly")
    last_reviewed = Column(DateTime(timezone=True))
    effectiveness_score = Column(Float)  # 0-100

    created_by = Column(String(255))
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("idx_cc_control", "original_framework", "original_control_id"),
        Index("idx_cc_status", "status"),
    )


# ---------------------------------------------------------------------------
# Risk Acceptance
# ---------------------------------------------------------------------------


class RiskAcceptance(Base):
    """Formal risk acceptance with AO-level approval and expiry."""

    __tablename__ = "risk_acceptances"

    id = Column(String(36), primary_key=True, default=_uuid)
    framework = Column(String(50), nullable=False)
    control_id = Column(String(50), nullable=False)
    poam_id = Column(String(36), ForeignKey("poams.id", ondelete="SET NULL"))
    system_profile_id = Column(String(36), ForeignKey("system_profiles.id", ondelete="SET NULL"))

    risk_description = Column(Text, nullable=False)
    risk_level = Column(String(20), nullable=False)  # critical, high, moderate, low
    residual_risk_level = Column(String(20))
    conditions = Column(SQLiteJSON, default=list)  # [{condition, met: bool}]

    # Lifecycle: requested -> reviewed -> approved -> active -> expired | revoked
    status = Column(String(20), nullable=False, default="requested")

    requested_by = Column(String(255), nullable=False)
    reviewed_by = Column(String(255))
    reviewed_at = Column(DateTime(timezone=True))
    approved_by = Column(String(255))  # Must be AO-level
    approved_at = Column(DateTime(timezone=True))
    expiry_date = Column(DateTime(timezone=True), nullable=False)
    auto_reeval_triggers = Column(
        SQLiteJSON, default=dict
    )  # {"severity_change": true, "new_finding": true}

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("idx_ra_control", "framework", "control_id"),
        Index("idx_ra_status", "status"),
        Index("idx_ra_expiry", "expiry_date"),
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
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"))
    control_result_id = Column(String(36), ForeignKey("control_results.id", ondelete="SET NULL"))
    poam_id = Column(String(36), ForeignKey("poams.id", ondelete="SET NULL"))
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
    issue_id = Column(String(36), ForeignKey("issues.id", ondelete="CASCADE"), nullable=False)
    author = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    comment_type = Column(
        String(20), default="comment"
    )  # comment, status_change, assignment, evidence
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (Index("idx_comment_issue", "issue_id"),)


# ---------------------------------------------------------------------------
# Attestation & Audit Collaboration
# ---------------------------------------------------------------------------


class Attestation(Base):
    """Sign-off workflow for control assessments."""

    __tablename__ = "attestations"

    id = Column(String(36), primary_key=True, default=_uuid)
    engagement_id = Column(String(36), ForeignKey("audit_engagements.id", ondelete="SET NULL"))
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
    target_type = Column(
        String(30), nullable=False
    )  # "control", "finding", "attestation", "engagement"
    target_id = Column(
        String(50), nullable=False
    )  # control_id, finding_id, attestation_id, or engagement_id

    # Content
    author = Column(String(255), nullable=False)
    author_role = Column(String(20))  # "auditor", "practitioner", "management"
    external_auditor_id = Column(String(36), ForeignKey("external_auditors.id"))  # Phase 5b
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
        Index("idx_auditcomment_auditor", "external_auditor_id"),
    )


# ---------------------------------------------------------------------------
# Legal Holds — prevent data purging during investigations
# ---------------------------------------------------------------------------


class LegalHold(Base):
    """Legal hold that prevents data purging during investigations or litigation."""

    __tablename__ = "legal_holds"

    id = Column(String(36), primary_key=True, default=_uuid)
    reason = Column(Text, nullable=False)
    start_date = Column(DateTime(timezone=True), nullable=False)
    end_date = Column(DateTime(timezone=True))  # null = indefinite
    created_by = Column(String(255))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    # W-5: Optional scoping fields
    framework = Column(String(50), nullable=True)
    system_profile_id = Column(
        String(36),
        ForeignKey("system_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )
    date_range_start = Column(DateTime(timezone=True), nullable=True)
    date_range_end = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_legal_hold_active", "is_active"),
        Index("idx_legal_hold_dates", "start_date", "end_date"),
    )


# ---------------------------------------------------------------------------
# Trust Portal — access requests
# ---------------------------------------------------------------------------


class TrustAccessRequest(Base):
    """Tracks requests for compliance documentation via the trust portal."""

    __tablename__ = "trust_access_requests"

    id = Column(String(36), primary_key=True, default=_uuid)
    company_name = Column(String(255), nullable=False)
    contact_name = Column(String(255), nullable=False)
    contact_email = Column(String(255), nullable=False)
    document_types = Column(SQLiteJSON, default=list)
    reason = Column(Text, default="")
    nda_accepted = Column(Boolean, default=False)
    status = Column(String(20), nullable=False, default="pending")  # pending, approved, denied
    reviewed_by = Column(String(255))
    reviewed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("idx_trust_req_status", "status"),
        Index("idx_trust_req_email", "contact_email"),
    )


class TrustDocument(Base):
    """NDA-gated compliance documents (SOC 2 reports, pen test summaries, etc.).

    Classification tiers:
    - public:   visible to all (e.g. security whitepaper)
    - nda:      requires NDA acceptance (approved TrustAccessRequest)
    - contract: requires active contract (highest gate)
    """

    __tablename__ = "trust_documents"

    id = Column(String(36), primary_key=True, default=_uuid)
    title = Column(String(255), nullable=False)
    description = Column(Text, default="")
    classification_tier = Column(String(20), nullable=False, default="nda")
    # public | nda | contract
    file_path = Column(Text, nullable=False)  # server-side storage path
    content_type = Column(String(100), default="application/pdf")
    file_size_bytes = Column(Integer, default=0)
    uploaded_by = Column(String(255), nullable=False)
    uploaded_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    is_active = Column(Boolean, default=True)

    __table_args__ = (
        Index("idx_trust_doc_tier", "classification_tier"),
        Index("idx_trust_doc_active", "is_active"),
        Index("idx_trust_doc_uploaded", "uploaded_at"),
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

    # Phase 5g: Retention
    retention_policy_days = Column(Integer, default=2555)  # 7 years

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("idx_system_name", "name"),
        Index("idx_system_status", "authorization_status"),
    )


# ---------------------------------------------------------------------------
# Personnel Management + IdP Cross-Reference
# ---------------------------------------------------------------------------


class Personnel(Base):
    """Unified personnel record cross-referencing HR + IdP + training data."""

    __tablename__ = "personnel"

    id = Column(String(36), primary_key=True, default=_uuid)

    # Identity
    email = Column(String(255), nullable=False, unique=True)
    full_name = Column(String(255), nullable=False)
    department = Column(String(100))
    title = Column(String(255))
    manager_email = Column(String(255))
    employee_type = Column(String(30), default="employee")  # employee, contractor, vendor, intern

    # HR source (Workday)
    hr_employee_id = Column(String(100))
    hire_date = Column(DateTime(timezone=True))
    termination_date = Column(DateTime(timezone=True))
    hr_status = Column(String(30))  # active, terminated, leave
    background_check_status = Column(String(30))  # completed, pending, not_started
    background_check_date = Column(DateTime(timezone=True))
    agreements_signed = Column(SQLiteJSON, default=list)  # [{type, signed_date}]

    # IdP source (Okta/Entra)
    idp_user_id = Column(String(255))
    idp_provider = Column(String(30))  # okta, entra_id, google
    idp_status = Column(String(30))  # active, suspended, deprovisioned
    idp_last_login = Column(DateTime(timezone=True))
    mfa_enabled = Column(Boolean)
    idp_groups = Column(SQLiteJSON, default=list)

    # Training (KnowBe4)
    training_status = Column(String(30))  # current, overdue, not_enrolled
    last_training_date = Column(DateTime(timezone=True))
    phishing_score = Column(Float)  # 0-100
    training_completions = Column(SQLiteJSON, default=list)  # [{campaign, completed_date}]

    # Access reviews
    last_access_review = Column(DateTime(timezone=True))
    access_review_status = Column(String(30))  # completed, pending, overdue

    # Compliance flags
    flags = Column(SQLiteJSON, default=list)  # ["terminated_but_active_idp", "no_mfa", ...]
    risk_score = Column(Float, default=0.0)  # 0-100

    is_active = Column(Boolean, default=True)
    last_synced = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("idx_personnel_email", "email"),
        Index("idx_personnel_dept", "department"),
        Index("idx_personnel_status", "hr_status"),
        Index("idx_personnel_flags", "risk_score"),
    )


# ---------------------------------------------------------------------------
# Vendor Questionnaires
# ---------------------------------------------------------------------------


class QuestionnaireTemplate(Base):
    """Reusable questionnaire templates (SIG, DDQ, CAIQ, custom)."""

    __tablename__ = "questionnaire_templates"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)  # "SIG Lite", "CAIQ v4", "Custom Security DDQ"
    template_type = Column(String(30), nullable=False)  # sig, sig_lite, ddq, caiq, custom
    version = Column(String(20), default="1.0")
    description = Column(Text)
    questions = Column(SQLiteJSON, nullable=False, default=list)
    # [{id, category, text, response_type, required, help_text, mapped_controls}]
    # response_type: "yes_no", "text", "file", "multi_select", "rating"
    # mapped_controls: ["NIST AC-2", "SOC2 CC6.1"] -- which controls this question satisfies
    total_questions = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (Index("idx_template_type", "template_type"),)


class Questionnaire(Base):
    """A questionnaire sent to a specific vendor."""

    __tablename__ = "questionnaires"

    id = Column(String(36), primary_key=True, default=_uuid)
    template_id = Column(String(36), ForeignKey("questionnaire_templates.id"), nullable=False)
    vendor_name = Column(String(255), nullable=False)
    vendor_contact_email = Column(String(255))

    # Lifecycle: draft -> sent -> in_progress -> completed -> reviewed -> accepted/rejected
    status = Column(String(20), nullable=False, default="draft")

    # Responses
    responses = Column(SQLiteJSON, default=dict)  # {question_id: {answer, notes, attachments}}
    completion_pct = Column(Float, default=0.0)

    # AI auto-answer
    ai_suggested_answers = Column(
        SQLiteJSON, default=dict
    )  # {question_id: {answer, confidence, source}}

    # Scoring
    risk_score = Column(Float)  # 0-100 based on responses
    risk_findings = Column(SQLiteJSON, default=list)  # [{question_id, finding, severity}]

    # Dates
    sent_at = Column(DateTime(timezone=True))
    due_date = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    reviewed_by = Column(String(255))
    reviewed_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow)
    created_by = Column(String(255))

    __table_args__ = (
        Index("idx_questionnaire_vendor", "vendor_name"),
        Index("idx_questionnaire_status", "status"),
        Index("idx_questionnaire_template", "template_id"),
    )


# ---------------------------------------------------------------------------
# Data Silo Scanning
# ---------------------------------------------------------------------------


class DataSilo(Base):
    """Tracks discovered data stores and their sensitive data classification."""

    __tablename__ = "data_silos"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)
    silo_type = Column(
        String(30), nullable=False
    )  # s3_bucket, rds_database, sharepoint_site, snowflake_db, github_repo
    provider = Column(String(30))  # aws, azure, gcp, github, sharepoint
    location = Column(String(500))  # ARN, URL, connection string (masked)

    # Classification
    data_classification = Column(
        String(20), default="unknown"
    )  # public, internal, confidential, restricted, unknown
    contains_pii = Column(Boolean, default=False)
    contains_phi = Column(Boolean, default=False)
    contains_pci = Column(Boolean, default=False)
    contains_credentials = Column(Boolean, default=False)

    # Scan results
    last_scan_date = Column(DateTime(timezone=True))
    scan_status = Column(
        String(20), default="not_scanned"
    )  # not_scanned, scanning, completed, error
    sensitive_field_count = Column(Integer, default=0)
    total_records = Column(Integer)
    scan_findings = Column(
        SQLiteJSON, default=list
    )  # [{field_name, data_type, sample_masked, confidence}]

    # Protection status
    encrypted_at_rest = Column(Boolean)
    encrypted_in_transit = Column(Boolean)
    access_logging_enabled = Column(Boolean)
    backup_enabled = Column(Boolean)
    retention_days = Column(Integer)

    # Ownership
    owner = Column(String(255))
    team = Column(String(100))

    # Compliance
    applicable_frameworks = Column(SQLiteJSON, default=list)  # ["hipaa", "gdpr", "pci_dss"]
    remediation_status = Column(String(20), default="none")  # none, in_progress, completed
    remediation_notes = Column(Text)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("idx_silo_type", "silo_type"),
        Index("idx_silo_classification", "data_classification"),
        Index("idx_silo_provider", "provider"),
        Index("idx_silo_pii", "contains_pii"),
    )


# ---------------------------------------------------------------------------
# Phase 3: Control Inheritance
# ---------------------------------------------------------------------------


class ControlInheritance(Base):
    """Maps control responsibility: inherited, shared, common, or system-specific."""

    __tablename__ = "control_inheritances"

    id = Column(String(36), primary_key=True, default=_uuid)
    system_profile_id = Column(String(36), ForeignKey("system_profiles.id"), nullable=False)
    framework = Column(String(50), nullable=False)
    control_id = Column(String(50), nullable=False)

    # Per NIST SP 800-53A / FedRAMP CRM
    inheritance_type = Column(
        String(20), nullable=False
    )  # inherited, shared, common, system_specific
    provider_system_id = Column(String(36), ForeignKey("system_profiles.id"))
    provider_description = Column(Text)
    responsibility_description = Column(Text)
    evidence_requirement = Column(String(20), default="both")  # provider_only, consumer_only, both

    status = Column(String(20), default="active")  # active, under_review, deprecated

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("idx_ci_system_control", "system_profile_id", "framework", "control_id", unique=True),
        Index("idx_ci_provider", "provider_system_id"),
    )


# ---------------------------------------------------------------------------
# Phase 3: System Dependencies
# ---------------------------------------------------------------------------


class SystemDependency(Base):
    """Models cross-system control inheritance dependencies."""

    __tablename__ = "system_dependencies"

    id = Column(String(36), primary_key=True, default=_uuid)
    consumer_system_id = Column(String(36), ForeignKey("system_profiles.id"), nullable=False)
    provider_system_id = Column(String(36), ForeignKey("system_profiles.id"), nullable=False)

    shared_controls = Column(SQLiteJSON, default=list)  # ["nist_800_53:AC-2", "soc2:CC6.1"]
    dependency_type = Column(
        String(30), nullable=False
    )  # infrastructure, identity, network, application
    description = Column(Text)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("idx_sd_consumer", "consumer_system_id"),
        Index("idx_sd_provider", "provider_system_id"),
    )


# ---------------------------------------------------------------------------
# Phase 4: Change Events
# ---------------------------------------------------------------------------


class ChangeEvent(Base):
    """Generic change event from cloud audit logs, CI/CD, ITSM, IaC."""

    __tablename__ = "change_events"

    id = Column(String(36), primary_key=True, default=_uuid)
    source = Column(String(50), nullable=False)  # cloudtrail, github, servicenow, terraform
    source_type = Column(String(30), nullable=False)  # cloud_audit, ci_cd, itsm, iac
    event_type = Column(String(100), nullable=False)
    actor = Column(String(255))
    action = Column(String(255), nullable=False)
    resource_id = Column(Text)
    resource_type = Column(String(100))
    detail = Column(JSONType)
    occurred_at = Column(DateTime(timezone=True), nullable=False)
    ingested_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    sha256 = Column(String(64), nullable=False)

    __table_args__ = (
        Index("idx_ce_source", "source", "source_type"),
        Index("idx_ce_occurred", "occurred_at"),
        Index("idx_ce_resource", "resource_id"),
        Index("idx_ce_sha256", "sha256"),
    )


# ---------------------------------------------------------------------------
# Phase 4: Compliance Drift
# ---------------------------------------------------------------------------


class ComplianceDrift(Base):
    """Records compliance status changes with correlated change events."""

    __tablename__ = "compliance_drifts"

    id = Column(String(36), primary_key=True, default=_uuid)
    framework = Column(String(50), nullable=False)
    control_id = Column(String(50), nullable=False)
    system_profile_id = Column(String(36), ForeignKey("system_profiles.id"))

    previous_status = Column(String(20), nullable=False)
    new_status = Column(String(20), nullable=False)
    drift_direction = Column(String(20), nullable=False)  # improved, degraded
    previous_posture_score = Column(Float)
    new_posture_score = Column(Float)

    correlated_change_event_ids = Column(SQLiteJSON, default=list)
    root_cause_summary = Column(Text)
    correlation_confidence = Column(Float)

    detected_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    snapshot_id = Column(String(36))

    __table_args__ = (
        Index("idx_drift_control", "framework", "control_id"),
        Index("idx_drift_detected", "detected_at"),
        Index("idx_drift_direction", "drift_direction"),
        Index("idx_drift_system", "system_profile_id"),
    )


# ---------------------------------------------------------------------------
# Phase 5a: Policy Overrides (OPA)
# ---------------------------------------------------------------------------


class PolicyOverride(Base):
    """Custom Rego policies for ABAC escalation via OPA."""

    __tablename__ = "policy_overrides"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    policy_rego = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)
    created_by = Column(String(255))
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (Index("idx_policy_override_active", "is_active"),)


# ---------------------------------------------------------------------------
# Phase 5b: External Auditors
# ---------------------------------------------------------------------------


class ExternalAuditor(Base):
    """Lightweight auditor account with magic-link authentication."""

    __tablename__ = "external_auditors"

    id = Column(String(36), primary_key=True, default=_uuid)
    email = Column(String(255), nullable=False, unique=True)
    name = Column(String(255), nullable=False)
    firm = Column(String(255))

    magic_link_hash = Column(String(64))
    token_expires_at = Column(DateTime(timezone=True))
    last_accessed = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("idx_ext_auditor_email", "email"),
        Index("idx_ext_auditor_magic_hash", "magic_link_hash"),
    )


class AuditorEngagementAssignment(Base):
    """Junction table: auditor ↔ engagement (many-to-many)."""

    __tablename__ = "auditor_engagement_assignments"

    auditor_id = Column(String(36), ForeignKey("external_auditors.id"), primary_key=True)
    engagement_id = Column(String(36), ForeignKey("audit_engagements.id"), primary_key=True)
    assigned_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)


class EvidenceRequest(Base):
    """Auditor request for additional evidence during an engagement."""

    __tablename__ = "evidence_requests"

    id = Column(String(36), primary_key=True, default=_uuid)
    engagement_id = Column(String(36), ForeignKey("audit_engagements.id"), nullable=False)
    auditor_id = Column(String(36), ForeignKey("external_auditors.id"), nullable=False)
    framework = Column(String(50))
    control_id = Column(String(50))
    description = Column(Text, nullable=False)

    status = Column(
        String(20), default="requested"
    )  # requested -> in_progress -> fulfilled -> closed
    fulfilled_by = Column(String(255))
    fulfilled_at = Column(DateTime(timezone=True))
    fulfillment_notes = Column(Text)
    evidence_ids = Column(JSONType, default=list)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


# ---------------------------------------------------------------------------
# Vector Embeddings — RAG-based semantic control matching
# ---------------------------------------------------------------------------


class Embedding(Base):
    """Stored embedding vectors for semantic search over controls and findings.

    Vectors are stored as JSON arrays (list[float]) for SQLite compatibility.
    For production PostgreSQL deployments with pgvector, a migration can add
    a proper vector column alongside the JSON representation.
    """

    __tablename__ = "embeddings"

    id = Column(String(36), primary_key=True, default=_uuid)
    entity_type = Column(String(50), nullable=False)  # "control", "remediation", "finding"
    entity_id = Column(String(100), nullable=False)  # control_id, remediation KB key, etc.
    entity_text = Column(Text, nullable=False)  # the text that was embedded
    vector = Column(JSONType, nullable=False)  # embedding vector as JSON array
    model_name = Column(String(100), nullable=False)  # which model produced this embedding
    dimensions = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (Index("idx_embedding_entity", "entity_type", "entity_id", unique=True),)
