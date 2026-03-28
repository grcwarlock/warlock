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
    CheckConstraint,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    Boolean,
    ForeignKey,
    UniqueConstraint,
)
from sqlalchemy import (
    JSON as SQLiteJSON,
)  # Generic JSON: maps to JSONB on PostgreSQL, JSON on SQLite
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import event as _sa_event
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
# Multi-tenancy: Tenant model and mixin
# ---------------------------------------------------------------------------

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000000"
"""Well-known UUID for the default/system tenant.

All data created before multi-tenancy was enabled is backfilled to this
tenant.  Single-tenant deployments use this tenant exclusively.
"""


class Tenant(Base):
    """Organisation-level tenant for data isolation."""

    __tablename__ = "tenants"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False, unique=True)
    slug = Column(String(100), nullable=False, unique=True)
    is_active = Column(Boolean, nullable=False, default=True)
    config_overrides = Column(JSONType, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("idx_tenant_slug", "slug", unique=True),
        Index("idx_tenant_active", "is_active"),
    )


@_sa_event.listens_for(Tenant.__table__, "after_create")
def _insert_default_tenant(target, connection, **kw):
    """Auto-insert the default system tenant when the tenants table is created.

    Uses a SELECT guard instead of INSERT OR IGNORE for cross-DB compatibility.
    """
    from sqlalchemy import text as _text

    row = connection.execute(
        _text("SELECT id FROM tenants WHERE id = :tid"),
        {"tid": DEFAULT_TENANT_ID},
    ).first()
    if row is None:
        connection.execute(
            target.insert(),
            {
                "id": DEFAULT_TENANT_ID,
                "name": "System",
                "slug": "system",
                "is_active": True,
                "created_at": _utcnow(),
            },
        )


class TenantMixin:
    """Mixin that adds ``tenant_id`` FK to every tenant-scoped model.

    All models in the system inherit this so that row-level data isolation
    can be enforced via a session-level filter.  The column defaults to
    :data:`DEFAULT_TENANT_ID` for backwards compatibility with existing data.
    """

    tenant_id = Column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
        index=True,
    )


# ---------------------------------------------------------------------------
# Stage 0: Connector runs — tracks each collection execution
# ---------------------------------------------------------------------------


class ConnectorRun(TenantMixin, Base):
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

    __table_args__ = (
        CheckConstraint(
            "status IN ('running','success','partial','error')",
            name="ck_connector_runs_status",
        ),
    )


# ---------------------------------------------------------------------------
# Stage 1: Raw events — verbatim data from sources. Never mutated.
# ---------------------------------------------------------------------------


class RawEvent(TenantMixin, Base):
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


class Finding(TenantMixin, Base):
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

    # PII
    pii_detected = Column(Boolean, default=False, nullable=False, server_default="0")

    # SAC-3: Data classification
    classification = Column(String(50))  # public, internal, confidential, restricted

    # Integrity
    sha256 = Column(String(64), nullable=False)

    raw_event = relationship("RawEvent", back_populates="findings")
    control_mappings = relationship("ControlMapping", back_populates="finding")

    # GAP-066: Link findings to assets via resource_id natural join
    assets = relationship(
        "Asset",
        primaryjoin="foreign(Asset.resource_id) == Finding.resource_id",
        viewonly=True,
    )

    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name="ck_findings_severity",
        ),
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


class ControlMapping(TenantMixin, Base):
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


class ControlResult(TenantMixin, Base):
    __tablename__ = "control_results"

    id = Column(String(36), primary_key=True, default=_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)
    control_mapping_id = Column(
        String(36), ForeignKey("control_mappings.id", ondelete="CASCADE"), nullable=True
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

    # RQM-21: Inherent risk (ALE with zero control effectiveness)
    inherent_risk_ale = Column(Float)  # annual loss expectancy without controls

    # Lineage
    evidence_ids = Column(JSONType)  # [raw_event UUIDs] that informed this
    assessed_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    assessor = Column(String(255), nullable=False)  # "assertion:mfa_check" or "ai:claude"

    # Phase 5b: Auditor examination
    examined_at = Column(DateTime(timezone=True))
    examined_by = Column(String(255))

    control_mapping = relationship("ControlMapping", back_populates="control_results")

    __table_args__ = (
        CheckConstraint(
            "status IN ('compliant','non_compliant','partial','not_assessed',"
            "'not_applicable','risk_accepted','inherited_compliant','inherited_at_risk')",
            name="ck_control_results_status",
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name="ck_control_results_severity",
        ),
        Index("idx_result_control", "framework", "control_id"),
        Index("idx_result_status", "status"),
        Index("idx_result_assessed", "assessed_at"),
        Index("idx_result_finding", "finding_id"),
        Index("idx_result_mapping", "control_mapping_id"),
        Index("idx_result_system_profile", "system_profile_id"),
        UniqueConstraint(
            "finding_id",
            "control_mapping_id",
            "system_profile_id",
            name="uq_result_finding_mapping_system",
        ),
    )


# ---------------------------------------------------------------------------
# Immutable Audit Trail — append-only evidence chain
# ---------------------------------------------------------------------------


class AuditEntry(TenantMixin, Base):
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


class PostureSnapshot(TenantMixin, Base):
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
        UniqueConstraint(
            "snapshot_date",
            "framework",
            "control_id",
            "system_profile_id",
            name="uq_posture_date_framework_control_system",
        ),
    )


# ---------------------------------------------------------------------------
# Users & RBAC
# ---------------------------------------------------------------------------


class User(TenantMixin, Base):
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

    # PLT-3: Role hierarchy
    parent_role = Column(String(50))  # role this role inherits from
    delegated_by = Column(String(36))  # user_id who delegated admin

    # SAC-2: Session management
    session_expires_at = Column(DateTime(timezone=True))
    max_concurrent_sessions = Column(Integer, default=5)

    # INT-1: SSO/OIDC
    sso_provider = Column(String(50))  # okta, azure_ad, google
    sso_subject_id = Column(String(255))  # external IdP subject identifier

    __table_args__ = (Index("idx_user_role", "role"),)


class APIKey(TenantMixin, Base):
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


class RiskAnalysis(TenantMixin, Base):
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

    # RQM-23: Risk culture metrics
    risk_culture_score = Column(Float)  # 0-100 organizational risk maturity
    mttr_days = Column(Float)  # mean time to remediate in days

    __table_args__ = (
        Index("idx_risk_framework", "framework"),
        Index("idx_risk_created", "created_at"),
    )


class AuditEngagement(TenantMixin, Base):
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


class POAM(TenantMixin, Base):
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

    # POAM-1: Cost tracking and resource allocation
    cost_estimate = Column(Float)  # estimated remediation cost in USD
    resource_allocation = Column(Text)  # who/what is allocated to remediate

    # POAM-3: Escalation tracking
    escalation_sent_at = Column(DateTime(timezone=True))  # last escalation notification
    escalation_level = Column(Integer, default=0)  # 0=none, 1=owner, 2=lead, 3=CISO

    created_by = Column(String(255))
    updated_by = Column(String(255))
    approved_by = Column(String(255))
    approved_at = Column(DateTime(timezone=True))
    vendor_dependency = Column(String(255))

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        CheckConstraint(
            "status IN ('draft','open','in_progress','remediated','verified','completed','closed','risk_accepted','cancelled')",
            name="ck_poams_status",
        ),
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


class CompensatingControl(TenantMixin, Base):
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
        CheckConstraint(
            "status IN ('proposed','approved','active','expired','revoked')",
            name="ck_compensating_controls_status",
        ),
        Index("idx_cc_control", "original_framework", "original_control_id"),
        Index("idx_cc_status", "status"),
        Index("idx_cc_poam_id", "poam_id"),
        Index("idx_cc_system_profile_id", "system_profile_id"),
    )


# ---------------------------------------------------------------------------
# Risk Acceptance
# ---------------------------------------------------------------------------


class RiskAcceptance(TenantMixin, Base):
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
        CheckConstraint(
            "status IN ('requested','reviewed','approved','active','expired','revoked')",
            name="ck_risk_acceptances_status",
        ),
        Index("idx_ra_control", "framework", "control_id"),
        Index("idx_ra_status", "status"),
        Index("idx_ra_expiry", "expiry_date"),
        Index("idx_ra_poam_id", "poam_id"),
        Index("idx_ra_system_profile_id", "system_profile_id"),
    )


# ---------------------------------------------------------------------------
# Issue Tracking & Remediation
# ---------------------------------------------------------------------------


class Issue(TenantMixin, Base):
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

    # ISS-7: Root cause grouping
    root_cause_id = Column(String(36))  # groups related issues under same root cause

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    created_by = Column(String(255))

    # ISS-4: Watchers relationship
    watchers = relationship(
        "WatchSubscription", back_populates="issue", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('open','assigned','in_progress','remediated','verified','closed','risk_accepted')",
            name="ck_issues_status",
        ),
        Index("idx_issue_status", "status"),
        Index("idx_issue_priority", "priority"),
        Index("idx_issue_framework", "framework", "control_id"),
        Index("idx_issue_assigned", "assigned_to"),
        Index("idx_issue_due", "due_date"),
        Index("idx_issue_finding_id", "finding_id"),
        Index("idx_issue_control_result_id", "control_result_id"),
        Index("idx_issue_poam_id", "poam_id"),
    )


class IssueComment(TenantMixin, Base):
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


class Attestation(TenantMixin, Base):
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
        CheckConstraint(
            "status IN ('draft','submitted','reviewed','approved','rejected')",
            name="ck_attestations_status",
        ),
        Index("idx_attest_engagement", "engagement_id"),
        Index("idx_attest_framework", "framework", "control_id"),
        Index("idx_attest_status", "status"),
    )


class AuditComment(TenantMixin, Base):
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


class LegalHold(TenantMixin, Base):
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


class TrustAccessRequest(TenantMixin, Base):
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


class TrustDocument(TenantMixin, Base):
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


class SystemProfile(TenantMixin, Base):
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


class Personnel(TenantMixin, Base):
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


class QuestionnaireTemplate(TenantMixin, Base):
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


class Questionnaire(TenantMixin, Base):
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


class DataSilo(TenantMixin, Base):
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


class ControlInheritance(TenantMixin, Base):
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


class SystemDependency(TenantMixin, Base):
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


class ChangeEvent(TenantMixin, Base):
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


class ComplianceDrift(TenantMixin, Base):
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


class PolicyOverride(TenantMixin, Base):
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


class ExternalAuditor(TenantMixin, Base):
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


class AuditorEngagementAssignment(TenantMixin, Base):
    """Junction table: auditor ↔ engagement (many-to-many)."""

    __tablename__ = "auditor_engagement_assignments"

    auditor_id = Column(String(36), ForeignKey("external_auditors.id"), primary_key=True)
    engagement_id = Column(String(36), ForeignKey("audit_engagements.id"), primary_key=True)
    assigned_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)


class EvidenceRequest(TenantMixin, Base):
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

    __table_args__ = (
        Index("idx_evidence_req_engagement_id", "engagement_id"),
        Index("idx_evidence_req_auditor_id", "auditor_id"),
    )


# ---------------------------------------------------------------------------
# Vector Embeddings — RAG-based semantic control matching
# ---------------------------------------------------------------------------


class Embedding(TenantMixin, Base):
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


# ---------------------------------------------------------------------------
# Domain Architecture: Policy, Asset, Vendor models
# ---------------------------------------------------------------------------


class Policy(TenantMixin, Base):
    __tablename__ = "policies"

    id = Column(String(36), primary_key=True, default=_uuid)
    policy_type = Column(String(50), nullable=False, index=True)
    scope = Column(JSONType, nullable=False, default=dict)
    rules = Column(JSONType, nullable=False)
    priority = Column(Integer, default=0)
    enabled = Column(Boolean, default=True)
    created_by = Column(String(200), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    effective_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    description = Column(Text, default="")

    __table_args__ = (Index("ix_policies_type_enabled", "policy_type", "enabled"),)


class PolicyHistory(TenantMixin, Base):
    __tablename__ = "policy_history"

    id = Column(String(36), primary_key=True, default=_uuid)
    policy_id = Column(
        String(36), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action = Column(String(20), nullable=False)
    old_rules = Column(JSONType, nullable=True)
    new_rules = Column(JSONType, nullable=False)
    actor = Column(String(200), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    policy = relationship("Policy", backref="history")


class Asset(TenantMixin, Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=_uuid)
    resource_id = Column(String(500), nullable=False, unique=True, index=True)
    resource_type = Column(String(100), nullable=False, index=True)
    resource_name = Column(String(500), nullable=True)
    system_id = Column(
        String(36), ForeignKey("system_profiles.id", ondelete="SET NULL"), nullable=True
    )
    owner = Column(String(200), nullable=True)
    classification = Column(String(20), nullable=True)
    criticality = Column(Integer, nullable=True)
    status = Column(String(20), default="active")
    first_seen = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    metadata_ = Column("metadata", JSONType, default=dict)

    # GAP-055: Finding UUIDs linked to this asset (JSON list, like evidence_ids on ControlResult)
    finding_ids = Column(JSONType, default=list)

    system = relationship("SystemProfile", backref="assets")


class Vendor(TenantMixin, Base):
    __tablename__ = "vendors"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(200), nullable=False, unique=True, index=True)
    tier = Column(String(20), nullable=True)
    risk_score = Column(Float, nullable=True)
    contract_expires = Column(DateTime(timezone=True), nullable=True)
    last_assessment = Column(DateTime(timezone=True), nullable=True)
    assessment_cadence_days = Column(Integer, nullable=True)
    metadata_ = Column("metadata", JSONType, default=dict)

    # RQM-14: Vendor blast radius
    blast_radius_score = Column(Float)  # 0-100 impact if vendor fails
    dependent_systems = Column(SQLiteJSON, default=list)  # system_profile_ids affected
    dependent_frameworks = Column(SQLiteJSON, default=list)  # frameworks affected
    dependent_control_count = Column(Integer, default=0)  # total controls affected


# ---------------------------------------------------------------------------
# Watch Subscriptions — ISS-4: users watching issues/entities for changes
# ---------------------------------------------------------------------------


class WatchSubscription(TenantMixin, Base):
    """Tracks user subscriptions to entity status changes."""

    __tablename__ = "watch_subscriptions"

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    entity_type = Column(String(50), nullable=False)  # issue, poam, finding, vendor
    entity_id = Column(String(36), nullable=False)
    issue_id = Column(String(36), ForeignKey("issues.id", ondelete="CASCADE"))
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    issue = relationship("Issue", back_populates="watchers")

    __table_args__ = (
        UniqueConstraint("user_id", "entity_type", "entity_id", name="uq_watch_user_entity"),
        Index("idx_watch_entity", "entity_type", "entity_id"),
        Index("idx_watch_user", "user_id"),
    )


# ---------------------------------------------------------------------------
# Escalation Policies — AUT-4: configurable escalation chains
# ---------------------------------------------------------------------------


class EscalationPolicy(TenantMixin, Base):
    """Defines escalation chains for overdue items."""

    __tablename__ = "escalation_policies"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text)

    # Levels: [{level: 1, role: "control_owner", delay_hours: 24},
    #          {level: 2, role: "team_lead", delay_hours: 48},
    #          {level: 3, role: "ciso", delay_hours: 72}]
    levels = Column(SQLiteJSON, nullable=False, default=list)
    cooldown_minutes = Column(Integer, default=60)  # min time between notifications
    active = Column(Boolean, default=True)

    # Scope: which entity types this policy applies to
    entity_types = Column(SQLiteJSON, default=list)  # ["issue", "poam", "finding"]
    min_severity = Column(String(20), default="high")  # minimum severity to trigger

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    created_by = Column(String(255))

    __table_args__ = (Index("idx_escalation_active", "active"),)


# ---------------------------------------------------------------------------
# Saved Queries — DLA-1: persistent analytics queries
# ---------------------------------------------------------------------------


class SavedQuery(TenantMixin, Base):
    """Saved lake/analytics queries for reuse."""

    __tablename__ = "saved_queries"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    sql_text = Column(Text, nullable=False)
    query_type = Column(String(50), default="custom")  # custom, template, sla_breach, drift, etc.
    parameters = Column(SQLiteJSON, default=dict)  # template parameters with defaults
    shared = Column(Boolean, default=False)  # visible to all users
    created_by = Column(String(255))
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    last_run_at = Column(DateTime(timezone=True))
    run_count = Column(Integer, default=0)

    __table_args__ = (
        Index("idx_saved_query_type", "query_type"),
        Index("idx_saved_query_shared", "shared"),
        Index("idx_saved_query_created_by", "created_by"),
    )


# ---------------------------------------------------------------------------
# IP Allowlist — SAC-1: restrict API access by IP/CIDR
# ---------------------------------------------------------------------------


class IPAllowlistEntry(TenantMixin, Base):
    """IP allowlist entries for API access restriction."""

    __tablename__ = "ip_allowlist"

    id = Column(String(36), primary_key=True, default=_uuid)
    cidr = Column(String(50), nullable=False)  # e.g. "10.0.0.0/8" or "203.0.113.5/32"
    description = Column(Text)
    active = Column(Boolean, default=True)
    created_by = Column(String(255))
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    expires_at = Column(DateTime(timezone=True))  # optional expiry

    __table_args__ = (Index("idx_ip_allowlist_active", "active"),)


# ---------------------------------------------------------------------------
# Risk Dependencies — RQM-9: risk interconnection mapping
# ---------------------------------------------------------------------------


class RiskDependency(TenantMixin, Base):
    """Maps dependencies and cascade effects between risks."""

    __tablename__ = "risk_dependencies"

    id = Column(String(36), primary_key=True, default=_uuid)
    risk_id = Column(String(36), ForeignKey("risk_analyses.id", ondelete="CASCADE"), nullable=False)
    depends_on_risk_id = Column(
        String(36), ForeignKey("risk_analyses.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type = Column(
        String(50), nullable=False
    )  # causes, amplifies, mitigates, correlates
    weight = Column(Float, default=1.0)  # strength of dependency (0-1)
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        UniqueConstraint("risk_id", "depends_on_risk_id", name="uq_risk_dependency"),
        Index("idx_risk_dep_risk", "risk_id"),
        Index("idx_risk_dep_depends_on", "depends_on_risk_id"),
    )


# ---------------------------------------------------------------------------
# Alerts — triggered by rules, threshold breaches, or policy violations
# ---------------------------------------------------------------------------


class Alert(TenantMixin, Base):
    """Alert generated by rule engine, threshold breach, or policy violation."""

    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=_uuid)
    title = Column(Text, nullable=False)
    description = Column(Text)

    # Severity and classification
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    category = Column(
        String(50), nullable=False
    )  # control_drift, new_finding, connector_failure, threshold_breach, policy_violation

    # Links to compliance data
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"))
    control_result_id = Column(String(36), ForeignKey("control_results.id", ondelete="SET NULL"))
    connector_name = Column(String(100))  # which connector triggered
    framework = Column(String(50))
    control_id = Column(String(50))

    # MITRE ATT&CK (optional)
    mitre_tactic = Column(String(100))
    mitre_technique = Column(String(100))

    # Lifecycle
    status = Column(
        String(20), nullable=False, default="open"
    )  # open, acknowledged, investigating, resolved, dismissed
    acknowledged_by = Column(String(255))
    acknowledged_at = Column(DateTime(timezone=True))
    resolved_by = Column(String(255))
    resolved_at = Column(DateTime(timezone=True))
    resolution_notes = Column(Text)

    # Rule that triggered this alert
    rule_name = Column(String(255))
    rule_metadata = Column(SQLiteJSON, default=dict)  # arbitrary rule context

    # Timestamps
    triggered_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        CheckConstraint(
            "status IN ('open','acknowledged','investigating','resolved','dismissed')",
            name="ck_alerts_status",
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name="ck_alerts_severity",
        ),
        Index("idx_alert_status", "status"),
        Index("idx_alert_severity", "severity"),
        Index("idx_alert_category", "category"),
        Index("idx_alert_triggered_at", "triggered_at"),
        Index("idx_alert_finding_id", "finding_id"),
        Index("idx_alert_control_result_id", "control_result_id"),
    )


# ---------------------------------------------------------------------------
# Remediations — structured remediation tracking with 5-stage workflow
# ---------------------------------------------------------------------------


class Remediation(TenantMixin, Base):
    """Tracks remediation of findings/alerts through a 5-stage workflow."""

    __tablename__ = "remediations"

    id = Column(String(36), primary_key=True, default=_uuid)
    title = Column(Text, nullable=False)
    description = Column(Text)

    # Links
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"))
    control_result_id = Column(String(36), ForeignKey("control_results.id", ondelete="SET NULL"))
    alert_id = Column(String(36), ForeignKey("alerts.id", ondelete="SET NULL"))
    issue_id = Column(String(36), ForeignKey("issues.id", ondelete="SET NULL"))
    framework = Column(String(50))
    control_id = Column(String(50))

    # 5-stage state machine: open -> assigned -> in_progress -> verification -> closed
    status = Column(String(20), nullable=False, default="open")

    # Assignment
    assigned_to = Column(String(255))
    assigned_by = Column(String(255))
    assigned_at = Column(DateTime(timezone=True))

    # Remediation details
    remediation_plan = Column(Text)
    remediation_steps = Column(SQLiteJSON, default=list)  # [{step, description, completed}]
    evidence = Column(SQLiteJSON, default=list)  # [{description, url, uploaded_at}]

    # Verification
    verified_by = Column(String(255))
    verified_at = Column(DateTime(timezone=True))
    verification_notes = Column(Text)

    # Dates
    due_date = Column(DateTime(timezone=True))
    closed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    created_by = Column(String(255))

    __table_args__ = (
        CheckConstraint(
            "status IN ('open','assigned','in_progress','verification','closed')",
            name="ck_remediations_status",
        ),
        Index("idx_remediation_status", "status"),
        Index("idx_remediation_finding_id", "finding_id"),
        Index("idx_remediation_control_result_id", "control_result_id"),
        Index("idx_remediation_alert_id", "alert_id"),
        Index("idx_remediation_assigned_to", "assigned_to"),
        Index("idx_remediation_due_date", "due_date"),
    )


# ---------------------------------------------------------------------------
# Pipeline Runs — persists pipeline execution history and stats
# ---------------------------------------------------------------------------


class PipelineRun(TenantMixin, Base):
    """Tracks pipeline execution runs with stats and timing."""

    __tablename__ = "pipeline_runs"

    id = Column(String(36), primary_key=True, default=_uuid)
    status = Column(String(20), nullable=False, default="running")  # running, completed, failed

    # Stats
    connectors_succeeded = Column(Integer, default=0)
    connectors_failed = Column(Integer, default=0)
    raw_events_collected = Column(Integer, default=0)
    findings_normalized = Column(Integer, default=0)
    controls_mapped = Column(Integer, default=0)
    errors = Column(SQLiteJSON, default=list)

    # Timing
    started_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Float)

    # Trigger
    triggered_by = Column(String(255))  # user email or "scheduler"
    source_filter = Column(SQLiteJSON, default=list)  # connectors requested

    __table_args__ = (
        CheckConstraint(
            "status IN ('running','completed','failed')",
            name="ck_pipeline_runs_status",
        ),
        Index("idx_pipeline_run_status", "status"),
        Index("idx_pipeline_run_started_at", "started_at"),
    )


# ---------------------------------------------------------------------------
# Dead Letter Queue — failed pipeline events for retry/inspection
# ---------------------------------------------------------------------------


class DeadLetterEntry(TenantMixin, Base):
    """Captures pipeline events that failed processing for later retry."""

    __tablename__ = "dead_letter_queue"

    id = Column(String(36), primary_key=True, default=_uuid)
    event_type = Column(String(100), nullable=False)
    payload = Column(JSONType, nullable=False)
    error_message = Column(Text, nullable=False)
    retry_count = Column(Integer, default=0)
    status = Column(String(20), default="failed")  # failed, retried, purged
    original_event_id = Column(String(36))
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    last_retry_at = Column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(
            "status IN ('failed','retried','purged')",
            name="ck_dlq_status",
        ),
        Index("idx_dlq_status", "status"),
        Index("idx_dlq_event_type", "event_type"),
        Index("idx_dlq_created_at", "created_at"),
    )


# ---------------------------------------------------------------------------
# GAP-084: Compliance Calendar — obligation tracking
# ---------------------------------------------------------------------------


class ComplianceObligation(TenantMixin, Base):
    """Tracks recurring compliance obligations (audits, filings, assessments)."""

    __tablename__ = "compliance_obligations"

    id = Column(String(36), primary_key=True, default=_uuid)
    title = Column(String(500), nullable=False)
    framework = Column(String(50))
    control_id = Column(String(50))
    obligation_type = Column(String(50))  # audit, assessment, report, filing
    frequency = Column(String(20))  # monthly, quarterly, annual
    next_due = Column(DateTime(timezone=True))
    owner = Column(String(255))
    status = Column(String(20), default="pending")  # pending, in_progress, completed, overdue
    completed_at = Column(DateTime(timezone=True))
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','in_progress','completed','overdue')",
            name="ck_compliance_obligations_status",
        ),
        Index("idx_obligation_status", "status"),
        Index("idx_obligation_next_due", "next_due"),
        Index("idx_obligation_framework", "framework"),
    )


# ---------------------------------------------------------------------------
# GAP-092: Change Requests with CAB approval
# ---------------------------------------------------------------------------


class ChangeRequest(TenantMixin, Base):
    """Change request with Change Advisory Board (CAB) approval workflow."""

    __tablename__ = "change_requests"

    id = Column(String(36), primary_key=True, default=_uuid)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    change_type = Column(String(50))  # standard, normal, emergency
    risk_level = Column(String(20))
    system_profile_id = Column(String(36), ForeignKey("system_profiles.id", ondelete="SET NULL"))
    requester = Column(String(255), nullable=False)
    status = Column(String(20), default="draft")
    cab_decision = Column(String(20))  # approved, rejected, deferred
    cab_notes = Column(Text)
    cab_date = Column(DateTime(timezone=True))
    implementation_date = Column(DateTime(timezone=True))
    rollback_plan = Column(Text)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("idx_change_request_status", "status"),
        Index("idx_change_request_system", "system_profile_id"),  # #20: FK index
        Index("idx_change_request_cab_decision", "cab_decision"),
    )


# ---------------------------------------------------------------------------
# GAP-097: Delegation Grants — persisted to DB
# ---------------------------------------------------------------------------


class DelegationGrant(TenantMixin, Base):
    """Persistent record of delegated admin authority between users."""

    __tablename__ = "delegation_grants"

    id = Column(String(36), primary_key=True, default=_uuid)
    delegator_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    delegate_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    permissions = Column(JSONType, default=list)
    expires_at = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("idx_delegation_delegator", "delegator_id"),  # #20: FK index
        Index("idx_delegation_delegate", "delegate_id"),  # #20: FK index
        Index("idx_delegation_active", "is_active"),
    )


# ---------------------------------------------------------------------------
# GAP-098: Sandbox Environments — persisted to DB
# ---------------------------------------------------------------------------


class SandboxEnvironment(TenantMixin, Base):
    """Persistent sandbox/staging environment for policy testing."""

    __tablename__ = "sandbox_environments"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    config = Column(JSONType, default=dict)
    status = Column(String(20), default="active")
    expires_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("idx_sandbox_owner", "owner_id"),  # #20: FK index
        Index("idx_sandbox_status", "status"),
    )


# ---------------------------------------------------------------------------
# STUB-009: Workpaper — persisted audit workpapers
# ---------------------------------------------------------------------------


class Workpaper(TenantMixin, Base):
    """Persistent audit workpaper linked to an engagement and control."""

    __tablename__ = "workpapers"

    id = Column(String(36), primary_key=True, default=_uuid)
    engagement_id = Column(
        String(36), ForeignKey("audit_engagements.id", ondelete="CASCADE"), nullable=False
    )
    control_id = Column(String(50), nullable=False)
    framework = Column(String(50))
    template_type = Column(String(50))  # test_of_design, test_of_effectiveness, walkthrough
    status = Column(String(20), default="draft")  # draft, reviewed, signed_off
    reviewer = Column(String(255))
    notes = Column(Text)
    review_history = Column(JSONType, default=list)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        CheckConstraint(
            "status IN ('draft','reviewed','signed_off')",
            name="ck_workpapers_status",
        ),
        Index("idx_workpaper_engagement", "engagement_id"),  # #20: FK index
        Index("idx_workpaper_status", "status"),
    )


# ---------------------------------------------------------------------------
# PLT-2 / GAP-100: White-label branding configuration
# ---------------------------------------------------------------------------


class BrandingConfig(TenantMixin, Base):
    """Persisted per-tenant branding configuration for white-label deployments."""

    __tablename__ = "branding_configs"

    id = Column(String(36), primary_key=True, default=_uuid)
    tenant_id_unique = Column(String(36), unique=True)  # one config per tenant
    logo_url = Column(String(500))
    primary_color = Column(String(20), default="#6366f1")
    accent_color = Column(String(20), default="#8b5cf6")
    app_name = Column(String(100), default="Warlock")
    favicon_url = Column(String(500))
    custom_css = Column(Text)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("idx_branding_tenant", "tenant_id"),  # #20: FK index
        Index("idx_branding_tenant_unique", "tenant_id_unique", unique=True),
    )
