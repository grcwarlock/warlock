"""Post-pipeline seed steps and demo seed `main()` entrypoint."""

from __future__ import annotations

import hashlib
import random
from datetime import timedelta
from pathlib import Path

from sqlalchemy import func

from scripts.seed_impl.constants import NOW, REPO_ROOT
from scripts.seed_impl.helpers import RICH_DATA, _ensure_rich_data
from warlock.assessors.engine import Assessor
from warlock.assessors.engine import engine as assertion_engine
from warlock.connectors.base import (
    ConnectorConfig,
    ConnectorRegistry,
)
from warlock.db.engine import get_session, init_db
from warlock.db.models import (
    POAM,
    Attestation,
    AuditEngagement,
    AuditorEngagementAssignment,
    ChangeEvent,
    CompensatingControl,
    ComplianceDrift,
    ControlInheritance,
    ControlResult,
    DataSilo,
    EvidenceRequest,
    ExternalAuditor,
    Finding,
    Issue,
    LegalHold,
    Personnel,
    Policy,
    PolicyOverride,
    PostureSnapshot,
    RawEvent,
    RiskAcceptance,
    SystemDependency,
    SystemProfile,
    Vendor,
)
from warlock.mappers.control_mapper import ControlMapper
from warlock.normalizers.base import NormalizerRegistry
from warlock.pipeline.bus import EventBus
from warlock.pipeline.loader import load_assertions, load_framework_configs
from warlock.pipeline.orchestrator import Pipeline

try:
    from scripts.demo_connectors_new import ALL_NEW_CONNECTORS
except ImportError:
    from demo_connectors_new import ALL_NEW_CONNECTORS  # type: ignore[no-redef]

try:
    from scripts.demo_connectors_expansion import ALL_EXPANSION_CONNECTORS
except ImportError:
    from demo_connectors_expansion import ALL_EXPANSION_CONNECTORS  # type: ignore[no-redef]

from scripts.seed_impl.connectors import *
from scripts.seed_impl.normalizer_imports import *

# ---------------------------------------------------------------------------
# Post-pipeline seed functions
# ---------------------------------------------------------------------------


def seed_systems(session):
    """Create 5 SystemProfile records representing Acme Corp's systems."""
    # Dedup: skip if systems already exist (prevents duplicates on re-run)
    existing_names = {row[0] for row in session.query(SystemProfile.name).all()}
    systems_defs = [
        SystemProfile(
            name="Acme Production Platform",
            acronym="APP",
            description="Primary SaaS platform serving customer workloads. Hosts APIs, web app, and background workers on AWS.",
            confidentiality_impact="high",
            integrity_impact="high",
            availability_impact="high",
            overall_impact="high",
            frameworks=["nist_800_53", "soc2", "iso_27001"],
            connector_scope=["aws", "crowdstrike", "okta"],
            cloud_accounts=[
                {
                    "provider": "aws",
                    "account_id": "912345678012",
                    "regions": ["us-east-1", "us-west-2"],
                }
            ],
            network_boundaries=[{"cidr": "10.0.0.0/16", "description": "Production VPC"}],
            system_owner="Frank Torres",
            system_owner_email="frank.torres@acme.com",
            isso="Eve Nakamura",
            isso_email="eve.nakamura@acme.com",
            authorizing_official="Hassan Ali",
            ao_email="hassan.ali@acme.com",
            authorization_status="authorized",
            authorization_date=NOW - timedelta(days=180),
            authorization_expiry=NOW + timedelta(days=185),
            deployment_model="cloud",
            service_model="IaaS",
        ),
        SystemProfile(
            name="Customer Data Warehouse",
            acronym="CDW",
            description="Analytics and reporting platform. Ingests customer telemetry into Redshift for BI dashboards.",
            confidentiality_impact="high",
            integrity_impact="high",
            availability_impact="moderate",
            overall_impact="high",
            frameworks=["nist_800_53", "soc2", "iso_27701"],
            connector_scope=["aws"],
            cloud_accounts=[
                {"provider": "aws", "account_id": "912345678012", "regions": ["us-east-1"]}
            ],
            system_owner="Carol Park",
            system_owner_email="carol.park@acme.com",
            authorization_status="in_process",
            deployment_model="cloud",
            service_model="IaaS",
        ),
        SystemProfile(
            name="Corporate IT",
            acronym="CIT",
            description="Internal IT services: identity, email, endpoint management, and collaboration tools.",
            confidentiality_impact="moderate",
            integrity_impact="moderate",
            availability_impact="moderate",
            overall_impact="moderate",
            frameworks=["iso_27001", "soc2"],
            connector_scope=["okta", "crowdstrike"],
            system_owner="Bob Martinez",
            system_owner_email="bob.martinez@acme.com",
            authorization_status="authorized",
            authorization_date=NOW - timedelta(days=365),
            authorization_expiry=NOW + timedelta(days=1),
            deployment_model="hybrid",
            service_model="SaaS",
        ),
        SystemProfile(
            name="AI/ML Analytics Platform",
            acronym="AIML",
            description="Machine learning model training and inference. Processes anonymized customer data for product insights.",
            confidentiality_impact="moderate",
            integrity_impact="moderate",
            availability_impact="low",
            overall_impact="moderate",
            frameworks=["iso_42001", "nist_800_53"],
            connector_scope=["aws"],
            system_owner="Alice Chen",
            system_owner_email="alice.chen@acme.com",
            authorization_status="not_authorized",
            deployment_model="cloud",
            service_model="PaaS",
        ),
        SystemProfile(
            name="Development and Staging",
            acronym="DEV",
            description="Non-production environments for development, testing, and staging. No real customer data.",
            confidentiality_impact="low",
            integrity_impact="low",
            availability_impact="low",
            overall_impact="low",
            frameworks=["soc2"],
            connector_scope=["aws", "crowdstrike"],
            system_owner="Frank Torres",
            system_owner_email="frank.torres@acme.com",
            authorization_status="authorized",
            authorization_date=NOW - timedelta(days=90),
            authorization_expiry=NOW + timedelta(days=275),
            deployment_model="cloud",
            service_model="IaaS",
        ),
    ]
    systems = [s for s in systems_defs if s.name not in existing_names]
    for system in systems:
        session.add(system)
    session.commit()
    return len(systems)


def seed_personnel(session):
    """Sync personnel records from pipeline findings (HR, IdP, training)."""
    from warlock.workflows.personnel import PersonnelManager

    manager = PersonnelManager()
    hr = manager.sync_from_hr(session)
    idp = manager.sync_from_idp(session)
    training = manager.sync_from_training(session)
    return {"hr": hr, "idp": idp, "training": training, "total": session.query(Personnel).count()}


def seed_questionnaires(session):
    """Create questionnaire templates and vendor questionnaire instances."""
    from warlock.workflows.questionnaires import QuestionnaireManager

    manager = QuestionnaireManager()
    templates = manager.seed_default_templates(session)
    sig_template = next((t for t in templates if "sig" in t.name.lower()), None)
    ddq_template = next(
        (t for t in templates if "ddq" in t.name.lower() or "due diligence" in t.name.lower()), None
    )
    created = []
    if sig_template:
        q = manager.create_questionnaire(
            session,
            template_id=sig_template.id,
            vendor_name="Stripe",
            vendor_email="security@stripe.com",
            due_days=30,
            created_by="eve.nakamura@acme.com",
        )
        responses = {}
        for question in sig_template.questions[:18]:
            qid = question["id"]
            if question.get("response_type") == "yes_no":
                responses[qid] = {"answer": "yes", "notes": "Verified via SOC 2 Type II report"}
            elif question.get("response_type") == "rating":
                responses[qid] = {"answer": "4", "notes": "Strong controls in place"}
            else:
                responses[qid] = {"answer": "Implemented and documented", "notes": ""}
        manager.submit_bulk_responses(session, q.id, responses)
        manager.score_responses(session, q.id)
        created.append("Stripe (SIG Lite, completed)")
    if ddq_template:
        q = manager.create_questionnaire(
            session,
            template_id=ddq_template.id,
            vendor_name="CloudBackup Pro",
            vendor_email="compliance@cloudbackuppro.example.com",
            due_days=30,
            created_by="eve.nakamura@acme.com",
        )
        responses = {}
        for question in ddq_template.questions[:4]:
            qid = question["id"]
            if question.get("response_type") == "yes_no":
                responses[qid] = {"answer": "no", "notes": "In progress"}
            else:
                responses[qid] = {"answer": "Under review", "notes": ""}
        manager.submit_bulk_responses(session, q.id, responses)
        created.append("CloudBackup Pro (DDQ, in_progress)")
    return {"templates": len(templates), "questionnaires": created}


def seed_data_silos(session):
    """Discover data silos from findings and add direct silo records."""
    from warlock.workflows.data_silos import DataSiloManager

    manager = DataSiloManager()
    result = manager.discover_from_findings(session)
    # GAP-11: Data silos with varied encryption, logging, classification, PII/PHI/PCI
    direct_silos = [
        DataSilo(
            name="acme-prod-data",
            silo_type="s3_bucket",
            provider="aws",
            location="arn:aws:s3:::acme-prod-data",
            data_classification="confidential",
            contains_pii=True,
            contains_phi=False,
            contains_pci=False,
            encrypted_at_rest=True,  # AES-256 (SSE-KMS)
            encrypted_in_transit=True,
            access_logging_enabled=True,
            backup_enabled=True,
            retention_days=365,
            owner="Frank Torres",
            team="Engineering",
            applicable_frameworks=["soc2", "iso_27001"],
            scan_findings=[
                {"field_name": "users.email", "data_type": "pii_email", "confidence": 0.99},
            ],
            sensitive_field_count=3,
            scan_status="completed",
            last_scan_date=NOW - timedelta(days=3),
        ),
        DataSilo(
            name="acme-public-assets",
            silo_type="s3_bucket",
            provider="aws",
            location="arn:aws:s3:::acme-public-assets",
            data_classification="public",
            contains_pii=False,
            contains_phi=False,
            contains_pci=False,
            encrypted_at_rest=False,  # No encryption — public assets
            encrypted_in_transit=True,
            access_logging_enabled=False,
            backup_enabled=False,
            owner="Bob Martinez",
            team="DevOps",
            applicable_frameworks=[],
            scan_status="completed",
            last_scan_date=NOW - timedelta(days=14),
        ),
        DataSilo(
            name="acme-logs",
            silo_type="s3_bucket",
            provider="aws",
            location="arn:aws:s3:::acme-logs",
            data_classification="internal",
            contains_pii=False,
            contains_phi=False,
            contains_pci=False,
            encrypted_at_rest=True,  # SSE-S3 (default encryption)
            encrypted_in_transit=True,
            access_logging_enabled=True,
            backup_enabled=True,
            retention_days=1095,
            owner="Bob Martinez",
            team="DevOps",
            applicable_frameworks=["nist_800_53"],
            scan_status="completed",
            last_scan_date=NOW - timedelta(days=7),
        ),
        DataSilo(
            name="prod-customers",
            silo_type="rds_database",
            provider="aws",
            location="arn:aws:rds:us-east-1:912345678012:db/prod-customers",
            data_classification="restricted",
            contains_pii=True,
            contains_pci=True,
            contains_phi=False,
            encrypted_at_rest=True,  # AES-256 (RDS encryption)
            encrypted_in_transit=True,
            access_logging_enabled=True,
            backup_enabled=True,
            retention_days=30,
            owner="Frank Torres",
            team="Engineering",
            applicable_frameworks=["pci_dss", "soc2", "iso_27001"],
            scan_findings=[
                {"field_name": "customers.ssn", "data_type": "pii_ssn", "confidence": 0.97},
                {"field_name": "customers.card_last4", "data_type": "pci", "confidence": 0.95},
            ],
            sensitive_field_count=8,
            scan_status="completed",
            last_scan_date=NOW - timedelta(days=1),
        ),
        DataSilo(
            name="analytics-warehouse",
            silo_type="redshift",
            provider="aws",
            location="arn:aws:redshift:us-east-1:912345678012:namespace/analytics-warehouse",
            data_classification="confidential",
            contains_pii=True,
            contains_phi=True,
            contains_pci=False,
            encrypted_at_rest=True,  # AES-256 (Redshift encryption)
            encrypted_in_transit=True,
            access_logging_enabled=False,  # Gap: logging not enabled
            backup_enabled=False,  # Gap: no backups
            owner="Carol Park",
            team="Finance",
            applicable_frameworks=["hipaa", "soc2"],
            scan_findings=[
                {"field_name": "claims.diagnosis_code", "data_type": "phi", "confidence": 0.93},
                {"field_name": "claims.patient_name", "data_type": "phi", "confidence": 0.98},
            ],
            sensitive_field_count=12,
            scan_status="completed",
            last_scan_date=NOW - timedelta(days=5),
        ),
        DataSilo(
            name="eng-wiki",
            silo_type="sharepoint_site",
            provider="sharepoint",
            location="https://acme.sharepoint.com/sites/engineering",
            data_classification="internal",
            contains_pii=False,
            contains_phi=False,
            contains_pci=False,
            encrypted_at_rest=False,  # No server-side encryption
            encrypted_in_transit=True,
            access_logging_enabled=True,
            backup_enabled=True,
            owner="Frank Torres",
            team="Engineering",
            applicable_frameworks=["iso_27001"],
            scan_status="not_scanned",
        ),
        DataSilo(
            name="acme-app",
            silo_type="github_repo",
            provider="github",
            location="https://github.com/acme-corp/acme-app",
            data_classification="confidential",
            contains_credentials=True,
            contains_pii=False,
            contains_phi=False,
            contains_pci=False,
            encrypted_at_rest=True,
            encrypted_in_transit=True,
            access_logging_enabled=True,
            backup_enabled=True,
            owner="Frank Torres",
            team="Engineering",
            applicable_frameworks=["soc2", "iso_27001"],
            scan_findings=[
                {"field_name": ".env.production", "data_type": "credential", "confidence": 0.95},
                {"field_name": "config/secrets.yml", "data_type": "credential", "confidence": 0.88},
            ],
            sensitive_field_count=2,
            scan_status="completed",
            last_scan_date=NOW - timedelta(days=7),
        ),
        DataSilo(
            name="hr-records-lake",
            silo_type="s3_bucket",
            provider="aws",
            location="arn:aws:s3:::acme-hr-records",
            data_classification="restricted",
            contains_pii=True,
            contains_phi=True,
            contains_pci=False,
            encrypted_at_rest=True,  # AES-256 (SSE-KMS with CMK)
            encrypted_in_transit=True,
            access_logging_enabled=True,
            backup_enabled=True,
            retention_days=2555,
            owner="Carol Park",
            team="HR",
            applicable_frameworks=["hipaa", "gdpr", "soc2"],
            scan_findings=[
                {"field_name": "employees.ssn", "data_type": "pii_ssn", "confidence": 0.99},
                {"field_name": "benefits.medical_plan", "data_type": "phi", "confidence": 0.91},
            ],
            sensitive_field_count=15,
            scan_status="completed",
            last_scan_date=NOW - timedelta(days=2),
        ),
        DataSilo(
            name="dev-staging-db",
            silo_type="rds_database",
            provider="aws",
            location="arn:aws:rds:us-west-2:912345678012:db/dev-staging",
            data_classification="internal",
            contains_pii=True,
            contains_phi=False,
            contains_pci=False,
            encrypted_at_rest=False,  # Gap: dev DB not encrypted
            encrypted_in_transit=False,  # Gap: no TLS on dev
            access_logging_enabled=False,
            backup_enabled=False,
            owner="Frank Torres",
            team="Engineering",
            applicable_frameworks=["soc2"],
            remediation_status="in_progress",
            remediation_notes="PII found in staging DB copied from prod. Masking in progress.",
            scan_findings=[
                {"field_name": "users.email", "data_type": "pii_email", "confidence": 0.96},
            ],
            sensitive_field_count=4,
            scan_status="completed",
            last_scan_date=NOW - timedelta(days=1),
        ),
    ]
    existing_names = {row[0] for row in session.query(DataSilo.name).all()}
    added = 0
    for silo in direct_silos:
        if silo.name not in existing_names:
            session.add(silo)
            added += 1
    session.flush()

    # Enrich auto-discovered silos that have placeholder values (GAP-11)
    classifications = ["confidential", "internal", "public", "restricted"]
    classification_weights = [0.3, 0.4, 0.1, 0.2]
    unknown_silos = (
        session.query(DataSilo)
        .filter(
            (DataSilo.data_classification == "unknown") | (DataSilo.encrypted_at_rest.is_(None))
        )
        .all()
    )
    for silo in unknown_silos:
        if silo.data_classification == "unknown":
            silo.data_classification = random.choices(
                classifications, weights=classification_weights, k=1
            )[0]
        if silo.encrypted_at_rest is None:
            silo.encrypted_at_rest = random.random() < 0.80
        if silo.encrypted_in_transit is None:
            silo.encrypted_in_transit = random.random() < 0.85
        if silo.access_logging_enabled is None:
            silo.access_logging_enabled = random.random() < 0.70
        if silo.contains_pii is None or not silo.contains_pii:
            silo.contains_pii = random.random() < 0.30
        if silo.contains_phi is None or not silo.contains_phi:
            silo.contains_phi = random.random() < 0.10
        if silo.contains_pci is None or not silo.contains_pci:
            silo.contains_pci = random.random() < 0.15

    session.commit()
    enriched = len(unknown_silos)
    return {"discovered": result.get("created", 0), "direct": added, "enriched": enriched}


def seed_legal_holds(session):
    """Create legal hold records."""
    holds = [
        LegalHold(
            reason="FTC investigation — preserve all authentication and access logs",
            start_date=NOW - timedelta(days=60),
            end_date=None,
            created_by="grace.kim@acme.com",
            is_active=True,
        ),
        LegalHold(
            reason="Q3 2025 SOC 2 audit evidence preservation",
            start_date=NOW - timedelta(days=120),
            end_date=NOW - timedelta(days=30),
            created_by="eve.nakamura@acme.com",
            is_active=False,
        ),
    ]
    for hold in holds:
        session.add(hold)
    session.commit()
    return len(holds)


def seed_issues(session):
    """Auto-create issues from non-compliant results + add manual issues."""
    from warlock.workflows.issues import IssueManager

    manager = IssueManager()
    auto = manager.auto_create_from_results(session)
    manual_issues = [
        Issue(
            title="Vendor risk acceptance needed: CloudBackup Pro",
            description="CloudBackup Pro scored 45/100 on SecurityScorecard. Evaluate alternatives or accept risk with compensating controls.",
            framework="soc2",
            control_id="CC9.1",
            status="open",
            priority="high",
            assigned_to="eve.nakamura@acme.com",
            due_date=NOW + timedelta(days=14),
            source="manual",
            tags=["vendor-risk", "third-party"],
            created_by="hassan.ali@acme.com",
        ),
        Issue(
            title="Overdue access review for Product department",
            description="Product department has not completed quarterly access review. Last review was 120+ days ago.",
            framework="iso_27001",
            control_id="A.5.18",
            status="assigned",
            priority="medium",
            assigned_to="hassan.ali@acme.com",
            assigned_by="eve.nakamura@acme.com",
            assigned_at=NOW - timedelta(days=7),
            due_date=NOW + timedelta(days=7),
            source="manual",
            tags=["access-review", "overdue"],
            created_by="eve.nakamura@acme.com",
        ),
        Issue(
            title="Policy gap: No Audit Logging Policy documented",
            description="Policy coverage check shows AU-family controls have no mapped policy document. Need to draft and publish.",
            framework="nist_800_53",
            control_id="AU-1",
            status="in_progress",
            priority="medium",
            assigned_to="grace.kim@acme.com",
            assigned_by="eve.nakamura@acme.com",
            assigned_at=NOW - timedelta(days=14),
            due_date=NOW + timedelta(days=21),
            remediation_plan="Draft AU policy in Confluence, route through legal review, publish to SEC space.",
            source="manual",
            tags=["policy-gap", "documentation"],
            created_by="eve.nakamura@acme.com",
        ),
    ]
    for issue in manual_issues:
        session.add(issue)
    session.commit()
    return {"auto_created": len(auto), "manual": len(manual_issues)}


# ---------------------------------------------------------------------------
# Phase 2-5 seed functions
# ---------------------------------------------------------------------------


def _sha(data: str) -> str:
    """Helper to produce SHA256 hex digest for demo records."""
    return hashlib.sha256(data.encode()).hexdigest()


def seed_phase2_poams(session) -> int:
    """Create 18 POA&Ms across frameworks with realistic lifecycle states."""
    # Get a system profile for linking
    prod = session.query(SystemProfile).filter(SystemProfile.acronym == "APP").first()
    cdw = session.query(SystemProfile).filter(SystemProfile.acronym == "CDW").first()
    cit = session.query(SystemProfile).filter(SystemProfile.acronym == "CIT").first()

    poams = [
        # --- 5 draft (auto-created from pipeline) ---
        POAM(
            framework="nist_800_53",
            control_id="AC-2",
            weakness_description="Root account has active access keys enabling unauthenticated programmatic access",
            severity="critical",
            risk_level="very_high",
            status="draft",
            system_profile_id=prod.id if prod else None,
            created_by="pipeline",
        ),
        POAM(
            framework="nist_800_53",
            control_id="IA-2",
            weakness_description="MFA not enforced for privileged users across all console and API access",
            severity="high",
            risk_level="high",
            status="draft",
            system_profile_id=prod.id if prod else None,
            created_by="pipeline",
        ),
        POAM(
            framework="nist_800_53",
            control_id="AU-6",
            weakness_description="CloudTrail is single-region only; events in us-west-2, eu-west-1 are not captured",
            severity="high",
            risk_level="high",
            status="draft",
            system_profile_id=prod.id if prod else None,
            created_by="pipeline",
        ),
        POAM(
            framework="soc2",
            control_id="CC6.1",
            weakness_description="Okta password policy allows 8-char minimum with no symbol requirement",
            severity="medium",
            risk_level="moderate",
            status="draft",
            system_profile_id=cit.id if cit else None,
            created_by="pipeline",
        ),
        POAM(
            framework="iso_27001",
            control_id="A.8.9",
            weakness_description="Security group sg-0a1b2c3d4e5f allows SSH (port 22) from 0.0.0.0/0",
            severity="high",
            risk_level="high",
            status="draft",
            system_profile_id=prod.id if prod else None,
            created_by="pipeline",
        ),
        # --- 4 open with milestones ---
        POAM(
            framework="nist_800_53",
            control_id="SI-4",
            weakness_description="GuardDuty findings not forwarded to centralized SIEM for correlation",
            severity="medium",
            risk_level="moderate",
            status="open",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW + timedelta(days=45),
            milestones=[
                {
                    "description": "Evaluate SIEM integration options",
                    "due_date": (NOW + timedelta(days=15)).isoformat(),
                    "status": "not_started",
                },
                {
                    "description": "Deploy GuardDuty-to-SIEM forwarder",
                    "due_date": (NOW + timedelta(days=30)).isoformat(),
                    "status": "not_started",
                },
                {
                    "description": "Validate alert correlation rules",
                    "due_date": (NOW + timedelta(days=45)).isoformat(),
                    "status": "not_started",
                },
            ],
            created_by="eve.nakamura@acme.com",
        ),
        POAM(
            framework="nist_800_53",
            control_id="CM-6",
            weakness_description="AWS Config recorder not deployed in us-west-2 region; configuration drift undetected",
            severity="medium",
            risk_level="moderate",
            status="open",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW + timedelta(days=30),
            milestones=[
                {
                    "description": "Enable Config recorder in us-west-2",
                    "due_date": (NOW + timedelta(days=10)).isoformat(),
                    "status": "not_started",
                },
                {
                    "description": "Deploy conformance pack",
                    "due_date": (NOW + timedelta(days=25)).isoformat(),
                    "status": "not_started",
                },
            ],
            created_by="bob.martinez@acme.com",
        ),
        POAM(
            framework="nist_800_53",
            control_id="SC-7",
            weakness_description="Legacy Windows security group allows RDP (3389) from any source IP",
            severity="high",
            risk_level="high",
            status="open",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW + timedelta(days=21),
            milestones=[
                {
                    "description": "Identify active RDP sessions",
                    "due_date": (NOW + timedelta(days=7)).isoformat(),
                    "status": "not_started",
                },
                {
                    "description": "Restrict RDP to VPN CIDR",
                    "due_date": (NOW + timedelta(days=14)).isoformat(),
                    "status": "not_started",
                },
                {
                    "description": "Decommission legacy-windows SG",
                    "due_date": (NOW + timedelta(days=21)).isoformat(),
                    "status": "not_started",
                },
            ],
            created_by="eve.nakamura@acme.com",
        ),
        POAM(
            framework="soc2",
            control_id="CC7.2",
            weakness_description="CrowdStrike prevention policy not applied on 1 contained endpoint (ws-marketing-03)",
            severity="medium",
            risk_level="moderate",
            status="open",
            system_profile_id=cit.id if cit else None,
            scheduled_completion=NOW + timedelta(days=14),
            milestones=[
                {
                    "description": "Investigate containment reason",
                    "due_date": (NOW + timedelta(days=5)).isoformat(),
                    "status": "not_started",
                },
                {
                    "description": "Re-enable prevention policy or decommission",
                    "due_date": (NOW + timedelta(days=14)).isoformat(),
                    "status": "not_started",
                },
            ],
            created_by="eve.nakamura@acme.com",
        ),
        # --- 3 in_progress with partial milestone completion ---
        POAM(
            framework="nist_800_53",
            control_id="IA-5",
            weakness_description="Password policy minimum length is 8 characters; NIST 800-63B recommends 12+",
            severity="medium",
            risk_level="moderate",
            status="in_progress",
            system_profile_id=cit.id if cit else None,
            scheduled_completion=NOW + timedelta(days=14),
            milestones=[
                {
                    "description": "Draft updated password policy",
                    "due_date": (NOW - timedelta(days=14)).isoformat(),
                    "completed_date": (NOW - timedelta(days=12)).isoformat(),
                    "status": "completed",
                },
                {
                    "description": "Get CISO approval",
                    "due_date": (NOW - timedelta(days=7)).isoformat(),
                    "completed_date": (NOW - timedelta(days=5)).isoformat(),
                    "status": "completed",
                },
                {
                    "description": "Deploy to Okta and AWS IAM",
                    "due_date": (NOW + timedelta(days=7)).isoformat(),
                    "status": "in_progress",
                },
                {
                    "description": "Validate enforcement",
                    "due_date": (NOW + timedelta(days=14)).isoformat(),
                    "status": "not_started",
                },
            ],
            created_by="bob.martinez@acme.com",
            updated_by="bob.martinez@acme.com",
        ),
        POAM(
            framework="nist_800_53",
            control_id="RA-5",
            weakness_description="Critical CVE-2024-3094 (xz-utils) on srv-web-01 not remediated within 48-hour SLA",
            severity="critical",
            risk_level="very_high",
            status="in_progress",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW + timedelta(days=3),
            milestones=[
                {
                    "description": "Identify affected hosts",
                    "due_date": (NOW - timedelta(days=5)).isoformat(),
                    "completed_date": (NOW - timedelta(days=5)).isoformat(),
                    "status": "completed",
                },
                {
                    "description": "Test patch in staging",
                    "due_date": (NOW - timedelta(days=2)).isoformat(),
                    "completed_date": (NOW - timedelta(days=1)).isoformat(),
                    "status": "completed",
                },
                {
                    "description": "Deploy patch to production",
                    "due_date": (NOW + timedelta(days=1)).isoformat(),
                    "status": "in_progress",
                },
                {
                    "description": "Verify and close vulnerability",
                    "due_date": (NOW + timedelta(days=3)).isoformat(),
                    "status": "not_started",
                },
            ],
            created_by="eve.nakamura@acme.com",
            updated_by="frank.torres@acme.com",
        ),
        POAM(
            framework="iso_27001",
            control_id="A.5.15",
            weakness_description="Stale Okta accounts (120+ days inactive) not disabled per access lifecycle policy",
            severity="medium",
            risk_level="moderate",
            status="in_progress",
            system_profile_id=cit.id if cit else None,
            scheduled_completion=NOW + timedelta(days=10),
            milestones=[
                {
                    "description": "Run access review report",
                    "due_date": (NOW - timedelta(days=7)).isoformat(),
                    "completed_date": (NOW - timedelta(days=6)).isoformat(),
                    "status": "completed",
                },
                {
                    "description": "Notify managers of stale accounts",
                    "due_date": (NOW - timedelta(days=3)).isoformat(),
                    "status": "in_progress",
                },
                {
                    "description": "Disable confirmed stale accounts",
                    "due_date": (NOW + timedelta(days=10)).isoformat(),
                    "status": "not_started",
                },
            ],
            created_by="bob.martinez@acme.com",
        ),
        # --- 2 completed ---
        POAM(
            framework="nist_800_53",
            control_id="SC-28",
            weakness_description="S3 bucket acme-public-assets did not have server-side encryption enabled",
            severity="medium",
            risk_level="moderate",
            status="completed",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW - timedelta(days=30),
            actual_completion=NOW - timedelta(days=35),
            milestones=[
                {
                    "description": "Enable SSE-S3 default encryption",
                    "due_date": (NOW - timedelta(days=40)).isoformat(),
                    "completed_date": (NOW - timedelta(days=38)).isoformat(),
                    "status": "completed",
                },
                {
                    "description": "Verify existing objects encrypted",
                    "due_date": (NOW - timedelta(days=30)).isoformat(),
                    "completed_date": (NOW - timedelta(days=35)).isoformat(),
                    "status": "completed",
                },
            ],
            created_by="bob.martinez@acme.com",
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=35),
        ),
        POAM(
            framework="soc2",
            control_id="CC6.6",
            weakness_description="Redshift cluster analytics-warehouse had automated snapshots disabled",
            severity="high",
            risk_level="high",
            status="completed",
            system_profile_id=cdw.id if cdw else None,
            scheduled_completion=NOW - timedelta(days=14),
            actual_completion=NOW - timedelta(days=18),
            milestones=[
                {
                    "description": "Enable automated snapshots with 7-day retention",
                    "due_date": (NOW - timedelta(days=20)).isoformat(),
                    "completed_date": (NOW - timedelta(days=19)).isoformat(),
                    "status": "completed",
                },
                {
                    "description": "Validate backup restore procedure",
                    "due_date": (NOW - timedelta(days=14)).isoformat(),
                    "completed_date": (NOW - timedelta(days=18)).isoformat(),
                    "status": "completed",
                },
            ],
            created_by="carol.park@acme.com",
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=18),
        ),
        # --- 2 overdue (scheduled_completion in past, still open) ---
        POAM(
            framework="nist_800_53",
            control_id="AC-6",
            weakness_description="Bob Martinez granted Super Admin role in Okta without documented approval workflow",
            severity="high",
            risk_level="high",
            status="open",
            system_profile_id=cit.id if cit else None,
            scheduled_completion=NOW - timedelta(days=10),
            milestones=[
                {
                    "description": "Review privilege grant audit trail",
                    "due_date": (NOW - timedelta(days=20)).isoformat(),
                    "status": "not_started",
                },
                {
                    "description": "Implement approval workflow in Okta",
                    "due_date": (NOW - timedelta(days=10)).isoformat(),
                    "status": "not_started",
                },
            ],
            created_by="eve.nakamura@acme.com",
        ),
        POAM(
            framework="iso_27001",
            control_id="A.7.2",
            weakness_description="3 employees have overdue security awareness training (30-60 days past due date)",
            severity="medium",
            risk_level="moderate",
            status="open",
            system_profile_id=cit.id if cit else None,
            scheduled_completion=NOW - timedelta(days=7),
            milestones=[
                {
                    "description": "Send escalation notices to managers",
                    "due_date": (NOW - timedelta(days=14)).isoformat(),
                    "status": "not_started",
                },
                {
                    "description": "Enforce training completion or account suspension",
                    "due_date": (NOW - timedelta(days=7)).isoformat(),
                    "status": "not_started",
                },
            ],
            created_by="eve.nakamura@acme.com",
        ),
        # --- 2 with delay_count > 0 ---
        POAM(
            framework="nist_800_53",
            control_id="AU-2",
            weakness_description="CloudTrail log file validation enabled but no S3 bucket integrity monitoring",
            severity="medium",
            risk_level="moderate",
            status="in_progress",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW + timedelta(days=30),
            delay_count=2,
            delay_justifications=[
                {
                    "date": (NOW - timedelta(days=60)).isoformat(),
                    "justification": "Engineering resource re-allocated to critical CVE remediation",
                    "approved_by": "hassan.ali@acme.com",
                },
                {
                    "date": (NOW - timedelta(days=20)).isoformat(),
                    "justification": "Vendor tooling integration delayed; new ETA from vendor confirmed",
                    "approved_by": "hassan.ali@acme.com",
                },
            ],
            milestones=[
                {
                    "description": "Select S3 integrity monitoring tool",
                    "due_date": (NOW - timedelta(days=45)).isoformat(),
                    "completed_date": (NOW - timedelta(days=40)).isoformat(),
                    "status": "completed",
                },
                {
                    "description": "Deploy monitoring to prod trail bucket",
                    "due_date": (NOW + timedelta(days=15)).isoformat(),
                    "status": "in_progress",
                },
                {
                    "description": "Validate alerting pipeline",
                    "due_date": (NOW + timedelta(days=30)).isoformat(),
                    "status": "not_started",
                },
            ],
            created_by="bob.martinez@acme.com",
            updated_by="hassan.ali@acme.com",
        ),
        POAM(
            framework="soc2",
            control_id="CC8.1",
            weakness_description="Change management approval records missing for 3 production deployments in last quarter",
            severity="high",
            risk_level="high",
            status="open",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW + timedelta(days=7),
            delay_count=1,
            delay_justifications=[
                {
                    "date": (NOW - timedelta(days=15)).isoformat(),
                    "justification": "ServiceNow integration delayed due to API rate limiting; workaround identified",
                    "approved_by": "hassan.ali@acme.com",
                },
            ],
            milestones=[
                {
                    "description": "Enforce PR approval requirement in GitHub",
                    "due_date": (NOW - timedelta(days=5)).isoformat(),
                    "status": "not_started",
                },
                {
                    "description": "Link ServiceNow change requests to deployments",
                    "due_date": (NOW + timedelta(days=7)).isoformat(),
                    "status": "not_started",
                },
            ],
            created_by="frank.torres@acme.com",
        ),
    ]

    for p in poams:
        session.add(p)
    session.commit()
    return len(poams)


def link_issues_and_poams(session) -> dict:
    """Cross-link Issues to POA&Ms and POA&Ms to ControlResults by framework + control_id.

    After both Issues and POA&Ms are seeded, this step:
    1. For each POA&M that has no control_result_id, finds a matching ControlResult
       (same framework + control_id) and links it.
    2. For each Issue that has no poam_id but shares a framework + control_id with
       a POA&M, links the issue to that POA&M.

    Returns a dict with counts of links created.
    """
    # --- Link POA&Ms to ControlResults ---
    poams = session.query(POAM).filter(POAM.control_result_id.is_(None)).all()
    poam_linked = 0
    # Build a lookup: (framework, control_id) -> first matching ControlResult id
    # Query all distinct (framework, control_id) pairs from POA&Ms to batch the lookup
    poam_keys = {(p.framework, p.control_id) for p in poams}
    cr_lookup: dict[tuple[str, str], str] = {}
    for fw, cid in poam_keys:
        cr = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == fw,
                ControlResult.control_id == cid,
            )
            .first()
        )
        if cr:
            cr_lookup[(fw, cid)] = cr.id

    for p in poams:
        cr_id = cr_lookup.get((p.framework, p.control_id))
        if cr_id:
            p.control_result_id = cr_id
            poam_linked += 1

    # --- Link Issues to POA&Ms ---
    # Build lookup: (framework, control_id) -> POA&M id (prefer non-completed POA&Ms)
    all_poams = session.query(POAM).all()
    poam_lookup: dict[tuple[str, str], str] = {}
    for p in all_poams:
        key = (p.framework, p.control_id)
        # Prefer open/in_progress POA&Ms over completed ones
        if key not in poam_lookup or p.status in ("open", "in_progress", "draft"):
            poam_lookup[key] = p.id

    issues = session.query(Issue).filter(Issue.poam_id.is_(None)).all()
    issue_linked = 0
    for issue in issues:
        if issue.framework and issue.control_id:
            poam_id = poam_lookup.get((issue.framework, issue.control_id))
            if poam_id:
                issue.poam_id = poam_id
                issue_linked += 1

    session.commit()
    return {"poams_to_results": poam_linked, "issues_to_poams": issue_linked}


def seed_phase2_compensating_controls(session) -> int:
    """Create 10 compensating controls with realistic lifecycle states."""
    prod = session.query(SystemProfile).filter(SystemProfile.acronym == "APP").first()
    cit = session.query(SystemProfile).filter(SystemProfile.acronym == "CIT").first()

    # Grab some POA&M IDs to link
    poam_ac2 = session.query(POAM).filter(POAM.control_id == "AC-2").first()
    poam_ia2 = session.query(POAM).filter(POAM.control_id == "IA-2").first()
    poam_sc7 = session.query(POAM).filter(POAM.control_id == "SC-7").first()
    poam_ac6 = session.query(POAM).filter(POAM.control_id == "AC-6").first()

    controls = [
        # --- 3 active with effectiveness_score ---
        CompensatingControl(
            original_framework="nist_800_53",
            original_control_id="AC-2",
            poam_id=poam_ac2.id if poam_ac2 else None,
            system_profile_id=prod.id if prod else None,
            title="Weekly privileged access review by team leads",
            description="All team leads conduct a weekly manual review of privileged accounts in their scope. Findings reported to ISSO via Jira ticket.",
            implementation_details="Team leads receive automated Monday 8am email with current privileged user list. They confirm or flag revocations within 48 hours via Jira SEC project.",
            evidence_references=[
                {
                    "type": "process",
                    "description": "Jira SEC project tickets",
                    "url": "https://acme.atlassian.net/projects/SEC",
                }
            ],
            status="active",
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=60),
            expiry_date=NOW + timedelta(days=120),
            review_frequency="monthly",
            last_reviewed=NOW - timedelta(days=15),
            effectiveness_score=78.0,
            created_by="eve.nakamura@acme.com",
        ),
        CompensatingControl(
            original_framework="nist_800_53",
            original_control_id="IA-2",
            poam_id=poam_ia2.id if poam_ia2 else None,
            system_profile_id=prod.id if prod else None,
            title="Hardware security key requirement for privileged accounts",
            description="All AWS IAM users with admin or power-user policies must use YubiKey 5 for MFA. Software MFA tokens disabled for privileged roles.",
            implementation_details="AWS IAM policy condition requires hardware MFA (aws:MultiFactorAuthPresent with FIDO2). Okta enrollment forced for hardware key factor.",
            evidence_references=[
                {
                    "type": "configuration",
                    "description": "IAM policy document",
                    "url": "s3://acme-policies/iam-mfa-policy.json",
                }
            ],
            status="active",
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=45),
            expiry_date=NOW + timedelta(days=180),
            review_frequency="quarterly",
            last_reviewed=NOW - timedelta(days=10),
            effectiveness_score=92.0,
            created_by="eve.nakamura@acme.com",
        ),
        CompensatingControl(
            original_framework="nist_800_53",
            original_control_id="SC-7",
            poam_id=poam_sc7.id if poam_sc7 else None,
            system_profile_id=prod.id if prod else None,
            title="Network segmentation via micro-segmentation with AWS PrivateLink",
            description="Until legacy SG is decommissioned, micro-segmentation isolates legacy-windows instances. PrivateLink enforces private connectivity for all API traffic.",
            implementation_details="VPC endpoint policies restrict legacy-windows subnet to approved internal CIDRs only. PrivateLink endpoints configured for S3, STS, and SSM.",
            evidence_references=[
                {"type": "configuration", "description": "VPC endpoint policies", "url": ""}
            ],
            status="active",
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=30),
            expiry_date=NOW + timedelta(days=60),
            review_frequency="monthly",
            last_reviewed=NOW - timedelta(days=5),
            effectiveness_score=65.0,
            created_by="bob.martinez@acme.com",
        ),
        # --- 2 proposed ---
        CompensatingControl(
            original_framework="nist_800_53",
            original_control_id="CM-6",
            system_profile_id=prod.id if prod else None,
            title="Quarterly manual vulnerability scan of non-Config regions",
            description="Until AWS Config is deployed to all regions, conduct quarterly Nessus scans of infrastructure in us-west-2 and eu-west-1.",
            implementation_details="Nessus Professional scans scheduled quarterly. Results triaged by SecOps and fed into Jira SEC.",
            status="proposed",
            created_by="eve.nakamura@acme.com",
        ),
        CompensatingControl(
            original_framework="soc2",
            original_control_id="CC8.1",
            system_profile_id=prod.id if prod else None,
            title="Manual deployment approval via Slack sign-off",
            description="Until ServiceNow integration is complete, all production deployments require explicit Slack approval from engineering lead in #deployments channel.",
            implementation_details="GitHub Actions deployment workflow blocked until Slack bot confirms approval reaction from authorized deployers.",
            status="proposed",
            created_by="frank.torres@acme.com",
        ),
        # --- 2 approved ---
        CompensatingControl(
            original_framework="nist_800_53",
            original_control_id="AC-6",
            poam_id=poam_ac6.id if poam_ac6 else None,
            system_profile_id=cit.id if cit else None,
            title="Just-in-time privileged access via Okta workflows",
            description="Privileged Okta roles granted for 4-hour windows only, with automatic revocation. Permanent admin assignments eliminated.",
            implementation_details="Okta Workflows configured with time-boxed group membership. Slack approval from ISSO required before elevation.",
            status="approved",
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=3),
            expiry_date=NOW + timedelta(days=90),
            review_frequency="monthly",
            created_by="bob.martinez@acme.com",
        ),
        CompensatingControl(
            original_framework="iso_27001",
            original_control_id="A.7.2",
            system_profile_id=cit.id if cit else None,
            title="Manager-led monthly security briefing for overdue training personnel",
            description="For employees with overdue security awareness training, their direct managers deliver a 15-minute monthly security briefing covering current threat landscape.",
            implementation_details="Calendar invites auto-generated from KnowBe4 overdue report. Attendance tracked in Workday.",
            status="approved",
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=5),
            expiry_date=NOW + timedelta(days=60),
            review_frequency="monthly",
            created_by="eve.nakamura@acme.com",
        ),
        # --- 1 expired ---
        CompensatingControl(
            original_framework="nist_800_53",
            original_control_id="AU-6",
            system_profile_id=prod.id if prod else None,
            title="Daily manual CloudTrail log review by SecOps analyst",
            description="SecOps analyst manually reviews CloudTrail events for suspicious activity daily at 9am ET. Superseded by automated SIEM integration.",
            implementation_details="Analyst queries CloudTrail via Athena using pre-built queries. Findings logged in Jira SEC.",
            status="expired",
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=120),
            expiry_date=NOW - timedelta(days=30),
            review_frequency="monthly",
            last_reviewed=NOW - timedelta(days=45),
            effectiveness_score=45.0,
            created_by="eve.nakamura@acme.com",
        ),
        # --- 2 more active for diversity ---
        CompensatingControl(
            original_framework="nist_800_53",
            original_control_id="RA-5",
            system_profile_id=prod.id if prod else None,
            title="Automated container image scanning in CI/CD pipeline",
            description="Trivy scans all container images on PR and blocks merge on critical/high CVEs. Compensates for delayed host-level patching SLA.",
            implementation_details="GitHub Actions workflow runs trivy image scan. Fail threshold: CRITICAL or HIGH with fix available.",
            evidence_references=[
                {
                    "type": "automation",
                    "description": "GitHub Actions workflow",
                    "url": "https://github.com/acme-corp/acme-app/actions/workflows/trivy.yml",
                }
            ],
            status="active",
            approved_by="frank.torres@acme.com",
            approved_at=NOW - timedelta(days=90),
            expiry_date=NOW + timedelta(days=90),
            review_frequency="quarterly",
            last_reviewed=NOW - timedelta(days=30),
            effectiveness_score=88.0,
            created_by="frank.torres@acme.com",
        ),
        CompensatingControl(
            original_framework="nist_800_53",
            original_control_id="SI-4",
            system_profile_id=prod.id if prod else None,
            title="Enhanced VPC flow log analysis with anomaly detection",
            description="Until GuardDuty-to-SIEM integration is complete, VPC flow logs are analyzed with CloudWatch Anomaly Detection for network-based threat indicators.",
            implementation_details="CloudWatch Anomaly Detection enabled on VPC flow log metric filters for rejected connections, unusual port access, and data exfiltration patterns.",
            status="active",
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=20),
            expiry_date=NOW + timedelta(days=60),
            review_frequency="monthly",
            last_reviewed=NOW - timedelta(days=8),
            effectiveness_score=72.0,
            created_by="bob.martinez@acme.com",
        ),
    ]

    for c in controls:
        session.add(c)
    session.commit()
    return len(controls)


def seed_phase2_risk_acceptances(session) -> int:
    """Create 7 risk acceptances with varied lifecycle states."""
    prod = session.query(SystemProfile).filter(SystemProfile.acronym == "APP").first()
    cit = session.query(SystemProfile).filter(SystemProfile.acronym == "CIT").first()
    dev = session.query(SystemProfile).filter(SystemProfile.acronym == "DEV").first()

    poam_ac2 = (
        session.query(POAM)
        .filter(POAM.control_id == "AC-2", POAM.framework == "nist_800_53")
        .first()
    )

    acceptances = [
        # --- 3 active with future expiry ---
        RiskAcceptance(
            framework="nist_800_53",
            control_id="AC-2",
            poam_id=poam_ac2.id if poam_ac2 else None,
            system_profile_id=prod.id if prod else None,
            risk_description="Root account access keys remain active pending organizational migration to AWS Organizations with SCP-enforced root lockout. Compensating control in place for weekly privileged access review.",
            risk_level="high",
            residual_risk_level="moderate",
            conditions=[
                {"condition": "Weekly privileged access reviews must continue", "met": True},
                {"condition": "Root account CloudTrail alerts must be active", "met": True},
                {
                    "condition": "Migration to AWS Organizations must begin within 90 days",
                    "met": False,
                },
            ],
            status="active",
            requested_by="eve.nakamura@acme.com",
            reviewed_by="frank.torres@acme.com",
            reviewed_at=NOW - timedelta(days=58),
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=55),
            expiry_date=NOW + timedelta(days=125),
            auto_reeval_triggers={"severity_change": True, "new_finding": True},
        ),
        RiskAcceptance(
            framework="soc2",
            control_id="CC6.1",
            system_profile_id=cit.id if cit else None,
            risk_description="Okta password policy minimum length remains at 8 characters pending organization-wide rollout of passkey authentication. Users with passkeys bypass password entirely.",
            risk_level="moderate",
            residual_risk_level="low",
            conditions=[
                {
                    "condition": "Passkey rollout must cover 50% of users within 60 days",
                    "met": True,
                },
                {"condition": "Phishing-resistant MFA must remain enforced", "met": True},
            ],
            status="active",
            requested_by="bob.martinez@acme.com",
            reviewed_by="eve.nakamura@acme.com",
            reviewed_at=NOW - timedelta(days=30),
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=28),
            expiry_date=NOW + timedelta(days=92),
            auto_reeval_triggers={"severity_change": True},
        ),
        RiskAcceptance(
            framework="nist_800_53",
            control_id="SC-7",
            system_profile_id=dev.id if dev else None,
            risk_description="Development environment allows broader network access (SSH from office CIDR) to support rapid iteration. No customer data in dev environment.",
            risk_level="low",
            residual_risk_level="low",
            conditions=[
                {"condition": "No customer or production data in dev environment", "met": True},
                {"condition": "Dev environment isolated from production VPC", "met": True},
            ],
            status="active",
            requested_by="frank.torres@acme.com",
            reviewed_by="eve.nakamura@acme.com",
            reviewed_at=NOW - timedelta(days=80),
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=78),
            expiry_date=NOW + timedelta(days=287),
        ),
        # --- 1 expired (status still active to test checker) ---
        RiskAcceptance(
            framework="nist_800_53",
            control_id="AU-6",
            system_profile_id=prod.id if prod else None,
            risk_description="Single-region CloudTrail accepted while multi-region deployment was planned. Risk acceptance has expired and must be renewed or control remediated.",
            risk_level="high",
            residual_risk_level="moderate",
            conditions=[
                {
                    "condition": "Daily manual log review compensating control must be active",
                    "met": False,
                },
            ],
            status="active",
            requested_by="bob.martinez@acme.com",
            reviewed_by="eve.nakamura@acme.com",
            reviewed_at=NOW - timedelta(days=100),
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=98),
            expiry_date=NOW - timedelta(days=8),
        ),
        # --- 1 requested pending approval ---
        RiskAcceptance(
            framework="iso_27001",
            control_id="A.7.2",
            system_profile_id=cit.id if cit else None,
            risk_description="3 employees (Alice Chen, Carol Park, Grace Kim) have overdue security awareness training. Requesting 30-day risk acceptance while escalated remediation proceeds.",
            risk_level="moderate",
            residual_risk_level="moderate",
            conditions=[
                {
                    "condition": "Manager-led security briefing compensating control must be approved",
                    "met": True,
                },
                {
                    "condition": "Affected employees must not have access to restricted data",
                    "met": True,
                },
            ],
            status="requested",
            requested_by="eve.nakamura@acme.com",
            expiry_date=NOW + timedelta(days=30),
        ),
        # --- 1 revoked ---
        RiskAcceptance(
            framework="nist_800_53",
            control_id="IA-5",
            system_profile_id=cit.id if cit else None,
            risk_description="8-character minimum password policy was accepted pending password manager rollout. Revoked after phishing incident demonstrated credential stuffing risk.",
            risk_level="moderate",
            residual_risk_level="high",
            status="revoked",
            requested_by="bob.martinez@acme.com",
            reviewed_by="eve.nakamura@acme.com",
            reviewed_at=NOW - timedelta(days=60),
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=58),
            expiry_date=NOW + timedelta(days=30),
        ),
        # --- 1 more active for coverage ---
        RiskAcceptance(
            framework="nist_800_53",
            control_id="CM-6",
            system_profile_id=prod.id if prod else None,
            risk_description="AWS Config not deployed in us-west-2. Minimal production workloads in that region (only DR standby). Quarterly manual scans compensate.",
            risk_level="moderate",
            residual_risk_level="low",
            conditions=[
                {"condition": "No primary workloads deployed to us-west-2", "met": True},
                {"condition": "Quarterly manual Nessus scans completed on time", "met": True},
            ],
            status="active",
            requested_by="bob.martinez@acme.com",
            reviewed_by="eve.nakamura@acme.com",
            reviewed_at=NOW - timedelta(days=25),
            approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=23),
            expiry_date=NOW + timedelta(days=67),
        ),
    ]

    for a in acceptances:
        session.add(a)
    session.commit()
    return len(acceptances)


def seed_phase3_inheritance(session) -> int:
    """Create 25 ControlInheritance records across system profiles."""
    profiles = {sp.acronym: sp for sp in session.query(SystemProfile).all()}
    prod = profiles.get("APP")
    cdw = profiles.get("CDW")
    cit = profiles.get("CIT")
    aiml = profiles.get("AIML")
    dev = profiles.get("DEV")

    if not all([prod, cdw, cit]):
        return 0

    records = []

    # PE-* (Physical and Environmental): inherited from AWS for all cloud systems
    pe_controls = ["PE-1", "PE-2", "PE-3", "PE-6", "PE-10", "PE-11", "PE-12", "PE-13", "PE-14"]
    cloud_systems = [s for s in [prod, cdw, aiml, dev] if s]
    for ctrl in pe_controls:
        for csys in cloud_systems:
            records.append(
                ControlInheritance(
                    system_profile_id=csys.id,
                    framework="nist_800_53",
                    control_id=ctrl,
                    inheritance_type="inherited",
                    provider_description="AWS is responsible for physical security of data center facilities per shared responsibility model.",
                    responsibility_description="Customer inherits physical controls from AWS. No customer action required.",
                    evidence_requirement="provider_only",
                    status="active",
                )
            )

    # AC-2, IA-2: shared between Corporate IT (provider) and Production/CDW/AIML (consumer)
    shared_identity_controls = ["AC-2", "IA-2"]
    identity_consumers = [s for s in [prod, cdw, aiml, dev] if s]
    for ctrl in shared_identity_controls:
        for csys in identity_consumers:
            records.append(
                ControlInheritance(
                    system_profile_id=csys.id,
                    framework="nist_800_53",
                    control_id=ctrl,
                    inheritance_type="shared",
                    provider_system_id=cit.id,
                    provider_description="Corporate IT manages Okta IdP, SSO federation, and MFA enforcement for all employees.",
                    responsibility_description="Consumer system must enforce Okta SSO integration and implement application-level RBAC.",
                    evidence_requirement="both",
                    status="active",
                )
            )

    # AT-* (Awareness and Training): common (org-wide)
    at_controls = ["AT-1", "AT-2", "AT-3", "AT-4"]
    all_systems = [s for s in [prod, cdw, cit, aiml, dev] if s]
    for ctrl in at_controls:
        for csys in all_systems:
            records.append(
                ControlInheritance(
                    system_profile_id=csys.id,
                    framework="nist_800_53",
                    control_id=ctrl,
                    inheritance_type="common",
                    provider_description="Organization-wide security awareness and training program managed by Security team.",
                    responsibility_description="All personnel must complete organization-wide training. No system-specific training required.",
                    evidence_requirement="provider_only",
                    status="active",
                )
            )

    # SC-*, CM-* some controls: system_specific for production
    system_specific_controls = ["SC-7", "SC-8", "SC-28", "CM-6", "CM-7", "CM-8"]
    if prod:
        for ctrl in system_specific_controls:
            records.append(
                ControlInheritance(
                    system_profile_id=prod.id,
                    framework="nist_800_53",
                    control_id=ctrl,
                    inheritance_type="system_specific",
                    responsibility_description="Production platform team is fully responsible for implementation and evidence.",
                    evidence_requirement="consumer_only",
                    status="active",
                )
            )

    for r in records:
        session.add(r)
    session.commit()
    return len(records)


def seed_phase3_dependencies(session) -> int:
    """Create 6 SystemDependency records modeling cross-system relationships."""
    profiles = {sp.acronym: sp for sp in session.query(SystemProfile).all()}
    prod = profiles.get("APP")
    cdw = profiles.get("CDW")
    cit = profiles.get("CIT")
    aiml = profiles.get("AIML")
    dev = profiles.get("DEV")

    if not all([prod, cdw, cit]):
        return 0

    deps = [
        SystemDependency(
            consumer_system_id=prod.id,
            provider_system_id=cit.id,
            shared_controls=[
                "nist_800_53:AC-2",
                "nist_800_53:IA-2",
                "nist_800_53:IA-5",
                "soc2:CC6.1",
            ],
            dependency_type="identity",
            description="Production platform relies on Corporate IT for identity federation via Okta SSO, MFA enforcement, and password policy.",
        ),
        SystemDependency(
            consumer_system_id=cdw.id,
            provider_system_id=prod.id,
            shared_controls=["nist_800_53:AC-4", "nist_800_53:SC-8"],
            dependency_type="application",
            description="Customer Data Warehouse ingests data from Production platform via encrypted ETL pipeline. Data classification controls inherited from source.",
        ),
        SystemDependency(
            consumer_system_id=aiml.id if aiml else prod.id,
            provider_system_id=prod.id,
            shared_controls=["nist_800_53:AC-4", "nist_800_53:SC-13", "nist_800_53:MP-5"],
            dependency_type="infrastructure",
            description="AI/ML platform consumes anonymized datasets from Production. Depends on Production for data anonymization and encryption in transit.",
        ),
        SystemDependency(
            consumer_system_id=dev.id if dev else prod.id,
            provider_system_id=cit.id,
            shared_controls=["nist_800_53:AC-2", "nist_800_53:IA-2", "nist_800_53:IA-5"],
            dependency_type="identity",
            description="Dev/Staging environment uses Corporate IT Okta for developer authentication. Same SSO and MFA policies as production.",
        ),
        SystemDependency(
            consumer_system_id=cdw.id,
            provider_system_id=cit.id,
            shared_controls=["nist_800_53:AC-2", "nist_800_53:IA-2"],
            dependency_type="identity",
            description="Data Warehouse team authenticates via Corporate IT Okta. Analysts access Redshift through SSO-federated IAM roles.",
        ),
        SystemDependency(
            consumer_system_id=aiml.id if aiml else prod.id,
            provider_system_id=cit.id,
            shared_controls=["nist_800_53:AC-2", "nist_800_53:IA-2"],
            dependency_type="identity",
            description="AI/ML engineers authenticate via Corporate IT Okta for SageMaker and notebook access.",
        ),
    ]

    for d in deps:
        session.add(d)
    session.commit()
    return len(deps)


def seed_phase4_change_events(session) -> int:
    """Create 40 ChangeEvent records from CloudTrail, GitHub, and ServiceNow."""
    random.seed(42)  # Deterministic demo data
    events = []

    actors_aws = [
        "arn:aws:iam::912345678012:user/bob.martinez",
        "arn:aws:iam::912345678012:user/alice.chen",
        "arn:aws:iam::912345678012:user/svc-deploy",
        "arn:aws:iam::912345678012:role/github-actions-deploy",
        "arn:aws:iam::912345678012:root",
    ]
    actors_github = ["alice.chen", "bob.martinez", "frank.torres", "svc-deploy"]
    actors_snow = ["eve.nakamura@acme.com", "bob.martinez@acme.com", "frank.torres@acme.com"]

    # CloudTrail IAM events
    cloudtrail_events = [
        (
            "PutUserPolicy",
            "arn:aws:iam::912345678012:user/alice.chen",
            "iam_user",
            "Inline policy attached granting S3 full access",
        ),
        (
            "AttachRolePolicy",
            "arn:aws:iam::912345678012:role/lambda-processor",
            "iam_role",
            "AmazonS3FullAccess policy attached to Lambda role",
        ),
        (
            "CreateAccessKey",
            "arn:aws:iam::912345678012:user/svc-deploy",
            "iam_user",
            "New access key created for service account",
        ),
        (
            "DeleteTrail",
            "arn:aws:cloudtrail:us-east-1:912345678012:trail/dev-trail",
            "cloudtrail",
            "Dev environment CloudTrail deleted",
        ),
        (
            "PutBucketPolicy",
            "arn:aws:s3:::acme-public-assets",
            "s3_bucket",
            "Bucket policy updated to allow public read",
        ),
        (
            "AuthorizeSecurityGroupIngress",
            "sg-0a1b2c3d4e5f",
            "security_group",
            "Ingress rule added: TCP/22 from 0.0.0.0/0",
        ),
        (
            "AuthorizeSecurityGroupIngress",
            "sg-9z8y7x6w5v4u",
            "security_group",
            "Ingress rule added: TCP/443 from 10.0.0.0/8",
        ),
        (
            "ModifyDBInstance",
            "arn:aws:rds:us-east-1:912345678012:db/prod-customers",
            "rds_instance",
            "Multi-AZ enabled, backup retention changed to 30d",
        ),
        (
            "DeactivateMFADevice",
            "arn:aws:iam::912345678012:user/carol.park",
            "iam_user",
            "MFA device deactivated for carol.park",
        ),
        (
            "CreateRole",
            "arn:aws:iam::912345678012:role/data-pipeline-v2",
            "iam_role",
            "New IAM role for data pipeline v2",
        ),
        (
            "PutBucketEncryption",
            "arn:aws:s3:::acme-prod-data",
            "s3_bucket",
            "AES-256 server-side encryption enabled",
        ),
        (
            "UpdateDetector",
            "d-abc123def456",
            "guardduty_detector",
            "GuardDuty S3 protection enabled",
        ),
        (
            "StopConfigurationRecorder",
            "default",
            "config_recorder",
            "Config recorder stopped in us-east-1",
        ),
        (
            "PutBucketPublicAccessBlock",
            "arn:aws:s3:::acme-logs",
            "s3_bucket",
            "Public access block enabled on logs bucket",
        ),
        (
            "ConsoleLogin",
            "arn:aws:iam::912345678012:root",
            "iam_root",
            "Root account console login from 203.0.113.42",
        ),
    ]

    for i, (action, resource_id, resource_type, detail_text) in enumerate(cloudtrail_events):
        events.append(
            ChangeEvent(
                source="cloudtrail",
                source_type="cloud_audit",
                event_type=f"AwsApiCall:{action}",
                actor=random.choice(actors_aws),
                action=action,
                resource_id=resource_id,
                resource_type=resource_type,
                detail={
                    "description": detail_text,
                    "region": "us-east-1",
                    "account_id": "912345678012",
                },
                occurred_at=NOW
                - timedelta(days=random.randint(0, 29), hours=random.randint(0, 23)),
                sha256=_sha(f"cloudtrail-{i}-{action}-{resource_id}"),
            )
        )

    # GitHub events
    github_events = [
        (
            "pull_request.merged",
            "acme-corp/acme-app#342",
            "repository",
            "feat: Add rate limiting to API gateway",
        ),
        (
            "pull_request.merged",
            "acme-corp/acme-app#345",
            "repository",
            "fix: Patch xz-utils CVE-2024-3094 in base image",
        ),
        (
            "pull_request.merged",
            "acme-corp/acme-app#348",
            "repository",
            "chore: Update Terraform AWS provider to 5.40",
        ),
        (
            "pull_request.merged",
            "acme-corp/infra#112",
            "repository",
            "feat: Enable GuardDuty S3 protection",
        ),
        (
            "deployment.created",
            "acme-corp/acme-app@v2.14.0",
            "deployment",
            "Production deployment v2.14.0",
        ),
        (
            "deployment.created",
            "acme-corp/acme-app@v2.14.1",
            "deployment",
            "Hotfix deployment v2.14.1 (CVE patch)",
        ),
        (
            "branch_protection.updated",
            "acme-corp/acme-app:main",
            "branch",
            "Require 2 approvals for main branch",
        ),
        (
            "secret_scanning.alert",
            "acme-corp/acme-app",
            "repository",
            "AWS access key detected in commit history",
        ),
        (
            "pull_request.merged",
            "acme-corp/infra#115",
            "repository",
            "feat: Deploy Config recorder to us-west-2",
        ),
        (
            "dependabot.alert",
            "acme-corp/acme-app",
            "repository",
            "Critical vulnerability in transitive dependency",
        ),
    ]

    for i, (event_type, resource_id, resource_type, detail_text) in enumerate(github_events):
        events.append(
            ChangeEvent(
                source="github",
                source_type="ci_cd",
                event_type=event_type,
                actor=random.choice(actors_github),
                action=event_type.split(".")[1] if "." in event_type else event_type,
                resource_id=resource_id,
                resource_type=resource_type,
                detail={
                    "description": detail_text,
                    "repository": resource_id.split("#")[0] if "#" in resource_id else resource_id,
                },
                occurred_at=NOW
                - timedelta(days=random.randint(0, 29), hours=random.randint(0, 23)),
                sha256=_sha(f"github-{i}-{event_type}-{resource_id}"),
            )
        )

    # ServiceNow events
    snow_events = [
        (
            "change_request.approved",
            "CHG0045123",
            "change_request",
            "Enable multi-region CloudTrail",
            "standard",
        ),
        (
            "change_request.implemented",
            "CHG0045124",
            "change_request",
            "Patch xz-utils on srv-web-01",
            "emergency",
        ),
        (
            "change_request.approved",
            "CHG0045125",
            "change_request",
            "Deploy AWS Config to us-west-2",
            "standard",
        ),
        (
            "change_request.implemented",
            "CHG0045126",
            "change_request",
            "Update Okta password policy to 12-char minimum",
            "standard",
        ),
        (
            "change_request.approved",
            "CHG0045127",
            "change_request",
            "Decommission legacy-windows security group",
            "standard",
        ),
        (
            "change_request.rejected",
            "CHG0045128",
            "change_request",
            "Open port 8080 on production ALB",
            "standard",
        ),
        (
            "change_request.implemented",
            "CHG0045129",
            "change_request",
            "Enable S3 bucket encryption on acme-public-assets",
            "standard",
        ),
        (
            "incident.resolved",
            "INC0089001",
            "incident",
            "Resolved: CrowdStrike agent in reduced functionality mode on ws-marketing-03",
            "P2",
        ),
        (
            "incident.created",
            "INC0089002",
            "incident",
            "Suspicious PowerShell execution on ws-finance-01",
            "P1",
        ),
        (
            "change_request.implemented",
            "CHG0045130",
            "change_request",
            "Rotate svc-deploy IAM access keys",
            "standard",
        ),
        (
            "change_request.approved",
            "CHG0045131",
            "change_request",
            "Enable GuardDuty S3 protection",
            "standard",
        ),
        (
            "change_request.implemented",
            "CHG0045132",
            "change_request",
            "Enable public access block on acme-logs bucket",
            "standard",
        ),
        (
            "change_request.approved",
            "CHG0045133",
            "change_request",
            "Implement GitHub branch protection (2 approvals)",
            "standard",
        ),
        (
            "incident.created",
            "INC0089003",
            "incident",
            "Credential dumping detected on srv-dc-01",
            "P1",
        ),
        (
            "change_request.implemented",
            "CHG0045134",
            "change_request",
            "Restrict RDP SG to VPN CIDR (10.100.0.0/16)",
            "emergency",
        ),
    ]

    for i, (event_type, resource_id, resource_type, detail_text, cat) in enumerate(snow_events):
        events.append(
            ChangeEvent(
                source="servicenow",
                source_type="itsm",
                event_type=event_type,
                actor=random.choice(actors_snow),
                action=event_type.split(".")[1] if "." in event_type else event_type,
                resource_id=resource_id,
                resource_type=resource_type,
                detail={"description": detail_text, "category": cat},
                occurred_at=NOW
                - timedelta(days=random.randint(0, 29), hours=random.randint(0, 23)),
                sha256=_sha(f"snow-{i}-{event_type}-{resource_id}"),
            )
        )

    for e in events:
        session.add(e)
    session.commit()
    return len(events)


def seed_phase4_posture_snapshots(session) -> int:
    """Create 30 days of daily posture snapshots for 12 key controls."""
    random.seed(42)
    prod = session.query(SystemProfile).filter(SystemProfile.acronym == "APP").first()
    cit = session.query(SystemProfile).filter(SystemProfile.acronym == "CIT").first()

    # Define controls with their trend behavior
    controls = [
        # (framework, control_id, system, base_score, trend, base_status)
        # Degrading
        ("nist_800_53", "AC-6", prod, 90.0, "degrade", "compliant"),
        # Improving
        ("nist_800_53", "IA-2", prod, 40.0, "improve", "non_compliant"),
        # Stable
        ("nist_800_53", "SC-7", prod, 85.0, "stable", "partial"),
        # Various stable controls
        ("nist_800_53", "AC-2", prod, 72.0, "stable", "partial"),
        ("nist_800_53", "AU-6", prod, 55.0, "stable", "non_compliant"),
        ("nist_800_53", "CM-6", prod, 68.0, "stable", "partial"),
        ("nist_800_53", "RA-5", prod, 45.0, "slight_improve", "non_compliant"),
        ("nist_800_53", "SI-4", prod, 78.0, "stable", "partial"),
        ("nist_800_53", "IA-5", cit, 60.0, "improve", "non_compliant"),
        ("nist_800_53", "SC-28", prod, 82.0, "slight_improve", "compliant"),
        ("soc2", "CC6.1", cit, 65.0, "stable", "partial"),
        ("soc2", "CC7.2", cit, 88.0, "stable", "compliant"),
    ]

    count = 0
    for day_offset in range(30, 0, -1):
        snapshot_date = NOW - timedelta(days=day_offset)
        day_index = 30 - day_offset  # 0..29

        for fw, ctrl, sys_profile, base, trend, base_status in controls:
            noise = random.uniform(-3.0, 3.0)

            if trend == "degrade":
                score = base - (day_index * 1.0) + noise  # 90 -> ~60
            elif trend == "improve":
                score = base + (day_index * 1.33) + noise  # 40 -> ~80
            elif trend == "slight_improve":
                score = base + (day_index * 0.4) + noise
            else:  # stable
                score = base + noise

            score = max(0.0, min(100.0, round(score, 1)))

            if score >= 80:
                status = "compliant"
            elif score >= 50:
                status = "partial"
            else:
                status = "non_compliant"

            # Realistic evidence metrics
            total = random.randint(3, 12)
            compliant_count = max(0, int(total * score / 100))
            non_compliant_count = total - compliant_count
            sufficiency = min(100.0, max(0.0, score + random.uniform(-10, 10)))

            snapshot = PostureSnapshot(
                snapshot_date=snapshot_date,
                framework=fw,
                control_id=ctrl,
                status=status,
                posture_score=score,
                total_findings=total,
                compliant_findings=compliant_count,
                non_compliant_findings=non_compliant_count,
                evidence_sources=["aws", "okta", "crowdstrike"]
                if sys_profile == prod
                else ["okta", "crowdstrike"],
                evidence_freshness_hours=random.uniform(1.0, 24.0),
                sufficiency_score=round(sufficiency, 1),
                sufficiency_details={
                    "source_count": random.randint(2, 4),
                    "evidence_types": ["config", "telemetry", "process"],
                },
                system_profile_id=sys_profile.id if sys_profile else None,
                uptime_pct=round(max(50.0, min(100.0, score + random.uniform(-5, 5))), 1),
                mttr_hours=round(max(0.5, (100 - score) / 10 + random.uniform(-1, 2)), 1),
                drift_count=random.randint(0, 3) if score < 70 else random.randint(0, 1),
            )
            session.add(snapshot)
            count += 1

    session.commit()
    return count


def seed_phase4_drift(session) -> int:
    """Create 10 ComplianceDrift records linked to posture snapshots and change events."""
    prod = session.query(SystemProfile).filter(SystemProfile.acronym == "APP").first()
    cit = session.query(SystemProfile).filter(SystemProfile.acronym == "CIT").first()

    # Get some change event IDs for correlation
    change_events = session.query(ChangeEvent).limit(10).all()
    ce_ids = [ce.id for ce in change_events]

    drifts = [
        # Degraded controls
        ComplianceDrift(
            framework="nist_800_53",
            control_id="AC-6",
            system_profile_id=prod.id if prod else None,
            previous_status="compliant",
            new_status="partial",
            drift_direction="degraded",
            previous_posture_score=90.0,
            new_posture_score=72.0,
            correlated_change_event_ids=ce_ids[:2] if len(ce_ids) >= 2 else [],
            root_cause_summary="Privilege escalation via Okta Super Admin grant to bob.martinez without approval workflow. IAM policy change detected in CloudTrail.",
            correlation_confidence=0.92,
            detected_at=NOW - timedelta(days=15),
        ),
        ComplianceDrift(
            framework="nist_800_53",
            control_id="AC-6",
            system_profile_id=prod.id if prod else None,
            previous_status="partial",
            new_status="non_compliant",
            drift_direction="degraded",
            previous_posture_score=72.0,
            new_posture_score=60.0,
            correlated_change_event_ids=[ce_ids[2]] if len(ce_ids) >= 3 else [],
            root_cause_summary="Additional inline policy attached to alice.chen granting S3 full access. No change request found in ServiceNow.",
            correlation_confidence=0.85,
            detected_at=NOW - timedelta(days=5),
        ),
        ComplianceDrift(
            framework="nist_800_53",
            control_id="AU-6",
            system_profile_id=prod.id if prod else None,
            previous_status="partial",
            new_status="non_compliant",
            drift_direction="degraded",
            previous_posture_score=60.0,
            new_posture_score=52.0,
            correlated_change_event_ids=[ce_ids[3]] if len(ce_ids) >= 4 else [],
            root_cause_summary="Dev environment CloudTrail deleted. Single-region trail in prod remains only audit coverage.",
            correlation_confidence=0.88,
            detected_at=NOW - timedelta(days=12),
        ),
        ComplianceDrift(
            framework="nist_800_53",
            control_id="SC-7",
            system_profile_id=prod.id if prod else None,
            previous_status="compliant",
            new_status="partial",
            drift_direction="degraded",
            previous_posture_score=88.0,
            new_posture_score=82.0,
            correlated_change_event_ids=[ce_ids[5]] if len(ce_ids) >= 6 else [],
            root_cause_summary="New security group ingress rule added allowing SSH from 0.0.0.0/0 to web-bastion.",
            correlation_confidence=0.95,
            detected_at=NOW - timedelta(days=20),
        ),
        # Improved controls
        ComplianceDrift(
            framework="nist_800_53",
            control_id="IA-2",
            system_profile_id=prod.id if prod else None,
            previous_status="non_compliant",
            new_status="partial",
            drift_direction="improved",
            previous_posture_score=40.0,
            new_posture_score=58.0,
            correlated_change_event_ids=[],
            root_cause_summary="Hardware security key compensating control deployed. 60% of privileged users now on FIDO2 MFA.",
            correlation_confidence=0.78,
            detected_at=NOW - timedelta(days=18),
        ),
        ComplianceDrift(
            framework="nist_800_53",
            control_id="IA-2",
            system_profile_id=prod.id if prod else None,
            previous_status="partial",
            new_status="compliant",
            drift_direction="improved",
            previous_posture_score=58.0,
            new_posture_score=80.0,
            correlated_change_event_ids=[],
            root_cause_summary="All privileged users now enrolled in hardware MFA. Compensating control fully effective.",
            correlation_confidence=0.90,
            detected_at=NOW - timedelta(days=3),
        ),
        ComplianceDrift(
            framework="nist_800_53",
            control_id="SC-28",
            system_profile_id=prod.id if prod else None,
            previous_status="partial",
            new_status="compliant",
            drift_direction="improved",
            previous_posture_score=75.0,
            new_posture_score=88.0,
            correlated_change_event_ids=[ce_ids[6]] if len(ce_ids) >= 7 else [],
            root_cause_summary="S3 bucket encryption enabled on acme-public-assets. All data silos now encrypted at rest.",
            correlation_confidence=0.97,
            detected_at=NOW - timedelta(days=22),
        ),
        ComplianceDrift(
            framework="nist_800_53",
            control_id="IA-5",
            system_profile_id=cit.id if cit else None,
            previous_status="non_compliant",
            new_status="partial",
            drift_direction="improved",
            previous_posture_score=55.0,
            new_posture_score=70.0,
            correlated_change_event_ids=[],
            root_cause_summary="Password policy update in progress. Okta policy updated to 12-char minimum, AWS IAM pending.",
            correlation_confidence=0.82,
            detected_at=NOW - timedelta(days=8),
        ),
        ComplianceDrift(
            framework="nist_800_53",
            control_id="RA-5",
            system_profile_id=prod.id if prod else None,
            previous_status="non_compliant",
            new_status="partial",
            drift_direction="improved",
            previous_posture_score=45.0,
            new_posture_score=55.0,
            correlated_change_event_ids=[ce_ids[1]] if len(ce_ids) >= 2 else [],
            root_cause_summary="CVE-2024-3094 patch deployed to staging. Container image scanning compensating control blocking new critical vulnerabilities.",
            correlation_confidence=0.75,
            detected_at=NOW - timedelta(days=2),
        ),
        ComplianceDrift(
            framework="soc2",
            control_id="CC6.1",
            system_profile_id=cit.id if cit else None,
            previous_status="non_compliant",
            new_status="partial",
            drift_direction="improved",
            previous_posture_score=50.0,
            new_posture_score=65.0,
            correlated_change_event_ids=[],
            root_cause_summary="Passkey rollout reached 50% adoption. Effective password strength improved through passwordless authentication.",
            correlation_confidence=0.70,
            detected_at=NOW - timedelta(days=10),
        ),
    ]

    for d in drifts:
        session.add(d)
    session.commit()
    return len(drifts)


def seed_phase5_auditor_engagement(session) -> int:
    """Create external auditors, an engagement, assignments, and evidence requests."""
    # Upsert auditors — check-before-insert to avoid UNIQUE constraint on email
    auditor1 = (
        session.query(ExternalAuditor)
        .filter(ExternalAuditor.email == "sarah.chen@deloitte.com")
        .first()
    )
    if not auditor1:
        auditor1 = ExternalAuditor(
            email="sarah.chen@deloitte.com",
            name="Sarah Chen",
            firm="Deloitte",
            is_active=True,
        )
        session.add(auditor1)
    auditor2 = (
        session.query(ExternalAuditor)
        .filter(ExternalAuditor.email == "marcus.johnson@ey.com")
        .first()
    )
    if not auditor2:
        auditor2 = ExternalAuditor(
            email="marcus.johnson@ey.com",
            name="Marcus Johnson",
            firm="Ernst & Young",
            is_active=True,
        )
        session.add(auditor2)
    session.flush()

    # Create or find an engagement
    engagement = session.query(AuditEngagement).first()
    if not engagement:
        engagement = AuditEngagement(
            name="SOC 2 Type II 2025-2026",
            framework="soc2",
            period_start=NOW - timedelta(days=180),
            period_end=NOW + timedelta(days=185),
            status="active",
            auditor_name="Sarah Chen",
            auditor_firm="Deloitte",
        )
        session.add(engagement)
        session.flush()

    # Create a second engagement for NIST
    nist_engagement = AuditEngagement(
        name="NIST 800-53 Annual Assessment 2026",
        framework="nist_800_53",
        period_start=NOW - timedelta(days=30),
        period_end=NOW + timedelta(days=60),
        status="active",
        auditor_name="Marcus Johnson",
        auditor_firm="Ernst & Young",
    )
    session.add(nist_engagement)
    session.flush()

    # Assign auditors to engagements
    session.add(
        AuditorEngagementAssignment(
            auditor_id=auditor1.id,
            engagement_id=engagement.id,
        )
    )
    session.add(
        AuditorEngagementAssignment(
            auditor_id=auditor2.id,
            engagement_id=nist_engagement.id,
        )
    )
    session.flush()

    # Create evidence requests
    evidence_requests = [
        EvidenceRequest(
            engagement_id=engagement.id,
            auditor_id=auditor1.id,
            framework="soc2",
            control_id="CC6.1",
            description="Provide IAM credential report showing MFA enrollment status for all users with console access.",
            status="fulfilled",
            fulfilled_by="eve.nakamura@acme.com",
            fulfilled_at=NOW - timedelta(days=5),
            fulfillment_notes="Credential report exported from AWS IAM. Shows 3/4 console users with MFA enabled.",
        ),
        EvidenceRequest(
            engagement_id=engagement.id,
            auditor_id=auditor1.id,
            framework="soc2",
            control_id="CC6.6",
            description="Provide encryption at rest configuration evidence for all data stores containing customer data.",
            status="fulfilled",
            fulfilled_by="bob.martinez@acme.com",
            fulfilled_at=NOW - timedelta(days=3),
            fulfillment_notes="S3 bucket encryption configs and RDS encryption status exported. All customer data stores encrypted.",
        ),
        EvidenceRequest(
            engagement_id=engagement.id,
            auditor_id=auditor1.id,
            framework="soc2",
            control_id="CC7.2",
            description="Provide CrowdStrike deployment coverage report showing agent status across all endpoints.",
            status="requested",
        ),
        EvidenceRequest(
            engagement_id=engagement.id,
            auditor_id=auditor1.id,
            framework="soc2",
            control_id="CC8.1",
            description="Provide change management records for all production deployments in the audit period, including approval evidence.",
            status="in_progress",
        ),
        EvidenceRequest(
            engagement_id=nist_engagement.id,
            auditor_id=auditor2.id,
            framework="nist_800_53",
            control_id="AC-2",
            description="Provide evidence of account management procedures including provisioning, modification, and deprovisioning workflows.",
            status="requested",
        ),
        EvidenceRequest(
            engagement_id=nist_engagement.id,
            auditor_id=auditor2.id,
            framework="nist_800_53",
            control_id="RA-5",
            description="Provide vulnerability scan reports for the last 90 days covering all production hosts and containers.",
            status="fulfilled",
            fulfilled_by="eve.nakamura@acme.com",
            fulfilled_at=NOW - timedelta(days=2),
            fulfillment_notes="CrowdStrike Spotlight vulnerability report and Trivy container scan results provided.",
        ),
        EvidenceRequest(
            engagement_id=nist_engagement.id,
            auditor_id=auditor2.id,
            framework="nist_800_53",
            control_id="AU-6",
            description="Provide evidence of audit log review procedures and any findings from log analysis over the audit period.",
            status="requested",
        ),
    ]

    for er in evidence_requests:
        session.add(er)
    session.flush()

    # --- Attestations (GAP-5) ---
    attestations = [
        Attestation(
            engagement_id=engagement.id,
            framework="soc2",
            control_id="CC6.1",
            status="approved",
            statement="Management asserts that logical access to production systems containing customer data is restricted to authorized personnel through role-based access controls, multi-factor authentication, and quarterly access reviews.",
            evidence_references=[
                {
                    "finding_id": "iam-cred-report-001",
                    "description": "AWS IAM credential report showing MFA enrollment",
                },
                {
                    "finding_id": "okta-access-review-q4",
                    "description": "Quarterly access review completion evidence",
                },
            ],
            prepared_by="eve.nakamura@acme.com",
            prepared_at=NOW - timedelta(days=30),
            submitted_by="eve.nakamura@acme.com",
            submitted_at=NOW - timedelta(days=28),
            reviewed_by="hassan.ali@acme.com",
            reviewed_at=NOW - timedelta(days=21),
            review_notes="Evidence is comprehensive. IAM report confirms 97% MFA coverage. Access review shows timely revocation of terminated accounts.",
            approved_by="sarah.chen@deloitte.com",
            approved_at=NOW - timedelta(days=14),
        ),
        Attestation(
            engagement_id=engagement.id,
            framework="iso_27001",
            control_id="A.9.1",
            status="submitted",
            statement="Management asserts that an access control policy has been established, documented, and reviewed in accordance with business and information security requirements.",
            evidence_references=[
                {
                    "finding_id": "policy-access-control-v3",
                    "description": "Access Control Policy v3.2 (approved 2025-11-01)",
                },
            ],
            prepared_by="bob.martinez@acme.com",
            prepared_at=NOW - timedelta(days=10),
            submitted_by="bob.martinez@acme.com",
            submitted_at=NOW - timedelta(days=7),
        ),
        Attestation(
            engagement_id=nist_engagement.id,
            framework="nist_800_53",
            control_id="AC-2",
            status="draft",
            statement="Management asserts that information system accounts are managed through automated provisioning and deprovisioning workflows integrated with the HR system, with periodic access reviews conducted quarterly.",
            evidence_references=[],
            prepared_by="frank.torres@acme.com",
            prepared_at=NOW - timedelta(days=3),
        ),
        Attestation(
            engagement_id=nist_engagement.id,
            framework="nist_800_53",
            control_id="RA-5",
            status="approved",
            statement="Management asserts that vulnerability scanning is performed on all production hosts and containers on a weekly cadence, with critical findings remediated within 72 hours per the vulnerability management SLA.",
            evidence_references=[
                {
                    "finding_id": "crowdstrike-vuln-scan-weekly",
                    "description": "CrowdStrike Spotlight weekly scan results",
                },
                {
                    "finding_id": "trivy-container-scan",
                    "description": "Trivy container image scan report",
                },
            ],
            prepared_by="eve.nakamura@acme.com",
            prepared_at=NOW - timedelta(days=20),
            submitted_by="eve.nakamura@acme.com",
            submitted_at=NOW - timedelta(days=18),
            reviewed_by="hassan.ali@acme.com",
            reviewed_at=NOW - timedelta(days=12),
            review_notes="Scan cadence verified. Remediation SLAs met for 94% of critical findings in audit period.",
            approved_by="marcus.johnson@ey.com",
            approved_at=NOW - timedelta(days=8),
        ),
    ]
    for att in attestations:
        session.add(att)
    session.commit()
    return {
        "auditors": 2,
        "engagements": 2,
        "evidence_requests": len(evidence_requests),
        "attestations": len(attestations),
    }


def seed_phase5_policy_overrides(session) -> int:
    """Create 3 PolicyOverride records with realistic Rego policies."""
    overrides = [
        PolicyOverride(
            name="Emergency break-glass access escalation",
            description="Allows security team members to temporarily bypass approval workflows during active incidents. Requires incident ID and auto-revokes after 4 hours.",
            policy_rego="""package grc.overrides.break_glass

import rego.v1

default allow := false

allow if {
    input.user.role == "security"
    input.context.incident_id != ""
    input.context.duration_hours <= 4
}

audit_note := sprintf("Break-glass access granted for incident %s", [input.context.incident_id])
""",
            is_active=True,
            created_by="hassan.ali@acme.com",
        ),
        PolicyOverride(
            name="Auditor read-only scope expansion",
            description="Extends auditor read access to include raw evidence and finding details during active engagements. Scoped to assigned engagement only.",
            policy_rego="""package grc.overrides.auditor_scope

import rego.v1

default allow := false

allow if {
    input.user.role == "auditor"
    input.action in {"read_finding", "read_evidence", "read_raw_event"}
    input.context.engagement_id in input.user.assigned_engagements
}
""",
            is_active=True,
            created_by="eve.nakamura@acme.com",
        ),
        PolicyOverride(
            name="System owner remediation approval",
            description="Allows system owners to approve low-severity POA&M closures without AO sign-off. Medium and above still require AO.",
            policy_rego="""package grc.overrides.poam_approval

import rego.v1

default allow := false

allow if {
    input.user.role == "owner"
    input.action == "close_poam"
    input.poam.severity == "low"
    input.poam.system_profile_id in input.user.owned_systems
}
""",
            is_active=True,
            created_by="hassan.ali@acme.com",
        ),
    ]

    for o in overrides:
        session.add(o)
    session.flush()

    # Create matching audit entries so `warlock exceptions list` shows policy/approver
    from warlock.db.audit import AuditTrail

    trail = AuditTrail(session)
    policy_names = [
        "grc.overrides.break_glass",
        "grc.overrides.auditor_scope",
        "grc.overrides.poam_approval",
    ]
    approvers = [
        "eve.nakamura@acme.com",
        "hassan.ali@acme.com",
        "eve.nakamura@acme.com",
    ]
    for o, policy, approver in zip(overrides, policy_names, approvers):
        trail.record(
            action="policy_exception",
            entity_type="exception",
            entity_id=o.id,
            actor=o.created_by,
            metadata={
                "policy": policy,
                "approver": approver,
                "justification": o.description,
                "expiry": "2026-06-30T00:00:00+00:00",
            },
        )

    session.commit()
    return len(overrides)


def seed_50_personnel(session) -> int:
    """Expand personnel to ~50 users with diverse departments and compliance states."""
    # Count existing personnel
    existing_count = session.query(Personnel).count()
    existing_emails = {row[0] for row in session.query(Personnel.email).all()}

    random.seed(42)

    departments = [
        "Engineering",
        "Product",
        "Finance",
        "Legal",
        "HR",
        "Sales",
        "Marketing",
        "Security",
        "DevOps",
        "Data Science",
    ]
    first_names = [
        "Aiden",
        "Bella",
        "Carlos",
        "Diana",
        "Ethan",
        "Fatima",
        "George",
        "Hannah",
        "Isaac",
        "Julia",
        "Kevin",
        "Luna",
        "Marco",
        "Nadia",
        "Oscar",
        "Priya",
        "Quinn",
        "Rosa",
        "Samuel",
        "Tanya",
        "Umar",
        "Victoria",
        "Wei",
        "Xena",
        "Yuki",
        "Zara",
        "Adrian",
        "Bianca",
        "Chase",
        "Daria",
        "Eli",
        "Fiona",
        "Gabriel",
        "Holly",
        "Ivan",
        "Jade",
        "Kyle",
        "Lily",
        "Miguel",
        "Nina",
        "Oliver",
        "Petra",
        "Ravi",
        "Sofia",
    ]
    last_names = [
        "Anderson",
        "Bharati",
        "Costa",
        "Diaz",
        "Evans",
        "Fischer",
        "Garcia",
        "Huang",
        "Ibrahim",
        "Jensen",
        "Kim",
        "Lopez",
        "Muller",
        "Ng",
        "Olsen",
        "Patel",
        "Quinn",
        "Reyes",
        "Singh",
        "Tanaka",
        "Ueda",
        "Vasquez",
        "Wang",
        "Xu",
        "Yamamoto",
        "Zhang",
        "Baker",
        "Chen",
        "Davis",
        "Edwards",
        "Foster",
        "Gonzalez",
        "Hill",
        "Ishida",
        "Jackson",
        "Klein",
        "Lee",
        "Martinez",
        "Nelson",
        "Ortiz",
        "Park",
        "Reed",
        "Smith",
    ]

    new_personnel = []
    target = 50 - existing_count
    if target <= 0:
        return existing_count

    for i in range(min(target, len(first_names))):
        first = first_names[i]
        last = last_names[i % len(last_names)]
        email = f"{first.lower()}.{last.lower()}@acme.com"
        if email in existing_emails:
            continue

        dept = departments[i % len(departments)]
        hire_days_ago = random.randint(30, 1800)

        # Determine status
        if i in (38, 39, 40):  # 3 terminated but still active IdP
            hr_status = "terminated"
            idp_status = "active"
            is_active = False
            termination_date = NOW - timedelta(days=random.randint(10, 60))
            flags = ["terminated_but_active_idp"]
            risk_score = random.uniform(70.0, 95.0)
        elif i == 37:
            hr_status = "leave"
            idp_status = "suspended"
            is_active = True
            termination_date = None
            flags = []
            risk_score = random.uniform(10.0, 30.0)
        elif i == 36:
            hr_status = "leave"
            idp_status = "active"
            is_active = True
            termination_date = None
            flags = []
            risk_score = random.uniform(5.0, 20.0)
        else:
            hr_status = "active"
            idp_status = "active"
            is_active = True
            termination_date = None
            flags = []
            risk_score = random.uniform(0.0, 25.0)

        # MFA: ~80% enabled
        mfa = random.random() < 0.80
        if not mfa and hr_status == "active":
            flags.append("no_mfa")
            risk_score = max(risk_score, random.uniform(40.0, 65.0))

        # Training
        training_roll = random.random()
        if training_roll < 0.60:
            training_status = "current"
            last_training = NOW - timedelta(days=random.randint(1, 90))
        elif training_roll < 0.85:
            training_status = "overdue"
            last_training = NOW - timedelta(days=random.randint(120, 365))
            flags.append("training_overdue")
            risk_score = max(risk_score, random.uniform(30.0, 50.0))
        else:
            training_status = "not_enrolled"
            last_training = None
            if hr_status == "active":
                flags.append("training_not_enrolled")
                risk_score = max(risk_score, random.uniform(20.0, 40.0))

        # Background check
        if hire_days_ago > 60:
            bg_status = "completed"
            bg_date = NOW - timedelta(days=hire_days_ago - random.randint(5, 15))
        elif hire_days_ago > 14:
            bg_status = "completed"
            bg_date = NOW - timedelta(days=hire_days_ago - 5)
        else:
            bg_status = "in_progress"
            bg_date = None

        p = Personnel(
            email=email,
            full_name=f"{first} {last}",
            department=dept,
            title=random.choice(
                [
                    "Engineer",
                    "Senior Engineer",
                    "Manager",
                    "Analyst",
                    "Director",
                    "Lead",
                    "Specialist",
                ]
            ),
            manager_email=f"manager.{dept.lower()}@acme.com",
            employee_type=random.choice(["employee", "employee", "employee", "contractor"])
            if i not in (38, 39, 40)
            else "employee",
            hr_employee_id=f"WD-{100 + i:03d}",
            hire_date=NOW - timedelta(days=hire_days_ago),
            termination_date=termination_date,
            hr_status=hr_status,
            background_check_status=bg_status,
            background_check_date=bg_date,
            agreements_signed=[
                {
                    "type": "employment_agreement",
                    "signed_date": (NOW - timedelta(days=hire_days_ago)).isoformat(),
                },
                {"type": "nda", "signed_date": (NOW - timedelta(days=hire_days_ago)).isoformat()},
            ],
            idp_user_id=f"00u{i:04d}",
            idp_provider="okta",
            idp_status=idp_status,
            idp_last_login=NOW - timedelta(days=random.randint(0, 30))
            if idp_status == "active"
            else NOW - timedelta(days=random.randint(30, 120)),
            mfa_enabled=mfa,
            training_status=training_status,
            last_training_date=last_training,
            phishing_score=round(random.uniform(40.0, 100.0), 1),
            training_completions=(
                [
                    {
                        "campaign": random.choice(
                            [
                                "Security Awareness 2026",
                                "GDPR Privacy Essentials",
                                "Phishing Defense Workshop",
                                "Insider Threat Recognition",
                                "Secure Coding Fundamentals",
                            ]
                        ),
                        "completed_date": (NOW - timedelta(days=random.randint(1, 180))).strftime(
                            "%Y-%m-%d"
                        ),
                        "status": "completed",
                    }
                    for _ in range(random.randint(1, 3))
                ]
                if training_status == "current"
                else []
            ),
            last_access_review=NOW - timedelta(days=random.randint(10, 120)),
            access_review_status="completed" if random.random() < 0.7 else "overdue",
            flags=flags,
            risk_score=round(risk_score, 1),
            is_active=is_active,
            last_synced=NOW,
        )
        new_personnel.append(p)

    for p in new_personnel:
        session.add(p)
    session.commit()
    return session.query(Personnel).count()


# ---------------------------------------------------------------------------
# Post-pipeline enrichment helpers
# ---------------------------------------------------------------------------


def _age_some_findings(session) -> int:
    """Set older observed_at dates on a subset of findings for SLA breach demo.

    Picks 50 random findings and sets their observed_at to 7-90 days ago,
    creating a realistic age distribution for SLA/overdue dashboards.
    """
    all_ids = [row[0] for row in session.query(Finding.id).all()]
    if not all_ids:
        return 0

    sample_size = min(50, len(all_ids))
    sampled_ids = random.sample(all_ids, sample_size)

    aged = 0
    for fid in sampled_ids:
        finding = session.query(Finding).get(fid)
        if finding:
            days_ago = random.randint(7, 90)
            finding.observed_at = NOW - timedelta(days=days_ago)
            aged += 1

    session.commit()
    return aged


def _seed_vendors(session) -> int:
    """Create Vendor records with varied risk scores from mock data.

    Uses the rich vendor_assessments data to populate the vendors table
    with realistic score distribution (most between 40-75).
    """
    _ensure_rich_data()
    vendor_data = RICH_DATA.get("vendor_assessments", [])

    # Also add the 5 hand-crafted SSC vendors from the connector
    hardcoded_vendors = [
        {"name": "Stripe", "tier": "1", "score": 92.0, "cadence": 90},
        {"name": "Datadog", "tier": "1", "score": 88.0, "cadence": 90},
        {"name": "Acme Staffing Co", "tier": "3", "score": 58.0, "cadence": 365},
        {"name": "CloudBackup Pro", "tier": "2", "score": 45.0, "cadence": 180},
        {"name": "QuickDocs", "tier": "2", "score": 72.0, "cadence": 180},
    ]

    existing_names = {row[0] for row in session.query(Vendor.name).all()}
    created = 0

    # Insert hardcoded vendors first
    for hv in hardcoded_vendors:
        if hv["name"] not in existing_names:
            session.add(
                Vendor(
                    name=hv["name"],
                    tier=hv["tier"],
                    risk_score=hv["score"],
                    last_assessment=NOW - timedelta(days=random.randint(5, 45)),
                    assessment_cadence_days=hv["cadence"],
                    contract_expires=NOW + timedelta(days=random.randint(60, 400)),
                    metadata_={"source": "securityscorecard"},
                )
            )
            existing_names.add(hv["name"])
            created += 1

    # Insert rich data vendors with their varied scores (20-100 range)
    tier_map = {"A": "1", "B": "1", "C": "2", "D": "3", "F": "3"}
    cadence_map = {"1": 90, "2": 180, "3": 365}

    for v in vendor_data:
        name = v["vendor_name"]
        if name in existing_names:
            continue
        tier = tier_map.get(v.get("rating", "C"), "2")
        session.add(
            Vendor(
                name=name,
                tier=tier,
                risk_score=float(v["risk_score"]),
                last_assessment=NOW - timedelta(days=random.randint(5, 90)),
                assessment_cadence_days=cadence_map.get(tier, 180),
                contract_expires=NOW + timedelta(days=random.randint(30, 500)),
                metadata_={
                    "source": "securityscorecard",
                    "category": v.get("category", ""),
                    "certifications": v.get("certifications", []),
                },
            )
        )
        existing_names.add(name)
        created += 1

    session.commit()
    return created


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _assign_findings_to_systems(session):
    """Assign findings to system profiles based on connector_scope matching."""
    systems = session.query(SystemProfile).all()
    if not systems:
        return 0

    # Build source -> system mapping from connector_scope
    source_to_system = {}
    for sp in systems:
        for source in sp.connector_scope or []:
            # First match wins (most specific system)
            if source not in source_to_system:
                source_to_system[source] = sp.id

    findings = session.query(Finding).filter(Finding.system_profile_id.is_(None)).all()
    assigned = 0
    for f in findings:
        sys_id = source_to_system.get(f.source)
        if sys_id:
            f.system_profile_id = sys_id
            assigned += 1

    # Also propagate to control results
    from warlock.db.models import ControlResult as CR

    results = session.query(CR).filter(CR.system_profile_id.is_(None)).all()
    finding_system_map = {f.id: f.system_profile_id for f in findings if f.system_profile_id}
    for r in results:
        if r.finding_id in finding_system_map:
            r.system_profile_id = finding_system_map[r.finding_id]

    session.commit()
    return assigned


def _backfill_monitoring_frequency(session):
    """Backfill monitoring_frequency on control mappings from framework YAML data."""
    import yaml

    # Load frequencies from YAML files
    freq_map = {}  # (framework, control_id) -> frequency
    fw_dir = REPO_ROOT / "warlock" / "frameworks"
    for yaml_path in fw_dir.glob("*.yaml"):
        if "crosswalk" in yaml_path.name:
            continue
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        fw_id = data.get("framework_id", yaml_path.stem)
        for family_id, family in data.get("control_families", {}).items():
            for ctrl_id, ctrl in family.get("controls", {}).items():
                freq = ctrl.get("monitoring_frequency", "monthly")
                freq_map[(fw_id, ctrl_id)] = freq

    # Update mappings missing frequency
    from warlock.db.models import ControlMapping as CM

    mappings = session.query(CM).filter(CM.monitoring_frequency.is_(None)).all()
    updated = 0
    for m in mappings:
        freq = freq_map.get((m.framework, m.control_id))
        if freq:
            m.monitoring_frequency = freq
            updated += 1

    session.commit()
    return updated


def _create_demo_users(session):
    """Create demo user accounts for API testing."""
    from warlock.api.auth import hash_password
    from warlock.db.models import User as UserModel

    demo_users = [
        UserModel(
            email="admin@acme.com",
            name="Admin User",
            hashed_password=hash_password("WarlockAdmin2026!"),
            role="admin",
        ),
        UserModel(
            email="eve.nakamura@acme.com",
            name="Eve Nakamura",
            hashed_password=hash_password("SecurityFirst2026!"),
            role="auditor",
        ),
        UserModel(
            email="frank.torres@acme.com",
            name="Frank Torres",
            hashed_password=hash_password("EngineerBuild2026!"),
            role="owner",
            allowed_frameworks=["nist_800_53", "soc2", "iso_27001"],
            allowed_sources=["aws", "crowdstrike", "okta"],
        ),
        UserModel(
            email="carol.park@acme.com",
            name="Carol Park",
            hashed_password=hash_password("FinanceReview2026!"),
            role="viewer",
            allowed_frameworks=["soc2"],
        ),
    ]

    created = 0
    existing_emails = {row[0] for row in session.query(UserModel.email).all()}
    for user in demo_users:
        if user.email not in existing_emails:
            session.add(user)
            created += 1

    session.commit()
    return created


def _seed_audit_trail(session) -> int:
    """Populate the hash-chained audit trail with representative entries."""
    from warlock.db.audit import AuditTrail
    from warlock.db.models import ControlResult, Finding

    trail = AuditTrail(session)
    count = 0

    # evidence_collected for 5 RawEvents
    raw_events = session.query(RawEvent).limit(5).all()
    for re in raw_events:
        trail.record(
            action="evidence_collected",
            entity_type="RawEvent",
            entity_id=re.id,
            actor="pipeline",
            evidence_sha256=re.sha256,
            metadata={"source": re.source, "event_type": re.event_type},
        )
        count += 1

    # finding_created for 10 Findings
    findings = session.query(Finding).limit(10).all()
    for f in findings:
        trail.record(
            action="finding_created",
            entity_type="Finding",
            entity_id=f.id,
            actor="pipeline",
            evidence_sha256=f.sha256,
            metadata={"title": f.title[:80], "severity": f.severity, "source": f.source},
        )
        count += 1

    # control_assessed for 10 ControlResults (no hash field on ControlResult)
    results = session.query(ControlResult).limit(10).all()
    for cr in results:
        trail.record(
            action="control_assessed",
            entity_type="ControlResult",
            entity_id=cr.id,
            actor="pipeline",
            metadata={
                "framework": cr.framework,
                "control_id": cr.control_id,
                "status": cr.status,
            },
        )
        count += 1

    # 3 user actions
    trail.record(
        action="user_login",
        entity_type="User",
        entity_id="admin@acme.com",
        actor="admin@acme.com",
        metadata={"ip": "10.0.1.42", "user_agent": "Mozilla/5.0"},
    )
    count += 1

    trail.record(
        action="report_exported",
        entity_type="Report",
        entity_id="soc2-type2-2026-q1",
        actor="eve.nakamura@acme.com",
        metadata={"format": "pdf", "framework": "soc2", "pages": 47},
    )
    count += 1

    trail.record(
        action="issue_created",
        entity_type="Issue",
        entity_id="ISS-MANUAL-001",
        actor="hassan.ali@acme.com",
        metadata={
            "title": "Elevated privileges not revoked after incident",
            "severity": "high",
        },
    )
    count += 1

    session.commit()
    return count


# ---------------------------------------------------------------------------
# GAP-5: Attestations
# ---------------------------------------------------------------------------


def _seed_attestations(session) -> int:
    """Create 4 attestation records spanning different workflows and frameworks."""
    engagement = session.query(AuditEngagement).first()
    engagement_id = engagement.id if engagement else None

    attestations = [
        Attestation(
            engagement_id=engagement_id,
            framework="soc2",
            control_id="CC6.1",
            status="approved",
            statement="Management asserts that logical access to production systems "
            "is restricted to authorized personnel via MFA-enforced IAM policies.",
            evidence_references=[
                {"finding_id": "okta-mfa-001", "description": "Okta MFA enrollment report"},
                {"finding_id": "aws-iam-002", "description": "IAM credential report"},
            ],
            prepared_by="eve.nakamura@acme.com",
            prepared_at=NOW - timedelta(days=14),
            submitted_by="eve.nakamura@acme.com",
            submitted_at=NOW - timedelta(days=12),
            reviewed_by="sarah.chen@deloitte.com",
            reviewed_at=NOW - timedelta(days=8),
            review_notes="Evidence is complete and consistent with control objective.",
            approved_by="sarah.chen@deloitte.com",
            approved_at=NOW - timedelta(days=7),
        ),
        Attestation(
            engagement_id=engagement_id,
            framework="soc2",
            control_id="CC7.2",
            status="submitted",
            statement="Management asserts that endpoint detection and response agents "
            "are deployed on all corporate endpoints with prevention mode enabled.",
            evidence_references=[
                {"finding_id": "cs-edr-001", "description": "CrowdStrike deployment report"},
            ],
            prepared_by="frank.torres@acme.com",
            prepared_at=NOW - timedelta(days=5),
            submitted_by="frank.torres@acme.com",
            submitted_at=NOW - timedelta(days=3),
        ),
        Attestation(
            engagement_id=engagement_id,
            framework="nist_800_53",
            control_id=None,
            status="draft",
            statement="Management asserts that the organization has implemented "
            "a comprehensive risk management framework aligned with NIST 800-53 Rev 5 "
            "Moderate baseline across all information systems.",
            evidence_references=[],
            prepared_by="hassan.ali@acme.com",
            prepared_at=NOW - timedelta(days=2),
        ),
        Attestation(
            engagement_id=engagement_id,
            framework="iso_27001",
            control_id="A.8.1",
            status="rejected",
            statement="Management asserts that all information assets are inventoried "
            "and classified according to the data classification policy.",
            evidence_references=[
                {"finding_id": "silo-scan-001", "description": "Data silo discovery report"},
            ],
            prepared_by="carol.park@acme.com",
            prepared_at=NOW - timedelta(days=20),
            submitted_by="carol.park@acme.com",
            submitted_at=NOW - timedelta(days=18),
            reviewed_by="sarah.chen@deloitte.com",
            reviewed_at=NOW - timedelta(days=15),
            review_notes="Asset inventory does not include shadow IT resources discovered in cloud scan.",
            rejected_by="sarah.chen@deloitte.com",
            rejected_at=NOW - timedelta(days=15),
            rejection_reason="Incomplete coverage: 12 unclassified S3 buckets found by automated scan.",
        ),
    ]

    for a in attestations:
        session.add(a)
    session.commit()
    return len(attestations)


# ---------------------------------------------------------------------------
# GAP-9/GAP-10: Age ~50 findings for SLA breach / aging demos
# ---------------------------------------------------------------------------


def _age_findings(session) -> int:
    """Backdate ~50 findings across 7-90 days ago for SLA/aging demos."""
    findings = session.query(Finding).limit(50).all()
    if not findings:
        return 0

    aged = 0
    age_buckets = [
        (7, 14),  # 10 findings: 1-2 weeks old
        (15, 30),  # 15 findings: 2-4 weeks old
        (31, 60),  # 15 findings: 1-2 months old
        (61, 90),  # 10 findings: 2-3 months old
    ]
    bucket_sizes = [10, 15, 15, 10]
    idx = 0
    for bucket_idx, (lo, hi) in enumerate(age_buckets):
        for _ in range(bucket_sizes[bucket_idx]):
            if idx >= len(findings):
                break
            days_ago = random.randint(lo, hi)
            old_ts = NOW - timedelta(days=days_ago, hours=random.randint(0, 23))
            findings[idx].created_at = old_ts
            findings[idx].observed_at = old_ts
            idx += 1
            aged += 1

    session.commit()
    return aged


# ---------------------------------------------------------------------------
# GAP-12: Seed vendors with varied risk scores
# ---------------------------------------------------------------------------


def _seed_vendors(session) -> int:
    """Create Vendor records with varied risk scores (30-90 range)."""
    existing = {row[0] for row in session.query(Vendor.name).all()}
    vendors = [
        Vendor(
            name="Stripe",
            tier="critical",
            risk_score=32.0,
            contract_expires=NOW + timedelta(days=365),
            last_assessment=NOW - timedelta(days=30),
            assessment_cadence_days=90,
            metadata_={"industry": "Financial Services", "ssc_grade": "A"},
        ),
        Vendor(
            name="Datadog",
            tier="critical",
            risk_score=38.0,
            contract_expires=NOW + timedelta(days=200),
            last_assessment=NOW - timedelta(days=45),
            assessment_cadence_days=90,
            metadata_={"industry": "Technology", "ssc_grade": "A"},
        ),
        Vendor(
            name="CloudBackup Pro",
            tier="high",
            risk_score=82.0,
            contract_expires=NOW + timedelta(days=60),
            last_assessment=NOW - timedelta(days=120),
            assessment_cadence_days=90,
            metadata_={"industry": "Technology", "ssc_grade": "F", "overdue_assessment": True},
        ),
        Vendor(
            name="Acme Staffing Co",
            tier="medium",
            risk_score=67.0,
            contract_expires=NOW + timedelta(days=180),
            last_assessment=NOW - timedelta(days=60),
            assessment_cadence_days=180,
            metadata_={"industry": "Staffing", "ssc_grade": "D"},
        ),
        Vendor(
            name="QuickDocs",
            tier="low",
            risk_score=53.0,
            contract_expires=NOW + timedelta(days=400),
            last_assessment=NOW - timedelta(days=90),
            assessment_cadence_days=365,
            metadata_={"industry": "SaaS", "ssc_grade": "C"},
        ),
        Vendor(
            name="SecureAuth Corp",
            tier="critical",
            risk_score=30.0,
            contract_expires=NOW + timedelta(days=300),
            last_assessment=NOW - timedelta(days=15),
            assessment_cadence_days=90,
            metadata_={"industry": "Cybersecurity", "ssc_grade": "A"},
        ),
        Vendor(
            name="LegacySoft Inc",
            tier="high",
            risk_score=89.0,
            contract_expires=NOW + timedelta(days=30),
            last_assessment=NOW - timedelta(days=200),
            assessment_cadence_days=90,
            metadata_={
                "industry": "Enterprise Software",
                "ssc_grade": "F",
                "overdue_assessment": True,
                "eol_product": True,
            },
        ),
        Vendor(
            name="GlobalPayments Ltd",
            tier="critical",
            risk_score=45.0,
            contract_expires=NOW + timedelta(days=540),
            last_assessment=NOW - timedelta(days=25),
            assessment_cadence_days=90,
            metadata_={"industry": "Financial Services", "ssc_grade": "B", "pci_compliant": True},
        ),
    ]

    added = 0
    for v in vendors:
        if v.name not in existing:
            session.add(v)
            added += 1
    session.commit()
    return added


def _seed_alerts(session) -> int:
    """Create sample alerts across severities and categories."""
    from warlock.db.models import Alert

    now = NOW
    alerts_data = [
        {
            "title": "Control drift: NIST 800-53 AC-2 regressed to non_compliant",
            "description": "AC-2 was compliant last week, now failing after IAM policy change.",
            "severity": "high",
            "category": "control_drift",
            "framework": "nist_800_53",
            "control_id": "AC-2",
            "status": "open",
            "rule_name": "control_previously_passing_now_failing",
        },
        {
            "title": "Critical finding: Root account MFA disabled",
            "description": "AWS root account does not have MFA enabled.",
            "severity": "critical",
            "category": "new_finding",
            "status": "open",
            "rule_name": "critical_finding_detected",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1078 - Valid Accounts",
            "framework": "nist_800_53",
            "control_id": "IA-2",
        },
        {
            "title": "Connector failure: tenable_io",
            "description": "Tenable.io connector returned HTTP 503 during scan import.",
            "severity": "high",
            "category": "connector_failure",
            "connector_name": "tenable_io",
            "status": "acknowledged",
            "rule_name": "connector_health_failure",
        },
        {
            "title": "High non-compliance: HIPAA at 62%",
            "description": "HIPAA framework has 40/64 controls non-compliant.",
            "severity": "high",
            "category": "threshold_breach",
            "framework": "hipaa",
            "status": "open",
            "rule_name": "high_non_compliance_rate",
        },
        {
            "title": "Stale connector: crowdstrike_falcon",
            "description": "CrowdStrike Falcon connector last ran 36 hours ago.",
            "severity": "medium",
            "category": "policy_violation",
            "connector_name": "crowdstrike_falcon",
            "status": "open",
            "rule_name": "stale_connector",
        },
        {
            "title": "Critical finding: S3 bucket publicly accessible",
            "description": "Bucket acme-prod-data has public read access enabled.",
            "severity": "critical",
            "category": "new_finding",
            "status": "resolved",
            "rule_name": "critical_finding_detected",
            "mitre_tactic": "Collection",
            "mitre_technique": "T1530 - Data from Cloud Storage",
            "framework": "nist_800_53",
            "control_id": "AC-3",
        },
        {
            "title": "Control drift: SOC 2 CC6.1 regressed",
            "description": "Logical access control CC6.1 failing after firewall rule change.",
            "severity": "high",
            "category": "control_drift",
            "framework": "soc2",
            "control_id": "CC6.1",
            "status": "open",
            "rule_name": "control_previously_passing_now_failing",
        },
        {
            "title": "Connector failure: okta_system_log",
            "description": "Okta system log connector timed out after 60s.",
            "severity": "medium",
            "category": "connector_failure",
            "connector_name": "okta_system_log",
            "status": "dismissed",
            "rule_name": "connector_health_failure",
        },
        {
            "title": "High non-compliance: PCI DSS at 55%",
            "description": "PCI DSS v4.0 has 35/63 controls non-compliant.",
            "severity": "high",
            "category": "threshold_breach",
            "framework": "pci_dss",
            "status": "open",
            "rule_name": "high_non_compliance_rate",
        },
        {
            "title": "Critical finding: Unencrypted RDS instance",
            "description": "RDS instance prod-db-01 does not have encryption at rest.",
            "severity": "critical",
            "category": "new_finding",
            "status": "acknowledged",
            "rule_name": "critical_finding_detected",
            "mitre_tactic": "Exfiltration",
            "mitre_technique": "T1567 - Exfiltration Over Web Service",
        },
        {
            "title": "Stale connector: qualys_vmdr",
            "description": "Qualys VMDR connector last ran 48 hours ago.",
            "severity": "medium",
            "category": "policy_violation",
            "connector_name": "qualys_vmdr",
            "status": "open",
            "rule_name": "stale_connector",
        },
        {
            "title": "Control drift: ISO 27001 A.9.2.3 regressed",
            "description": "Privileged access management control now non_compliant.",
            "severity": "high",
            "category": "control_drift",
            "framework": "iso_27001",
            "control_id": "A.9.2.3",
            "status": "open",
            "rule_name": "control_previously_passing_now_failing",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1078.004 - Cloud Accounts",
        },
        {
            "title": "Lateral movement detected: Pass-the-Hash via compromised service account",
            "description": "EDR detected NTLM relay attack from svc-deploy to prod-db-01.",
            "severity": "critical",
            "category": "new_finding",
            "status": "open",
            "rule_name": "edr_behavioral_detection",
            "mitre_tactic": "Lateral Movement",
            "mitre_technique": "T1550.002 - Pass the Hash",
            "framework": "nist_800_53",
            "control_id": "AC-17",
        },
        {
            "title": "Credential stuffing campaign targeting SSO portal",
            "description": "50K+ failed login attempts from rotating IPs against login.acme.com.",
            "severity": "high",
            "category": "new_finding",
            "status": "open",
            "rule_name": "siem_brute_force_detection",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110.004 - Credential Stuffing",
            "framework": "nist_800_53",
            "control_id": "AC-7",
        },
        {
            "title": "Suspicious PowerShell execution on endpoint WIN-SRV-042",
            "description": "Encoded PowerShell command downloading payload from external IP.",
            "severity": "high",
            "category": "new_finding",
            "status": "acknowledged",
            "rule_name": "edr_behavioral_detection",
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059.001 - PowerShell",
        },
        {
            "title": "Data exfiltration attempt to unauthorized cloud storage",
            "description": "DLP alert: 2.3GB uploaded to personal Google Drive from corp device.",
            "severity": "critical",
            "category": "policy_violation",
            "status": "open",
            "rule_name": "dlp_exfiltration_detection",
            "mitre_tactic": "Exfiltration",
            "mitre_technique": "T1567.002 - Exfiltration to Cloud Storage",
        },
    ]

    import uuid

    added = 0
    for data in alerts_data:
        alert = Alert(
            id=str(uuid.uuid4()),
            title=data["title"],
            description=data.get("description"),
            severity=data["severity"],
            category=data["category"],
            framework=data.get("framework"),
            control_id=data.get("control_id"),
            connector_name=data.get("connector_name"),
            mitre_tactic=data.get("mitre_tactic"),
            mitre_technique=data.get("mitre_technique"),
            status=data["status"],
            rule_name=data.get("rule_name"),
            rule_metadata={"seeded": True},
            triggered_at=now - timedelta(hours=random.randint(1, 72)),
            created_at=now - timedelta(hours=random.randint(1, 72)),
        )
        if data["status"] == "acknowledged":
            alert.acknowledged_by = "security-analyst@acme.com"
            alert.acknowledged_at = now - timedelta(hours=random.randint(0, 12))
        elif data["status"] == "resolved":
            alert.resolved_by = "security-lead@acme.com"
            alert.resolved_at = now - timedelta(hours=random.randint(0, 6))
            alert.resolution_notes = "Remediated and verified."
        elif data["status"] == "dismissed":
            alert.resolved_by = "security-analyst@acme.com"
            alert.resolved_at = now - timedelta(hours=random.randint(0, 6))
            alert.resolution_notes = "False positive -- transient API error."
        session.add(alert)
        added += 1

    session.commit()
    return added


def _seed_remediations(session) -> int:
    """Create sample remediations in various lifecycle stages."""
    from warlock.db.models import Remediation

    now = NOW
    remediations_data = [
        {
            "title": "Enable MFA on AWS root account",
            "description": "Root account MFA must be enabled per NIST AC-2.",
            "framework": "nist_800_53",
            "control_id": "AC-2",
            "status": "open",
        },
        {
            "title": "Encrypt RDS instance prod-db-01",
            "description": "Enable encryption at rest for production database.",
            "framework": "pci_dss",
            "control_id": "3.4.1",
            "status": "assigned",
            "assigned_to": "dba-team@acme.com",
        },
        {
            "title": "Restrict S3 bucket acme-prod-data",
            "description": "Remove public read ACL and enable bucket policy.",
            "framework": "soc2",
            "control_id": "CC6.1",
            "status": "in_progress",
            "assigned_to": "cloud-ops@acme.com",
        },
        {
            "title": "Update CrowdStrike Falcon connector credentials",
            "description": "API token expired, causing connector failures.",
            "status": "verification",
            "assigned_to": "secops@acme.com",
        },
        {
            "title": "Patch CVE-2025-1234 on web servers",
            "description": "Critical OpenSSL vulnerability requires patching.",
            "framework": "nist_800_53",
            "control_id": "SI-2",
            "status": "closed",
            "assigned_to": "infra-team@acme.com",
        },
        {
            "title": "Implement privileged access review workflow",
            "description": "Quarterly PAM review required by ISO 27001 A.9.2.3.",
            "framework": "iso_27001",
            "control_id": "A.9.2.3",
            "status": "in_progress",
            "assigned_to": "iam-team@acme.com",
        },
        {
            "title": "Fix HIPAA audit log retention policy",
            "description": "Audit logs must be retained for 6 years per HIPAA.",
            "framework": "hipaa",
            "control_id": "164.312(b)",
            "status": "assigned",
            "assigned_to": "compliance@acme.com",
        },
    ]

    import uuid

    added = 0
    for data in remediations_data:
        rem = Remediation(
            id=str(uuid.uuid4()),
            title=data["title"],
            description=data.get("description"),
            framework=data.get("framework"),
            control_id=data.get("control_id"),
            status=data["status"],
            created_by="demo-seed@warlock",
            created_at=now - timedelta(days=random.randint(1, 14)),
            updated_at=now - timedelta(hours=random.randint(0, 48)),
        )
        if data.get("assigned_to"):
            rem.assigned_to = data["assigned_to"]
            rem.assigned_by = "security-lead@acme.com"
            rem.assigned_at = now - timedelta(days=random.randint(0, 7))
        if data["status"] == "closed":
            rem.closed_at = now - timedelta(hours=random.randint(1, 24))
            rem.verified_by = "audit-lead@acme.com"
            rem.verified_at = now - timedelta(hours=random.randint(1, 24))
            rem.verification_notes = "Verified via scan rescan and manual check."
        if data["status"] == "verification":
            rem.verified_by = None  # awaiting verification
        session.add(rem)
        added += 1

    session.commit()
    return added


def _seed_pipeline_runs(session) -> int:
    """Create sample PipelineRun records."""
    import uuid

    from warlock.db.models import PipelineRun

    now = NOW
    runs = [
        PipelineRun(
            id=str(uuid.uuid4()),
            status="completed",
            connectors_succeeded=351,
            connectors_failed=0,
            raw_events_collected=1071,
            findings_normalized=7325,
            controls_mapped=373852,
            started_at=now - timedelta(hours=2),
            completed_at=now - timedelta(hours=2) + timedelta(seconds=7),
            duration_seconds=7.0,
            triggered_by="scheduler",
        ),
        PipelineRun(
            id=str(uuid.uuid4()),
            status="completed",
            connectors_succeeded=351,
            connectors_failed=0,
            raw_events_collected=1071,
            findings_normalized=7320,
            controls_mapped=373840,
            started_at=now - timedelta(days=1),
            completed_at=now - timedelta(days=1) + timedelta(seconds=8),
            duration_seconds=8.0,
            triggered_by="demo-seed@warlock",
        ),
        PipelineRun(
            id=str(uuid.uuid4()),
            status="failed",
            connectors_succeeded=160,
            connectors_failed=5,
            raw_events_collected=550,
            findings_normalized=0,
            controls_mapped=0,
            errors=["Timeout on tenable_io", "Auth failure on okta", "Rate limit on crowdstrike"],
            started_at=now - timedelta(days=3),
            completed_at=now - timedelta(days=3) + timedelta(seconds=120),
            duration_seconds=120.0,
            triggered_by="ci-pipeline@acme.com",
        ),
    ]

    for run in runs:
        session.add(run)
    session.commit()
    return len(runs)


def _seed_feature_coverage(session) -> dict:
    """Seed data for 20 features that currently show 'no data' in the demo.

    Returns a dict with counts of records created/updated per feature.
    """
    import uuid

    from warlock.db.audit import AuditTrail
    from warlock.db.models import ControlMapping, ControlResult, Finding, Issue

    trail = AuditTrail(session)
    now = NOW
    counts = {}

    # SEED-1: Access review campaigns (via AuditEntry)
    campaigns = [
        {
            "name": "Q1-2026 Privileged Access Review",
            "status": "completed",
            "started": (now - timedelta(days=60)).isoformat(),
            "completed": (now - timedelta(days=30)).isoformat(),
            "users_reviewed": 35,
            "findings": 2,
        },
        {
            "name": "Q2-2026 SOX Critical Systems Review",
            "status": "active",
            "started": (now - timedelta(days=5)).isoformat(),
            "completed": None,
            "users_reviewed": 12,
            "findings": 0,
        },
    ]
    for i, c in enumerate(campaigns):
        trail.record(
            action="access_review_campaign",
            entity_type="access_review",
            entity_id=f"ARC-{i + 1:03d}",
            actor="identity-governance@acme.com",
            metadata=c,
        )
    counts["access_review_campaigns"] = len(campaigns)

    # SEED-2: Group membership change audit entries
    # CLI queries: action in ["group_membership_changed","idp_group_change","access_review_campaign"]
    #              entity_type in ["personnel","idp","access_review"]
    group_changes = [
        {
            "user_email": "alice.wong@acme.com",
            "group_added": "prod-admins",
            "approved_by": "hassan.ali@acme.com",
        },
        {
            "user_email": "bob.singh@acme.com",
            "group_removed": "security-readers",
            "approved_by": "eve.nakamura@acme.com",
        },
        {
            "user_email": "carol.park@acme.com",
            "group_added": "database-admins",
            "approved_by": "hassan.ali@acme.com",
        },
    ]
    for i, gc in enumerate(group_changes):
        trail.record(
            action="group_membership_changed",
            entity_type="personnel",
            entity_id=f"GRP-{i + 1:03d}",
            actor=gc["approved_by"],
            metadata=gc,
        )
    counts["group_changes"] = len(group_changes)

    # SEED-3: Attestation near expiry (update existing)
    from warlock.db.models import Attestation

    near_expiry_attest = session.query(Attestation).filter(Attestation.status == "approved").first()
    if near_expiry_attest:
        near_expiry_attest.approved_at = now - timedelta(days=335)
        session.flush()
        counts["attestation_near_expiry"] = 1
    else:
        counts["attestation_near_expiry"] = 0

    # SEED-5: Additional audit trail entries (diverse actions)
    extra_actions = [
        (
            "policy_updated",
            "Policy",
            "POL-SEC-001",
            "eve.nakamura@acme.com",
            {"policy": "Information Security Policy", "version": "3.2"},
        ),
        (
            "policy_updated",
            "Policy",
            "POL-ACC-001",
            "hassan.ali@acme.com",
            {"policy": "Access Control Policy", "version": "2.1"},
        ),
        (
            "risk_assessment_completed",
            "RiskAssessment",
            "RA-2026-Q1",
            "grace.kim@acme.com",
            {"framework": "nist_800_53", "scope": "production", "residual_risk": "medium"},
        ),
        (
            "control_override",
            "ControlResult",
            "CO-001",
            "eve.nakamura@acme.com",
            {
                "control_id": "AC-6",
                "from_status": "non_compliant",
                "to_status": "risk_accepted",
                "justification": "Compensating control in place",
            },
        ),
        (
            "evidence_uploaded",
            "Evidence",
            "EV-2026-042",
            "frank.torres@acme.com",
            {"filename": "penetration_test_report_q1.pdf", "size_bytes": 2450000},
        ),
        (
            "evidence_uploaded",
            "Evidence",
            "EV-2026-043",
            "carol.park@acme.com",
            {"filename": "access_review_q1.xlsx", "size_bytes": 185000},
        ),
        (
            "system_registered",
            "SystemProfile",
            "SYS-NEW-001",
            "hassan.ali@acme.com",
            {"name": "AI Model Registry", "classification": "internal"},
        ),
        (
            "vendor_assessed",
            "Vendor",
            "VND-005",
            "grace.kim@acme.com",
            {"vendor": "CloudBackup Pro", "risk_score": 45, "tier": "critical"},
        ),
        (
            "training_completed",
            "Personnel",
            "PER-028",
            "system",
            {"course": "Security Awareness 2026", "score": 92},
        ),
        (
            "training_completed",
            "Personnel",
            "PER-031",
            "system",
            {"course": "GDPR Privacy Essentials", "score": 88},
        ),
    ]
    for action, etype, eid, actor, meta in extra_actions:
        trail.record(
            action=action,
            entity_type=etype,
            entity_id=eid,
            actor=actor,
            metadata=meta,
        )
    counts["extra_audit_entries"] = len(extra_actions)

    # SEED-6: Automation rules
    auto_rules = [
        {
            "rule_name": "auto_create_issue_on_critical",
            "trigger": "finding.severity == critical",
            "action": "create_issue",
            "enabled": True,
        },
        {
            "rule_name": "auto_notify_drift",
            "trigger": "control.status_changed",
            "action": "send_alert",
            "channel": "slack:#grc-alerts",
            "enabled": True,
        },
        {
            "rule_name": "auto_assign_pci",
            "trigger": "issue.framework == pci_dss",
            "action": "assign_to",
            "assignee": "pci-team@acme.com",
            "enabled": False,
        },
    ]
    for i, rule in enumerate(auto_rules):
        trail.record(
            action="automation_rule",
            entity_type="AutomationRule",
            entity_id=f"RULE-{i + 1:03d}",
            actor="admin@acme.com",
            metadata=rule,
        )
    counts["automation_rules"] = len(auto_rules)

    # SEED-7: Automation schedules
    schedules = [
        {
            "name": "nightly_pipeline_run",
            "cron": "0 2 * * *",
            "task": "pipeline.run",
            "enabled": True,
            "last_run": (now - timedelta(hours=8)).isoformat(),
        },
        {
            "name": "weekly_posture_snapshot",
            "cron": "0 6 * * 1",
            "task": "posture.snapshot",
            "enabled": True,
            "last_run": (now - timedelta(days=3)).isoformat(),
        },
    ]
    for i, sched in enumerate(schedules):
        trail.record(
            action="automation_schedule",
            entity_type="Schedule",
            entity_id=f"SCHED-{i + 1:03d}",
            actor="admin@acme.com",
            metadata=sched,
        )
    counts["automation_schedules"] = len(schedules)

    # SEED-8: Automation webhooks
    webhooks = [
        {
            "url": "https://hooks.slack.com/services/T00/B00/xxxx",
            "events": ["alert.created", "alert.critical"],
            "name": "Slack GRC Alerts",
            "active": True,
        },
        {
            "url": "https://api.pagerduty.com/webhooks/v3/grc",
            "events": ["connector.failed", "pipeline.failed"],
            "name": "PagerDuty Escalation",
            "active": True,
        },
    ]
    for i, wh in enumerate(webhooks):
        trail.record(
            action="webhook_registered",
            entity_type="Webhook",
            entity_id=f"WH-{i + 1:03d}",
            actor="admin@acme.com",
            metadata=wh,
        )
    counts["webhooks"] = len(webhooks)

    # SEED-9: Unassigned open issues (update existing)
    unassigned_issues = (
        session.query(Issue)
        .filter(Issue.assigned_to.isnot(None), Issue.status != "closed")
        .limit(5)
        .all()
    )
    for issue in unassigned_issues:
        issue.assigned_to = None
        issue.status = "open"
    session.flush()
    counts["unassigned_issues"] = len(unassigned_issues)

    # SEED-10: Issues with stale linked findings
    stale_findings = (
        session.query(Finding).filter(Finding.observed_at < now - timedelta(days=30)).limit(3).all()
    )
    stale_issue_count = 0
    for sf in stale_findings:
        stale_issue = Issue(
            title=f"Stale finding requires re-scan: {sf.title[:60]}",
            description=(
                f"Finding from source '{sf.source}' is over 30 days old. "
                "Re-scan required to validate current state."
            ),
            finding_id=sf.id,
            framework=None,
            status="open",
            priority="medium",
            source="pipeline",
            tags=["stale-finding", "re-scan-needed"],
            created_by="system",
        )
        session.add(stale_issue)
        stale_issue_count += 1
    session.flush()
    counts["stale_finding_issues"] = stale_issue_count

    # SEED-11: BCP/DR test results
    # CLI queries AuditComment with target_type="dr_test", NOT AuditEntry.
    # AuditComment requires an engagement_id, so use the first engagement.
    import json as _json

    from warlock.db.models import AuditComment, AuditEngagement, SystemProfile

    engagement = session.query(AuditEngagement).first()
    sys_profiles = session.query(SystemProfile).limit(3).all()
    dr_count = 0
    if engagement and sys_profiles:
        dr_tests_data = [
            {
                "sys_idx": 0,
                "test_type": "full_failover",
                "test_result": "pass",
                "rto_target_minutes": 240,
                "rto_actual_minutes": 150,
                "rpo_target_minutes": 60,
                "rpo_actual_minutes": 30,
                "tested_at": (now - timedelta(days=45)).isoformat(),
                "tested_by": "bcp-lead@acme.com",
                "notes": "Full site failover to us-west-2 completed successfully",
                "days_ago": 45,
            },
            {
                "sys_idx": 1,
                "test_type": "backup_restore",
                "test_result": "fail",
                "rto_target_minutes": 120,
                "rto_actual_minutes": 186,
                "tested_at": (now - timedelta(days=20)).isoformat(),
                "tested_by": "dba@acme.com",
                "notes": "Database restore took longer than RTO target",
                "days_ago": 20,
            },
            {
                "sys_idx": 2 % len(sys_profiles),
                "test_type": "tabletop",
                "test_result": "pass",
                "tested_at": (now - timedelta(days=10)).isoformat(),
                "tested_by": "ciso@acme.com",
                "notes": "Ransomware tabletop exercise - gap in weekend comms",
                "days_ago": 10,
            },
        ]
        for dt in dr_tests_data:
            sp = sys_profiles[dt["sys_idx"]]
            content = {
                "system_name": sp.name,
                "test_type": dt["test_type"],
                "test_result": dt["test_result"],
                "rto_target_minutes": dt.get("rto_target_minutes"),
                "rto_actual_minutes": dt.get("rto_actual_minutes"),
                "rpo_target_minutes": dt.get("rpo_target_minutes"),
                "rpo_actual_minutes": dt.get("rpo_actual_minutes"),
                "tested_at": dt["tested_at"],
                "tested_by": dt["tested_by"],
                "notes": dt["notes"],
            }
            comment = AuditComment(
                engagement_id=engagement.id,
                target_type="dr_test",
                target_id=sp.id,
                author=dt["tested_by"],
                author_role="practitioner",
                content=_json.dumps(content),
                created_at=now - timedelta(days=dt["days_ago"]),
            )
            session.add(comment)
            dr_count += 1
        session.flush()
    counts["dr_tests"] = dr_count

    # SEED-12: Calendar items
    # CLI queries: action="calendar_item", entity_type="calendar"
    # Extra must have "due_date" (ISO string), "title", "type", optional "recurring"
    cal_items = [
        {
            "title": "SOC 2 Type II Audit - Fieldwork Start",
            "due_date": (now + timedelta(days=14)).isoformat(),
            "type": "audit",
            "recurring": None,
            "created_by": "eve.nakamura@acme.com",
            "created_at": now.isoformat(),
        },
        {
            "title": "Quarterly Access Review Deadline",
            "due_date": (now + timedelta(days=7)).isoformat(),
            "type": "review",
            "recurring": "quarterly",
            "created_by": "hassan.ali@acme.com",
            "created_at": now.isoformat(),
        },
        {
            "title": "PCI DSS Self-Assessment Due",
            "due_date": (now + timedelta(days=30)).isoformat(),
            "type": "deadline",
            "recurring": "annual",
            "created_by": "frank.torres@acme.com",
            "created_at": now.isoformat(),
        },
        {
            "title": "ISO 27001 Surveillance Audit",
            "due_date": (now + timedelta(days=60)).isoformat(),
            "type": "audit",
            "recurring": "annual",
            "created_by": "eve.nakamura@acme.com",
            "created_at": now.isoformat(),
        },
    ]
    for i, ci in enumerate(cal_items):
        trail.record(
            action="calendar_item",
            entity_type="calendar",
            entity_id=f"CAL-{i + 1:03d}",
            actor=ci["created_by"],
            metadata=ci,
        )
    counts["calendar_items"] = len(cal_items)

    # SEED-13: Change requests
    # CLI queries: action="change_request", entity_type="change_mgmt"
    # Extra must have: type, title, impact, description, status, created_by, created_at, history
    change_reqs = [
        {
            "type": "standard",
            "title": "Firewall rule change: allow port 8443 for API gateway",
            "impact": "medium",
            "description": "Open port 8443 on prod ALB for new API gateway endpoint.",
            "status": "approved",
            "created_by": "devops@acme.com",
            "created_at": (now - timedelta(days=5)).isoformat(),
            "approved_by": "security-lead@acme.com",
            "approved_at": (now - timedelta(days=3)).isoformat(),
            "history": [
                {
                    "action": "created",
                    "by": "devops@acme.com",
                    "at": (now - timedelta(days=5)).isoformat(),
                },
                {
                    "action": "approved",
                    "by": "security-lead@acme.com",
                    "at": (now - timedelta(days=3)).isoformat(),
                },
            ],
        },
        {
            "type": "normal",
            "title": "IAM policy update: restrict S3 cross-account access",
            "impact": "high",
            "description": "Tighten S3 bucket policies to deny cross-account access without explicit allow.",
            "status": "pending",
            "created_by": "cloud-team@acme.com",
            "created_at": (now - timedelta(days=2)).isoformat(),
            "history": [
                {
                    "action": "created",
                    "by": "cloud-team@acme.com",
                    "at": (now - timedelta(days=2)).isoformat(),
                },
            ],
        },
        {
            "type": "standard",
            "title": "TLS certificate rotation for *.acme.com",
            "impact": "low",
            "description": "Rotate wildcard TLS cert before expiry.",
            "status": "implemented",
            "created_by": "infra@acme.com",
            "created_at": (now - timedelta(days=10)).isoformat(),
            "history": [
                {
                    "action": "created",
                    "by": "infra@acme.com",
                    "at": (now - timedelta(days=10)).isoformat(),
                },
                {
                    "action": "approved",
                    "by": "security-lead@acme.com",
                    "at": (now - timedelta(days=8)).isoformat(),
                },
                {
                    "action": "implemented",
                    "by": "infra@acme.com",
                    "at": (now - timedelta(days=3)).isoformat(),
                },
            ],
        },
        {
            "type": "emergency",
            "title": "Emergency patch: log4j CVE-2024-XXXX mitigation",
            "impact": "critical",
            "description": "Apply emergency WAF rule to block exploit attempts.",
            "status": "implemented",
            "created_by": "security-ops@acme.com",
            "created_at": (now - timedelta(days=1)).isoformat(),
            "emergency_justified_by": "ciso@acme.com",
            "history": [
                {
                    "action": "created",
                    "by": "security-ops@acme.com",
                    "at": (now - timedelta(days=1)).isoformat(),
                },
                {
                    "action": "emergency_escalation",
                    "by": "ciso@acme.com",
                    "at": (now - timedelta(days=1)).isoformat(),
                    "note": "Active exploitation in the wild",
                },
                {
                    "action": "implemented",
                    "by": "security-ops@acme.com",
                    "at": (now - timedelta(hours=20)).isoformat(),
                },
            ],
        },
    ]
    for i, cr in enumerate(change_reqs):
        trail.record(
            action="change_request",
            entity_type="change_mgmt",
            entity_id=f"CR-{i + 1:03d}",
            actor=cr.get("created_by", "system"),
            metadata=cr,
        )
    counts["change_requests"] = len(change_reqs)

    # SEED-14: Regulatory changes
    # RegulatoryChangeManager queries: action="regulatory_change", entity_type="regulatory_change"
    # Extra must have: title, framework, description, effective_date, impact_level, status, created_by
    reg_changes = [
        {
            "title": "EU AI Act enforcement deadline approaching",
            "framework": "eu_ai_act",
            "status": "pending",
            "effective_date": "2026-08-01",
            "impact_level": "high",
            "description": "High-risk AI systems must comply by Aug 2026",
            "created_by": "compliance-intel@acme.com",
        },
        {
            "title": "NIST CSF 2.0 updated supply chain risk guidance",
            "framework": "nist_csf",
            "status": "pending",
            "effective_date": "2026-06-15",
            "impact_level": "medium",
            "description": "New GV.SC subcategories require updated controls",
            "created_by": "compliance-intel@acme.com",
        },
        {
            "title": "PCI DSS 4.0 migration deadline",
            "framework": "pci_dss",
            "status": "assessed",
            "effective_date": "2025-03-31",
            "impact_level": "critical",
            "description": "All organizations must be fully compliant with v4.0",
            "created_by": "compliance-intel@acme.com",
        },
    ]
    for i, rc in enumerate(reg_changes):
        trail.record(
            action="regulatory_change",
            entity_type="regulatory_change",
            entity_id=f"REG-{i + 1:03d}",
            actor="compliance-intel@acme.com",
            metadata=rc,
        )
    counts["regulatory_changes"] = len(reg_changes)

    # SEED-15: Shared dashboards
    # CLI queries: action="shared_dashboard", entity_type="dashboard"
    # Extra must have: name, type, owner, shared_with, created_at
    dashboards = [
        {
            "name": "Executive Compliance Overview",
            "type": "posture",
            "owner": "eve.nakamura@acme.com",
            "shared_with": ["ciso@acme.com", "cto@acme.com"],
            "created_at": now.isoformat(),
            "config": {},
        },
        {
            "name": "SOC 2 Audit Prep Board",
            "type": "audit",
            "owner": "hassan.ali@acme.com",
            "shared_with": ["audit-team@acme.com", "eve.nakamura@acme.com"],
            "created_at": now.isoformat(),
            "config": {},
        },
        {
            "name": "Vulnerability Management Tracker",
            "type": "risk",
            "owner": "frank.torres@acme.com",
            "shared_with": ["security-ops@acme.com"],
            "created_at": now.isoformat(),
            "config": {},
        },
    ]
    for i, db in enumerate(dashboards):
        trail.record(
            action="shared_dashboard",
            entity_type="dashboard",
            entity_id=f"DASH-{i + 1:03d}",
            actor=db["owner"],
            metadata=db,
        )
    counts["shared_dashboards"] = len(dashboards)

    # SEED-16a: False-positive findings
    # CLI queries Finding.detail["_false_positive"] or ["_suppressed"]
    from warlock.db.models import Finding as _Finding

    fp_findings = session.query(_Finding).filter(_Finding.detail.isnot(None)).limit(5).all()
    fp_count = 0
    for i, f in enumerate(fp_findings):
        detail = dict(f.detail) if isinstance(f.detail, dict) else {}
        if i < 3:
            detail["_false_positive"] = True
            detail["_false_positive_reason"] = [
                "Duplicate of finding in production scanner",
                "Test environment artifact - not applicable to prod",
                "Verified compensating control in place per CAB approval",
            ][i]
            detail["_false_positive_by"] = "security-analyst@acme.com"
            detail["_false_positive_at"] = (now - timedelta(days=i + 1)).isoformat()
        else:
            detail["_suppressed"] = True
            detail["_suppressed_reason"] = "Risk accepted per exception EXC-001"
            detail["_suppressed_by"] = "ciso@acme.com"
            detail["_suppressed_at"] = (now - timedelta(days=i + 1)).isoformat()
        f.detail = detail
        fp_count += 1
    session.flush()
    counts["false_positive_findings"] = fp_count

    # SEED-16b: Privacy breach records
    # CLI queries: entity_type="privacy_breach", action="breach_created"
    breaches = [
        {
            "title": "Stolen laptop with customer PII",
            "description": "Employee laptop containing customer PII stolen from vehicle",
            "severity": "high",
            "status": "investigating",
            "individuals_affected": 2500,
            "data_types": ["name", "email", "SSN"],
            "reported_to_authority": True,
            "authority_notification_date": (now - timedelta(days=3)).isoformat(),
            "discovery_date": (now - timedelta(days=5)).strftime("%Y-%m-%d"),
        },
        {
            "title": "S3 bucket exposure of customer invoices",
            "description": "Misconfigured S3 bucket exposed customer invoices for 48 hours",
            "severity": "medium",
            "status": "contained",
            "individuals_affected": 850,
            "data_types": ["name", "email", "billing_address"],
            "reported_to_authority": False,
            "discovery_date": (now - timedelta(days=12)).strftime("%Y-%m-%d"),
        },
        {
            "title": "HR shared drive compromised via phishing",
            "description": "Phishing attack compromised HR shared drive with employee records",
            "severity": "critical",
            "status": "notified",
            "individuals_affected": 5200,
            "data_types": ["name", "SSN", "salary", "health_plan"],
            "reported_to_authority": True,
            "authority_notification_date": (now - timedelta(days=1)).isoformat(),
            "discovery_date": (now - timedelta(days=2)).strftime("%Y-%m-%d"),
        },
    ]
    for i, b in enumerate(breaches):
        trail.record(
            action="breach_created",
            entity_type="privacy_breach",
            entity_id=f"BREACH-{i + 1:03d}",
            actor="privacy-officer@acme.com",
            metadata=b,
        )
    counts["privacy_breaches"] = len(breaches)

    # SEED-16c: DSAR records
    # CLI queries: entity_type="dsar", action="dsar_created"
    dsars = [
        {
            "subject": "john.doe@example.com",
            "type": "access",
            "status": "open",
            "deadline": (now + timedelta(days=25)).isoformat(),
            "notes": "Subject requesting copy of all personal data held",
        },
        {
            "subject": "jane.smith@example.com",
            "type": "erasure",
            "status": "in_progress",
            "deadline": (now + timedelta(days=10)).isoformat(),
            "notes": "Right to be forgotten request - customer account closure",
        },
        {
            "subject": "acme-employee-142@acme.com",
            "type": "portability",
            "status": "completed",
            "deadline": (now - timedelta(days=5)).isoformat(),
            "completed_at": (now - timedelta(days=7)).isoformat(),
            "notes": "Employee data export for transfer to new employer",
        },
    ]
    for i, d in enumerate(dsars):
        trail.record(
            action="dsar_created",
            entity_type="dsar",
            entity_id=f"DSAR-{i + 1:03d}",
            actor="privacy-officer@acme.com",
            metadata=d,
        )
    counts["dsars"] = len(dsars)

    # SEED-16d: Data transfer records
    # CLI queries: entity_type="data_transfer", action="transfer_recorded"
    transfers = [
        {
            "source_country": "US",
            "destination": "Germany (Acme GmbH)",
            "mechanism": "SCCs",
            "data_categories": ["customer_pii", "usage_analytics"],
            "recipient": "Acme GmbH (subsidiary)",
            "status": "active",
            "pia_completed": True,
        },
        {
            "source_country": "US",
            "destination": "India (Acme India Pvt Ltd)",
            "mechanism": "BCRs",
            "data_categories": ["employee_data"],
            "recipient": "Acme India Pvt Ltd (subsidiary)",
            "status": "active",
            "pia_completed": True,
        },
        {
            "source_country": "EU",
            "destination": "United States (Acme Corp HQ)",
            "mechanism": "EU-US DPF",
            "data_categories": ["customer_pii", "support_tickets"],
            "recipient": "Acme Corp (HQ)",
            "status": "active",
            "pia_completed": True,
        },
    ]
    for i, t in enumerate(transfers):
        trail.record(
            action="transfer_recorded",
            entity_type="data_transfer",
            entity_id=f"XFER-{i + 1:03d}",
            actor="privacy-officer@acme.com",
            metadata=t,
        )
    counts["data_transfers"] = len(transfers)

    # SEED-16e: Audit workpapers
    # CLI queries: action in ["workpaper_created","workpaper_reviewed","workpaper_signed_off"]
    # Extra must have: engagement_id, control_id, template_type, reviewer
    eng = session.query(AuditEngagement).first()
    if eng:
        workpapers = [
            {
                "engagement_id": eng.id,
                "control_id": "AC-2",
                "template_type": "test_of_design",
                "reviewer": "sarah.chen@deloitte.com",
                "status": "draft",
            },
            {
                "engagement_id": eng.id,
                "control_id": "AC-6",
                "template_type": "test_of_effectiveness",
                "reviewer": "marcus.johnson@ey.com",
                "status": "reviewed",
            },
            {
                "engagement_id": eng.id,
                "control_id": "AU-2",
                "template_type": "walkthrough",
                "reviewer": "sarah.chen@deloitte.com",
                "status": "signed_off",
            },
        ]
        for i, wp in enumerate(workpapers):
            wp_id = f"WP-{i + 1:03d}"
            trail.record(
                action="workpaper_created",
                entity_type="workpaper",
                entity_id=wp_id,
                actor=wp["reviewer"],
                metadata=wp,
            )
            # Add status-change entries for reviewed/signed_off workpapers
            if wp["status"] == "reviewed":
                trail.record(
                    action="workpaper_reviewed",
                    entity_type="workpaper",
                    entity_id=wp_id,
                    actor=wp["reviewer"],
                    metadata=wp,
                )
            elif wp["status"] == "signed_off":
                trail.record(
                    action="workpaper_reviewed",
                    entity_type="workpaper",
                    entity_id=wp_id,
                    actor=wp["reviewer"],
                    metadata=wp,
                )
                trail.record(
                    action="workpaper_signed_off",
                    entity_type="workpaper",
                    entity_id=wp_id,
                    actor="lead-auditor@deloitte.com",
                    metadata=wp,
                )
        counts["workpapers"] = len(workpapers)
    else:
        counts["workpapers"] = 0

    # SEED-17: AI-assessed control results (update 10 existing)
    ai_results = (
        session.query(ControlResult).filter(ControlResult.ai_confidence.is_(None)).limit(10).all()
    )
    ai_texts = [
        "Control operating effectively per IAM policy and CloudTrail evidence.",
        "MFA enforcement verified across all privileged accounts.",
        "Encryption at rest enabled but key rotation exceeds policy threshold.",
        "Network segmentation verified via VPC flow log analysis.",
        "Endpoint protection at 98.5%. Two servers pending agent deployment.",
        "Access review completed within SLA. Three dormant accounts flagged.",
        "Backup restoration test passed. RTO within 4-hour SLA target.",
        "Audit logging enabled across all production systems.",
        "96% of critical patches applied within 14-day window.",
        "Vendor risk score 72/100 meets minimum threshold.",
    ]
    for i, cr in enumerate(ai_results):
        cr.ai_confidence = round(0.7 + random.random() * 0.25, 2)
        cr.ai_model = "demo"
        cr.ai_assessment = ai_texts[i % len(ai_texts)]
    session.flush()
    counts["ai_assessed_results"] = len(ai_results)

    # SEED-18: Closed issues (update 5 existing)
    closeable_issues = (
        session.query(Issue)
        .filter(Issue.status.in_(["open", "assigned", "in_progress", "remediated"]))
        .limit(5)
        .all()
    )
    for i, issue in enumerate(closeable_issues):
        issue.status = "closed"
        issue.closed_at = now - timedelta(days=random.randint(1, 14))
        issue.remediated_at = issue.closed_at - timedelta(days=random.randint(1, 7))
        issue.verification_notes = "Verified remediation through automated scan and manual review."
    session.flush()
    counts["closed_issues"] = len(closeable_issues)

    # SEED-19: Control test gaps — create mappings for controls with NO results at all
    # These show up as "never_tested" in `warlock control-tests gaps`
    anchor_finding_19 = session.query(Finding).first()
    gap_count = 0
    if anchor_finding_19:
        never_tested_controls = [
            ("nist_800_53", "AU-16", "Cross-Organizational Audit", "quarterly"),
            ("nist_800_53", "SC-40", "Wireless Link Protection", "monthly"),
            ("iso_27001", "A.8.28", "Secure Coding", "monthly"),
            ("soc2", "CC9.2", "Risk Mitigation", "daily"),
            ("hipaa", "164.312(e)(2)", "Encryption Mechanism", "weekly"),
            ("pci_dss", "12.10.7", "Incident Response Testing", "quarterly"),
        ]
        for fw, cid, family, freq in never_tested_controls:
            # Only add if no ControlResult exists for this fw/control_id
            existing = (
                session.query(ControlResult)
                .filter(ControlResult.framework == fw, ControlResult.control_id == cid)
                .first()
            )
            if not existing:
                mapping = ControlMapping(
                    id=str(uuid.uuid4()),
                    finding_id=anchor_finding_19.id,
                    framework=fw,
                    control_id=cid,
                    control_family=family,
                    mapping_method="keyword",
                    confidence=0.6,
                    monitoring_frequency=freq,
                    created_at=now - timedelta(days=60),
                )
                session.add(mapping)
                gap_count += 1
    session.flush()
    counts["control_test_gaps"] = gap_count

    # SEED-20: Orphan controls -- mappings with no corresponding result
    anchor_finding = session.query(Finding).first()
    orphan_count = 0
    if anchor_finding:
        orphan_controls = [
            ("nist_800_53", "SA-22", "System and Services Acquisition"),
            ("nist_800_53", "PM-32", "Program Management"),
            ("iso_27001", "A.5.37", "Documented Operating Procedures"),
            ("soc2", "PI1.5", "Processing Integrity"),
        ]
        for fw, cid, family in orphan_controls:
            mapping = ControlMapping(
                id=str(uuid.uuid4()),
                finding_id=anchor_finding.id,
                framework=fw,
                control_id=cid,
                control_family=family,
                mapping_method="keyword",
                confidence=0.4,
                created_at=now - timedelta(days=90),
            )
            session.add(mapping)
            orphan_count += 1
    session.flush()
    counts["orphan_controls"] = orphan_count

    session.commit()
    return counts


def _seed_frontend_enrichment(session) -> dict:
    """Enrich demo data for the frontend rebuild.

    Adds:
    - Failed connector runs (non-zero KRI error rate)
    - More remediations with steps, due dates, and lifecycle variety
    - Better issue status distribution (not all "open")
    - Richer POA&M scenarios (overdue, approaching deadlines)
    """
    import uuid

    from warlock.db.models import POAM, ConnectorRun, Issue, Remediation

    now = NOW
    counts: dict[str, int] = {}

    # --- 1. Failed connector runs (makes KRI error rate ~3%) ---
    failed_runs = [
        {
            "provider": "crowdstrike",
            "source_type": "edr",
            "status": "error",
            "error_count": 1,
            "event_count": 0,
            "started_at": now - timedelta(days=2, hours=6),
            "completed_at": now - timedelta(days=2, hours=6) + timedelta(seconds=5),
        },
        {
            "provider": "splunk",
            "source_type": "siem",
            "status": "error",
            "error_count": 3,
            "event_count": 0,
            "started_at": now - timedelta(days=5, hours=14),
            "completed_at": now - timedelta(days=5, hours=14) + timedelta(seconds=2),
        },
        {
            "provider": "tenable",
            "source_type": "scanner",
            "status": "error",
            "error_count": 1,
            "event_count": 12,
            "started_at": now - timedelta(days=8, hours=3),
            "completed_at": now - timedelta(days=8, hours=3) + timedelta(seconds=45),
        },
        {
            "provider": "okta",
            "source_type": "iam",
            "status": "error",
            "error_count": 2,
            "event_count": 0,
            "started_at": now - timedelta(days=12, hours=9),
            "completed_at": now - timedelta(days=12, hours=9) + timedelta(seconds=3),
        },
        {
            "provider": "wiz",
            "source_type": "scanner",
            "status": "error",
            "error_count": 1,
            "event_count": 5,
            "started_at": now - timedelta(days=20),
            "completed_at": now - timedelta(days=20) + timedelta(seconds=15),
        },
    ]
    for fr in failed_runs:
        session.add(
            ConnectorRun(
                id=str(uuid.uuid4()),
                connector_name=f"demo-{fr['provider']}",
                source=fr["provider"],
                provider=fr["provider"],
                source_type=fr["source_type"],
                status=fr["status"],
                error_count=fr["error_count"],
                event_count=fr["event_count"],
                errors=[f"Connection timed out to {fr['provider']} API"],
                started_at=fr["started_at"],
                completed_at=fr["completed_at"],
                duration_seconds=int((fr["completed_at"] - fr["started_at"]).total_seconds()),
            )
        )
    counts["failed_connector_runs"] = len(failed_runs)

    # --- 2. Additional remediations with steps and due dates ---
    extra_remediations = [
        {
            "title": "Enforce TLS 1.3 on all load balancers",
            "description": "3 ALBs still allow TLS 1.0/1.1. Update security policies to require TLS 1.3.",
            "framework": "pci_dss",
            "control_id": "4.2.1",
            "status": "in_progress",
            "assigned_to": "network-team@acme.com",
            "due_date": now + timedelta(days=7),
            "remediation_steps": [
                {"step": 1, "action": "Identify ALBs with TLS < 1.3", "status": "done"},
                {"step": 2, "action": "Create TLS 1.3-only security policy", "status": "done"},
                {"step": 3, "action": "Apply to staging ALB and test", "status": "in_progress"},
                {
                    "step": 4,
                    "action": "Apply to production ALBs during maintenance window",
                    "status": "pending",
                },
                {"step": 5, "action": "Verify with SSL Labs scan", "status": "pending"},
            ],
        },
        {
            "title": "Rotate all IAM access keys older than 90 days",
            "description": "47 IAM users have access keys >90 days old. Per NIST AC-2, keys must rotate quarterly.",
            "framework": "nist_800_53",
            "control_id": "AC-2",
            "status": "assigned",
            "assigned_to": "iam-team@acme.com",
            "due_date": now + timedelta(days=14),
            "remediation_steps": [
                {"step": 1, "action": "Export credential report from IAM", "status": "pending"},
                {"step": 2, "action": "Identify keys >90 days", "status": "pending"},
                {"step": 3, "action": "Notify users via Slack", "status": "pending"},
                {"step": 4, "action": "Create new keys and deactivate old", "status": "pending"},
                {
                    "step": 5,
                    "action": "Delete deactivated keys after 7-day grace",
                    "status": "pending",
                },
            ],
        },
        {
            "title": "Enable GuardDuty in ap-southeast-1 and eu-central-1",
            "description": "GuardDuty only enabled in us-east-1 and us-west-2. Must cover all active regions.",
            "framework": "nist_800_53",
            "control_id": "SI-4",
            "status": "open",
            "due_date": now + timedelta(days=21),
            "remediation_steps": [
                {"step": 1, "action": "Enable GuardDuty in ap-southeast-1", "status": "pending"},
                {"step": 2, "action": "Enable GuardDuty in eu-central-1", "status": "pending"},
                {
                    "step": 3,
                    "action": "Configure delegated admin for multi-region",
                    "status": "pending",
                },
                {"step": 4, "action": "Verify findings flow to SecurityHub", "status": "pending"},
            ],
        },
        {
            "title": "Remediate open S3 bucket policies (3 buckets)",
            "description": "acme-public-assets, acme-logs-backup, acme-temp-uploads have overly permissive policies.",
            "framework": "soc2",
            "control_id": "CC6.1",
            "status": "verification",
            "assigned_to": "cloud-ops@acme.com",
            "due_date": now - timedelta(days=2),
            "remediation_steps": [
                {"step": 1, "action": "Audit all S3 bucket policies", "status": "done"},
                {
                    "step": 2,
                    "action": "Restrict acme-public-assets to CloudFront OAI",
                    "status": "done",
                },
                {"step": 3, "action": "Move acme-logs-backup to private", "status": "done"},
                {"step": 4, "action": "Delete acme-temp-uploads (unused)", "status": "done"},
                {"step": 5, "action": "Re-scan with Wiz to confirm", "status": "in_progress"},
            ],
        },
        {
            "title": "Implement CMMC L2 encryption at rest for all databases",
            "description": "3 RDS instances and 1 DynamoDB table lack encryption. CMMC SC.L2-3.13.16 requires it.",
            "framework": "cmmc_l2",
            "control_id": "SC.L2-3.13.16",
            "status": "in_progress",
            "assigned_to": "dba-team@acme.com",
            "due_date": now + timedelta(days=3),
            "remediation_steps": [
                {"step": 1, "action": "Snapshot unencrypted RDS instances", "status": "done"},
                {
                    "step": 2,
                    "action": "Restore snapshots with encryption enabled",
                    "status": "done",
                },
                {
                    "step": 3,
                    "action": "Migrate application connections to new endpoints",
                    "status": "in_progress",
                },
                {"step": 4, "action": "Enable encryption on DynamoDB table", "status": "pending"},
                {"step": 5, "action": "Delete old unencrypted instances", "status": "pending"},
            ],
        },
        {
            "title": "Close unused security group rules (12 rules)",
            "description": "12 security group rules reference deprecated CIDR ranges or unused ports.",
            "framework": "nist_800_53",
            "control_id": "SC-7",
            "status": "closed",
            "assigned_to": "infra-team@acme.com",
            "due_date": now - timedelta(days=10),
            "remediation_steps": [
                {
                    "step": 1,
                    "action": "Identify unused SG rules via VPC Flow Logs",
                    "status": "done",
                },
                {"step": 2, "action": "Remove 8 rules in dev/staging", "status": "done"},
                {
                    "step": 3,
                    "action": "Remove 4 rules in production (change window)",
                    "status": "done",
                },
                {"step": 4, "action": "Verify no connectivity impact", "status": "done"},
            ],
        },
        {
            "title": "Configure GDPR-compliant log retention policies",
            "description": "CloudWatch log groups have indefinite retention. GDPR requires defined retention periods.",
            "framework": "gdpr",
            "control_id": "Art.5(1)(e)",
            "status": "in_progress",
            "assigned_to": "compliance@acme.com",
            "due_date": now + timedelta(days=30),
            "remediation_steps": [
                {"step": 1, "action": "Inventory all CloudWatch log groups", "status": "done"},
                {
                    "step": 2,
                    "action": "Classify by data type (PII, system, audit)",
                    "status": "done",
                },
                {
                    "step": 3,
                    "action": "Set retention: PII=90d, system=365d, audit=2555d",
                    "status": "in_progress",
                },
                {"step": 4, "action": "Apply via Terraform", "status": "pending"},
            ],
        },
        {
            "title": "Deploy WAF rules for OWASP Top 10 on API gateway",
            "description": "API gateway has no WAF. Requires SQL injection and XSS protection.",
            "framework": "nist_800_53",
            "control_id": "SI-10",
            "status": "assigned",
            "assigned_to": "appsec@acme.com",
            "due_date": now + timedelta(days=5),
            "remediation_steps": [
                {
                    "step": 1,
                    "action": "Create AWS WAF web ACL with managed rules",
                    "status": "pending",
                },
                {"step": 2, "action": "Enable AWSManagedRulesCommonRuleSet", "status": "pending"},
                {"step": 3, "action": "Enable AWSManagedRulesSQLiRuleSet", "status": "pending"},
                {"step": 4, "action": "Associate with API Gateway stage", "status": "pending"},
                {"step": 5, "action": "Test with OWASP ZAP scan", "status": "pending"},
            ],
        },
    ]

    for data in extra_remediations:
        rem = Remediation(
            id=str(uuid.uuid4()),
            title=data["title"],
            description=data.get("description"),
            framework=data.get("framework"),
            control_id=data.get("control_id"),
            status=data["status"],
            assigned_to=data.get("assigned_to"),
            assigned_by="security-lead@acme.com" if data.get("assigned_to") else None,
            assigned_at=now - timedelta(days=random.randint(1, 7))
            if data.get("assigned_to")
            else None,
            due_date=data.get("due_date"),
            remediation_plan=data.get("description"),
            remediation_steps=data.get("remediation_steps"),
            created_by="demo-seed@warlock",
            created_at=now - timedelta(days=random.randint(3, 21)),
            updated_at=now - timedelta(hours=random.randint(1, 72)),
        )
        if data["status"] == "closed":
            rem.closed_at = now - timedelta(days=random.randint(1, 5))
            rem.verified_by = "audit-lead@acme.com"
            rem.verified_at = now - timedelta(days=random.randint(1, 5))
            rem.verification_notes = "Verified via rescan. All findings resolved."
        session.add(rem)
    counts["extra_remediations"] = len(extra_remediations)

    # --- 3. Fix issue status distribution (move ~100 from open to other states) ---
    open_issues = (
        session.query(Issue)
        .filter(Issue.status == "open")
        .order_by(Issue.created_at)
        .limit(120)
        .all()
    )
    transitions = [
        ("assigned", 30),
        ("in_progress", 25),
        ("remediated", 20),
        ("verified", 10),
        ("closed", 25),
        ("risk_accepted", 10),
    ]
    idx = 0
    for target_status, count in transitions:
        for i in range(count):
            if idx >= len(open_issues):
                break
            issue = open_issues[idx]
            issue.status = target_status
            if target_status in ("assigned", "in_progress", "remediated"):
                issue.assigned_to = random.choice(
                    [
                        "cloud-ops@acme.com",
                        "iam-team@acme.com",
                        "secops@acme.com",
                        "compliance@acme.com",
                        "dba-team@acme.com",
                        "appsec@acme.com",
                    ]
                )
                issue.assigned_by = "security-lead@acme.com"
                issue.assigned_at = now - timedelta(days=random.randint(1, 14))
            if target_status == "remediated":
                issue.remediated_at = now - timedelta(days=random.randint(1, 7))
            if target_status == "closed":
                issue.closed_at = now - timedelta(days=random.randint(1, 10))
                issue.verified_at = now - timedelta(days=random.randint(1, 10))
            if target_status == "risk_accepted":
                issue.risk_accepted = True
                issue.risk_acceptance_owner = "ciso@acme.com"
                issue.risk_acceptance_justification = (
                    "Accepted per risk committee decision. Residual risk within tolerance."
                )
                issue.risk_acceptance_expiry = now + timedelta(days=90)
            if target_status == "verified":
                issue.verified_at = now - timedelta(days=random.randint(1, 7))
            idx += 1
    counts["issues_redistributed"] = idx

    # --- 4. POA&M enrichment (approaching deadlines and overdue) ---
    poam_scenarios = [
        {
            "framework": "pci_dss",
            "control_id": "1.3.1",
            "severity": "high",
            "status": "in_progress",
            "scheduled_completion": now + timedelta(days=5),
            "weakness_description": "Flat network allows lateral movement within PCI CDE.",
            "milestones": [
                {
                    "description": "Deploy micro-segmentation",
                    "due_date": (now + timedelta(days=3)).isoformat(),
                    "status": "pending",
                },
            ],
        },
        {
            "framework": "nist_800_53",
            "control_id": "IA-2",
            "severity": "critical",
            "status": "in_progress",
            "scheduled_completion": now - timedelta(days=3),  # OVERDUE
            "weakness_description": "12 privileged accounts lack MFA enforcement.",
            "milestones": [
                {
                    "description": "Enforce Okta MFA policy",
                    "due_date": (now - timedelta(days=10)).isoformat(),
                    "status": "overdue",
                },
            ],
        },
        {
            "framework": "nist_800_53",
            "control_id": "SI-2",
            "severity": "critical",
            "status": "open",
            "scheduled_completion": now + timedelta(days=2),
            "weakness_description": "4 CVEs with CVSS > 9.0 on nginx and OpenSSL.",
            "milestones": [
                {
                    "description": "Apply patches in maintenance window",
                    "due_date": (now + timedelta(days=1)).isoformat(),
                    "status": "pending",
                },
            ],
        },
        {
            "framework": "hipaa",
            "control_id": "164.312(a)(2)(iv)",
            "severity": "high",
            "status": "in_progress",
            "scheduled_completion": now + timedelta(days=45),
            "weakness_description": "Legacy Oracle 12c database stores PII without TDE.",
            "milestones": [
                {
                    "description": "Enable TDE on tablespaces",
                    "due_date": (now + timedelta(days=15)).isoformat(),
                    "status": "pending",
                },
                {
                    "description": "Migrate to Oracle 19c",
                    "due_date": (now + timedelta(days=40)).isoformat(),
                    "status": "pending",
                },
            ],
        },
    ]

    for data in poam_scenarios:
        poam = POAM(
            id=str(uuid.uuid4()),
            framework=data["framework"],
            control_id=data["control_id"],
            severity=data["severity"],
            status=data["status"],
            weakness_description=data["weakness_description"],
            scheduled_completion=data.get("scheduled_completion"),
            milestones=data.get("milestones", []),
            created_at=now - timedelta(days=random.randint(10, 30)),
            updated_at=now - timedelta(hours=random.randint(1, 48)),
        )
        session.add(poam)
    counts["extra_poams"] = len(poam_scenarios)

    session.commit()
    return counts


# ---------------------------------------------------------------------------
# GAP-055+: Seed all 18 previously-empty tables + access review items +
#           control test records + embeddings + watch subscriptions +
#           escalation policies + integrations + expanded audit trail +
#           expanded posture snapshots for cato-dashboard
# ---------------------------------------------------------------------------


def _seed_empty_tables(session) -> dict:
    """Seed data for 18+ previously-empty tables plus missing demo data.

    Covers Items 15-22, 25, 53, 80 from the fix list.
    """
    import hashlib
    import uuid

    from warlock.db.audit import AuditTrail
    from warlock.db.models import (
        POAM,
        APIKey,
        Asset,
        AuditEngagement,
        AuditEntry,
        BrandingConfig,
        ChangeRequest,
        ComplianceObligation,
        ControlResult,
        DeadLetterEntry,
        DelegationGrant,
        Embedding,
        EscalationPolicy,
        Finding,
        IPAllowlistEntry,
        Issue,
        Policy,
        PolicyHistory,
        PostureSnapshot,
        RiskAnalysis,
        RiskDependency,
        SandboxEnvironment,
        SavedQuery,
        SystemProfile,
        TrustAccessRequest,
        TrustDocument,
        User,
        WatchSubscription,
        Workpaper,
    )

    now = NOW
    counts: dict[str, int] = {}
    trail = AuditTrail(session)

    # -----------------------------------------------------------------------
    # Item 22: Explicit demo users (if not already created by _create_demo_users)
    # -----------------------------------------------------------------------
    users = session.query(User).all()
    user_map = {u.email: u for u in users}
    admin_user = user_map.get("admin@acme.com")
    auditor_user = user_map.get("eve.nakamura@acme.com")
    owner_user = user_map.get("frank.torres@acme.com")
    viewer_user = user_map.get("carol.park@acme.com")

    # -----------------------------------------------------------------------
    # Item 15: Embeddings — at least 5
    # -----------------------------------------------------------------------
    existing_embeddings = session.query(Embedding).count()
    if existing_embeddings == 0:
        embedding_data = [
            ("control", "AC-2", "Account Management - manage system accounts", 384),
            ("control", "IA-2", "Identification and Authentication", 384),
            ("control", "SC-7", "Boundary Protection - network segmentation", 384),
            ("control", "CC6.1", "Logical and Physical Access Controls", 384),
            ("control", "AU-6", "Audit Record Review, Analysis, and Reporting", 384),
            ("finding", "VULN-001", "Critical RCE in OpenSSL library", 384),
            ("remediation", "REM-001", "Apply vendor patch and restart services", 384),
        ]
        for etype, eid, text, dims in embedding_data:
            # Deterministic fake vector (seeded by entity_id hash)
            seed_val = int(hashlib.sha256(eid.encode()).hexdigest()[:8], 16)
            rng = random.Random(seed_val)
            vector = [round(rng.gauss(0, 0.1), 6) for _ in range(dims)]
            session.add(
                Embedding(
                    entity_type=etype,
                    entity_id=eid,
                    entity_text=text,
                    vector=vector,
                    model_name="text-embedding-3-small",
                    dimensions=dims,
                )
            )
        counts["embeddings"] = len(embedding_data)
    else:
        counts["embeddings"] = 0

    # -----------------------------------------------------------------------
    # Item 16: Watch subscriptions — at least 3
    # -----------------------------------------------------------------------
    existing_watches = session.query(WatchSubscription).count()
    if existing_watches == 0 and admin_user:
        issues = session.query(Issue).limit(3).all()
        watch_count = 0
        for i, issue in enumerate(issues):
            watcher = [admin_user, auditor_user, owner_user][i % 3]
            if watcher:
                session.add(
                    WatchSubscription(
                        user_id=watcher.id,
                        entity_type="issue",
                        entity_id=issue.id,
                        issue_id=issue.id,
                    )
                )
                watch_count += 1
        # Add a POAM watcher
        poam = session.query(POAM).first()
        if poam and auditor_user:
            session.add(
                WatchSubscription(
                    user_id=auditor_user.id,
                    entity_type="poam",
                    entity_id=poam.id,
                )
            )
            watch_count += 1
        counts["watch_subscriptions"] = watch_count
    else:
        counts["watch_subscriptions"] = 0

    # -----------------------------------------------------------------------
    # Item 17: Escalation policies — at least 2
    # -----------------------------------------------------------------------
    existing_ep = session.query(EscalationPolicy).count()
    if existing_ep == 0:
        session.add(
            EscalationPolicy(
                name="Critical Finding Escalation",
                description=(
                    "Three-tier escalation for critical and high severity findings "
                    "not remediated within SLA."
                ),
                levels=[
                    {"level": 1, "role": "control_owner", "delay_hours": 24},
                    {"level": 2, "role": "team_lead", "delay_hours": 48},
                    {"level": 3, "role": "ciso", "delay_hours": 72},
                ],
                cooldown_minutes=60,
                active=True,
                entity_types=["issue", "finding"],
                min_severity="high",
                created_by="ciso@acme.com",
            )
        )
        session.add(
            EscalationPolicy(
                name="Overdue POA&M Escalation",
                description="Escalation chain for POA&Ms past their scheduled completion date.",
                levels=[
                    {"level": 1, "role": "poam_owner", "delay_hours": 48},
                    {"level": 2, "role": "isso", "delay_hours": 96},
                    {"level": 3, "role": "authorizing_official", "delay_hours": 168},
                ],
                cooldown_minutes=120,
                active=True,
                entity_types=["poam"],
                min_severity="medium",
                created_by="isso@acme.com",
            )
        )
        session.add(
            EscalationPolicy(
                name="Vendor Assessment Overdue",
                description="Notify procurement and security when vendor assessments are past due.",
                levels=[
                    {"level": 1, "role": "vendor_manager", "delay_hours": 72},
                    {"level": 2, "role": "ciso", "delay_hours": 168},
                ],
                cooldown_minutes=240,
                active=True,
                entity_types=["vendor"],
                min_severity="medium",
                created_by="compliance@acme.com",
            )
        )
        counts["escalation_policies"] = 3
    else:
        counts["escalation_policies"] = 0

    # -----------------------------------------------------------------------
    # Item 18: Integrations — at least 2 (via AuditEntry)
    # -----------------------------------------------------------------------
    existing_integrations = (
        session.query(AuditEntry).filter(AuditEntry.action == "integration_configured").count()
    )
    if existing_integrations == 0:
        integration_configs = [
            {
                "integration_type": "jira",
                "status": "active",
                "config": {
                    "base_url": "https://acme.atlassian.net",
                    "project_key": "GRC",
                    "issue_type": "Task",
                    "sync_direction": "bidirectional",
                },
            },
            {
                "integration_type": "slack",
                "status": "active",
                "config": {
                    "workspace": "acme-corp",
                    "channel": "#grc-alerts",
                    "events": ["alert.critical", "finding.new", "poam.overdue"],
                },
            },
            {
                "integration_type": "servicenow",
                "status": "inactive",
                "config": {
                    "instance": "acme.service-now.com",
                    "table": "sn_grc_issue",
                    "sync_direction": "outbound",
                },
            },
        ]
        for ic in integration_configs:
            trail.record(
                action="integration_configured",
                entity_type="integration",
                entity_id=ic["integration_type"],
                actor="admin@acme.com",
                metadata=ic,
            )
        counts["integrations"] = len(integration_configs)
    else:
        counts["integrations"] = 0

    session.flush()

    # -----------------------------------------------------------------------
    # Item 21: API keys — 2 for admin/viewer
    # -----------------------------------------------------------------------
    existing_keys = session.query(APIKey).count()
    if existing_keys == 0:
        api_key_data = []
        if admin_user:
            api_key_data.append(
                APIKey(
                    user_id=admin_user.id,
                    key_hash=hashlib.sha256(b"wlk_demo_admin_key_2026").hexdigest(),
                    name="Admin CI/CD Pipeline Key",
                    scopes=["read", "write", "admin"],
                    is_active=True,
                    expires_at=now + timedelta(days=365),
                )
            )
        if viewer_user:
            api_key_data.append(
                APIKey(
                    user_id=viewer_user.id,
                    key_hash=hashlib.sha256(b"wlk_demo_viewer_key_2026").hexdigest(),
                    name="Dashboard Read-Only Key",
                    scopes=["read"],
                    is_active=True,
                    expires_at=now + timedelta(days=180),
                )
            )
        for ak in api_key_data:
            session.add(ak)
        counts["api_keys"] = len(api_key_data)
    else:
        counts["api_keys"] = 0

    # -----------------------------------------------------------------------
    # Item 21: Assets — 10 linked to findings
    # -----------------------------------------------------------------------
    existing_assets = session.query(Asset).count()
    if existing_assets == 0:
        systems = {sp.acronym: sp for sp in session.query(SystemProfile).all()}
        prod_id = systems.get("APP")
        cdw_id = systems.get("CDW")
        cit_id = systems.get("CIT")

        asset_defs = [
            (
                "arn:aws:ec2:us-east-1:912345678012:instance/i-0abc1234",
                "ec2_instance",
                "prod-api-server-01",
                prod_id,
                "frank.torres@acme.com",
                "restricted",
                5,
            ),
            (
                "arn:aws:ec2:us-east-1:912345678012:instance/i-0abc5678",
                "ec2_instance",
                "prod-api-server-02",
                prod_id,
                "frank.torres@acme.com",
                "restricted",
                5,
            ),
            (
                "arn:aws:rds:us-east-1:912345678012:db:prod-primary",
                "rds_instance",
                "prod-postgres-primary",
                prod_id,
                "dba@acme.com",
                "restricted",
                5,
            ),
            (
                "arn:aws:s3:::acme-customer-data",
                "s3_bucket",
                "acme-customer-data",
                cdw_id,
                "carol.park@acme.com",
                "confidential",
                4,
            ),
            (
                "arn:aws:redshift:us-east-1:912345678012:cluster:analytics",
                "redshift_cluster",
                "analytics-warehouse",
                cdw_id,
                "carol.park@acme.com",
                "confidential",
                4,
            ),
            (
                "arn:aws:lambda:us-east-1:912345678012:function:pipeline",
                "lambda_function",
                "data-pipeline-processor",
                prod_id,
                "frank.torres@acme.com",
                "internal",
                3,
            ),
            (
                "okta:app:0oa1234567890",
                "saas_application",
                "Okta SSO",
                cit_id,
                "bob.martinez@acme.com",
                "internal",
                4,
            ),
            (
                "crowdstrike:host:abc-def-123",
                "endpoint",
                "eng-laptop-pool",
                cit_id,
                "bob.martinez@acme.com",
                "internal",
                3,
            ),
            (
                "arn:aws:elasticloadbalancing:us-east-1:912345678012:loadbalancer/app/prod-alb",
                "load_balancer",
                "prod-alb",
                prod_id,
                "network-team@acme.com",
                "internal",
                4,
            ),
            (
                "github:repo:acme-corp/platform",
                "code_repository",
                "platform-monorepo",
                prod_id,
                "frank.torres@acme.com",
                "confidential",
                5,
            ),
        ]
        # Grab some finding IDs to link
        sample_findings = session.query(Finding.id).limit(20).all()
        finding_ids = [f[0] for f in sample_findings]

        for i, (rid, rtype, rname, sys_obj, owner, classif, crit) in enumerate(asset_defs):
            fids = finding_ids[i * 2 : i * 2 + 2] if i * 2 + 2 <= len(finding_ids) else []
            session.add(
                Asset(
                    resource_id=rid,
                    resource_type=rtype,
                    resource_name=rname,
                    system_id=sys_obj.id if sys_obj else None,
                    owner=owner,
                    classification=classif,
                    criticality=crit,
                    status="active",
                    finding_ids=fids,
                )
            )
        counts["assets"] = len(asset_defs)
    else:
        counts["assets"] = 0

    # -----------------------------------------------------------------------
    # Item 21: Branding config — 1 default
    # -----------------------------------------------------------------------
    existing_branding = session.query(BrandingConfig).count()
    if existing_branding == 0:
        session.add(
            BrandingConfig(
                tenant_id_unique="default",
                logo_url="https://acme.com/logo.svg",
                primary_color="#6366f1",
                accent_color="#8b5cf6",
                app_name="Warlock GRC",
                favicon_url="https://acme.com/favicon.ico",
                custom_css="/* Acme Corp brand overrides */",
            )
        )
        counts["branding_configs"] = 1
    else:
        counts["branding_configs"] = 0

    # -----------------------------------------------------------------------
    # Item 21: Change requests — 3 in various states
    # -----------------------------------------------------------------------
    existing_cr = session.query(ChangeRequest).count()
    if existing_cr == 0:
        prod_sp = session.query(SystemProfile).filter(SystemProfile.acronym == "APP").first()
        cr_defs = [
            ChangeRequest(
                title="Upgrade PostgreSQL from 14 to 16",
                description="Major version upgrade for prod-postgres-primary. Requires 30-min maintenance window.",
                change_type="normal",
                risk_level="high",
                system_profile_id=prod_sp.id if prod_sp else None,
                requester="dba@acme.com",
                status="approved",
                cab_decision="approved",
                cab_notes="Approved with rollback plan. Schedule for Sunday 02:00 UTC.",
                cab_date=now - timedelta(days=3),
                implementation_date=now + timedelta(days=4),
                rollback_plan="pg_basebackup snapshot taken pre-upgrade; revert via point-in-time recovery.",
            ),
            ChangeRequest(
                title="Enable WAF managed rules on prod-alb",
                description="Add AWS WAF with OWASP Top 10 managed rule set to production ALB.",
                change_type="standard",
                risk_level="low",
                system_profile_id=prod_sp.id if prod_sp else None,
                requester="network-team@acme.com",
                status="implemented",
                cab_decision="approved",
                cab_notes="Standard change — pre-approved.",
                cab_date=now - timedelta(days=7),
                implementation_date=now - timedelta(days=5),
                rollback_plan="Remove WAF association from ALB via Terraform revert.",
            ),
            ChangeRequest(
                title="Emergency patch: Log4Shell in analytics service",
                description="CVE-2021-44228 detected in analytics-warehouse log4j dependency. Emergency patching required.",
                change_type="emergency",
                risk_level="critical",
                system_profile_id=prod_sp.id if prod_sp else None,
                requester="security-lead@acme.com",
                status="draft",
                rollback_plan="Revert JAR to previous version and restart service.",
            ),
        ]
        for cr in cr_defs:
            session.add(cr)
        counts["change_requests"] = len(cr_defs)
    else:
        counts["change_requests"] = 0

    # -----------------------------------------------------------------------
    # Item 21: Compliance obligations — 5
    # -----------------------------------------------------------------------
    existing_co = session.query(ComplianceObligation).count()
    if existing_co == 0:
        co_defs = [
            ComplianceObligation(
                title="SOC 2 Type II Annual Audit",
                framework="soc2",
                obligation_type="audit",
                frequency="annual",
                next_due=now + timedelta(days=90),
                owner="eve.nakamura@acme.com",
                status="pending",
                notes="Deloitte engagement letter signed. Fieldwork starts Q2.",
            ),
            ComplianceObligation(
                title="PCI DSS Self-Assessment Questionnaire",
                framework="pci_dss",
                obligation_type="assessment",
                frequency="annual",
                next_due=now + timedelta(days=60),
                owner="frank.torres@acme.com",
                status="in_progress",
                notes="SAQ-D in progress. Penetration test scheduled for next month.",
            ),
            ComplianceObligation(
                title="GDPR Annual DPA Review",
                framework="gdpr",
                obligation_type="review",
                frequency="annual",
                next_due=now + timedelta(days=30),
                owner="dpo@acme.com",
                status="pending",
                notes="Review all data processing agreements with sub-processors.",
            ),
            ComplianceObligation(
                title="Quarterly Vulnerability Scan Report",
                framework="nist_800_53",
                control_id="RA-5",
                obligation_type="report",
                frequency="quarterly",
                next_due=now + timedelta(days=15),
                owner="security-lead@acme.com",
                status="pending",
            ),
            ComplianceObligation(
                title="ISO 27001 Surveillance Audit",
                framework="iso_27001",
                obligation_type="audit",
                frequency="annual",
                next_due=now + timedelta(days=120),
                owner="compliance@acme.com",
                status="pending",
                notes="BSI scheduled for June. Internal audit to complete first.",
            ),
        ]
        for co in co_defs:
            session.add(co)
        counts["compliance_obligations"] = len(co_defs)
    else:
        counts["compliance_obligations"] = 0

    # -----------------------------------------------------------------------
    # Item 21: Dead letter queue — 2 failed events
    # -----------------------------------------------------------------------
    existing_dlq = session.query(DeadLetterEntry).count()
    if existing_dlq == 0:
        session.add(
            DeadLetterEntry(
                event_type="finding.normalize",
                payload={
                    "source": "crowdstrike",
                    "event_id": "CS-ERR-001",
                    "raw": {"malformed": True, "missing_field": "severity"},
                },
                error_message="KeyError: 'severity' - required field missing from CrowdStrike event payload",
                retry_count=3,
                status="failed",
                original_event_id="evt-cs-001",
                created_at=now - timedelta(days=2),
                last_retry_at=now - timedelta(hours=6),
            )
        )
        session.add(
            DeadLetterEntry(
                event_type="control.map",
                payload={
                    "finding_id": "FND-TIMEOUT-001",
                    "framework": "nist_800_53",
                    "error": "timeout",
                },
                error_message="TimeoutError: OPA evaluation exceeded 30s limit for batch of 500 controls",
                retry_count=1,
                status="failed",
                original_event_id="evt-map-042",
                created_at=now - timedelta(days=5),
                last_retry_at=now - timedelta(days=4),
            )
        )
        counts["dead_letter_queue"] = 2
    else:
        counts["dead_letter_queue"] = 0

    # -----------------------------------------------------------------------
    # Item 21: Delegation grants — 2
    # -----------------------------------------------------------------------
    existing_dg = session.query(DelegationGrant).count()
    if existing_dg == 0 and owner_user and viewer_user and admin_user:
        session.add(
            DelegationGrant(
                delegator_id=owner_user.id,
                delegate_id=viewer_user.id,
                permissions=["read:findings", "read:results", "export:reports"],
                expires_at=now + timedelta(days=90),
                is_active=True,
            )
        )
        session.add(
            DelegationGrant(
                delegator_id=admin_user.id,
                delegate_id=auditor_user.id if auditor_user else owner_user.id,
                permissions=["read:all", "write:attestations", "write:evidence"],
                expires_at=now + timedelta(days=30),
                is_active=True,
            )
        )
        counts["delegation_grants"] = 2
    else:
        counts["delegation_grants"] = 0

    # -----------------------------------------------------------------------
    # Item 21: IP allowlist — 3
    # -----------------------------------------------------------------------
    existing_ip = session.query(IPAllowlistEntry).count()
    if existing_ip == 0:
        session.add(
            IPAllowlistEntry(
                cidr="10.0.0.0/8",
                description="Internal corporate network",
                active=True,
                created_by="admin@acme.com",
            )
        )
        session.add(
            IPAllowlistEntry(
                cidr="203.0.113.0/24",
                description="VPN egress range",
                active=True,
                created_by="admin@acme.com",
            )
        )
        session.add(
            IPAllowlistEntry(
                cidr="198.51.100.42/32",
                description="Deloitte auditor static IP (SOC 2 engagement)",
                active=True,
                created_by="admin@acme.com",
                expires_at=now + timedelta(days=60),
            )
        )
        counts["ip_allowlist"] = 3
    else:
        counts["ip_allowlist"] = 0

    # -----------------------------------------------------------------------
    # Item 21: Policy history — 5 records
    # -----------------------------------------------------------------------
    existing_ph = session.query(PolicyHistory).count()
    if existing_ph == 0:
        policies = session.query(Policy).limit(5).all()
        ph_count = 0
        for i, pol in enumerate(policies):
            session.add(
                PolicyHistory(
                    policy_id=pol.id,
                    action="updated" if i > 0 else "created",
                    old_rules={"version": "1.0"} if i > 0 else None,
                    new_rules=dict(pol.rules) if pol.rules else {"version": "2.0"},
                    actor=pol.created_by or "admin@acme.com",
                    timestamp=now - timedelta(days=30 - i * 5),
                )
            )
            ph_count += 1
        counts["policy_history"] = ph_count
    else:
        counts["policy_history"] = 0

    # -----------------------------------------------------------------------
    # Item 21: Risk dependencies — need RiskAnalysis records first
    # -----------------------------------------------------------------------
    existing_ra = session.query(RiskAnalysis).count()
    ra_ids: list[str] = []
    if existing_ra == 0:
        ra_defs = [
            RiskAnalysis(
                id=str(uuid.uuid4()),
                framework="nist_800_53",
                scenario_name="Data breach via compromised IAM credentials",
                mean_ale=1_250_000.0,
                var_95=3_500_000.0,
                var_99=8_200_000.0,
                control_effectiveness=0.72,
                iterations=10000,
                details={
                    "threat_event_frequency": {"min": 0.5, "max": 3.0, "mode": 1.2},
                    "loss_magnitude": {"min": 500_000, "max": 10_000_000, "mode": 2_000_000},
                },
                risk_culture_score=68.0,
                mttr_days=14.0,
            ),
            RiskAnalysis(
                id=str(uuid.uuid4()),
                framework="soc2",
                scenario_name="Service outage exceeding SLA commitment",
                mean_ale=420_000.0,
                var_95=1_100_000.0,
                var_99=2_800_000.0,
                control_effectiveness=0.85,
                iterations=10000,
                details={
                    "threat_event_frequency": {"min": 1.0, "max": 6.0, "mode": 2.5},
                    "loss_magnitude": {"min": 50_000, "max": 3_000_000, "mode": 300_000},
                },
                risk_culture_score=75.0,
                mttr_days=4.0,
            ),
            RiskAnalysis(
                id=str(uuid.uuid4()),
                framework="pci_dss",
                scenario_name="Payment card data exfiltration",
                mean_ale=2_800_000.0,
                var_95=7_500_000.0,
                var_99=15_000_000.0,
                control_effectiveness=0.88,
                iterations=10000,
                details={
                    "threat_event_frequency": {"min": 0.1, "max": 1.0, "mode": 0.3},
                    "loss_magnitude": {"min": 2_000_000, "max": 20_000_000, "mode": 5_000_000},
                },
                risk_culture_score=80.0,
                mttr_days=7.0,
            ),
            RiskAnalysis(
                id=str(uuid.uuid4()),
                framework="gdpr",
                scenario_name="Cross-border data transfer violation",
                mean_ale=950_000.0,
                var_95=4_200_000.0,
                var_99=12_000_000.0,
                control_effectiveness=0.65,
                iterations=10000,
                details={
                    "threat_event_frequency": {"min": 0.2, "max": 2.0, "mode": 0.8},
                    "loss_magnitude": {"min": 200_000, "max": 20_000_000, "mode": 1_500_000},
                },
                risk_culture_score=60.0,
                mttr_days=21.0,
            ),
        ]
        for ra in ra_defs:
            session.add(ra)
            ra_ids.append(ra.id)
        session.flush()
        counts["risk_analyses"] = len(ra_defs)
    else:
        ra_ids = [r[0] for r in session.query(RiskAnalysis.id).limit(4).all()]
        counts["risk_analyses"] = 0

    existing_rd = session.query(RiskDependency).count()
    if existing_rd == 0 and len(ra_ids) >= 4:
        session.add(
            RiskDependency(
                risk_id=ra_ids[0],
                depends_on_risk_id=ra_ids[1],
                relationship_type="amplifies",
                weight=0.7,
                description="IAM credential breach amplifies service outage risk",
            )
        )
        session.add(
            RiskDependency(
                risk_id=ra_ids[2],
                depends_on_risk_id=ra_ids[0],
                relationship_type="causes",
                weight=0.9,
                description="Credential compromise can lead to PCI data exfiltration",
            )
        )
        session.add(
            RiskDependency(
                risk_id=ra_ids[3],
                depends_on_risk_id=ra_ids[2],
                relationship_type="correlates",
                weight=0.5,
                description="PCI breach often co-occurs with GDPR data transfer issues",
            )
        )
        session.add(
            RiskDependency(
                risk_id=ra_ids[1],
                depends_on_risk_id=ra_ids[3],
                relationship_type="mitigates",
                weight=0.3,
                description="Outage mitigation controls reduce GDPR exposure window",
            )
        )
        counts["risk_dependencies"] = 4
    else:
        counts["risk_dependencies"] = 0

    # -----------------------------------------------------------------------
    # Item 21: Sandbox environments — 2
    # -----------------------------------------------------------------------
    existing_sb = session.query(SandboxEnvironment).count()
    if existing_sb == 0 and admin_user:
        session.add(
            SandboxEnvironment(
                name="Policy Testing Sandbox",
                owner_id=admin_user.id,
                config={
                    "frameworks": ["nist_800_53", "soc2"],
                    "mock_data": True,
                    "opa_fail_mode": "open",
                },
                status="active",
                expires_at=now + timedelta(days=30),
            )
        )
        test_owner = auditor_user or admin_user
        session.add(
            SandboxEnvironment(
                name="Auditor Review Environment",
                owner_id=test_owner.id,
                config={
                    "frameworks": ["soc2", "iso_27001"],
                    "read_only": True,
                    "snapshot_date": (now - timedelta(days=7)).isoformat(),
                },
                status="active",
                expires_at=now + timedelta(days=14),
            )
        )
        counts["sandbox_environments"] = 2
    else:
        counts["sandbox_environments"] = 0

    # -----------------------------------------------------------------------
    # Item 21: Saved queries — 3
    # -----------------------------------------------------------------------
    existing_sq = session.query(SavedQuery).count()
    if existing_sq == 0:
        session.add(
            SavedQuery(
                name="Non-compliant critical controls",
                description="All critical controls currently non-compliant across production systems",
                sql_text=(
                    "SELECT framework, control_id, status, assessed_at "
                    "FROM control_results "
                    "WHERE status = 'non_compliant' "
                    "ORDER BY assessed_at DESC"
                ),
                query_type="sla_breach",
                shared=True,
                created_by="eve.nakamura@acme.com",
                run_count=12,
                last_run_at=now - timedelta(hours=2),
            )
        )
        session.add(
            SavedQuery(
                name="Findings by severity trend (30d)",
                description="Daily finding counts by severity for the last 30 days",
                sql_text=(
                    "SELECT date(ingested_at) as day, severity, count(*) as cnt "
                    "FROM findings "
                    "WHERE ingested_at > date('now', '-30 days') "
                    "GROUP BY day, severity ORDER BY day"
                ),
                query_type="drift",
                shared=True,
                created_by="admin@acme.com",
                run_count=8,
                last_run_at=now - timedelta(days=1),
            )
        )
        session.add(
            SavedQuery(
                name="Vendor risk exposure summary",
                description="Vendor risk scores with contract expiry and blast radius",
                sql_text=(
                    "SELECT name, tier, risk_score, blast_radius_score, contract_expires "
                    "FROM vendors WHERE risk_score > 50 ORDER BY risk_score DESC"
                ),
                query_type="custom",
                shared=False,
                created_by="carol.park@acme.com",
                run_count=3,
            )
        )
        counts["saved_queries"] = 3
    else:
        counts["saved_queries"] = 0

    # -----------------------------------------------------------------------
    # Item 21: Trust access requests — 2
    # -----------------------------------------------------------------------
    existing_tar = session.query(TrustAccessRequest).count()
    if existing_tar == 0:
        session.add(
            TrustAccessRequest(
                contact_email="auditor@clientcorp.com",
                contact_name="Jane Smith",
                company_name="ClientCorp Inc.",
                document_types=["soc2_report", "pentest_summary"],
                status="approved",
                reviewed_by="eve.nakamura@acme.com",
                reviewed_at=now - timedelta(days=5),
                reason="Due diligence for vendor onboarding. NDA on file.",
                nda_accepted=True,
            )
        )
        session.add(
            TrustAccessRequest(
                contact_email="security@bigbank.com",
                contact_name="Michael Chen",
                company_name="BigBank Financial",
                document_types=[
                    "soc2_report",
                    "iso_cert",
                    "pentest_summary",
                    "security_whitepaper",
                ],
                status="pending",
                reason="Enterprise deal in pipeline. Priority review requested by sales.",
                nda_accepted=False,
            )
        )
        counts["trust_access_requests"] = 2
    else:
        counts["trust_access_requests"] = 0

    # -----------------------------------------------------------------------
    # Item 21: Trust documents — 3
    # -----------------------------------------------------------------------
    existing_td = session.query(TrustDocument).count()
    if existing_td == 0:
        session.add(
            TrustDocument(
                title="SOC 2 Type II Report — FY2025",
                description="Independent auditor report covering the period Jan 1 - Dec 31, 2025.",
                classification_tier="nda",
                file_path="/trust/soc2-type2-fy2025.pdf",
                content_type="application/pdf",
                file_size_bytes=2_450_000,
                uploaded_by="eve.nakamura@acme.com",
                is_active=True,
            )
        )
        session.add(
            TrustDocument(
                title="Annual Penetration Test Executive Summary — 2026 Q1",
                description="NCC Group penetration test results. No critical findings.",
                classification_tier="contract",
                file_path="/trust/pentest-summary-2026q1.pdf",
                content_type="application/pdf",
                file_size_bytes=1_280_000,
                uploaded_by="security-lead@acme.com",
                is_active=True,
            )
        )
        session.add(
            TrustDocument(
                title="ISO 27001:2022 Certificate",
                description="BSI-issued ISO 27001 certificate. Scope: SaaS platform and supporting infrastructure.",
                classification_tier="public",
                file_path="/trust/iso27001-cert-2025.pdf",
                content_type="application/pdf",
                file_size_bytes=520_000,
                uploaded_by="compliance@acme.com",
                is_active=True,
            )
        )
        counts["trust_documents"] = 3
    else:
        counts["trust_documents"] = 0

    # -----------------------------------------------------------------------
    # Item 21: Workpapers — 3 linked to engagements
    # -----------------------------------------------------------------------
    existing_wp = session.query(Workpaper).count()
    if existing_wp == 0:
        eng = session.query(AuditEngagement).first()
        if eng:
            session.add(
                Workpaper(
                    engagement_id=eng.id,
                    control_id="CC6.1",
                    framework="soc2",
                    template_type="test_of_design",
                    status="signed_off",
                    reviewer="sarah.chen@deloitte.com",
                    notes="Design of IAM controls verified. MFA enforced for all admin accounts.",
                    review_history=[
                        {
                            "action": "created",
                            "by": "eve.nakamura@acme.com",
                            "at": (now - timedelta(days=14)).isoformat(),
                        },
                        {
                            "action": "reviewed",
                            "by": "sarah.chen@deloitte.com",
                            "at": (now - timedelta(days=7)).isoformat(),
                        },
                        {
                            "action": "signed_off",
                            "by": "sarah.chen@deloitte.com",
                            "at": (now - timedelta(days=5)).isoformat(),
                        },
                    ],
                )
            )
            session.add(
                Workpaper(
                    engagement_id=eng.id,
                    control_id="CC6.6",
                    framework="soc2",
                    template_type="test_of_effectiveness",
                    status="reviewed",
                    reviewer="sarah.chen@deloitte.com",
                    notes="Encryption at rest verified for all S3 buckets and RDS instances.",
                    review_history=[
                        {
                            "action": "created",
                            "by": "bob.martinez@acme.com",
                            "at": (now - timedelta(days=10)).isoformat(),
                        },
                        {
                            "action": "reviewed",
                            "by": "sarah.chen@deloitte.com",
                            "at": (now - timedelta(days=3)).isoformat(),
                        },
                    ],
                )
            )
            session.add(
                Workpaper(
                    engagement_id=eng.id,
                    control_id="CC7.2",
                    framework="soc2",
                    template_type="walkthrough",
                    status="draft",
                    notes="Walkthrough of incident detection and response procedures. Pending auditor review.",
                    review_history=[
                        {
                            "action": "created",
                            "by": "frank.torres@acme.com",
                            "at": (now - timedelta(days=2)).isoformat(),
                        },
                    ],
                )
            )
            counts["workpapers"] = 3
        else:
            counts["workpapers"] = 0
    else:
        counts["workpapers"] = 0

    session.flush()

    # Item 53: Access review items — handled in step 31a (after campaigns created)

    # -----------------------------------------------------------------------
    # Item 80: Control test records — mark 10 controls as examined
    # -----------------------------------------------------------------------
    ct_count = 0
    unexamined = (
        session.query(ControlResult).filter(ControlResult.examined_at.is_(None)).limit(10).all()
    )
    testers = [
        "eve.nakamura@acme.com",
        "frank.torres@acme.com",
        "hassan.ali@acme.com",
    ]
    for i, cr in enumerate(unexamined):
        cr.examined_at = now - timedelta(days=random.randint(1, 30))
        cr.examined_by = testers[i % len(testers)]
        ct_count += 1
    counts["control_tests"] = ct_count

    # -----------------------------------------------------------------------
    # Item 25: Expanded audit trail — target 200+ total entries
    # -----------------------------------------------------------------------
    current_audit_count = session.query(AuditEntry).count()
    extra_needed = max(0, 200 - current_audit_count)
    if extra_needed > 0:
        audit_actions = [
            # Bulk finding creation batches
            (
                "finding_batch_created",
                "Pipeline",
                "BATCH",
                "pipeline",
                lambda i: {"batch_size": 50 + i * 10, "source": "crowdstrike", "duration_s": 2.1},
            ),
            (
                "finding_batch_created",
                "Pipeline",
                "BATCH",
                "pipeline",
                lambda i: {"batch_size": 75, "source": "aws", "duration_s": 3.4},
            ),
            (
                "finding_batch_created",
                "Pipeline",
                "BATCH",
                "pipeline",
                lambda i: {"batch_size": 120, "source": "okta", "duration_s": 1.8},
            ),
            # Control assessment batches
            (
                "control_assessment_batch",
                "Pipeline",
                "ASSESS",
                "pipeline",
                lambda i: {"framework": "nist_800_53", "controls_assessed": 200, "duration_s": 5.2},
            ),
            (
                "control_assessment_batch",
                "Pipeline",
                "ASSESS",
                "pipeline",
                lambda i: {"framework": "soc2", "controls_assessed": 46, "duration_s": 1.1},
            ),
            (
                "control_assessment_batch",
                "Pipeline",
                "ASSESS",
                "pipeline",
                lambda i: {"framework": "iso_27001", "controls_assessed": 93, "duration_s": 2.3},
            ),
            # Pipeline run events
            (
                "pipeline_run_started",
                "PipelineRun",
                "RUN",
                "scheduler",
                lambda i: {"connectors": 351, "trigger": "scheduled"},
            ),
            (
                "pipeline_run_completed",
                "PipelineRun",
                "RUN",
                "scheduler",
                lambda i: {"duration_s": 7.2, "findings": 7325, "controls": 373852},
            ),
            # Evidence collection
            (
                "evidence_collected",
                "Evidence",
                "EVC",
                "pipeline",
                lambda i: {"source": ["aws", "okta", "crowdstrike"][i % 3], "events": 15 + i},
            ),
            # User events
            (
                "login",
                "User",
                "USR",
                "admin@acme.com",
                lambda i: {"ip": "10.0.1.50", "user_agent": "Mozilla/5.0"},
            ),
            ("logout", "User", "USR", "admin@acme.com", lambda i: {"duration_minutes": 30 + i * 5}),
            (
                "login",
                "User",
                "USR",
                "eve.nakamura@acme.com",
                lambda i: {"ip": "10.0.1.51", "user_agent": "Mozilla/5.0"},
            ),
            # POA&M transitions
            (
                "poam_status_changed",
                "POAM",
                "POAM",
                "security-lead@acme.com",
                lambda i: {"from": "open", "to": "in_progress", "control_id": "AC-2"},
            ),
            (
                "poam_status_changed",
                "POAM",
                "POAM",
                "ciso@acme.com",
                lambda i: {"from": "in_progress", "to": "remediated", "control_id": "SC-7"},
            ),
            # System profile changes
            (
                "system_profile_updated",
                "SystemProfile",
                "SYS",
                "hassan.ali@acme.com",
                lambda i: {
                    "field": "authorization_status",
                    "old": "in_process",
                    "new": "authorized",
                },
            ),
        ]

        batch_idx = 0
        for action, etype, eid_prefix, actor, meta_fn in audit_actions:
            if batch_idx >= extra_needed:
                break
            trail.record(
                action=action,
                entity_type=etype,
                entity_id=f"{eid_prefix}-{batch_idx + 1:03d}",
                actor=actor,
                metadata=meta_fn(batch_idx),
            )
            batch_idx += 1

        # Fill remaining with diverse pipeline events
        while batch_idx < extra_needed:
            src_idx = batch_idx % 10
            sources = [
                "aws",
                "okta",
                "crowdstrike",
                "azure",
                "gcp",
                "tenable",
                "snyk",
                "splunk",
                "github",
                "workday",
            ]
            trail.record(
                action="evidence_collected",
                entity_type="RawEvent",
                entity_id=f"RE-EXTRA-{batch_idx:04d}",
                actor="pipeline",
                metadata={
                    "source": sources[src_idx],
                    "event_count": 3 + (batch_idx % 20),
                    "pipeline_stage": "collection",
                },
            )
            batch_idx += 1

        counts["extra_audit_entries"] = batch_idx
    else:
        counts["extra_audit_entries"] = 0

    # -----------------------------------------------------------------------
    # Item 20: Expanded posture snapshots for ALL system profiles
    # -----------------------------------------------------------------------
    all_profiles = session.query(SystemProfile).all()
    profiles_with_snapshots = set(
        row[0]
        for row in session.query(PostureSnapshot.system_profile_id)
        .filter(PostureSnapshot.system_profile_id.isnot(None))
        .distinct()
        .all()
    )
    profiles_needing_snapshots = [sp for sp in all_profiles if sp.id not in profiles_with_snapshots]
    snapshot_count = 0
    for sp in profiles_needing_snapshots:
        # Create 30 days of snapshots per framework the system covers
        sp_frameworks = sp.frameworks or ["soc2"]
        for fw in sp_frameworks[:2]:  # Limit to 2 frameworks per system
            base_score = random.uniform(50, 90)
            for day_offset in range(30, 0, -5):  # Every 5 days
                score = max(0, min(100, base_score + random.uniform(-8, 8)))
                status = (
                    "compliant" if score >= 80 else "partial" if score >= 50 else "non_compliant"
                )
                total = random.randint(3, 10)
                compliant_n = max(0, int(total * score / 100))
                session.add(
                    PostureSnapshot(
                        snapshot_date=now - timedelta(days=day_offset),
                        framework=fw,
                        control_id=f"{fw.upper()[:4]}-AGGR",
                        status=status,
                        posture_score=round(score, 1),
                        total_findings=total,
                        compliant_findings=compliant_n,
                        non_compliant_findings=total - compliant_n,
                        evidence_sources=sp.connector_scope or ["generic"],
                        system_profile_id=sp.id,
                    )
                )
                snapshot_count += 1
    counts["posture_snapshots_backfill"] = snapshot_count

    session.commit()
    return counts


def main():
    # Registry divergence note: this demo builds its own ConnectorRegistry,
    # NormalizerRegistry, and EventBus (in-process, in-memory) populated with
    # DemoXxxConnector mocks. Production pipelines use the global registry
    # constructed by warlock/pipeline/loader.py (build_pipeline / load_assertions),
    # which discovers real connectors from settings and wires the configured
    # queue backend (memory, Redis, Kafka, or SQS). Do not rely on the demo
    # registry for production behaviour -- it is intentionally isolated so that
    # demo seeds can run without any real credentials or external services.
    # Deterministic seed for reproducible demo data across all phases
    random.seed(42)

    # Always enable the lake for demo seed — the platform tagline is
    # "signals datalake of enterprises".
    import os as _lake_os

    _lake_os.environ.setdefault("WLK_LAKE_ENABLED", "true")

    print("=" * 60)
    print("  Warlock Demo Seed")
    print("=" * 60)

    # 1. Init DB
    print("\n[1/34] Initializing database...")
    init_db()  # Also creates default tenant automatically

    # 2. Build pipeline with real framework configs + assertions
    print("[2/34] Loading frameworks, assertions, and normalizers...")
    bus = EventBus()

    # Register lake writer if enabled (WLK_LAKE_ENABLED=true)
    import os as _os

    lake_writer = None
    if _os.environ.get("WLK_LAKE_ENABLED", "").lower() in ("true", "1", "yes"):
        from warlock.config import get_settings as _get_settings
        from warlock.lake.writer import LakeWriter as _LakeWriter

        _lake_settings = _get_settings()
        lake_writer = _LakeWriter(_lake_settings.lake_path)
        bus.subscribe_all(lake_writer.handle_event)
        print(f"  Lake writer enabled (path={_lake_settings.lake_path})")
    load_assertions()

    connectors = ConnectorRegistry()
    connectors.register("aws", DemoAWSConnector)
    connectors.register("okta", DemoOktaConnector)
    connectors.register("crowdstrike", DemoCrowdStrikeConnector)
    connectors.register("workday", DemoWorkdayConnector)
    connectors.register("knowbe4", DemoKnowBe4Connector)
    connectors.register("securityscorecard", DemoSecurityScorecardConnector)
    connectors.register("confluence", DemoConfluenceConnector)
    connectors.register("entra_id", DemoEntraIDConnector)
    connectors.register("cyberark", DemoCyberArkConnector)
    connectors.register("sailpoint", DemoSailPointConnector)
    connectors.register("vault", DemoVaultConnector)
    # Cloud providers
    connectors.register("azure", DemoAzureConnector)
    connectors.register("gcp", DemoGCPConnector)
    connectors.register("digitalocean", DemoDigitalOceanConnector)
    connectors.register("alibaba", DemoAlibabaConnector)
    connectors.register("huawei", DemoHuaweiConnector)
    connectors.register("ibm_cloud", DemoIBMCloudConnector)
    connectors.register("ovh", DemoOVHConnector)
    connectors.register("oci", DemoOCIConnector)
    connectors.register("cloudflare", DemoCloudflareConnector)
    connectors.register("kubernetes", DemoKubernetesConnector)
    # Endpoint & SIEM
    connectors.register("defender", DemoDefenderConnector)
    connectors.register("sentinelone", DemoSentinelOneConnector)
    connectors.register("intune", DemoIntuneConnector)
    connectors.register("sentinel", DemoSentinelConnector)
    connectors.register("splunk", DemoSplunkConnector)
    connectors.register("elastic", DemoElasticConnector)
    # Scanners & CSPM
    connectors.register("tenable", DemoTenableConnector)
    connectors.register("qualys", DemoQualysConnector)
    connectors.register("wiz", DemoWizConnector)
    connectors.register("prisma", DemoPrismaConnector)
    # ITSM & GRC
    connectors.register("servicenow", DemoServiceNowConnector)
    connectors.register("onetrust", DemoOneTrustConnector)
    connectors.register("mlflow", DemoMLflowConnector)
    # Code security
    connectors.register("snyk", DemoSnykConnector)
    connectors.register("github", DemoGitHubConnector)
    # Email, DLP, Backup, Physical
    connectors.register("proofpoint", DemoProofpointConnector)
    connectors.register("purview", DemoPurviewConnector)
    connectors.register("veeam", DemoVeeamConnector)
    connectors.register("verkada", DemoVerkadaConnector)
    # Network security
    connectors.register("palo_alto", DemoPaloAltoConnector)
    connectors.register("fortinet", DemoFortinetConnector)
    connectors.register("zscaler", DemoZscalerConnector)
    # MDM & Auth
    connectors.register("jamf", DemoJamfConnector)
    connectors.register("duo", DemoDuoConnector)
    connectors.register("onepassword", DemoOnePasswordConnector)
    connectors.register("bitwarden", DemoBitwardenConnector)
    # Cloud threat detection
    connectors.register("guardduty", DemoGuardDutyConnector)
    # Observability
    connectors.register("datadog", DemoDatadogConnector)
    connectors.register("newrelic", DemoNewRelicConnector)
    # Code security
    connectors.register("checkmarx", DemoCheckmarxConnector)
    connectors.register("sonarqube", DemoSonarQubeConnector)
    # Email security
    connectors.register("abnormal_security", DemoAbnormalSecurityConnector)
    # CASB / DLP
    connectors.register("netskope", DemoNetskopeConnector)
    # Scanner
    connectors.register("nessus", DemoNessusConnector)
    # HRIS
    connectors.register("bamboohr", DemoBambooHRConnector)
    # Endpoint
    connectors.register("sophos", DemoSophosConnector)

    # New connectors (batch 2)
    connectors.register("jumpcloud", DemoJumpCloudConnector)
    connectors.register("auth0", DemoAuth0Connector)
    connectors.register("gitlab", DemoGitLabConnector)
    connectors.register("jira", DemoJiraConnector)
    connectors.register("slack", DemoSlackConnector)
    connectors.register("google_workspace", DemoGoogleWorkspaceConnector)
    connectors.register("semgrep", DemoSemgrepConnector)
    connectors.register("trivy", DemoTrivyConnector)
    connectors.register("gitguardian", DemoGitGuardianConnector)
    connectors.register("veracode", DemoVeracodeConnector)
    connectors.register("hashicorp", DemoTerraformCloudConnector)
    connectors.register("aqua", DemoAquaConnector)
    connectors.register("kandji", DemoKandjiConnector)
    connectors.register("grafana", DemoGrafanaConnector)
    connectors.register("bitsight", DemoBitSightConnector)
    connectors.register("gusto", DemoGustoConnector)
    connectors.register("rippling", DemoRipplingConnector)
    connectors.register("aws_sagemaker", DemoSageMakerConnector)
    connectors.register("databricks", DemoDatabricksConnector)
    connectors.register("microsoft_exchange", DemoExchangeOnlineConnector)
    # CI/CD
    connectors.register("jenkins", DemoJenkinsConnector)
    connectors.register("github_actions", DemoGitHubActionsConnector)
    connectors.register("gitlab_ci", DemoGitLabCIConnector)
    connectors.register("circleci", DemoCircleCIConnector)

    # New connectors (84 new sources)
    _new_provider_map = [
        ("pagerduty", "DemoPagerDutyConnector"),
        ("opsgenie", "DemoOpsgenieConnector"),
        ("axonius", "DemoAxoniusConnector"),
        ("servicenow_cmdb", "DemoServiceNowCMDBConnector"),
        ("runzero", "DemoRunZeroConnector"),
        ("patch_mgmt_microsoft", "DemoPatchMgmtMicrosoftConnector"),
        ("ivanti", "DemoIvantiConnector"),
        ("venafi", "DemoVenafiConnector"),
        ("aws_acm", "DemoAWSACMConnector"),
        ("digicert", "DemoDigiCertConnector"),
        ("aws_secrets", "DemoAWSSecretsConnector"),
        ("azure_keyvault", "DemoAzureKeyVaultConnector"),
        ("gcp_secrets", "DemoGCPSecretsConnector"),
        ("servicenow_grc", "DemoServiceNowGRCConnector"),
        ("nightfall", "DemoNightfallConnector"),
        ("aws_backup", "DemoAWSBackupConnector"),
        ("orca", "DemoOrcaConnector"),
        ("lacework", "DemoLaceworkConnector"),
        ("rapid7", "DemoRapid7Connector"),
        ("crowdstrike_spotlight", "DemoCrowdStrikeSpotlightConnector"),
        ("ping_identity", "DemoPingIdentityConnector"),
        ("onelogin", "DemoOneLoginConnector"),
        ("workspace_one", "DemoWorkspaceOneConnector"),
        ("sumo_logic", "DemoSumoLogicConnector"),
        ("cisco_umbrella", "DemoCiscoUmbrellaConnector"),
        ("drata", "DemoDrataConnector"),
        ("vanta", "DemoVantaConnector"),
        ("archer", "DemoArcherConnector"),
        ("drata_api", "DemoDrataAPIConnector"),
        ("vanta_api", "DemoVantaAPIConnector"),
        ("secureframe", "DemoSecureframeConnector"),
        ("salesforce", "DemoSalesforceConnector"),
        ("teams_compliance", "DemoTeamsComplianceConnector"),
        ("zoom", "DemoZoomConnector"),
        ("smarsh", "DemoSmarshConnector"),
        ("ansible", "DemoAnsibleConnector"),
        ("adp", "DemoADPConnector"),
        ("ukg", "DemoUKGConnector"),
        ("sap_successfactors", "DemoSAPSuccessFactorsConnector"),
        ("wandb", "DemoWandBConnector"),
        ("vertex_ai", "DemoVertexAIConnector"),
        ("mimecast", "DemoMimecastConnector"),
        ("chainguard", "DemoChainGuardConnector"),
        ("syft_grype", "DemoSyftGrypeConnector"),
        ("fossa", "DemoFossaConnector"),
        ("snyk_container", "DemoSnykContainerConnector"),
        ("socketdev", "DemoSocketDevConnector"),
        ("salt_security", "DemoSaltSecurityConnector"),
        ("noname", "DemoNoNameConnector"),
        ("wallarm", "DemoWallarmConnector"),
        ("fortytwoCrunch", "DemoFortyTwoCrunchConnector"),
        ("tailscale", "DemoTailscaleConnector"),
        ("twingate", "DemoTwingateConnector"),
        ("banyan", "DemoBanyanConnector"),
        ("code42", "DemoCode42Connector"),
        ("varonis", "DemoVaronisConnector"),
        ("bigid", "DemoBigIDConnector"),
        ("rubrik_security", "DemoRubrikSecurityConnector"),
        ("commvault", "DemoCommvaultConnector"),
        ("rubrik", "DemoRubrikConnector"),
        ("cohesity", "DemoCohesityConnector"),
        ("druva", "DemoDruvaConnector"),
        ("ermetic", "DemoErmeticConnector"),
        ("trustarc", "DemoTrustArcConnector"),
        ("cookiebot", "DemoCookiebotConnector"),
        ("osano", "DemoOsanoConnector"),
        ("vulcan", "DemoVulcanConnector"),
        ("tanium", "DemoTaniumConnector"),
        ("automox", "DemoAutomoxConnector"),
        ("fleet", "DemoFleetConnector"),
        ("cobalt", "DemoCobaltConnector"),
        ("hackerone", "DemoHackerOneConnector"),
        ("linode", "DemoLinodeConnector"),
        ("hetzner", "DemoHetznerConnector"),
        ("logrhythm", "DemoLogRhythmConnector"),
        ("barracuda", "DemoBarracudaConnector"),
        ("f5", "DemoF5Connector"),
        ("paylocity", "DemoPaylocityConnector"),
        ("kubecost", "DemoKubecostConnector"),
        ("infracost", "DemoInfracostConnector"),
        ("spotio", "DemoSpotioConnector"),
        ("manageengine", "DemoManageEngineConnector"),
        ("ivanti_patch", "DemoIvantiPatchConnector"),
        ("plextrac", "DemoPlexTracConnector"),
    ]
    # Build class lookup from ALL_NEW_CONNECTORS
    _new_cls_map = {cls.__name__: cls for cls in ALL_NEW_CONNECTORS}
    for _provider, _cls_name in _new_provider_map:
        _cls = _new_cls_map.get(_cls_name)
        if _cls:
            connectors.register(_provider, _cls)

    # Expansion connectors (186 new sources)
    _expansion_provider_map = [
        ("heroku", "DemoHerokuConnector"),
        ("scaleway", "DemoScalewayConnector"),
        ("render", "DemoRenderConnector"),
        ("netlify", "DemoNetlifyConnector"),
        ("vercel_cloud", "DemoVercelCloudConnector"),
        ("mongodb_atlas", "DemoMongoDBAtlasConnector"),
        ("supabase", "DemoSupabaseConnector"),
        ("snowflake", "DemoSnowflakeConnector"),
        ("aws_govcloud", "DemoAWSGovCloudConnector"),
        ("aws_inspector", "DemoAWSInspectorConnector"),
        ("akamai", "DemoAkamaiConnector"),
        ("imperva", "DemoImpervaConnector"),
        ("ping_identity_new", "DemoPingIdentityNewConnector"),
        ("lastpass", "DemoLastPassConnector"),
        ("dashlane", "DemoDashlaneConnector"),
        ("nordpass", "DemoNordPassConnector"),
        ("keeper", "DemoKeeperConnector"),
        ("accessowl", "DemoAccessOwlConnector"),
        ("indent", "DemoIndentConnector"),
        ("saviynt", "DemoSaviyntConnector"),
        ("conductorone", "DemoConductorOneConnector"),
        ("boundary", "DemoBoundaryConnector"),
        ("teleport", "DemoTeleportConnector"),
        ("strongdm", "DemoStrongDMConnector"),
        ("doppler", "DemoDopplerConnector"),
        ("infisical", "DemoInfisicalConnector"),
        ("bitbucket", "DemoBitbucketConnector"),
        ("aws_codecommit", "DemoAWSCodeCommitConnector"),
        ("azure_repos", "DemoAzureReposConnector"),
        ("azure_devops", "DemoAzureDevOpsConnector"),
        ("argocd", "DemoArgoCDConnector"),
        ("harness", "DemoHarnessConnector"),
        ("buildkite", "DemoBuildkiteConnector"),
        ("launchdarkly", "DemoLaunchDarklyConnector"),
        ("fivetran", "DemoFivetranConnector"),
        ("dbt_labs", "DemoDbtLabsConnector"),
        ("asana", "DemoAsanaConnector"),
        ("linear", "DemoLinearConnector"),
        ("clickup", "DemoClickUpConnector"),
        ("trello", "DemoTrelloConnector"),
        ("monday", "DemoMondayConnector"),
        ("shortcut", "DemoShortcutConnector"),
        ("notion", "DemoNotionConnector"),
        ("smartsheet", "DemoSmartsheetConnector"),
        ("wrike", "DemoWrikeConnector"),
        ("basecamp", "DemoBasecampConnector"),
        ("height", "DemoHeightConnector"),
        ("freshservice", "DemoFreshserviceConnector"),
        ("freshdesk", "DemoFreshdeskConnector"),
        ("zendesk", "DemoZendeskConnector"),
        ("zoho_desk", "DemoZohoDeskConnector"),
        ("hibob", "DemoHiBobConnector"),
        ("justworks", "DemoJustworksConnector"),
        ("lattice", "DemoLatticeConnector"),
        ("trinet", "DemoTriNetConnector"),
        ("dayforce", "DemoDayforceConnector"),
        ("oracle_hcm", "DemoOracleHCMConnector"),
        ("personio", "DemoPersonioConnector"),
        ("deel", "DemoDeelConnector"),
        ("namely", "DemoNamelyConnector"),
        ("paychex_flex", "DemoPaychexFlexConnector"),
        ("humaans", "DemoHumaansConnector"),
        ("xero_payroll", "DemoXeroPayrollConnector"),
        ("fifteenfive", "DemoFifteenFiveConnector"),
        ("leapsome", "DemoLeapsomeConnector"),
        ("hr_cloud", "DemoHRCloudConnector"),
        ("isolved", "DemoISolvedConnector"),
        ("kenjo", "DemoKenjoConnector"),
        ("employment_hero", "DemoEmploymentHeroConnector"),
        ("zoho_people", "DemoZohoPeopleConnector"),
        ("greenhouse", "DemoGreenhouseConnector"),
        ("lever", "DemoLeverConnector"),
        ("ashby", "DemoAshbyConnector"),
        ("smartrecruiters", "DemoSmartRecruitersConnector"),
        ("teamtailor", "DemoTeamtailorConnector"),
        ("workable", "DemoWorkableConnector"),
        ("checkr", "DemoCheckrConnector"),
        ("certn", "DemoCertnConnector"),
        ("hireright", "DemoHireRightConnector"),
        ("sterling", "DemoSterlingConnector"),
        ("three60learning", "DemoThree60LearningConnector"),
        ("cornerstone", "DemoCornerstoneConnector"),
        ("coursera", "DemoCourseraConnector"),
        ("easyllama", "DemoEasyLlamaConnector"),
        ("infosec_iq", "DemoInfosecIQConnector"),
        ("linkedin_learning", "DemoLinkedInLearningConnector"),
        ("talentlms", "DemoTalentLMSConnector"),
        ("udemy", "DemoUdemyConnector"),
        ("docebo", "DemoDoceboConnector"),
        ("go1", "DemoGO1Connector"),
        ("sosafe", "DemoSoSafeConnector"),
        ("moxso", "DemoMoxsoConnector"),
        ("awarego", "DemoAwareGOConnector"),
        ("cybeready", "DemoCyberReadyConnector"),
        ("hexnode", "DemoHexnodeConnector"),
        ("ninjaone", "DemoNinjaOneConnector"),
        ("kolide", "DemoKolideConnector"),
        ("addigy", "DemoAddigyConnector"),
        ("miradore", "DemoMiradoreConnector"),
        ("aikido", "DemoAikidoConnector"),
        ("sonarcloud", "DemoSonarCloudConnector"),
        ("wiz_code", "DemoWizCodeConnector"),
        ("huntress", "DemoHuntressConnector"),
        ("jit_security", "DemoJitSecurityConnector"),
        ("upwind", "DemoUpwindConnector"),
        ("arnica", "DemoArnicaConnector"),
        ("pentera", "DemoPenteraConnector"),
        ("horizon3", "DemoHorizon3Connector"),
        ("bugcrowd", "DemoBugcrowdConnector"),
        ("intigriti", "DemoIntigritiConnector"),
        ("halo_security", "DemoHaloSecurityConnector"),
        ("traceable_ai", "DemoTraceableAIConnector"),
        ("sentry", "DemoSentryConnector"),
        ("rollbar", "DemoRollbarConnector"),
        ("dynatrace", "DemoDynatraceConnector"),
        ("sumo_logic_new", "DemoSumoLogicNewConnector"),
        ("hubspot", "DemoHubSpotConnector"),
        ("pipedrive", "DemoPipedriveConnector"),
        ("intercom", "DemoIntercomConnector"),
        ("gong", "DemoGongConnector"),
        ("freshsales", "DemoFreshsalesConnector"),
        ("attio", "DemoAttioConnector"),
        ("copper", "DemoCopperConnector"),
        ("close_crm", "DemoCloseCRMConnector"),
        ("microsoft_teams", "DemoMicrosoftTeamsConnector"),
        ("miro", "DemoMiroConnector"),
        ("webex", "DemoWebexConnector"),
        ("ringcentral", "DemoRingCentralConnector"),
        ("aircall", "DemoAircallConnector"),
        ("dialpad", "DemoDialpadConnector"),
        ("eight_x_eight", "DemoEightByEightConnector"),
        ("twilio", "DemoTwilioConnector"),
        ("box", "DemoBoxConnector"),
        ("dropbox", "DemoDropboxConnector"),
        ("google_drive", "DemoGoogleDriveConnector"),
        ("egnyte", "DemoEgnyteConnector"),
        ("ramp", "DemoRampConnector"),
        ("brex", "DemoBrexConnector"),
        ("netsuite", "DemoNetSuiteConnector"),
        ("vendr", "DemoVendrConnector"),
        ("docusign", "DemoDocuSignConnector"),
        ("ironclad", "DemoIroncladConnector"),
        ("dropbox_sign", "DemoDropboxSignConnector"),
        ("segment", "DemoSegmentConnector"),
        ("mixpanel", "DemoMixpanelConnector"),
        ("tableau", "DemoTableauConnector"),
        ("domo", "DemoDomoConnector"),
        ("qlik", "DemoQlikConnector"),
        ("sigma_computing", "DemoSigmaComputingConnector"),
        ("transcend", "DemoTranscendConnector"),
        ("ketch", "DemoKetchConnector"),
        ("openai_platform", "DemoOpenAIPlatformConnector"),
        ("anthropic_platform", "DemoAnthropicPlatformConnector"),
        ("aws_bedrock", "DemoAWSBedrockConnector"),
        ("credo_ai", "DemoCredoAIConnector"),
        ("arthur_ai", "DemoArthurAIConnector"),
        ("fiddler_ai", "DemoFiddlerAIConnector"),
        ("appomni", "DemoAppOmniConnector"),
        ("obsidian_security", "DemoObsidianSecurityConnector"),
        ("nudge_security", "DemoNudgeSecurityConnector"),
        ("rootly", "DemoRootlyConnector"),
        ("incident_io", "DemoIncidentIOConnector"),
        ("firehydrant", "DemoFireHydrantConnector"),
        ("snipe_it", "DemoSnipeITConnector"),
        ("oomnitza", "DemoOomnitzaConnector"),
        ("servicenow_itam", "DemoServiceNowITAMConnector"),
        ("monte_carlo", "DemoMonteCarloConnector"),
        ("bigeye", "DemoBigeyeConnector"),
        ("vantage_finops", "DemoVantageFinOpsConnector"),
        ("cloudhealth", "DemoCloudHealthConnector"),
        ("spot_netapp", "DemoSpotNetAppConnector"),
        ("zentry", "DemoZentryConnector"),
        ("openvpn", "DemoOpenVPNConnector"),
        ("teamviewer", "DemoTeamViewerConnector"),
        ("cyral", "DemoCyralConnector"),
        ("immuta", "DemoImmutaConnector"),
        ("sprinto", "DemoSprintoConnector"),
        ("thoropass", "DemoThoropassConnector"),
        ("backstage", "DemoBackstageConnector"),
        ("retool", "DemoRetoolConnector"),
        ("sendgrid", "DemoSendGridConnector"),
        ("envoy", "DemoEnvoyConnector"),
        ("canva", "DemoCanvaConnector"),
        ("jetbrains", "DemoJetBrainsConnector"),
        ("webflow", "DemoWebflowConnector"),
        ("contentful", "DemoContentfulConnector"),
    ]
    _expansion_cls_map = {cls.__name__: cls for cls in ALL_EXPANSION_CONNECTORS}
    for _provider, _cls_name in _expansion_provider_map:
        _cls = _expansion_cls_map.get(_cls_name)
        if _cls:
            connectors.register(_provider, _cls)

    # Create all connector instances
    from scripts.seed_impl.connector_config_lists import (
        DEMO_CONNECTOR_TUPLES,
        EXPANSION_CONNECTOR_TUPLES,
    )

    for name, stype, provider in DEMO_CONNECTOR_TUPLES + EXPANSION_CONNECTOR_TUPLES:
        connectors.create(ConnectorConfig(name=name, source_type=stype, provider=provider))

    normalizers = NormalizerRegistry()
    # Register all normalizers (order matters — specific before generic)
    normalizers.register(AWSNormalizer())
    normalizers.register(AzureNormalizer())
    normalizers.register(GCPNormalizer())
    normalizers.register(OktaNormalizer())
    normalizers.register(CrowdStrikeNormalizer())
    normalizers.register(WorkdayNormalizer())
    normalizers.register(KnowBe4Normalizer())
    normalizers.register(SecurityScorecardNormalizer())
    normalizers.register(ConfluenceNormalizer())
    normalizers.register(EntraIDNormalizer())
    normalizers.register(CyberArkNormalizer())
    normalizers.register(SailPointNormalizer())
    normalizers.register(VaultNormalizer())
    normalizers.register(DigitalOceanNormalizer())
    normalizers.register(AlibabaNormalizer())
    normalizers.register(HuaweiNormalizer())
    normalizers.register(IBMCloudNormalizer())
    normalizers.register(OVHNormalizer())
    normalizers.register(OCINormalizer())
    normalizers.register(CloudflareNormalizer())
    normalizers.register(KubernetesNormalizer())
    normalizers.register(DefenderNormalizer())
    normalizers.register(SentinelOneNormalizer())
    normalizers.register(IntuneNormalizer())
    normalizers.register(SentinelNormalizer())
    normalizers.register(SplunkNormalizer())
    normalizers.register(ElasticNormalizer())
    normalizers.register(TenableNormalizer())
    normalizers.register(QualysNormalizer())
    normalizers.register(WizNormalizer())
    normalizers.register(PrismaNormalizer())
    normalizers.register(ServiceNowNormalizer())
    normalizers.register(OneTrustNormalizer())
    normalizers.register(MLflowNormalizer())
    normalizers.register(SnykNormalizer())
    normalizers.register(GitHubNormalizer())
    normalizers.register(ProofpointNormalizer())
    normalizers.register(PurviewNormalizer())
    normalizers.register(VeeamNormalizer())
    normalizers.register(VerkadaNormalizer())
    normalizers.register(PaloAltoNormalizer())
    normalizers.register(FortinetNormalizer())
    normalizers.register(ZscalerNormalizer())
    normalizers.register(JamfNormalizer())
    normalizers.register(DuoNormalizer())
    normalizers.register(OnePasswordNormalizer())
    normalizers.register(BitwardenNormalizer())
    normalizers.register(GuardDutyNormalizer())
    normalizers.register(DatadogNormalizer())
    normalizers.register(NewRelicNormalizer())
    normalizers.register(CheckmarxNormalizer())
    normalizers.register(SonarQubeNormalizer())
    normalizers.register(AbnormalSecurityNormalizer())
    normalizers.register(NetskopeNormalizer())
    normalizers.register(NessusNormalizer())
    normalizers.register(BambooHRNormalizer())
    normalizers.register(SophosNormalizer())
    # --- New normalizers (84) ---
    normalizers.register(PagerDutyNormalizer())
    normalizers.register(OpsgenieNormalizer())
    normalizers.register(AxoniusNormalizer())
    normalizers.register(ServiceNowCMDBNormalizer())
    normalizers.register(RunZeroNormalizer())
    normalizers.register(MicrosoftPatchMgmtNormalizer())
    normalizers.register(IvantiNormalizer())
    normalizers.register(VenafiNormalizer())
    normalizers.register(AwsAcmNormalizer())
    normalizers.register(DigiCertNormalizer())
    normalizers.register(AwsSecretsNormalizer())
    normalizers.register(AzureKeyVaultNormalizer())
    normalizers.register(GcpSecretsNormalizer())
    normalizers.register(ServiceNowGRCNormalizer())
    normalizers.register(NightfallNormalizer())
    normalizers.register(AWSBackupNormalizer())
    normalizers.register(OrcaNormalizer())
    normalizers.register(LaceworkNormalizer())
    normalizers.register(Rapid7Normalizer())
    normalizers.register(CrowdStrikeSpotlightNormalizer())
    normalizers.register(PingIdentityNormalizer())
    normalizers.register(OneLoginNormalizer())
    normalizers.register(WorkspaceOneNormalizer())
    normalizers.register(SumoLogicNormalizer())
    normalizers.register(CiscoUmbrellaNormalizer())
    normalizers.register(DrataNormalizer())
    normalizers.register(VantaNormalizer())
    normalizers.register(ArcherNormalizer())
    normalizers.register(DrataApiNormalizer())
    normalizers.register(VantaApiNormalizer())
    normalizers.register(SecureframeNormalizer())
    normalizers.register(SalesforceNormalizer())
    normalizers.register(TeamsComplianceNormalizer())
    normalizers.register(ZoomNormalizer())
    normalizers.register(SmarshNormalizer())
    normalizers.register(AnsibleNormalizer())
    normalizers.register(ADPNormalizer())
    normalizers.register(UKGNormalizer())
    normalizers.register(SAPSuccessFactorsNormalizer())
    normalizers.register(WandbNormalizer())
    normalizers.register(VertexAINormalizer())
    normalizers.register(MimecastNormalizer())
    normalizers.register(ChainguardNormalizer())
    normalizers.register(SyftGrypeNormalizer())
    normalizers.register(FossaNormalizer())
    normalizers.register(SnykContainerNormalizer())
    normalizers.register(SocketdevNormalizer())
    normalizers.register(SaltSecurityNormalizer())
    normalizers.register(NonameNormalizer())
    normalizers.register(WallarmNormalizer())
    normalizers.register(FortyTwoCrunchNormalizer())
    normalizers.register(TailscaleNormalizer())
    normalizers.register(TwingateNormalizer())
    normalizers.register(BanyanNormalizer())
    normalizers.register(Code42Normalizer())
    normalizers.register(VaronisNormalizer())
    normalizers.register(BigIDNormalizer())
    normalizers.register(RubrikSecurityNormalizer())
    normalizers.register(CommvaultNormalizer())
    normalizers.register(RubrikNormalizer())
    normalizers.register(CohesityNormalizer())
    normalizers.register(DruvaNormalizer())
    normalizers.register(ErmeticNormalizer())
    normalizers.register(TrustArcNormalizer())
    normalizers.register(CookiebotNormalizer())
    normalizers.register(OsanoNormalizer())
    normalizers.register(VulcanNormalizer())
    normalizers.register(TaniumNormalizer())
    normalizers.register(AutomoxNormalizer())
    normalizers.register(FleetNormalizer())
    normalizers.register(CobaltNormalizer())
    normalizers.register(HackerOneNormalizer())
    normalizers.register(LinodeNormalizer())
    normalizers.register(HetznerNormalizer())
    normalizers.register(LogRhythmNormalizer())
    normalizers.register(BarracudaNormalizer())
    normalizers.register(F5Normalizer())
    normalizers.register(PaylocityNormalizer())
    normalizers.register(KubecostNormalizer())
    normalizers.register(InfracostNormalizer())
    normalizers.register(SpotioNormalizer())
    normalizers.register(ManageEngineNormalizer())
    normalizers.register(IvantiPatchNormalizer())
    normalizers.register(PlexTracNormalizer())
    # --- Expansion normalizers (186) ---
    normalizers.register(HerokuNormalizer())
    normalizers.register(ScalewayNormalizer())
    normalizers.register(RenderNormalizer())
    normalizers.register(NetlifyNormalizer())
    normalizers.register(VercelCloudNormalizer())
    normalizers.register(MongoDBAtlasNormalizer())
    normalizers.register(SupabaseNormalizer())
    normalizers.register(SnowflakeNormalizer())
    normalizers.register(AWSGovCloudNormalizer())
    normalizers.register(AWSInspectorNormalizer())
    normalizers.register(AkamaiNormalizer())
    normalizers.register(ImpervaNormalizer())
    normalizers.register(PingIdentityNewNormalizer())
    normalizers.register(LastPassNormalizer())
    normalizers.register(DashlaneNormalizer())
    normalizers.register(NordPassNormalizer())
    normalizers.register(KeeperNormalizer())
    normalizers.register(AccessOwlNormalizer())
    normalizers.register(IndentNormalizer())
    normalizers.register(SaviyntNormalizer())
    normalizers.register(ConductorOneNormalizer())
    normalizers.register(BoundaryNormalizer())
    normalizers.register(TeleportNormalizer())
    normalizers.register(StrongDMNormalizer())
    normalizers.register(DopplerNormalizer())
    normalizers.register(InfisicalNormalizer())
    normalizers.register(BitbucketNormalizer())
    normalizers.register(AWSCodeCommitNormalizer())
    normalizers.register(AzureReposNormalizer())
    normalizers.register(AzureDevOpsNormalizer())
    normalizers.register(ArgoCDNormalizer())
    normalizers.register(HarnessNormalizer())
    normalizers.register(BuildkiteNormalizer())
    normalizers.register(LaunchDarklyNormalizer())
    normalizers.register(FivetranNormalizer())
    normalizers.register(DbtLabsNormalizer())
    normalizers.register(AsanaNormalizer())
    normalizers.register(LinearNormalizer())
    normalizers.register(ClickUpNormalizer())
    normalizers.register(TrelloNormalizer())
    normalizers.register(MondayNormalizer())
    normalizers.register(ShortcutNormalizer())
    normalizers.register(NotionNormalizer())
    normalizers.register(SmartsheetNormalizer())
    normalizers.register(WrikeNormalizer())
    normalizers.register(BasecampNormalizer())
    normalizers.register(HeightNormalizer())
    normalizers.register(FreshserviceNormalizer())
    normalizers.register(FreshdeskNormalizer())
    normalizers.register(ZendeskNormalizer())
    normalizers.register(ZohoDeskNormalizer())
    normalizers.register(HiBobNormalizer())
    normalizers.register(JustworksNormalizer())
    normalizers.register(LatticeNormalizer())
    normalizers.register(TriNetNormalizer())
    normalizers.register(DayforceNormalizer())
    normalizers.register(OracleHCMNormalizer())
    normalizers.register(PersonioNormalizer())
    normalizers.register(DeelNormalizer())
    normalizers.register(NamelyNormalizer())
    normalizers.register(PaychexFlexNormalizer())
    normalizers.register(HumaansNormalizer())
    normalizers.register(XeroPayrollNormalizer())
    normalizers.register(FifteenFiveNormalizer())
    normalizers.register(LeapsomeNormalizer())
    normalizers.register(HRCloudNormalizer())
    normalizers.register(ISolvedNormalizer())
    normalizers.register(KenjoNormalizer())
    normalizers.register(EmploymentHeroNormalizer())
    normalizers.register(ZohoPeopleNormalizer())
    normalizers.register(GreenhouseNormalizer())
    normalizers.register(LeverNormalizer())
    normalizers.register(AshbyNormalizer())
    normalizers.register(SmartRecruitersNormalizer())
    normalizers.register(TeamtailorNormalizer())
    normalizers.register(WorkableNormalizer())
    normalizers.register(CheckrNormalizer())
    normalizers.register(CertnNormalizer())
    normalizers.register(HireRightNormalizer())
    normalizers.register(SterlingNormalizer())
    normalizers.register(Three60LearningNormalizer())
    normalizers.register(CornerstoneNormalizer())
    normalizers.register(CourseraNormalizer())
    normalizers.register(EasyLlamaNormalizer())
    normalizers.register(InfosecIQNormalizer())
    normalizers.register(LinkedInLearningNormalizer())
    normalizers.register(TalentLMSNormalizer())
    normalizers.register(UdemyNormalizer())
    normalizers.register(DoceboNormalizer())
    normalizers.register(GO1Normalizer())
    normalizers.register(SoSafeNormalizer())
    normalizers.register(MoxsoNormalizer())
    normalizers.register(AwareGONormalizer())
    normalizers.register(CyberReadyNormalizer())
    normalizers.register(HexnodeNormalizer())
    normalizers.register(NinjaOneNormalizer())
    normalizers.register(KolideNormalizer())
    normalizers.register(AddigyNormalizer())
    normalizers.register(MiradoreNormalizer())
    normalizers.register(AikidoNormalizer())
    normalizers.register(SonarCloudNormalizer())
    normalizers.register(WizCodeNormalizer())
    normalizers.register(HuntressNormalizer())
    normalizers.register(JitSecurityNormalizer())
    normalizers.register(UpwindNormalizer())
    normalizers.register(ArnicaNormalizer())
    normalizers.register(PenteraNormalizer())
    normalizers.register(Horizon3Normalizer())
    normalizers.register(BugcrowdNormalizer())
    normalizers.register(IntigritiNormalizer())
    normalizers.register(HaloSecurityNormalizer())
    normalizers.register(TraceableAINormalizer())
    normalizers.register(SentryNormalizer())
    normalizers.register(RollbarNormalizer())
    normalizers.register(DynatraceNormalizer())
    normalizers.register(SumoLogicNewNormalizer())
    normalizers.register(HubSpotNormalizer())
    normalizers.register(PipedriveNormalizer())
    normalizers.register(IntercomNormalizer())
    normalizers.register(GongNormalizer())
    normalizers.register(FreshsalesNormalizer())
    normalizers.register(AttioNormalizer())
    normalizers.register(CopperNormalizer())
    normalizers.register(CloseCRMNormalizer())
    normalizers.register(MicrosoftTeamsNormalizer())
    normalizers.register(MiroNormalizer())
    normalizers.register(WebexNormalizer())
    normalizers.register(RingCentralNormalizer())
    normalizers.register(AircallNormalizer())
    normalizers.register(DialpadNormalizer())
    normalizers.register(EightByEightNormalizer())
    normalizers.register(TwilioNormalizer())
    normalizers.register(BoxNormalizer())
    normalizers.register(DropboxNormalizer())
    normalizers.register(GoogleDriveNormalizer())
    normalizers.register(EgnyteNormalizer())
    normalizers.register(RampNormalizer())
    normalizers.register(BrexNormalizer())
    normalizers.register(NetSuiteNormalizer())
    normalizers.register(VendrNormalizer())
    normalizers.register(DocuSignNormalizer())
    normalizers.register(IroncladNormalizer())
    normalizers.register(DropboxSignNormalizer())
    normalizers.register(SegmentNormalizer())
    normalizers.register(MixpanelNormalizer())
    normalizers.register(TableauNormalizer())
    normalizers.register(DomoNormalizer())
    normalizers.register(QlikNormalizer())
    normalizers.register(SigmaComputingNormalizer())
    normalizers.register(TranscendNormalizer())
    normalizers.register(KetchNormalizer())
    normalizers.register(OpenAIPlatformNormalizer())
    normalizers.register(AnthropicPlatformNormalizer())
    normalizers.register(AWSBedrockNormalizer())
    normalizers.register(CredoAINormalizer())
    normalizers.register(ArthurAINormalizer())
    normalizers.register(FiddlerAINormalizer())
    normalizers.register(AppOmniNormalizer())
    normalizers.register(ObsidianSecurityNormalizer())
    normalizers.register(NudgeSecurityNormalizer())
    normalizers.register(RootlyNormalizer())
    normalizers.register(IncidentIONormalizer())
    normalizers.register(FireHydrantNormalizer())
    normalizers.register(SnipeITNormalizer())
    normalizers.register(OomnitzaNormalizer())
    normalizers.register(ServiceNowITAMNormalizer())
    normalizers.register(MonteCarloNormalizer())
    normalizers.register(BigeyeNormalizer())
    normalizers.register(VantageFinOpsNormalizer())
    normalizers.register(CloudHealthNormalizer())
    normalizers.register(SpotNetAppNormalizer())
    normalizers.register(ZentryNormalizer())
    normalizers.register(OpenVPNNormalizer())
    normalizers.register(TeamViewerNormalizer())
    normalizers.register(CyralNormalizer())
    normalizers.register(ImmutaNormalizer())
    normalizers.register(SprintoNormalizer())
    normalizers.register(ThoropassNormalizer())
    normalizers.register(BackstageNormalizer())
    normalizers.register(RetoolNormalizer())
    normalizers.register(SendGridNormalizer())
    normalizers.register(EnvoyNormalizer())
    normalizers.register(CanvaNormalizer())
    normalizers.register(JetBrainsNormalizer())
    normalizers.register(WebflowNormalizer())
    normalizers.register(ContentfulNormalizer())
    normalizers.register(GenericNormalizer())  # Generic must be last (fallback)

    mapper = ControlMapper()
    framework_dir = str(REPO_ROOT / "warlock" / "frameworks")
    load_framework_configs(framework_dir, mapper)

    # Wire AI reasoning (default: Ollama Cloud / qwen3-coder:30b)
    # Override with WLK_AI_PROVIDER, WLK_AI_API_KEY, WLK_AI_MODEL, WLK_AI_BASE_URL
    ai_reasoner = None
    try:
        from warlock.assessors.ai_reasoning import create_reasoner
        from warlock.config import get_settings

        settings = get_settings()
        if getattr(settings, "ai_enabled", True) and settings.ai_provider and settings.ai_api_key:
            ai_reasoner = create_reasoner(
                provider=settings.ai_provider,
                api_key=settings.ai_api_key,
                model=settings.ai_model,
                base_url=getattr(settings, "ai_base_url", ""),
            )
            print(f"       AI reasoning enabled: {settings.ai_provider}/{settings.ai_model}")
        elif settings.ai_provider and not settings.ai_api_key:
            print(
                f"       AI provider '{settings.ai_provider}' configured but no API key — deterministic only"
            )
    except Exception:
        pass  # No AI — deterministic only

    assessor = Assessor(engine=assertion_engine, ai_reasoner=ai_reasoner)

    pipeline = Pipeline(
        connectors=connectors,
        normalizers=normalizers,
        mapper=mapper,
        assessor=assessor,
        bus=bus,
    )

    # 3. Run pipeline
    ai_label = " + AI reasoning" if ai_reasoner else ""
    print(f"[3/34] Running pipeline (collect -> normalize -> map -> assess{ai_label})...")
    with get_session() as session:
        stats = pipeline.run(session)

    # 3b. Flush lake writer if enabled
    if lake_writer is not None:
        with get_session() as lake_session:
            lake_stats = lake_writer.flush(stats.run_id, lake_session)
            print(
                f"  Lake write: {lake_stats.raw_events_written} raw, "
                f"{lake_stats.findings_written} findings, "
                f"{lake_stats.control_results_written} results"
            )

    # 4. Print results
    print("[4/34] Done with pipeline!\n")
    print("-" * 60)
    print(f"  Raw events collected:   {stats.raw_events_collected}")
    print(f"  Findings normalized:    {stats.findings_normalized}")
    print(f"  Controls mapped:        {stats.controls_mapped}")
    print(f"  Results assessed:       {stats.results_assessed}")
    print(f"  Connectors succeeded:   {stats.connectors_succeeded}")
    print(f"  Connectors failed:      {stats.connectors_failed}")
    print(f"  Duration:               {stats.duration_seconds:.2f}s")
    if stats.errors:
        print(f"  Errors:                 {len(stats.errors)}")
        for err in stats.errors[:5]:
            print(f"    - {err}")
    print("-" * 60)

    # Show framework breakdown
    with get_session() as session:
        frameworks = (
            session.query(ControlResult.framework, func.count(ControlResult.id))
            .group_by(ControlResult.framework)
            .all()
        )
        if frameworks:
            print("\n  Results by framework:")
            for fw, count in sorted(frameworks):
                print(f"    {fw:20s}  {count} results")

        statuses = (
            session.query(ControlResult.status, func.count(ControlResult.id))
            .group_by(ControlResult.status)
            .all()
        )
        if statuses:
            print("\n  Results by status:")
            for status, count in sorted(statuses):
                print(f"    {status:20s}  {count}")

    # Verify lake was populated (if lake writer was active)
    if lake_writer is not None:
        print("[4a/34] Verifying lake population...")
        try:
            from warlock.lake.query import LakeQueryEngine as _LQE

            _lake_s = _get_settings()
            _lqe = _LQE(_lake_s.lake_path)
            _lake_base = Path(_lake_s.lake_path)
            _lake_dirs = [
                d.name for d in _lake_base.iterdir() if d.is_dir() and not d.name.startswith(".")
            ]
            print(f"       Lake partitions: {len(_lake_dirs)}")
            for _ld in sorted(_lake_dirs):
                _parquets = list((_lake_base / _ld).rglob("*.parquet"))
                if _parquets:
                    _tbl_glob = str(_lake_base / _ld / "**" / "*.parquet")
                    _cnt = _lqe.query(
                        f"SELECT COUNT(*) as cnt FROM read_parquet('{_tbl_glob}',"
                        " union_by_name=true)"
                    )
                    print(f"         {_ld}: {_cnt[0]['cnt'] if _cnt else 0} rows")
                else:
                    print(f"         {_ld}: (no parquet files)")
            _lqe.close()
        except Exception as _lake_exc:
            print(f"       Lake verification skipped: {_lake_exc}")

    print("[4b/20] Aging 50 findings for SLA breach demo...")
    with get_session() as session:
        n_aged = _age_some_findings(session)
        print(f"       Findings aged: {n_aged}")

    print("[4c/20] Seeding vendor records...")
    with get_session() as session:
        n_vendors = _seed_vendors(session)
        print(f"       Vendors created: {n_vendors}")

    print("[5/34] Seeding system profiles...")
    with get_session() as session:
        n = seed_systems(session)
        print(f"       Created {n} system profiles")

    print("[6/34] Syncing personnel from HR + IdP + training...")
    with get_session() as session:
        p = seed_personnel(session)
        print(f"       Personnel: {p['total']} records synced")

    print("[7/34] Seeding questionnaire templates and instances...")
    with get_session() as session:
        q = seed_questionnaires(session)
        print(f"       Templates: {q['templates']}, Questionnaires: {len(q['questionnaires'])}")

    print("[8/34] Seeding data silos, legal holds, and issues...")
    with get_session() as session:
        ds = seed_data_silos(session)
        print(
            f"       Data silos: {ds['discovered']} discovered + {ds['direct']} direct ({ds['enriched']} enriched)"
        )
        lh = seed_legal_holds(session)
        print(f"       Legal holds: {lh}")
        issues = seed_issues(session)
        print(f"       Issues: {issues['auto_created']} auto + {issues['manual']} manual")

    # --- Phase 2: POA&Ms, compensating controls, risk acceptances ---

    print("[9/34] Seeding POA&Ms...")
    with get_session() as session:
        n_poams = seed_phase2_poams(session)
        print(f"       POA&Ms: {n_poams}")

    print("[10/34] Seeding compensating controls...")
    with get_session() as session:
        n_cc = seed_phase2_compensating_controls(session)
        print(f"       Compensating controls: {n_cc}")

    print("[11/34] Seeding risk acceptances...")
    with get_session() as session:
        n_ra = seed_phase2_risk_acceptances(session)
        print(f"       Risk acceptances: {n_ra}")

    print("[12/34] Linking Issues <-> POA&Ms <-> ControlResults...")
    with get_session() as session:
        links = link_issues_and_poams(session)
        print(
            f"       POA&Ms linked to ControlResults: {links['poams_to_results']}, "
            f"Issues linked to POA&Ms: {links['issues_to_poams']}"
        )

    # --- Phase 3: Inheritance and dependencies ---

    print("[13/34] Seeding control inheritance records...")
    with get_session() as session:
        n_ci = seed_phase3_inheritance(session)
        print(f"       Control inheritances: {n_ci}")

    print("[14/34] Seeding system dependencies...")
    with get_session() as session:
        n_sd = seed_phase3_dependencies(session)
        print(f"       System dependencies: {n_sd}")

    # --- Phase 4: Change events, posture snapshots, drift ---

    print("[15/34] Seeding change events...")
    with get_session() as session:
        n_ce = seed_phase4_change_events(session)
        print(f"       Change events: {n_ce}")

    print("[16/34] Seeding posture snapshots (30 days)...")
    with get_session() as session:
        n_ps = seed_phase4_posture_snapshots(session)
        print(f"       Posture snapshots: {n_ps}")

    print("[17/34] Seeding compliance drift records...")
    with get_session() as session:
        n_drift = seed_phase4_drift(session)
        print(f"       Compliance drifts: {n_drift}")

    # --- Phase 5: Auditor engagement, policy overrides ---

    print("[18/34] Seeding auditor engagement and evidence requests...")
    with get_session() as session:
        ae = seed_phase5_auditor_engagement(session)
        print(
            f"       Auditors: {ae['auditors']}, Engagements: {ae['engagements']}, "
            f"Evidence requests: {ae['evidence_requests']}, Attestations: {ae['attestations']}"
        )

    print("[19/34] Seeding policy overrides + operational policies...")
    with get_session() as session:
        n_po = seed_phase5_policy_overrides(session)
        print(f"       Policy overrides: {n_po}")

        # Seed operational Policy records so `warlock policy list` shows data
        op_policies = [
            Policy(
                policy_type="sla",
                scope={"frameworks": ["nist_800_53", "soc2"]},
                rules={"remediation_days": 30, "escalate_after": 14},
                priority=10,
                created_by="ciso@acme.com",
                description="Default SLA for critical findings on NIST/SOC2 controls",
            ),
            Policy(
                policy_type="retention",
                scope={"frameworks": ["gdpr", "hipaa"]},
                rules={"days": 2555, "owner": "dpo@acme.com"},
                priority=5,
                created_by="dpo@acme.com",
                description="7-year evidence retention for regulated frameworks",
            ),
            Policy(
                policy_type="risk-appetite",
                scope={},
                rules={"max_ale": 500000, "max_var95": 250000},
                priority=1,
                created_by="cfo@acme.com",
                description="Enterprise risk appetite thresholds",
            ),
            Policy(
                policy_type="cadence",
                scope={"frameworks": ["nist_800_53"]},
                rules={"frequency": "quarterly"},
                priority=5,
                created_by="compliance@acme.com",
                description="Quarterly assessment cadence for NIST 800-53",
            ),
            Policy(
                policy_type="escalation",
                scope={"severity": ["critical", "high"]},
                rules={"escalate_after": 7, "notify": "security-leads@acme.com"},
                priority=20,
                created_by="ciso@acme.com",
                description="Auto-escalate critical/high findings after 7 days",
            ),
            Policy(
                policy_type="confidence",
                scope={"frameworks": ["soc2", "iso_27001"]},
                rules={"floor": 0.7},
                priority=5,
                created_by="compliance@acme.com",
                description="Minimum AI confidence floor for automated assessments",
            ),
            Policy(
                policy_type="evidence-requirement",
                scope={"frameworks": ["fedramp"]},
                rules={"max_age_days": 90, "require_attestation": True},
                priority=10,
                created_by="isso@acme.com",
                description="FedRAMP evidence must be <90 days old with attestation",
            ),
            Policy(
                policy_type="classification",
                scope={},
                rules={"default_level": "confidential", "pii_level": "restricted"},
                priority=1,
                created_by="dpo@acme.com",
                description="Default data classification levels",
            ),
        ]
        for p in op_policies:
            session.add(p)
        session.commit()
        print(f"       Operational policies: {len(op_policies)}")

    # --- Expand personnel ---

    print("[20/34] Expanding personnel to 50 users...")
    with get_session() as session:
        total_personnel = seed_50_personnel(session)
        print(f"       Total personnel: {total_personnel}")

    # --- Post-pipeline data enrichment ---

    print("[21/34] Assigning findings to system profiles...")
    with get_session() as session:
        assigned = _assign_findings_to_systems(session)
        print(f"       Findings assigned: {assigned}")

    print("[22/34] Backfilling monitoring_frequency on control mappings...")
    with get_session() as session:
        backfilled = _backfill_monitoring_frequency(session)
        print(f"       Mappings updated: {backfilled}")

    print("[23/34] Creating demo user accounts...")
    with get_session() as session:
        users_created = _create_demo_users(session)
        print(f"       Users created: {users_created}")

    print("[23a/34] Seeding 18 previously-empty tables + missing demo data...")
    with get_session() as session:
        et = _seed_empty_tables(session)
        total_et = sum(et.values())
        print(f"       Empty-table records: {total_et}")
        for k, v in sorted(et.items()):
            if v > 0:
                print(f"         {k}: {v}")

    # --- GAP-9/GAP-10: Aged findings for SLA breach / aging demos ---

    print("[24/34] Aging ~50 findings (7-90 days) for SLA demos...")
    with get_session() as session:
        n_aged = _age_findings(session)
        print(f"       Findings aged: {n_aged}")

    # --- GAP-5: Attestations ---

    print("[25/34] Seeding attestation records...")
    with get_session() as session:
        n_attest = _seed_attestations(session)
        print(f"       Attestations: {n_attest}")

    # --- GAP-12: Vendors with varied risk scores ---

    print("[26/34] Seeding vendor records...")
    with get_session() as session:
        n_vendors = _seed_vendors(session)
        print(f"       Vendors: {n_vendors}")

    # Enrich vendor metadata with SLA terms and sub-processors
    with get_session() as session:
        from warlock.db.models import Vendor as VendorModel

        sla_data = {
            "Stripe": {
                "sla_uptime_pct": 99.99,
                "sla_response_hours": 1,
                "subprocessors": [
                    {"name": "AWS", "purpose": "Infrastructure"},
                    {"name": "Cloudflare", "purpose": "CDN/DDoS"},
                ],
            },
            "Datadog": {
                "sla_uptime_pct": 99.9,
                "sla_response_hours": 4,
                "subprocessors": [
                    {"name": "AWS", "purpose": "Cloud hosting"},
                    {"name": "Google Cloud", "purpose": "ML pipeline"},
                ],
            },
            "CloudBackup Pro": {
                "sla_uptime_pct": 99.95,
                "sla_response_hours": 2,
                "subprocessors": [{"name": "Azure", "purpose": "Storage backend"}],
            },
            "SecureAuth Corp": {
                "sla_uptime_pct": 99.99,
                "sla_response_hours": 1,
                "subprocessors": [{"name": "Okta", "purpose": "Identity federation"}],
            },
            "GlobalPayments Ltd": {
                "sla_uptime_pct": 99.999,
                "sla_response_hours": 0.5,
                "subprocessors": [
                    {"name": "Visa", "purpose": "Card network"},
                    {"name": "Mastercard", "purpose": "Card network"},
                ],
            },
        }
        for v in session.query(VendorModel).all():
            if v.name in sla_data:
                meta = dict(v.metadata_ or {})
                meta.update(sla_data[v.name])
                v.metadata_ = meta
        session.commit()
        print(f"       Vendor metadata enriched: {len(sla_data)} vendors with SLA + sub-processors")

    # Seed webhook, user session events, and workpaper engagement links
    with get_session() as session:
        from warlock.db.audit import AuditTrail
        from warlock.db.models import AuditEngagement, AuditEntry, User

        trail = AuditTrail(session)
        # Webhook (action must be "automation_webhook" to match CLI query)
        trail.record(
            action="automation_webhook",
            entity_type="webhook",
            entity_id="WH-001",
            actor="admin@acme.com",
            metadata={
                "webhook_id": "WH-001",
                "name": "Slack Alerts",
                "url": "https://hooks.slack.com/services/T00/B00/xxx",
                "events": ["alert.created", "finding.critical"],
                "enabled": True,
            },
        )
        # User sessions (action must be "login"/"logout" to match CLI query, entity_id must be user UUID)
        for u in session.query(User).all():
            trail.record(
                action="login",
                entity_type="user",
                entity_id=u.id,
                actor=u.email,
                metadata={"ip": "10.0.1.50", "user_agent": "Mozilla/5.0"},
            )
            trail.record(
                action="logout",
                entity_type="user",
                entity_id=u.id,
                actor=u.email,
                metadata={"ip": "10.0.1.50", "duration_minutes": 45},
            )
        # Link workpapers to first engagement
        eng = session.query(AuditEngagement).first()
        if eng:
            for wp_entry in (
                session.query(AuditEntry).filter(AuditEntry.action == "workpaper_created").all()
            ):
                extra = dict(wp_entry.extra or {})
                extra["engagement_id"] = str(eng.id)
                wp_entry.extra = extra
        session.commit()
        print("       Webhooks, sessions, workpaper links seeded")

    # --- PG-2: Alerts, remediations, pipeline runs ---

    print("[27/34] Seeding sample alerts...")
    with get_session() as session:
        n_alerts = _seed_alerts(session)
        print(f"       Alerts: {n_alerts}")

    print("[28/34] Seeding sample remediations...")
    with get_session() as session:
        n_remediations = _seed_remediations(session)
        print(f"       Remediations: {n_remediations}")

    print("[29/34] Seeding pipeline run history...")
    with get_session() as session:
        n_pipeline_runs = _seed_pipeline_runs(session)
        print(f"       Pipeline runs: {n_pipeline_runs}")

    # --- GAP-2: Audit trail (hash-chained) ---

    print("[30/34] Populating audit trail (hash-chained)...")
    with get_session() as session:
        n_audit = _seed_audit_trail(session)
        print(f"       Audit entries: {n_audit}")

    # NOTE: Chain verification moved to step 37 (after ALL audit entries are
    # seeded, including feature coverage and phase expansions).  Verifying here
    # was premature — _seed_feature_coverage() and phase-5 expansions add more
    # audit entries, so an early "VERIFIED" was misleading (STUB-027).

    # --- Feature coverage: seed data for 20 features showing 'no data' ---

    print("[31/34] Seeding feature coverage data (20 features)...")
    with get_session() as session:
        fc = _seed_feature_coverage(session)
        total_fc = sum(fc.values())
        print(f"       Feature coverage records: {total_fc}")
        for k, v in sorted(fc.items()):
            print(f"         {k}: {v}")

    # --- Fix access review progress (Item 53) — campaigns created in step 31 ---
    print("[31a/34] Enriching access review campaigns with review items...")
    with get_session() as session:
        from warlock.db.models import AuditEntry as _AE

        ar_entries = (
            session.query(_AE)
            .filter(
                _AE.action == "access_review_campaign",
                _AE.entity_type == "access_review",
            )
            .all()
        )
        _personnel_emails = [
            "alice.wong@acme.com",
            "bob.singh@acme.com",
            "carol.park@acme.com",
            "dave.chen@acme.com",
            "eve.nakamura@acme.com",
            "frank.torres@acme.com",
        ]
        ar_fixed = 0
        for entry in ar_entries:
            extra = dict(entry.extra or {})
            if extra.get("total_users", 0) == 0 or not extra.get("certifications"):
                certs = []
                total_users = 8
                is_completed = extra.get("status") == "completed"
                cert_count = total_users - 1 if is_completed else 3
                for j in range(cert_count):
                    certs.append(
                        {
                            "user_email": _personnel_emails[j % len(_personnel_emails)],
                            "decision": "certified",
                            "certified_by": "identity-governance@acme.com",
                            "certified_at": (NOW - timedelta(days=10 + j)).isoformat(),
                            "notes": "Access verified and appropriate for role",
                        }
                    )
                extra["certifications"] = certs
                extra["total_users"] = total_users
                entry.extra = extra
                ar_fixed += 1
        session.commit()
        print(f"       Access review campaigns enriched: {ar_fixed}")

    # --- Seed expansions: richer demo data ---
    print("[32/38] Seeding Phase 2 expansions (zero-data gaps)...")
    try:
        from seed_expansions.phase2_zero_data_gaps import seed_phase2

        with get_session() as session:
            p2 = seed_phase2(session)
            for k, v in sorted(p2.items()):
                print(f"       {k}: {v}")
    except Exception as exc:
        print(f"       Phase 2 expansion failed: {exc}")

    print("[33/38] Seeding Phase 3 expansions (time depth)...")
    try:
        from seed_expansions.phase3_time_depth import seed_phase3

        with get_session() as session:
            p3 = seed_phase3(session)
            for k, v in sorted(p3.items()):
                print(f"       {k}: {v}")
    except Exception as exc:
        print(f"       Phase 3 expansion failed: {exc}")

    print("[34/38] Seeding Phase 5 expansions (scenario richness)...")
    try:
        from seed_expansions.phase5_scenario_richness import seed_phase5

        with get_session() as session:
            p5 = seed_phase5(session)
            for k, v in sorted(p5.items()):
                print(f"       {k}: {v}")
    except Exception as exc:
        print(f"       Phase 5 expansion failed: {exc}")

    print("[35/39] Enriching data for frontend demo...")
    with get_session() as session:
        fe = _seed_frontend_enrichment(session)
        for k, v in sorted(fe.items()):
            print(f"       {k}: {v}")

    print("[36/39] Verifying audit chain integrity (all entries)...")
    with get_session() as session:
        from warlock.db.audit import AuditTrail

        trail = AuditTrail(session)
        valid, errors = trail.verify_chain()
        if valid:
            print("       Chain integrity: VERIFIED")
        else:
            print(f"       Chain integrity: BROKEN ({len(errors)} errors)")
            for e in errors[:3]:
                print(f"         - {e}")

    print("[37/39] Seed complete!\n")

    print("=" * 60)
    print("  Try these commands:")
    print("=" * 60)
    print("  warlock results                    # control results")
    print("  warlock results --status non_compliant")
    print("  warlock coverage                   # compliance summary")
    print("  warlock findings                   # all findings")
    print("  warlock sources                    # registered sources")
    print("  warlock systems                    # system profiles")
    print("  warlock personnel                  # HR/IdP/training records")
    print("  warlock vendors                    # vendor risk scores")
    print("  warlock questionnaires             # vendor questionnaires")
    print("  warlock data-silos                 # storage inventory")
    print("  warlock retention report            # retention & legal holds")
    print("  warlock issues                     # compliance issues")
    print("  warlock policy-coverage -f iso_27001  # policy gaps")
    print("  warlock risk -f nist_800_53        # FAIR risk analysis")
    print("  warlock oscal                      # export OSCAL JSON")
    print()
    print("  --- Phase 2-5 commands ---")
    print("  warlock poams                      # POA&M tracking")
    print("  warlock poams --overdue            # overdue POA&Ms")
    print("  warlock compensating-controls      # compensating controls")
    print("  warlock risk-acceptances           # risk acceptances")
    print("  warlock inheritance                # control inheritance map")
    print("  warlock drift                      # compliance drift events")
    print("  warlock posture-history            # posture score trends")
    print("  warlock cadence                    # monitoring cadence")
    print("  warlock sufficiency                # evidence sufficiency")
    print("  warlock effectiveness              # control effectiveness")
    print("  warlock simulate-audit             # simulate audit readiness")
    print("  warlock framework-diff             # cross-framework delta")
    print()
    print("  --- Alerts & Remediation ---")
    print("  warlock alerts                     # alert summary")
    print("  warlock alerts list                # list all alerts")
    print("  warlock alerts evaluate            # run alert rules engine")
    print("  warlock remediate                  # remediation summary")
    print("  warlock remediate list             # list remediations")
    print("=" * 60)
