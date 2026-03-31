"""Phase 5 — Rich scenario data for POA&Ms, privacy, vendors, attestations,
alerts, and incidents.

Called from ``demo_seed.py`` via ``seed_phase5(session)``.  Every record uses
``str(uuid.uuid4())`` for IDs and ``datetime.now(timezone.utc)`` for
timestamps.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

from warlock.db.audit import AuditTrail
from warlock.db.models import (
    POAM,
    Alert,
    Attestation,
    AuditEngagement,
    Issue,
    Remediation,
    SystemProfile,
    Vendor,
)

NOW = datetime.now(timezone.utc)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ADMIN_ACTOR = "grc-admin@acme.com"


def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# 1. Richer POA&M lifecycle (10 POA&Ms)
# ---------------------------------------------------------------------------


def _seed_poams(session) -> int:
    """Create 10 additional POA&Ms with diverse lifecycle states."""
    prod = session.query(SystemProfile).filter(SystemProfile.acronym == "APP").first()
    cit = session.query(SystemProfile).filter(SystemProfile.acronym == "CIT").first()
    profile_id = prod.id if prod else (cit.id if cit else None)

    now = NOW
    poams = [
        # --- 2 overdue ---
        POAM(
            id=_uuid(),
            framework="nist_800_53",
            control_id="SC-7",
            weakness_description=(
                "Network boundary protections do not inspect encrypted east-west "
                "traffic between micro-services"
            ),
            severity="high",
            risk_level="high",
            status="in_progress",
            scheduled_completion=now - timedelta(days=14),
            system_profile_id=profile_id,
            created_by="pipeline",
            updated_by="security-lead@acme.com",
            delay_count=1,
            delay_justifications=[
                {
                    "date": (now - timedelta(days=7)).isoformat(),
                    "justification": "Vendor TLS inspection appliance delayed in shipping",
                    "approved_by": "ciso@acme.com",
                }
            ],
        ),
        POAM(
            id=_uuid(),
            framework="soc2",
            control_id="CC6.3",
            weakness_description=(
                "Role-based access reviews not completed within the quarterly "
                "cadence for cloud-admin group"
            ),
            severity="medium",
            risk_level="moderate",
            status="in_progress",
            scheduled_completion=now - timedelta(days=30),
            system_profile_id=profile_id,
            created_by="pipeline",
            updated_by="iam-lead@acme.com",
            delay_count=2,
            delay_justifications=[
                {
                    "date": (now - timedelta(days=20)).isoformat(),
                    "justification": "IAM team understaffed during holiday freeze",
                    "approved_by": "ciso@acme.com",
                },
                {
                    "date": (now - timedelta(days=5)).isoformat(),
                    "justification": "Extended to align with new Okta workflow rollout",
                    "approved_by": "ciso@acme.com",
                },
            ],
        ),
        # --- 2 approaching deadline ---
        POAM(
            id=_uuid(),
            framework="hipaa",
            control_id="164.312(e)(1)",
            weakness_description=(
                "PHI data transmitted to third-party transcription service "
                "without TLS 1.3 enforcement"
            ),
            severity="high",
            risk_level="high",
            status="in_progress",
            scheduled_completion=now + timedelta(days=7),
            system_profile_id=profile_id,
            created_by="pipeline",
            milestones=[
                {
                    "description": "Upgrade transcription API endpoint to TLS 1.3",
                    "due_date": (now + timedelta(days=3)).isoformat(),
                    "completed_date": None,
                    "status": "in_progress",
                },
                {
                    "description": "Validate certificate pinning on mobile client",
                    "due_date": (now + timedelta(days=6)).isoformat(),
                    "completed_date": None,
                    "status": "not_started",
                },
            ],
        ),
        POAM(
            id=_uuid(),
            framework="iso_27001",
            control_id="A.8.9",
            weakness_description=(
                "Removable media encryption policy not enforced via endpoint DLP"
            ),
            severity="medium",
            risk_level="moderate",
            status="in_progress",
            scheduled_completion=now + timedelta(days=7),
            system_profile_id=profile_id,
            created_by="pipeline",
            milestones=[
                {
                    "description": "Deploy CrowdStrike USB device control policy",
                    "due_date": (now + timedelta(days=2)).isoformat(),
                    "completed_date": (now - timedelta(days=1)).isoformat(),
                    "status": "completed",
                },
                {
                    "description": "Verify BitLocker-to-Go enforcement via GPO",
                    "due_date": (now + timedelta(days=5)).isoformat(),
                    "completed_date": None,
                    "status": "in_progress",
                },
            ],
        ),
        # --- 2 with cost estimates ---
        POAM(
            id=_uuid(),
            framework="nist_800_53",
            control_id="RA-5",
            weakness_description=(
                "Vulnerability scanning does not cover container images in CI/CD "
                "pipeline before deployment to production"
            ),
            severity="high",
            risk_level="high",
            status="open",
            cost_estimate=50000.0,
            resource_allocation="DevSecOps team (2 FTEs) + Snyk Enterprise license",
            system_profile_id=profile_id,
            created_by="pipeline",
        ),
        POAM(
            id=_uuid(),
            framework="pci_dss",
            control_id="6.3.2",
            weakness_description=(
                "Custom application code not reviewed via SAST/DAST before each "
                "release to cardholder data environment"
            ),
            severity="critical",
            risk_level="very_high",
            status="open",
            cost_estimate=120000.0,
            resource_allocation=("AppSec team + Veracode platform license + CI integration effort"),
            system_profile_id=profile_id,
            created_by="pipeline",
        ),
        # --- 2 recently completed ---
        POAM(
            id=_uuid(),
            framework="cmmc_l2",
            control_id="AC.L2-3.1.1",
            weakness_description=(
                "Authorized user list for CUI systems not reconciled with HR termination feed"
            ),
            severity="medium",
            risk_level="moderate",
            status="completed",
            scheduled_completion=now - timedelta(days=14),
            actual_completion=now - timedelta(days=3),
            system_profile_id=profile_id,
            created_by="pipeline",
            updated_by="iam-lead@acme.com",
            approved_by="ciso@acme.com",
            approved_at=now - timedelta(days=2),
        ),
        POAM(
            id=_uuid(),
            framework="gdpr",
            control_id="Art.32",
            weakness_description=(
                "Pseudonymisation of personal data in analytics pipeline not "
                "applied to join-key columns"
            ),
            severity="high",
            risk_level="high",
            status="completed",
            scheduled_completion=now - timedelta(days=10),
            actual_completion=now - timedelta(days=5),
            system_profile_id=profile_id,
            created_by="pipeline",
            updated_by="data-eng@acme.com",
            approved_by="dpo@acme.com",
            approved_at=now - timedelta(days=4),
        ),
        # --- 2 risk accepted ---
        POAM(
            id=_uuid(),
            framework="nist_800_53",
            control_id="CM-7",
            weakness_description=(
                "Legacy payroll application requires Java 8 runtime with known "
                "CVEs; vendor EOL Q3-2026"
            ),
            severity="high",
            risk_level="high",
            status="closed",
            system_profile_id=profile_id,
            created_by="pipeline",
            approved_by="ciso@acme.com",
            approved_at=now - timedelta(days=10),
            milestones=[
                {
                    "description": "Risk acceptance expires; vendor migration must complete",
                    "due_date": (now + timedelta(days=30)).isoformat(),
                    "completed_date": None,
                    "status": "not_started",
                }
            ],
        ),
        POAM(
            id=_uuid(),
            framework="soc2",
            control_id="CC8.1",
            weakness_description=(
                "Change management process bypassed for hotfixes to production during P1 incidents"
            ),
            severity="medium",
            risk_level="moderate",
            status="closed",
            system_profile_id=profile_id,
            created_by="pipeline",
            approved_by="cto@acme.com",
            approved_at=now - timedelta(days=5),
            milestones=[
                {
                    "description": "Implement post-incident CAB review within 48h SLA",
                    "due_date": (now + timedelta(days=90)).isoformat(),
                    "completed_date": None,
                    "status": "in_progress",
                }
            ],
        ),
    ]

    session.add_all(poams)
    session.flush()
    return len(poams)


# ---------------------------------------------------------------------------
# 2. DSARs and privacy scenarios (via AuditTrail)
# ---------------------------------------------------------------------------


def _seed_privacy(session) -> int:
    """Create DSAR and breach records via the audit trail."""
    trail = AuditTrail(session)
    now = NOW
    count = 0

    # --- 5 DSARs ---
    dsars = [
        # 2 new / submitted
        {
            "subject_name": "Maria Gonzalez",
            "subject_email": "m.gonzalez@example.com",
            "request_type": "access",
            "status": "submitted",
            "submitted_at": (now - timedelta(days=1)).isoformat(),
            "jurisdiction": "EU",
            "deadline": (now + timedelta(days=29)).isoformat(),
        },
        {
            "subject_name": "James Liu",
            "subject_email": "j.liu@example.com",
            "request_type": "access",
            "status": "submitted",
            "submitted_at": (now - timedelta(hours=6)).isoformat(),
            "jurisdiction": "California",
            "deadline": (now + timedelta(days=30)).isoformat(),
        },
        # 1 in progress (15 of 30 days elapsed)
        {
            "subject_name": "Anna Kowalski",
            "subject_email": "a.kowalski@example.com",
            "request_type": "erasure",
            "status": "in_progress",
            "submitted_at": (now - timedelta(days=15)).isoformat(),
            "jurisdiction": "EU",
            "deadline": (now + timedelta(days=15)).isoformat(),
            "systems_searched": ["CRM", "Analytics", "Email"],
            "progress_pct": 60,
        },
        # 1 completed
        {
            "subject_name": "Robert Chen",
            "subject_email": "r.chen@example.com",
            "request_type": "portability",
            "status": "completed",
            "submitted_at": (now - timedelta(days=25)).isoformat(),
            "completed_at": (now - timedelta(days=5)).isoformat(),
            "jurisdiction": "EU",
            "export_format": "JSON",
            "delivered_via": "Secure download link",
        },
        # 1 overdue (past 30-day deadline)
        {
            "subject_name": "Sophie Dupont",
            "subject_email": "s.dupont@example.com",
            "request_type": "erasure",
            "status": "in_progress",
            "submitted_at": (now - timedelta(days=35)).isoformat(),
            "jurisdiction": "EU",
            "deadline": (now - timedelta(days=5)).isoformat(),
            "overdue": True,
            "escalation_reason": "Complex cross-system data mapping required",
        },
    ]

    for i, dsar in enumerate(dsars):
        trail.record(
            action="dsar_created",
            entity_type="dsar",
            entity_id=f"DSAR-P5-{i + 1:03d}",
            actor="privacy-team@acme.com",
            metadata=dsar,
        )
        count += 1

    # --- 2 breaches ---
    breaches = [
        {
            "title": "Unauthorized access to customer PII via misconfigured S3 bucket",
            "severity": "high",
            "reported_to_authority": True,
            "authority": "Irish Data Protection Commission",
            "reported_at": (now - timedelta(days=3)).isoformat(),
            "discovered_at": (now - timedelta(days=5)).isoformat(),
            "records_affected": 2340,
            "data_categories": ["name", "email", "address"],
            "containment_status": "contained",
        },
        {
            "title": "Employee laptop with unencrypted HR data lost in transit",
            "severity": "medium",
            "reported_to_authority": False,
            "discovered_at": (now - timedelta(days=1)).isoformat(),
            "records_affected": 85,
            "data_categories": ["name", "SSN", "salary"],
            "containment_status": "assessing",
            "risk_assessment_pending": True,
        },
    ]

    for i, breach in enumerate(breaches):
        trail.record(
            action="breach_created",
            entity_type="privacy_breach",
            entity_id=f"BREACH-P5-{i + 1:03d}",
            actor="dpo@acme.com",
            metadata=breach,
        )
        count += 1

    return count


# ---------------------------------------------------------------------------
# 3. Enhanced vendor data
# ---------------------------------------------------------------------------


def _seed_vendors(session) -> int:
    """Add vendors with upcoming assessments, expiring reports, and high risk."""
    now = NOW
    existing = {row[0] for row in session.query(Vendor.name).all()}

    vendors = [
        # 5 vendors with assessment due within 30 days
        # (last_assessment + assessment_cadence_days = within 30 days from now)
        Vendor(
            id=_uuid(),
            name="NovaPay Solutions",
            tier="critical",
            risk_score=45.0,
            contract_expires=now + timedelta(days=180),
            last_assessment=now - timedelta(days=75),
            assessment_cadence_days=90,
            metadata_={
                "industry": "Payment Processing",
                "ssc_grade": "B",
                "next_assessment_date": (now + timedelta(days=15)).isoformat(),
                "soc2_report_expiry": (now + timedelta(days=45)).isoformat(),
            },
        ),
        Vendor(
            id=_uuid(),
            name="CloudMatrix AI",
            tier="high",
            risk_score=58.0,
            contract_expires=now + timedelta(days=120),
            last_assessment=now - timedelta(days=80),
            assessment_cadence_days=90,
            metadata_={
                "industry": "Artificial Intelligence",
                "ssc_grade": "C",
                "next_assessment_date": (now + timedelta(days=10)).isoformat(),
                "data_processing_agreement": True,
            },
        ),
        Vendor(
            id=_uuid(),
            name="SecureVault Backup",
            tier="critical",
            risk_score=40.0,
            contract_expires=now + timedelta(days=365),
            last_assessment=now - timedelta(days=60),
            assessment_cadence_days=90,
            metadata_={
                "industry": "Data Protection",
                "ssc_grade": "B+",
                "next_assessment_date": (now + timedelta(days=30)).isoformat(),
                "soc2_report_expiry": (now + timedelta(days=20)).isoformat(),
            },
        ),
        Vendor(
            id=_uuid(),
            name="FastTrack HR",
            tier="medium",
            risk_score=62.0,
            contract_expires=now + timedelta(days=90),
            last_assessment=now - timedelta(days=165),
            assessment_cadence_days=180,
            metadata_={
                "industry": "Human Resources",
                "ssc_grade": "D+",
                "next_assessment_date": (now + timedelta(days=15)).isoformat(),
                "handles_pii": True,
            },
        ),
        Vendor(
            id=_uuid(),
            name="EdgeNet CDN",
            tier="high",
            risk_score=35.0,
            contract_expires=now + timedelta(days=200),
            last_assessment=now - timedelta(days=82),
            assessment_cadence_days=90,
            metadata_={
                "industry": "Content Delivery",
                "ssc_grade": "A-",
                "next_assessment_date": (now + timedelta(days=8)).isoformat(),
                "soc2_report_expiry": (now + timedelta(days=25)).isoformat(),
            },
        ),
        # 2 high-risk vendors (risk_score < 60 is NOT high risk in the
        # existing seed convention -- higher score = higher risk)
        Vendor(
            id=_uuid(),
            name="BudgetCloud Hosting",
            tier="medium",
            risk_score=88.0,
            contract_expires=now + timedelta(days=45),
            last_assessment=now - timedelta(days=200),
            assessment_cadence_days=90,
            metadata_={
                "industry": "Cloud Hosting",
                "ssc_grade": "F",
                "overdue_assessment": True,
                "risk_flags": [
                    "No SOC 2 report",
                    "Data center in non-EU jurisdiction",
                    "No incident response SLA",
                ],
            },
        ),
        Vendor(
            id=_uuid(),
            name="LegacyERP Systems",
            tier="high",
            risk_score=91.0,
            contract_expires=now + timedelta(days=30),
            last_assessment=now - timedelta(days=300),
            assessment_cadence_days=90,
            metadata_={
                "industry": "Enterprise Software",
                "ssc_grade": "F",
                "overdue_assessment": True,
                "risk_flags": [
                    "End-of-life product",
                    "Known unpatched CVEs",
                    "No encryption at rest",
                ],
            },
        ),
        # 1 vendor being offboarded
        Vendor(
            id=_uuid(),
            name="DeprecatedSaaS Co",
            tier="low",
            risk_score=75.0,
            contract_expires=now + timedelta(days=14),
            last_assessment=now - timedelta(days=180),
            assessment_cadence_days=365,
            metadata_={
                "industry": "SaaS",
                "ssc_grade": "D",
                "status": "offboarding",
                "offboard_reason": "Migrating to in-house solution",
                "offboard_deadline": (now + timedelta(days=14)).isoformat(),
                "data_deletion_confirmed": False,
            },
        ),
    ]

    # Skip any vendors whose name already exists
    new_vendors = [v for v in vendors if v.name not in existing]
    session.add_all(new_vendors)
    session.flush()
    return len(new_vendors)


# ---------------------------------------------------------------------------
# 4. Expiring attestations
# ---------------------------------------------------------------------------


def _seed_attestations(session) -> int:
    """Create attestations approaching or past their approval window."""
    now = NOW
    engagement = session.query(AuditEngagement).first()
    engagement_id = engagement.id if engagement else None

    attestations = [
        # 3 approved attestations whose approval is aging (within 30 days of
        # a typical 90-day review cycle -- approved ~60-80 days ago)
        Attestation(
            id=_uuid(),
            engagement_id=engagement_id,
            framework="nist_800_53",
            control_id="AC-2",
            status="approved",
            statement=(
                "Management asserts that account provisioning and de-provisioning "
                "procedures are executed within 24 hours of HR status changes."
            ),
            evidence_references=[
                {
                    "finding_id": "okta-lifecycle-001",
                    "description": "Okta lifecycle automation logs",
                },
            ],
            prepared_by="eve.nakamura@acme.com",
            prepared_at=now - timedelta(days=75),
            submitted_by="eve.nakamura@acme.com",
            submitted_at=now - timedelta(days=73),
            reviewed_by="sarah.chen@deloitte.com",
            reviewed_at=now - timedelta(days=65),
            approved_by="sarah.chen@deloitte.com",
            approved_at=now - timedelta(days=64),
        ),
        Attestation(
            id=_uuid(),
            engagement_id=engagement_id,
            framework="hipaa",
            control_id="164.312(a)(1)",
            status="approved",
            statement=(
                "Management asserts that access to ePHI systems requires "
                "unique user identification and multi-factor authentication."
            ),
            evidence_references=[
                {"finding_id": "hipaa-access-001", "description": "Access control matrix"},
                {"finding_id": "mfa-report-001", "description": "MFA enrollment report"},
            ],
            prepared_by="frank.torres@acme.com",
            prepared_at=now - timedelta(days=70),
            submitted_by="frank.torres@acme.com",
            submitted_at=now - timedelta(days=68),
            reviewed_by="audit-lead@deloitte.com",
            reviewed_at=now - timedelta(days=62),
            approved_by="audit-lead@deloitte.com",
            approved_at=now - timedelta(days=60),
        ),
        Attestation(
            id=_uuid(),
            engagement_id=engagement_id,
            framework="pci_dss",
            control_id="8.3.1",
            status="approved",
            statement=(
                "Management asserts that all user access to cardholder data "
                "environment is authenticated via MFA and individual credentials."
            ),
            evidence_references=[
                {"finding_id": "pci-auth-001", "description": "CDE authentication logs"},
            ],
            prepared_by="eve.nakamura@acme.com",
            prepared_at=now - timedelta(days=68),
            submitted_by="eve.nakamura@acme.com",
            submitted_at=now - timedelta(days=66),
            reviewed_by="sarah.chen@deloitte.com",
            reviewed_at=now - timedelta(days=60),
            approved_by="sarah.chen@deloitte.com",
            approved_at=now - timedelta(days=58),
        ),
        # 2 recently expired (approved long enough ago that they need re-review)
        # Marked as approved but with approval dates > 90 days ago
        Attestation(
            id=_uuid(),
            engagement_id=engagement_id,
            framework="soc2",
            control_id="CC3.2",
            status="approved",
            statement=(
                "Management asserts that risk assessments are performed "
                "annually and after significant changes to the environment."
            ),
            evidence_references=[
                {"finding_id": "risk-assess-001", "description": "Annual risk assessment report"},
            ],
            prepared_by="frank.torres@acme.com",
            prepared_at=now - timedelta(days=105),
            submitted_by="frank.torres@acme.com",
            submitted_at=now - timedelta(days=103),
            reviewed_by="audit-lead@deloitte.com",
            reviewed_at=now - timedelta(days=100),
            review_notes="Evidence complete. Recommend 90-day re-review.",
            approved_by="audit-lead@deloitte.com",
            approved_at=now - timedelta(days=97),
        ),
        Attestation(
            id=_uuid(),
            engagement_id=engagement_id,
            framework="iso_27001",
            control_id="A.5.1",
            status="approved",
            statement=(
                "Management asserts that information security policies are "
                "reviewed and approved by senior management at planned intervals."
            ),
            evidence_references=[
                {"finding_id": "policy-review-001", "description": "Policy review sign-off sheet"},
            ],
            prepared_by="eve.nakamura@acme.com",
            prepared_at=now - timedelta(days=112),
            submitted_by="eve.nakamura@acme.com",
            submitted_at=now - timedelta(days=110),
            reviewed_by="sarah.chen@deloitte.com",
            reviewed_at=now - timedelta(days=107),
            approved_by="sarah.chen@deloitte.com",
            approved_at=now - timedelta(days=104),
        ),
    ]

    session.add_all(attestations)
    session.flush()
    return len(attestations)


# ---------------------------------------------------------------------------
# 5. Incidents with severity classification
# ---------------------------------------------------------------------------


def _seed_incidents(session) -> int:
    """Create 10 classified security incidents as Issue records."""
    now = NOW

    incidents = [
        # --- 3 critical ---
        {
            "title": "Unauthorized data access detected in production database",
            "description": (
                "Alert from GuardDuty: anomalous query pattern from service account "
                "sa-analytics accessing customer PII tables outside normal hours. "
                "IP source traced to non-corporate CIDR range."
            ),
            "severity": "critical",
            "status": "in_progress",
            "framework": "nist_800_53",
            "control_id": "AC-6",
            "days_ago": 2,
        },
        {
            "title": "Ransomware indicator on endpoint workstation",
            "description": (
                "CrowdStrike Falcon detected file encryption behavior matching "
                "LockBit 3.0 signature on WKSTN-0847. Process tree isolated. "
                "Network quarantine enacted automatically."
            ),
            "severity": "critical",
            "status": "in_progress",
            "framework": "nist_800_53",
            "control_id": "SI-3",
            "days_ago": 1,
        },
        {
            "title": "Exposed API credentials in public GitHub repository",
            "description": (
                "GitHub Secret Scanning alerted on AWS access key "
                "AKIA*** committed to public repo acme/data-tools. Key has "
                "S3 and DynamoDB permissions in production account."
            ),
            "severity": "critical",
            "status": "open",
            "framework": "soc2",
            "control_id": "CC6.1",
            "days_ago": 0,
        },
        # --- 3 high ---
        {
            "title": "Privilege escalation attempt via misconfigured IAM role",
            "description": (
                "CloudTrail shows AssumeRole calls from dev account to prod-admin "
                "role. Trust policy allows cross-account access without MFA condition."
            ),
            "severity": "high",
            "status": "assigned",
            "framework": "nist_800_53",
            "control_id": "AC-6(5)",
            "assigned_to": "iam-lead@acme.com",
            "days_ago": 5,
        },
        {
            "title": "Unencrypted PII in transit to third-party analytics",
            "description": (
                "Network packet capture revealed customer email addresses sent "
                "over HTTP (not HTTPS) to analytics.vendor-x.com endpoint. "
                "Approximately 12K records affected over 72-hour window."
            ),
            "severity": "high",
            "status": "in_progress",
            "framework": "hipaa",
            "control_id": "164.312(e)(1)",
            "assigned_to": "network-eng@acme.com",
            "days_ago": 8,
        },
        {
            "title": "Compliance control regression after infrastructure change",
            "description": (
                "Terraform apply removed WAF rules from ALB after module upgrade. "
                "OWASP Top-10 protections (SQLi, XSS) were disabled for 4 hours "
                "before automated drift detection triggered rollback."
            ),
            "severity": "high",
            "status": "remediated",
            "framework": "pci_dss",
            "control_id": "6.4.1",
            "assigned_to": "devops-lead@acme.com",
            "days_ago": 12,
        },
        # --- 2 medium ---
        {
            "title": "Suspicious login from new geography for admin account",
            "description": (
                "Okta detected sign-in from Bucharest, Romania for admin user "
                "hassan.ali@acme.com. User confirmed they were not traveling. "
                "Session was MFA-protected; investigating credential exposure."
            ),
            "severity": "medium",
            "status": "assigned",
            "framework": "iso_27001",
            "control_id": "A.8.5",
            "assigned_to": "soc-analyst@acme.com",
            "days_ago": 3,
        },
        {
            "title": "Overdue critical security patch on database servers",
            "description": (
                "Qualys scan detected CVE-2026-1234 (CVSS 8.1) on 3 PostgreSQL "
                "servers unpatched for 45 days. Patch available since Feb 2026. "
                "Exploitation requires network adjacency."
            ),
            "severity": "medium",
            "status": "open",
            "framework": "cmmc_l2",
            "control_id": "SI.L2-3.14.1",
            "days_ago": 15,
        },
        # --- 2 low ---
        {
            "title": "Phishing email blocked by gateway",
            "description": (
                "Proofpoint blocked spear-phishing email targeting CFO with "
                "credential harvesting link. No user interaction detected. "
                "IOCs shared with threat intel team."
            ),
            "severity": "low",
            "status": "closed",
            "framework": "nist_800_53",
            "control_id": "SI-8",
            "days_ago": 20,
        },
        {
            "title": "Failed authenticated vulnerability scan on staging",
            "description": (
                "Scheduled Nessus scan of staging environment failed due to "
                "expired service account credentials. Scan rescheduled after "
                "credential rotation."
            ),
            "severity": "low",
            "status": "closed",
            "framework": "soc2",
            "control_id": "CC7.1",
            "days_ago": 25,
        },
    ]

    issue_records = []
    for data in incidents:
        issue = Issue(
            id=_uuid(),
            title=data["title"],
            description=data["description"],
            priority=data["severity"],
            status=data["status"],
            framework=data.get("framework"),
            control_id=data.get("control_id"),
            source="incident",
            tags=["security-incident", data["severity"]],
            created_at=now - timedelta(days=data["days_ago"]),
            updated_at=now - timedelta(days=max(0, data["days_ago"] - 1)),
            created_by="soc-team@acme.com",
        )
        if data.get("assigned_to"):
            issue.assigned_to = data["assigned_to"]
            issue.assigned_by = "security-lead@acme.com"
            issue.assigned_at = now - timedelta(days=max(0, data["days_ago"] - 1))
        if data["status"] == "closed":
            issue.closed_at = now - timedelta(days=max(0, data["days_ago"] - 2))
        if data["status"] == "remediated":
            issue.remediated_at = now - timedelta(days=max(0, data["days_ago"] - 3))
        issue_records.append(issue)

    session.add_all(issue_records)
    session.flush()
    return len(issue_records)


# ---------------------------------------------------------------------------
# 6. Alerts and remediations
# ---------------------------------------------------------------------------


def _seed_alerts(session) -> int:
    """Create 10 alerts with varied severities and statuses."""
    now = NOW

    alert_data = [
        {
            "title": "Control drift: SC-7 boundary protection degraded",
            "description": "Firewall rule allowing 0.0.0.0/0 ingress on port 443 added outside change window",
            "severity": "critical",
            "category": "control_drift",
            "framework": "nist_800_53",
            "control_id": "SC-7",
            "status": "open",
            "rule_name": "control_drift_monitor",
        },
        {
            "title": "New critical finding: exposed S3 bucket with PII",
            "description": "AWS Config detected public read ACL on s3://acme-customer-exports",
            "severity": "critical",
            "category": "new_finding",
            "framework": "soc2",
            "control_id": "CC6.1",
            "connector_name": "aws_config",
            "status": "acknowledged",
            "rule_name": "public_bucket_detector",
        },
        {
            "title": "Connector failure: CrowdStrike API rate limited",
            "description": "CrowdStrike connector returned HTTP 429 for 3 consecutive polling cycles",
            "severity": "high",
            "category": "connector_failure",
            "connector_name": "crowdstrike_falcon",
            "status": "open",
            "rule_name": "connector_health_check",
        },
        {
            "title": "Threshold breach: failed logins exceed baseline",
            "description": "85 failed login attempts in 15-minute window (baseline: 20)",
            "severity": "high",
            "category": "threshold_breach",
            "framework": "nist_800_53",
            "control_id": "AC-7",
            "status": "investigating",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110 Brute Force",
            "rule_name": "failed_login_anomaly",
        },
        {
            "title": "Policy violation: MFA disabled for admin group",
            "description": "Okta policy change removed MFA requirement for cloud-admin group",
            "severity": "critical",
            "category": "policy_violation",
            "framework": "nist_800_53",
            "control_id": "IA-2(1)",
            "status": "open",
            "rule_name": "mfa_policy_monitor",
        },
        {
            "title": "Control drift: encryption at rest disabled on RDS instance",
            "description": "RDS instance db-analytics-prod modified to disable storage encryption",
            "severity": "high",
            "category": "control_drift",
            "framework": "pci_dss",
            "control_id": "3.4.1",
            "status": "acknowledged",
            "rule_name": "encryption_drift_monitor",
        },
        {
            "title": "New finding: outdated TLS 1.0 on load balancer",
            "description": "SSL Labs scan found TLS 1.0 enabled on prod-alb-external",
            "severity": "medium",
            "category": "new_finding",
            "framework": "hipaa",
            "control_id": "164.312(e)(1)",
            "connector_name": "qualys_ssl",
            "status": "open",
            "rule_name": "tls_version_check",
        },
        {
            "title": "Threshold breach: vulnerability scan backlog growing",
            "description": "142 critical/high vulnerabilities unpatched beyond 30-day SLA",
            "severity": "medium",
            "category": "threshold_breach",
            "framework": "cmmc_l2",
            "control_id": "RA.L2-3.11.2",
            "status": "acknowledged",
            "rule_name": "vuln_sla_monitor",
        },
        {
            "title": "Connector warning: Jira sync stale for 48 hours",
            "description": "Jira issue tracker connector last successful sync was 48h ago",
            "severity": "low",
            "category": "connector_failure",
            "connector_name": "jira_cloud",
            "status": "resolved",
            "rule_name": "connector_staleness_check",
        },
        {
            "title": "Policy info: new framework controls available",
            "description": "NIST SP 800-53 Rev 6 draft controls available for baseline comparison",
            "severity": "info",
            "category": "policy_violation",
            "framework": "nist_800_53",
            "status": "dismissed",
            "rule_name": "framework_update_notifier",
        },
    ]

    alerts = []
    for i, data in enumerate(alert_data):
        alert = Alert(
            id=_uuid(),
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
            rule_metadata={
                "seeded": True,
                "escalation_level": min(i // 3, 3),
            },
            triggered_at=now - timedelta(hours=random.randint(1, 72)),
            created_at=now - timedelta(hours=random.randint(1, 72)),
        )
        if data["status"] == "acknowledged":
            alert.acknowledged_by = "security-analyst@acme.com"
            alert.acknowledged_at = now - timedelta(hours=random.randint(1, 12))
        elif data["status"] == "resolved":
            alert.acknowledged_by = "security-analyst@acme.com"
            alert.acknowledged_at = now - timedelta(hours=random.randint(12, 24))
            alert.resolved_by = "soc-lead@acme.com"
            alert.resolved_at = now - timedelta(hours=random.randint(1, 6))
            alert.resolution_notes = "Issue resolved and verified via rescan."
        elif data["status"] == "dismissed":
            alert.acknowledged_by = "security-lead@acme.com"
            alert.acknowledged_at = now - timedelta(hours=random.randint(1, 6))
            alert.resolved_by = "security-lead@acme.com"
            alert.resolved_at = now - timedelta(hours=random.randint(0, 3))
            alert.resolution_notes = "Informational only; no action required."
        alerts.append(alert)

    session.add_all(alerts)
    session.flush()
    return len(alerts)


def _seed_remediations(session) -> int:
    """Create 5 remediations with varied completion percentages."""
    now = NOW

    remediation_data = [
        {
            "title": "Patch critical PostgreSQL CVE-2026-1234 on database fleet",
            "description": "Apply security patch to 3 production PostgreSQL servers",
            "framework": "nist_800_53",
            "control_id": "SI-2",
            "status": "in_progress",
            "assigned_to": "dba-team@acme.com",
            "completion_pct": 20,
            "steps": [
                {"step": 1, "description": "Test patch in staging environment", "completed": True},
                {"step": 2, "description": "Schedule maintenance window", "completed": False},
                {"step": 3, "description": "Apply patch to replica servers", "completed": False},
                {"step": 4, "description": "Apply patch to primary servers", "completed": False},
                {"step": 5, "description": "Verify application connectivity", "completed": False},
            ],
        },
        {
            "title": "Remediate public S3 bucket ACL misconfiguration",
            "description": "Remove public read ACL and enable bucket policy enforcement",
            "framework": "soc2",
            "control_id": "CC6.1",
            "status": "in_progress",
            "assigned_to": "cloud-eng@acme.com",
            "completion_pct": 45,
            "steps": [
                {
                    "step": 1,
                    "description": "Identify all objects with public ACLs",
                    "completed": True,
                },
                {"step": 2, "description": "Enable S3 Block Public Access", "completed": True},
                {
                    "step": 3,
                    "description": "Update application to use pre-signed URLs",
                    "completed": False,
                },
                {"step": 4, "description": "Verify no public access remains", "completed": False},
            ],
        },
        {
            "title": "Enforce TLS 1.2+ on all external-facing load balancers",
            "description": "Disable TLS 1.0 and 1.1 on ALBs and update security policy",
            "framework": "pci_dss",
            "control_id": "4.2.1",
            "status": "in_progress",
            "assigned_to": "network-eng@acme.com",
            "completion_pct": 80,
            "steps": [
                {"step": 1, "description": "Inventory all ALBs with TLS < 1.2", "completed": True},
                {
                    "step": 2,
                    "description": "Update ALB security policy to TLS 1.2",
                    "completed": True,
                },
                {"step": 3, "description": "Test client compatibility", "completed": True},
                {"step": 4, "description": "Apply to production ALBs", "completed": True},
                {"step": 5, "description": "Validate with SSL Labs scan", "completed": False},
            ],
        },
        {
            "title": "Implement automated access review for privileged accounts",
            "description": "Deploy Okta Access Certification for quarterly review automation",
            "framework": "iso_27001",
            "control_id": "A.5.18",
            "status": "closed",
            "assigned_to": "iam-lead@acme.com",
            "completion_pct": 100,
            "steps": [
                {
                    "step": 1,
                    "description": "Configure Okta Access Certification",
                    "completed": True,
                },
                {"step": 2, "description": "Define review campaigns", "completed": True},
                {"step": 3, "description": "Run pilot certification cycle", "completed": True},
                {"step": 4, "description": "Enable automated revocation", "completed": True},
            ],
        },
        {
            "title": "Deploy endpoint DLP for removable media control",
            "description": "Roll out CrowdStrike USB device control and BitLocker-to-Go enforcement",
            "framework": "cmmc_l2",
            "control_id": "MP.L2-3.8.7",
            "status": "open",
            "assigned_to": None,
            "completion_pct": 0,
            "steps": [
                {"step": 1, "description": "Define USB device policy", "completed": False},
                {
                    "step": 2,
                    "description": "Configure CrowdStrike device control",
                    "completed": False,
                },
                {"step": 3, "description": "Deploy GPO for BitLocker-to-Go", "completed": False},
                {"step": 4, "description": "Test with pilot group", "completed": False},
                {"step": 5, "description": "Roll out to all endpoints", "completed": False},
            ],
        },
    ]

    remediations = []
    for data in remediation_data:
        rem = Remediation(
            id=_uuid(),
            title=data["title"],
            description=data.get("description"),
            framework=data.get("framework"),
            control_id=data.get("control_id"),
            status=data["status"],
            remediation_steps=data["steps"],
            remediation_plan=data["description"],
            created_by="demo-seed@warlock",
            created_at=now - timedelta(days=random.randint(3, 21)),
            updated_at=now - timedelta(hours=random.randint(1, 48)),
        )
        if data.get("assigned_to"):
            rem.assigned_to = data["assigned_to"]
            rem.assigned_by = "security-lead@acme.com"
            rem.assigned_at = now - timedelta(days=random.randint(1, 10))
        if data["status"] == "closed":
            rem.closed_at = now - timedelta(hours=random.randint(1, 24))
            rem.verified_by = "audit-lead@acme.com"
            rem.verified_at = now - timedelta(hours=random.randint(24, 48))
            rem.verification_notes = "Verified via automated scan and manual spot-check."
        remediations.append(rem)

    session.add_all(remediations)
    session.flush()
    return len(remediations)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def seed_phase5(session) -> dict:
    """Seed rich scenario data for POA&Ms, privacy, vendors, attestations,
    alerts, and incidents.

    Args:
        session: An active SQLAlchemy session.

    Returns:
        A dict summarising the count of records created per category.
    """
    counts: dict[str, int] = {}

    counts["poams"] = _seed_poams(session)
    counts["privacy_entries"] = _seed_privacy(session)
    counts["vendors"] = _seed_vendors(session)
    counts["attestations"] = _seed_attestations(session)
    counts["incidents"] = _seed_incidents(session)
    counts["alerts"] = _seed_alerts(session)
    counts["remediations"] = _seed_remediations(session)

    session.commit()
    return counts
