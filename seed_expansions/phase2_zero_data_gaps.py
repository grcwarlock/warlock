"""Phase 2: Fill zero-data gaps — KRIs, BCP, training, ConMon, ROPA."""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

NOW = datetime.now(timezone.utc)


def seed_phase2(session) -> dict:
    """Fill data gaps for CLI commands that show empty or trivial results."""
    from warlock.db.audit import AuditTrail
    from warlock.db.models import AuditEntry, ConnectorRun, Personnel

    trail = AuditTrail(session)
    counts: dict[str, int] = {}

    # --- 2.1: Failed connector runs for non-zero KRI error rate ---
    # (Only if not already seeded by _seed_frontend_enrichment)
    existing_errors = session.query(ConnectorRun).filter(ConnectorRun.status == "error").count()
    if existing_errors < 3:
        for provider, stype in [
            ("crowdstrike", "edr"),
            ("splunk", "siem"),
        ]:
            session.add(
                ConnectorRun(
                    id=str(uuid.uuid4()),
                    connector_name=f"demo-{provider}",
                    source=provider,
                    provider=provider,
                    source_type=stype,
                    status="error",
                    error_count=1,
                    event_count=0,
                    errors=[f"API timeout connecting to {provider}"],
                    started_at=NOW - timedelta(days=random.randint(3, 15)),
                    completed_at=NOW - timedelta(days=random.randint(3, 15)) + timedelta(seconds=5),
                    duration_seconds=5.0,
                )
            )
        counts["failed_connector_runs"] = 2
    else:
        counts["failed_connector_runs"] = 0

    # --- 2.2: BCP data — DR test schedules and BIA records ---
    # DR test schedule entries (via AuditEntry, queried by bcp_cmd.py)
    dr_schedules = [
        {
            "system": "acme-production-web",
            "frequency": "quarterly",
            "last_test": (NOW - timedelta(days=45)).isoformat(),
            "next_test": (NOW + timedelta(days=45)).isoformat(),
            "rto_hours": 4,
            "rpo_hours": 1,
        },
        {
            "system": "acme-database-cluster",
            "frequency": "quarterly",
            "last_test": (NOW - timedelta(days=30)).isoformat(),
            "next_test": (NOW + timedelta(days=60)).isoformat(),
            "rto_hours": 2,
            "rpo_hours": 0.25,
        },
        {
            "system": "acme-identity-platform",
            "frequency": "semi-annual",
            "last_test": (NOW - timedelta(days=120)).isoformat(),
            "next_test": (NOW + timedelta(days=60)).isoformat(),
            "rto_hours": 1,
            "rpo_hours": 0,
        },
        {
            "system": "acme-ci-cd-pipeline",
            "frequency": "annual",
            "last_test": (NOW - timedelta(days=200)).isoformat(),
            "next_test": (NOW + timedelta(days=165)).isoformat(),
            "rto_hours": 8,
            "rpo_hours": 4,
        },
    ]
    for sched in dr_schedules:
        trail.append(
            action="dr_test_scheduled",
            entity_type="dr_schedule",
            entity_id=str(uuid.uuid4()),
            actor="bcp-manager@acme.com",
            details=sched,
        )
    counts["dr_schedules"] = len(dr_schedules)

    # --- 2.3: Training campaigns ---
    training_campaigns = [
        {
            "name": "Annual Security Awareness 2026",
            "status": "completed",
            "start_date": (NOW - timedelta(days=60)).isoformat(),
            "end_date": (NOW - timedelta(days=30)).isoformat(),
            "total_users": 50,
            "completed_users": 48,
            "pass_rate": 0.98,
        },
        {
            "name": "Phishing Simulation Q1 2026",
            "status": "completed",
            "start_date": (NOW - timedelta(days=45)).isoformat(),
            "end_date": (NOW - timedelta(days=15)).isoformat(),
            "total_users": 50,
            "completed_users": 44,
            "click_rate": 0.12,
        },
        {
            "name": "HIPAA Privacy Training",
            "status": "in_progress",
            "start_date": (NOW - timedelta(days=14)).isoformat(),
            "end_date": (NOW + timedelta(days=16)).isoformat(),
            "total_users": 50,
            "completed_users": 38,
            "pass_rate": 0.76,
        },
        {
            "name": "Incident Response Tabletop Q2",
            "status": "scheduled",
            "start_date": (NOW + timedelta(days=10)).isoformat(),
            "end_date": (NOW + timedelta(days=11)).isoformat(),
            "total_users": 15,
            "completed_users": 0,
        },
    ]
    for camp in training_campaigns:
        trail.append(
            action="training_campaign_created",
            entity_type="training_campaign",
            entity_id=str(uuid.uuid4()),
            actor="training-admin@acme.com",
            details=camp,
        )
    counts["training_campaigns"] = len(training_campaigns)

    # --- 2.4: ConMon deviations and significant changes ---
    conmon_deviations = [
        {
            "framework": "nist_800_53",
            "control_id": "AC-2",
            "reason": "Quarterly access review delayed due to IdP migration",
            "approved_by": "ciso@acme.com",
            "deviation_period_days": 30,
        },
        {
            "framework": "pci_dss",
            "control_id": "6.6",
            "reason": "WAF rule update postponed pending vendor patch",
            "approved_by": "security-lead@acme.com",
            "deviation_period_days": 14,
        },
        {
            "framework": "hipaa",
            "control_id": "164.308(a)(5)(ii)(B)",
            "reason": "Security awareness training delayed for new hire cohort",
            "approved_by": "compliance@acme.com",
            "deviation_period_days": 21,
        },
        {
            "framework": "soc2",
            "control_id": "CC7.2",
            "reason": "Incident response test rescheduled from Q1 to Q2",
            "approved_by": "ciso@acme.com",
            "deviation_period_days": 45,
        },
        {
            "framework": "iso_27001",
            "control_id": "A.12.4.1",
            "reason": "Log review frequency reduced during migration",
            "approved_by": "it-director@acme.com",
            "deviation_period_days": 60,
        },
    ]
    for dev in conmon_deviations:
        trail.append(
            action="conmon_deviation_created",
            entity_type="conmon_deviation",
            entity_id=str(uuid.uuid4()),
            actor=dev["approved_by"],
            details=dev,
        )
    counts["conmon_deviations"] = len(conmon_deviations)

    significant_changes = [
        {
            "change_type": "infrastructure",
            "description": "Migrated primary database from RDS MySQL to Aurora PostgreSQL",
            "impact": "high",
            "frameworks_affected": ["pci_dss", "soc2", "hipaa"],
            "reassessment_required": True,
        },
        {
            "change_type": "vendor",
            "description": "Onboarded new SIEM provider (replaced Splunk with Elastic)",
            "impact": "medium",
            "frameworks_affected": ["nist_800_53", "soc2"],
            "reassessment_required": True,
        },
        {
            "change_type": "personnel",
            "description": "CISO departure and interim appointment",
            "impact": "high",
            "frameworks_affected": ["iso_27001", "soc2"],
            "reassessment_required": False,
        },
    ]
    for sc in significant_changes:
        trail.append(
            action="significant_change_recorded",
            entity_type="significant_change",
            entity_id=str(uuid.uuid4()),
            actor="compliance@acme.com",
            details=sc,
        )
    counts["significant_changes"] = len(significant_changes)

    # --- 2.5: ROPA data ---
    ropa_entries = [
        {
            "processing_activity": "Employee payroll processing",
            "purpose": "Salary calculation, tax withholding, benefits administration",
            "lawful_basis": "Contract (Art. 6(1)(b))",
            "data_categories": ["name", "address", "SSN", "bank_account", "salary"],
            "data_subjects": "employees",
            "recipients": ["ADP", "IRS", "state_tax_authorities"],
            "retention_period": "7 years after employment ends",
            "transfer_mechanism": "Standard Contractual Clauses",
        },
        {
            "processing_activity": "Customer support ticket handling",
            "purpose": "Resolve customer issues, maintain service quality",
            "lawful_basis": "Legitimate interest (Art. 6(1)(f))",
            "data_categories": ["name", "email", "support_history", "usage_data"],
            "data_subjects": "customers",
            "recipients": ["Zendesk", "internal_support_team"],
            "retention_period": "3 years after last interaction",
            "transfer_mechanism": "Adequacy decision (US-EU DPF)",
        },
        {
            "processing_activity": "Marketing analytics and personalization",
            "purpose": "Targeted marketing, conversion optimization",
            "lawful_basis": "Consent (Art. 6(1)(a))",
            "data_categories": ["email", "browsing_history", "preferences", "location"],
            "data_subjects": "website_visitors",
            "recipients": ["Google Analytics", "HubSpot", "Meta"],
            "retention_period": "2 years from consent date",
            "transfer_mechanism": "Consent + SCCs",
        },
        {
            "processing_activity": "Security monitoring and threat detection",
            "purpose": "Protect IT infrastructure, detect unauthorized access",
            "lawful_basis": "Legitimate interest (Art. 6(1)(f))",
            "data_categories": ["IP_address", "user_agent", "access_logs", "authentication_events"],
            "data_subjects": "all_users",
            "recipients": ["CrowdStrike", "Splunk", "internal_SOC"],
            "retention_period": "1 year",
            "transfer_mechanism": "Standard Contractual Clauses",
        },
        {
            "processing_activity": "Vendor risk assessment questionnaires",
            "purpose": "Third-party risk management, compliance verification",
            "lawful_basis": "Legitimate interest (Art. 6(1)(f))",
            "data_categories": ["contact_name", "email", "company", "security_posture"],
            "data_subjects": "vendor_contacts",
            "recipients": ["SecurityScorecard", "OneTrust"],
            "retention_period": "Duration of vendor relationship + 2 years",
            "transfer_mechanism": "Adequacy decision",
        },
    ]
    for entry in ropa_entries:
        trail.append(
            action="ropa_entry_created",
            entity_type="ropa",
            entity_id=str(uuid.uuid4()),
            actor="dpo@acme.com",
            details=entry,
        )
    counts["ropa_entries"] = len(ropa_entries)

    session.commit()
    return counts
