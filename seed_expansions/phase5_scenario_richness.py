"""Phase 5: Scenario richness — POA&Ms, DSARs, vendors, attestations, alerts."""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

NOW = datetime.now(timezone.utc)


def seed_phase5(session) -> dict:
    """Add richer scenarios: POA&M lifecycles, DSARs, vendor assessments, alerts."""
    from warlock.db.audit import AuditTrail
    from warlock.db.models import Alert, POAM, Remediation

    trail = AuditTrail(session)
    counts: dict[str, int] = {}

    # --- 5.1: Richer POA&M lifecycle scenarios ---
    existing_poams = session.query(POAM).count()
    if existing_poams < 20:
        poam_data = [
            # Overdue POA&Ms
            {
                "framework": "nist_800_53",
                "control_id": "IA-5",
                "severity": "high",
                "status": "in_progress",
                "weakness_description": "Password complexity requirements not enforced on 3 legacy applications.",
                "scheduled_completion": NOW - timedelta(days=14),
                "milestones": [
                    {"description": "Audit legacy apps", "due_date": (NOW - timedelta(days=30)).isoformat(), "status": "done"},
                    {"description": "Implement password policy", "due_date": (NOW - timedelta(days=14)).isoformat(), "status": "overdue"},
                ],
            },
            {
                "framework": "pci_dss",
                "control_id": "8.3.1",
                "severity": "critical",
                "status": "open",
                "weakness_description": "MFA not enforced for CDE access from remote networks.",
                "scheduled_completion": NOW - timedelta(days=7),
                "milestones": [],
            },
            # Approaching deadline
            {
                "framework": "soc2",
                "control_id": "CC6.3",
                "severity": "medium",
                "status": "in_progress",
                "weakness_description": "Encryption key rotation not automated for 2 production databases.",
                "scheduled_completion": NOW + timedelta(days=5),
                "milestones": [
                    {"description": "Design key rotation workflow", "due_date": (NOW - timedelta(days=5)).isoformat(), "status": "done"},
                    {"description": "Implement in staging", "due_date": (NOW + timedelta(days=2)).isoformat(), "status": "in_progress"},
                    {"description": "Deploy to production", "due_date": (NOW + timedelta(days=5)).isoformat(), "status": "pending"},
                ],
            },
            # With cost estimate and vendor dependency
            {
                "framework": "cmmc_l2",
                "control_id": "SC.L2-3.13.11",
                "severity": "high",
                "status": "in_progress",
                "weakness_description": "FIPS 140-2 validated cryptography not used for CUI in transit.",
                "scheduled_completion": NOW + timedelta(days=60),
                "milestones": [
                    {"description": "Evaluate FIPS-compliant TLS libraries", "due_date": (NOW + timedelta(days=15)).isoformat(), "status": "pending"},
                    {"description": "Procure HSM modules", "due_date": (NOW + timedelta(days=30)).isoformat(), "status": "pending"},
                    {"description": "Deploy and validate", "due_date": (NOW + timedelta(days=55)).isoformat(), "status": "pending"},
                ],
            },
            # Recently completed with verification
            {
                "framework": "hipaa",
                "control_id": "164.312(a)(1)",
                "severity": "high",
                "status": "completed",
                "weakness_description": "EHR system lacked role-based access controls for clinical data.",
                "scheduled_completion": NOW - timedelta(days=10),
                "actual_completion": NOW - timedelta(days=12),
                "milestones": [
                    {"description": "Design RBAC matrix", "due_date": (NOW - timedelta(days=30)).isoformat(), "status": "done"},
                    {"description": "Implement in EHR", "due_date": (NOW - timedelta(days=15)).isoformat(), "status": "done"},
                    {"description": "Verify with penetration test", "due_date": (NOW - timedelta(days=10)).isoformat(), "status": "done"},
                ],
            },
            {
                "framework": "nist_800_53",
                "control_id": "AU-6",
                "severity": "medium",
                "status": "verified",
                "weakness_description": "Audit log review process was manual and inconsistent.",
                "scheduled_completion": NOW - timedelta(days=20),
                "actual_completion": NOW - timedelta(days=22),
                "milestones": [
                    {"description": "Deploy SIEM correlation rules", "due_date": (NOW - timedelta(days=25)).isoformat(), "status": "done"},
                    {"description": "Train SOC analysts", "due_date": (NOW - timedelta(days=20)).isoformat(), "status": "done"},
                ],
            },
            # Risk accepted
            {
                "framework": "iso_27001",
                "control_id": "A.8.1.3",
                "severity": "low",
                "status": "risk_accepted",
                "weakness_description": "Acceptable use policy not formally signed by 3 contractors (contract ending Q2).",
                "scheduled_completion": NOW + timedelta(days=90),
                "milestones": [],
            },
            # Additional approaching
            {
                "framework": "gdpr",
                "control_id": "Art.32",
                "severity": "high",
                "status": "in_progress",
                "weakness_description": "Encryption at rest not enabled for 2 EU data stores.",
                "scheduled_completion": NOW + timedelta(days=3),
                "milestones": [
                    {"description": "Enable encryption on eu-west-1 RDS", "due_date": (NOW + timedelta(days=1)).isoformat(), "status": "in_progress"},
                    {"description": "Enable encryption on eu-central-1 S3", "due_date": (NOW + timedelta(days=3)).isoformat(), "status": "pending"},
                ],
            },
        ]

        for data in poam_data:
            poam = POAM(
                id=str(uuid.uuid4()),
                framework=data["framework"],
                control_id=data["control_id"],
                severity=data["severity"],
                status=data["status"],
                weakness_description=data["weakness_description"],
                scheduled_completion=data.get("scheduled_completion"),
                actual_completion=data.get("actual_completion"),
                milestones=data.get("milestones", []),
                created_at=NOW - timedelta(days=random.randint(14, 60)),
                updated_at=NOW - timedelta(hours=random.randint(1, 72)),
            )
            session.add(poam)
        counts["poams"] = len(poam_data)
    else:
        counts["poams"] = 0

    # --- 5.2: Active DSARs ---
    dsar_scenarios = [
        {"status": "submitted", "subject": "john.doe@example.com", "type": "access", "days_elapsed": 2},
        {"status": "submitted", "subject": "jane.smith@example.com", "type": "erasure", "days_elapsed": 1},
        {"status": "in_progress", "subject": "mike.jones@example.com", "type": "portability", "days_elapsed": 15},
        {"status": "completed", "subject": "sarah.wilson@example.com", "type": "access", "days_elapsed": 28},
        {"status": "overdue", "subject": "alex.brown@example.com", "type": "erasure", "days_elapsed": 35},
    ]
    for d in dsar_scenarios:
        trail.append(
            action="dsar_created",
            entity_type="dsar",
            entity_id=str(uuid.uuid4()),
            actor="dpo@acme.com",
            details={
                "subject_email": d["subject"],
                "request_type": d["type"],
                "status": d["status"],
                "submitted_at": (NOW - timedelta(days=d["days_elapsed"])).isoformat(),
                "deadline": (NOW - timedelta(days=d["days_elapsed"]) + timedelta(days=30)).isoformat(),
            },
        )
    counts["dsars"] = len(dsar_scenarios)

    # Data breach notifications
    breach_data = [
        {
            "title": "Unauthorized access to customer PII via compromised API key",
            "severity": "high",
            "status": "reported_to_authority",
            "records_affected": 1250,
            "reported_at": (NOW - timedelta(days=5)).isoformat(),
        },
        {
            "title": "Email misconfiguration exposed employee directory",
            "severity": "medium",
            "status": "under_investigation",
            "records_affected": 340,
            "reported_at": (NOW - timedelta(days=2)).isoformat(),
        },
    ]
    for b in breach_data:
        trail.append(
            action="breach_notification_created",
            entity_type="breach",
            entity_id=str(uuid.uuid4()),
            actor="dpo@acme.com",
            details=b,
        )
    counts["breach_notifications"] = len(breach_data)

    # --- 5.3: Vendor assessment enrichment ---
    vendor_assessments = [
        {"vendor": "Stripe", "score": 92, "risk_level": "low", "soc2_expiry": (NOW + timedelta(days=45)).isoformat()},
        {"vendor": "Datadog", "score": 88, "risk_level": "low", "soc2_expiry": (NOW + timedelta(days=120)).isoformat()},
        {"vendor": "CrowdStrike", "score": 95, "risk_level": "low", "soc2_expiry": (NOW + timedelta(days=200)).isoformat()},
        {"vendor": "Legacy ERP Vendor", "score": 52, "risk_level": "high", "soc2_expiry": (NOW - timedelta(days=30)).isoformat()},
        {"vendor": "Cloud Backup Co", "score": 58, "risk_level": "high", "soc2_expiry": (NOW + timedelta(days=15)).isoformat()},
        {"vendor": "HR SaaS Platform", "score": 74, "risk_level": "medium", "assessment_due": (NOW + timedelta(days=10)).isoformat()},
        {"vendor": "Marketing Analytics", "score": 65, "risk_level": "medium", "status": "offboarding"},
    ]
    for v in vendor_assessments:
        trail.append(
            action="vendor_assessment_completed",
            entity_type="vendor_assessment",
            entity_id=str(uuid.uuid4()),
            actor="vendor-mgmt@acme.com",
            details=v,
        )
    counts["vendor_assessments"] = len(vendor_assessments)

    # --- 5.4: Expiring attestations and calendar items ---
    calendar_items = [
        {"type": "attestation_expiry", "title": "SOC 2 Type II attestation expires", "due": (NOW + timedelta(days=20)).isoformat()},
        {"type": "attestation_expiry", "title": "ISO 27001 certification renewal", "due": (NOW + timedelta(days=45)).isoformat()},
        {"type": "attestation_expiry", "title": "PCI DSS AOC expires", "due": (NOW + timedelta(days=10)).isoformat()},
        {"type": "evidence_collection", "title": "Quarterly evidence collection deadline", "due": (NOW + timedelta(days=7)).isoformat()},
        {"type": "audit_prep", "title": "SOC 2 audit preparation meeting", "due": (NOW + timedelta(days=14)).isoformat()},
        {"type": "vendor_review", "title": "Annual vendor risk review due", "due": (NOW + timedelta(days=30)).isoformat()},
        {"type": "training", "title": "Q2 security awareness training deadline", "due": (NOW + timedelta(days=21)).isoformat()},
    ]
    for item in calendar_items:
        trail.append(
            action="calendar_item_created",
            entity_type="calendar",
            entity_id=str(uuid.uuid4()),
            actor="compliance@acme.com",
            details=item,
        )
    counts["calendar_items"] = len(calendar_items)

    # --- 5.5: More alerts ---
    existing_alerts = session.query(Alert).count()
    if existing_alerts < 15:
        extra_alerts = [
            {"title": "Unauthorized API access detected from unknown IP", "severity": "critical", "category": "access_anomaly", "status": "active"},
            {"title": "Failed login brute force attempt on admin account", "severity": "critical", "category": "authentication", "status": "active"},
            {"title": "S3 bucket policy changed to public", "severity": "high", "category": "configuration_drift", "status": "active"},
            {"title": "IAM user created outside approved process", "severity": "high", "category": "access_anomaly", "status": "acknowledged"},
            {"title": "Encryption disabled on RDS instance", "severity": "high", "category": "configuration_drift", "status": "active"},
            {"title": "VPN tunnel down for >30 minutes", "severity": "medium", "category": "availability", "status": "acknowledged"},
            {"title": "Certificate expiring in 14 days (api.acme.com)", "severity": "medium", "category": "certificate", "status": "active"},
            {"title": "Unusual data download volume detected", "severity": "medium", "category": "data_exfiltration", "status": "investigating"},
            {"title": "Stale access key detected (>180 days)", "severity": "low", "category": "hygiene", "status": "active"},
            {"title": "Non-compliant password policy on legacy system", "severity": "low", "category": "compliance", "status": "acknowledged"},
        ]
        for a in extra_alerts:
            session.add(
                Alert(
                    id=str(uuid.uuid4()),
                    title=a["title"],
                    description=f"Automated alert: {a['title']}",
                    severity=a["severity"],
                    category=a["category"],
                    status=a["status"],
                    rule_name=f"rule_{a['category']}",
                    triggered_at=NOW - timedelta(hours=random.randint(1, 168)),
                    created_at=NOW - timedelta(hours=random.randint(1, 168)),
                )
            )
        counts["alerts"] = len(extra_alerts)
    else:
        counts["alerts"] = 0

    # --- 5.5b: More remediations ---
    existing_rems = session.query(Remediation).count()
    if existing_rems < 10:
        extra_rems = [
            {
                "title": "Disable TLS 1.0/1.1 on all endpoints",
                "framework": "pci_dss",
                "control_id": "4.2.1",
                "status": "in_progress",
                "assigned_to": "network-team@acme.com",
                "due_date": NOW + timedelta(days=14),
                "remediation_steps": [
                    {"step": 1, "action": "Scan for TLS 1.0/1.1 endpoints", "status": "done"},
                    {"step": 2, "action": "Update ALB listener policies", "status": "in_progress"},
                    {"step": 3, "action": "Update CloudFront distributions", "status": "pending"},
                ],
            },
            {
                "title": "Enable CloudTrail log file validation",
                "framework": "nist_800_53",
                "control_id": "AU-9",
                "status": "open",
                "due_date": NOW + timedelta(days=7),
                "remediation_steps": [
                    {"step": 1, "action": "Update CloudTrail configuration", "status": "pending"},
                    {"step": 2, "action": "Verify log integrity via digest files", "status": "pending"},
                ],
            },
            {
                "title": "Implement database activity monitoring for PCI CDE",
                "framework": "pci_dss",
                "control_id": "10.2.1",
                "status": "assigned",
                "assigned_to": "dba-team@acme.com",
                "due_date": NOW + timedelta(days=21),
                "remediation_steps": [
                    {"step": 1, "action": "Deploy Imperva DAM agent", "status": "pending"},
                    {"step": 2, "action": "Configure audit policies", "status": "pending"},
                    {"step": 3, "action": "Test alert routing to SIEM", "status": "pending"},
                ],
            },
            {
                "title": "Rotate expired SSH keys on bastion hosts",
                "framework": "nist_800_53",
                "control_id": "IA-5",
                "status": "closed",
                "assigned_to": "infra-team@acme.com",
                "remediation_steps": [
                    {"step": 1, "action": "Generate new ED25519 keys", "status": "done"},
                    {"step": 2, "action": "Deploy via Ansible", "status": "done"},
                    {"step": 3, "action": "Revoke old keys", "status": "done"},
                ],
            },
            {
                "title": "Enable AWS Config rules for CIS Benchmark",
                "framework": "cmmc_l2",
                "control_id": "CM.L2-3.4.2",
                "status": "verification",
                "assigned_to": "cloud-ops@acme.com",
                "remediation_steps": [
                    {"step": 1, "action": "Enable AWS Config in all regions", "status": "done"},
                    {"step": 2, "action": "Deploy CIS conformance pack", "status": "done"},
                    {"step": 3, "action": "Review non-compliant resources", "status": "done"},
                    {"step": 4, "action": "Verify via SecurityHub findings", "status": "in_progress"},
                ],
            },
        ]
        for data in extra_rems:
            rem = Remediation(
                id=str(uuid.uuid4()),
                title=data["title"],
                description=data["title"],
                framework=data.get("framework"),
                control_id=data.get("control_id"),
                status=data["status"],
                assigned_to=data.get("assigned_to"),
                assigned_by="security-lead@acme.com" if data.get("assigned_to") else None,
                assigned_at=NOW - timedelta(days=random.randint(1, 7)) if data.get("assigned_to") else None,
                due_date=data.get("due_date"),
                remediation_plan=data["title"],
                remediation_steps=data.get("remediation_steps"),
                created_by="demo-seed@warlock",
                created_at=NOW - timedelta(days=random.randint(3, 21)),
                updated_at=NOW - timedelta(hours=random.randint(1, 72)),
            )
            if data["status"] == "closed":
                rem.closed_at = NOW - timedelta(days=random.randint(1, 5))
                rem.verified_by = "audit-lead@acme.com"
                rem.verified_at = NOW - timedelta(days=random.randint(1, 5))
                rem.verification_notes = "Verified via rescan."
            session.add(rem)
        counts["remediations"] = len(extra_rems)
    else:
        counts["remediations"] = 0

    session.commit()
    return counts
