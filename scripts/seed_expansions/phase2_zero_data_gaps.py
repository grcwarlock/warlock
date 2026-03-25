"""Phase 2 seed expansion: fill zero-data gaps for CLI commands.

Creates training campaigns, DataSilos, overdue POA&Ms, failed ConnectorRuns,
and ConMon significant-change audit entries so that CLI commands like
``warlock training campaigns``, ``warlock privacy ropa``,
``warlock dashboard kri list``, and ``warlock conmon checklist`` return
meaningful data instead of empty tables.

Called from demo_seed.py after the main seed completes.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from warlock.db.models import (
    AuditEntry,
    ConnectorRun,
    DataSilo,
    Personnel,
    POAM,
)


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _days_ago(n: int) -> datetime:
    return _utcnow() - timedelta(days=n)


# ---------------------------------------------------------------------------
# 1. Training campaigns
# ---------------------------------------------------------------------------

# Campaign definitions: (name, completed_count, status_for_remainder)
_CAMPAIGNS = [
    ("Annual Security Awareness 2026", 48, "completed", None),
    ("Phishing Simulation Q1 2026", 44, "completed", None),
    ("HIPAA Privacy Training", 38, "completed", "in_progress"),
    ("Incident Response Tabletop", 0, None, "scheduled"),
]


def _seed_training_campaigns(session: Session) -> int:
    """Update existing Personnel records with training_completions JSON.

    The ``warlock training campaigns`` command reads
    ``Personnel.training_completions`` (a JSON list) and aggregates by the
    ``campaign`` key in each entry.
    """
    personnel = (
        session.query(Personnel)
        .filter(Personnel.is_active == True)  # noqa: E712
        .order_by(Personnel.email)
        .all()
    )
    if not personnel:
        return 0

    campaigns_seeded = 0
    for camp_name, completed_count, completed_status, remainder_status in _CAMPAIGNS:
        for i, person in enumerate(personnel[:50]):
            existing = list(person.training_completions or [])

            if i < completed_count:
                # Person completed this campaign
                entry = {
                    "campaign": camp_name,
                    "status": completed_status or "completed",
                    "completed_date": (_days_ago(30) + timedelta(days=i % 14)).strftime("%Y-%m-%d"),
                }
            elif remainder_status:
                # Person has a non-completed status (in_progress / scheduled)
                entry = {
                    "campaign": camp_name,
                    "status": remainder_status,
                }
            else:
                continue

            existing.append(entry)
            person.training_completions = existing

        campaigns_seeded += 1

    session.flush()
    return campaigns_seeded


# ---------------------------------------------------------------------------
# 2. DataSilos for ``warlock privacy ropa``
# ---------------------------------------------------------------------------

_SILO_DEFS: list[dict] = [
    {
        "name": "acme-prod-db",
        "silo_type": "rds_database",
        "provider": "aws",
        "location": "arn:aws:rds:us-east-1:123456789012:db/acme-prod",
        "data_classification": "confidential",
        "contains_pii": True,
        "contains_phi": False,
        "contains_pci": True,
        "contains_credentials": False,
        "encrypted_at_rest": True,
        "encrypted_in_transit": True,
        "access_logging_enabled": True,
        "backup_enabled": True,
        "retention_days": 365,
        "owner": "platform-team@acme.com",
        "team": "Platform Engineering",
        "applicable_frameworks": ["pci_dss", "soc2", "nist_800_53"],
        "scan_status": "completed",
        "sensitive_field_count": 42,
        "total_records": 2_500_000,
    },
    {
        "name": "acme-logs",
        "silo_type": "s3_bucket",
        "provider": "aws",
        "location": "s3://acme-centralized-logs",
        "data_classification": "internal",
        "contains_pii": False,
        "contains_phi": False,
        "contains_pci": False,
        "contains_credentials": False,
        "encrypted_at_rest": True,
        "encrypted_in_transit": True,
        "access_logging_enabled": True,
        "backup_enabled": False,
        "retention_days": 90,
        "owner": "sre-team@acme.com",
        "team": "SRE",
        "applicable_frameworks": ["soc2", "nist_800_53"],
        "scan_status": "completed",
        "sensitive_field_count": 0,
        "total_records": 15_000_000,
    },
    {
        "name": "acme-analytics",
        "silo_type": "snowflake_db",
        "provider": "aws",
        "location": "acme-analytics.us-east-1.redshift.amazonaws.com:5439/analytics",
        "data_classification": "restricted",
        "contains_pii": True,
        "contains_phi": True,
        "contains_pci": False,
        "contains_credentials": False,
        "encrypted_at_rest": True,
        "encrypted_in_transit": True,
        "access_logging_enabled": True,
        "backup_enabled": True,
        "retention_days": 730,
        "owner": "data-team@acme.com",
        "team": "Data Engineering",
        "applicable_frameworks": ["hipaa", "gdpr", "nist_800_53"],
        "scan_status": "completed",
        "sensitive_field_count": 87,
        "total_records": 8_000_000,
    },
    {
        "name": "customer-uploads",
        "silo_type": "s3_bucket",
        "provider": "aws",
        "location": "s3://acme-customer-uploads",
        "data_classification": "confidential",
        "contains_pii": True,
        "contains_phi": False,
        "contains_pci": False,
        "contains_credentials": False,
        "encrypted_at_rest": True,
        "encrypted_in_transit": True,
        "access_logging_enabled": True,
        "backup_enabled": True,
        "retention_days": 180,
        "owner": "product-team@acme.com",
        "team": "Product",
        "applicable_frameworks": ["gdpr", "soc2"],
        "scan_status": "completed",
        "sensitive_field_count": 12,
        "total_records": 450_000,
    },
    {
        "name": "hr-records",
        "silo_type": "rds_database",
        "provider": "aws",
        "location": "arn:aws:rds:us-east-1:123456789012:db/acme-hris",
        "data_classification": "restricted",
        "contains_pii": True,
        "contains_phi": False,
        "contains_pci": False,
        "contains_credentials": False,
        "encrypted_at_rest": True,
        "encrypted_in_transit": True,
        "access_logging_enabled": True,
        "backup_enabled": True,
        "retention_days": 2555,
        "owner": "hr-ops@acme.com",
        "team": "Human Resources",
        "applicable_frameworks": ["gdpr", "hipaa", "soc2"],
        "scan_status": "completed",
        "sensitive_field_count": 34,
        "total_records": 12_000,
    },
    {
        "name": "email-archive",
        "silo_type": "sharepoint_site",
        "provider": "azure",
        "location": "https://acme.sharepoint.com/sites/email-archive",
        "data_classification": "confidential",
        "contains_pii": True,
        "contains_phi": False,
        "contains_pci": False,
        "contains_credentials": False,
        "encrypted_at_rest": True,
        "encrypted_in_transit": True,
        "access_logging_enabled": False,
        "backup_enabled": True,
        "retention_days": 365,
        "owner": "it-ops@acme.com",
        "team": "IT Operations",
        "applicable_frameworks": ["gdpr", "soc2", "nist_800_53"],
        "scan_status": "completed",
        "sensitive_field_count": 8,
        "total_records": 3_200_000,
    },
    {
        "name": "source-code",
        "silo_type": "github_repo",
        "provider": "github",
        "location": "https://github.com/acme-corp",
        "data_classification": "confidential",
        "contains_pii": False,
        "contains_phi": False,
        "contains_pci": False,
        "contains_credentials": True,
        "encrypted_at_rest": True,
        "encrypted_in_transit": True,
        "access_logging_enabled": True,
        "backup_enabled": True,
        "retention_days": None,
        "owner": "security-team@acme.com",
        "team": "Security",
        "applicable_frameworks": ["soc2", "nist_800_53"],
        "scan_status": "completed",
        "sensitive_field_count": 3,
        "total_records": None,
    },
    {
        "name": "public-docs",
        "silo_type": "sharepoint_site",
        "provider": "azure",
        "location": "https://acme.sharepoint.com/sites/public-docs",
        "data_classification": "public",
        "contains_pii": False,
        "contains_phi": False,
        "contains_pci": False,
        "contains_credentials": False,
        "encrypted_at_rest": True,
        "encrypted_in_transit": True,
        "access_logging_enabled": False,
        "backup_enabled": False,
        "retention_days": None,
        "owner": "marketing@acme.com",
        "team": "Marketing",
        "applicable_frameworks": [],
        "scan_status": "not_scanned",
        "sensitive_field_count": 0,
        "total_records": 500,
    },
]


def _seed_data_silos(session: Session) -> int:
    """Create DataSilo records for ``warlock privacy ropa``."""
    silos = []
    now = _utcnow()
    for defn in _SILO_DEFS:
        silo = DataSilo(
            id=_uuid(),
            name=defn["name"],
            silo_type=defn["silo_type"],
            provider=defn["provider"],
            location=defn["location"],
            data_classification=defn["data_classification"],
            contains_pii=defn["contains_pii"],
            contains_phi=defn["contains_phi"],
            contains_pci=defn["contains_pci"],
            contains_credentials=defn["contains_credentials"],
            encrypted_at_rest=defn["encrypted_at_rest"],
            encrypted_in_transit=defn["encrypted_in_transit"],
            access_logging_enabled=defn["access_logging_enabled"],
            backup_enabled=defn["backup_enabled"],
            retention_days=defn["retention_days"],
            owner=defn["owner"],
            team=defn["team"],
            applicable_frameworks=defn["applicable_frameworks"],
            scan_status=defn["scan_status"],
            sensitive_field_count=defn["sensitive_field_count"],
            total_records=defn["total_records"],
            last_scan_date=now - timedelta(days=2) if defn["scan_status"] == "completed" else None,
            is_active=True,
        )
        silos.append(silo)

    session.add_all(silos)
    session.flush()
    return len(silos)


# ---------------------------------------------------------------------------
# 3. Overdue POA&Ms for ``warlock dashboard kri list`` overdue_poam_count
# ---------------------------------------------------------------------------

_OVERDUE_POAMS = [
    {
        "framework": "nist_800_53",
        "control_id": "AC-2",
        "weakness_description": (
            "Account management procedures lack automated deprovisioning for "
            "terminated employees within the required 24-hour window."
        ),
        "severity": "high",
        "risk_level": "high",
        "status": "open",
        "days_overdue": 30,
        "created_by": "security-team",
    },
    {
        "framework": "soc2",
        "control_id": "CC6.1",
        "weakness_description": (
            "Logical access controls for production database lack multi-factor "
            "authentication for privileged users."
        ),
        "severity": "critical",
        "risk_level": "high",
        "status": "in_progress",
        "days_overdue": 14,
        "created_by": "audit-team",
    },
    {
        "framework": "hipaa",
        "control_id": "164.312(a)(1)",
        "weakness_description": (
            "Access control mechanisms for ePHI systems do not enforce unique "
            "user identification for shared service accounts."
        ),
        "severity": "high",
        "risk_level": "moderate",
        "status": "open",
        "days_overdue": 7,
        "created_by": "compliance-team",
    },
]


def _seed_overdue_poams(session: Session) -> int:
    """Create overdue POA&M records so KRI ``overdue_poam_count`` is non-zero."""
    now = _utcnow()
    poams = []
    for defn in _OVERDUE_POAMS:
        poam = POAM(
            id=_uuid(),
            framework=defn["framework"],
            control_id=defn["control_id"],
            weakness_description=defn["weakness_description"],
            severity=defn["severity"],
            risk_level=defn["risk_level"],
            status=defn["status"],
            scheduled_completion=now - timedelta(days=defn["days_overdue"]),
            milestones=[
                {
                    "description": "Initial assessment complete",
                    "due_date": (now - timedelta(days=defn["days_overdue"] + 14)).isoformat(),
                    "completed_date": (now - timedelta(days=defn["days_overdue"] + 10)).isoformat(),
                    "status": "completed",
                },
                {
                    "description": "Remediation implementation",
                    "due_date": (now - timedelta(days=defn["days_overdue"])).isoformat(),
                    "completed_date": None,
                    "status": "in_progress",
                },
            ],
            cost_estimate=25_000.0 if defn["severity"] == "critical" else 10_000.0,
            resource_allocation="Security Engineering team",
            created_by=defn["created_by"],
            created_at=now - timedelta(days=defn["days_overdue"] + 30),
        )
        poams.append(poam)

    session.add_all(poams)
    session.flush()
    return len(poams)


# ---------------------------------------------------------------------------
# 4. Failed ConnectorRuns for ``warlock dashboard kri list`` connector_error_rate
# ---------------------------------------------------------------------------


def _seed_failed_connector_runs(session: Session) -> int:
    """Create ConnectorRun records with status='error' in the last 24 hours.

    The KRI ``connector_error_rate`` divides error runs by total runs within
    a 24-hour window.
    """
    now = _utcnow()
    runs = [
        ConnectorRun(
            id=_uuid(),
            connector_name="aws-guardduty-prod",
            source="aws_guardduty",
            source_type="cloud",
            provider="aws",
            status="error",
            event_count=0,
            error_count=1,
            errors=[{"message": "AssumeRole failed: expired STS token", "code": "AUTH_ERROR"}],
            started_at=now - timedelta(hours=6),
            completed_at=now - timedelta(hours=6, minutes=-1),
            duration_seconds=60.0,
        ),
        ConnectorRun(
            id=_uuid(),
            connector_name="azure-sentinel-prod",
            source="azure_sentinel",
            source_type="cloud",
            provider="azure",
            status="error",
            event_count=0,
            error_count=1,
            errors=[
                {
                    "message": "HTTP 429 Too Many Requests from Sentinel API",
                    "code": "RATE_LIMIT",
                }
            ],
            started_at=now - timedelta(hours=2),
            completed_at=now - timedelta(hours=2, minutes=-2),
            duration_seconds=120.0,
        ),
    ]
    session.add_all(runs)
    session.flush()
    return len(runs)


# ---------------------------------------------------------------------------
# 5. ConMon significant-change AuditEntry records
# ---------------------------------------------------------------------------

_SIGNIFICANT_CHANGES = [
    {
        "title": "Production database migrated to Aurora PostgreSQL",
        "description": (
            "Migrated acme-prod-db from RDS MySQL 8.0 to Aurora PostgreSQL 15. "
            "All encryption-at-rest keys rotated. New connection endpoints "
            "distributed to application teams."
        ),
        "frameworks": ["nist_800_53", "soc2", "pci_dss"],
        "actor": "platform-lead@acme.com",
    },
    {
        "title": "CISO departure and interim appointment",
        "description": (
            "CISO Jane Rodriguez departed 2026-03-10. VP of Engineering "
            "Alex Chen appointed interim CISO pending executive search."
        ),
        "frameworks": ["nist_800_53", "soc2", "hipaa"],
        "actor": "hr-ops@acme.com",
    },
    {
        "title": "Network boundary expanded for acquisition integration",
        "description": (
            "Corporate network extended to include WidgetCo VPN tunnel "
            "(10.200.0.0/16). Firewall rules updated. Requires re-assessment "
            "of boundary protection controls."
        ),
        "frameworks": ["nist_800_53", "fedramp", "cmmc_l2"],
        "actor": "network-team@acme.com",
    },
]


def _seed_significant_changes(session: Session) -> int:
    """Create AuditEntry records representing ConMon significant changes.

    The ``warlock conmon significant-change`` command stores changes as
    AuditEntry records with ``action='significant_change'`` and
    ``entity_type='conmon'``.
    """
    now = _utcnow()

    # Find the current max sequence to continue the hash chain correctly
    last_entry = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
    seq = (last_entry.sequence + 1) if last_entry else 1
    prev_hash = last_entry.entry_hash if last_entry else "genesis"

    entries = []
    for i, change in enumerate(_SIGNIFICANT_CHANGES):
        payload = f"{seq}:{prev_hash}:significant_change:conmon:{change['actor']}:{change['title']}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()

        entry = AuditEntry(
            id=_uuid(),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="significant_change",
            entity_type="conmon",
            entity_id=f"sigchange-{seq}",
            actor=change["actor"],
            extra={
                "title": change["title"],
                "description": change["description"],
                "system": None,
                "frameworks": change["frameworks"],
                "recorded_at": (now - timedelta(days=10 - i * 3)).isoformat(),
            },
            created_at=now - timedelta(days=10 - i * 3),
        )
        entries.append(entry)

        # Advance chain
        prev_hash = entry_hash
        seq += 1

    session.add_all(entries)
    session.flush()
    return len(entries)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def seed_phase2(session: Session) -> dict:
    """Seed data that fills zero-data gaps for CLI commands.

    Args:
        session: An active SQLAlchemy session (caller manages commit).

    Returns:
        Summary dict with counts of records created/updated per category.
    """
    results: dict[str, int] = {}

    results["training_campaigns"] = _seed_training_campaigns(session)
    results["data_silos"] = _seed_data_silos(session)
    results["overdue_poams"] = _seed_overdue_poams(session)
    results["failed_connector_runs"] = _seed_failed_connector_runs(session)
    results["significant_changes"] = _seed_significant_changes(session)

    return results
