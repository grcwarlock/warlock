"""Phase 3 seed expansion: 90-day historical depth for time-series commands.

Expands PostureSnapshots, PipelineRuns, ComplianceDrift, ChangeEvents, and
backfills Finding.observed_at across a 90-day window so that trend, drift, and
analytics CLI commands show realistic historical data.

Called from demo_seed.py after the main seed completes.
"""

from __future__ import annotations

import hashlib
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.models import (
    ChangeEvent,
    ComplianceDrift,
    Finding,
    PipelineRun,
    PostureSnapshot,
)


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _days_ago(n: int) -> datetime:
    return _utcnow() - timedelta(days=n)


def _sha256(data: dict[str, Any]) -> str:
    content = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(content.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Control definitions for 90-day posture snapshots
# ---------------------------------------------------------------------------

_CONTROLS_90D = [
    # (framework, control_id, base_score_day0)
    # NIST 800-53
    ("nist_800_53", "AC-2", 62.0),
    ("nist_800_53", "AU-2", 68.0),
    ("nist_800_53", "SC-7", 70.0),
    ("nist_800_53", "IA-2", 58.0),
    # SOC 2
    ("soc2", "CC6.1", 66.0),
    ("soc2", "CC7.2", 60.0),
    ("soc2", "CC8.1", 72.0),
    # ISO 27001
    ("iso_27001", "A.8.5", 64.0),
    ("iso_27001", "A.8.9", 69.0),
    # HIPAA
    ("hipaa", "164.312(a)(1)", 63.0),
    ("hipaa", "164.312(d)", 67.0),
    ("hipaa", "164.312(e)(1)", 61.0),
]

# Evidence source sets per framework
_EVIDENCE_SOURCES = {
    "nist_800_53": ["aws", "okta", "crowdstrike", "tenable"],
    "soc2": ["aws", "github", "okta"],
    "iso_27001": ["okta", "crowdstrike", "aws"],
    "hipaa": ["aws", "okta", "sentinelone"],
}

# ---------------------------------------------------------------------------
# 1. Posture snapshots — 90 days x 12 controls
# ---------------------------------------------------------------------------


def _seed_posture_snapshots_90d(session: Session) -> int:
    """Create 90 days of PostureSnapshot records for 12 key controls.

    Scores follow a gradual improvement trend from ~65% to ~82% with
    periodic 2-3% dips every 10-15 days to simulate realistic drift.
    """
    existing = session.query(PostureSnapshot).count()
    if existing >= 1000:
        return 0  # Already expanded; skip to avoid dupes

    random.seed(90)  # Deterministic for reproducibility
    now = _utcnow()
    snapshots: list[PostureSnapshot] = []

    for day_offset in range(90, 0, -1):
        snapshot_date = now - timedelta(days=day_offset)
        day_index = 90 - day_offset  # 0..89

        for framework, control_id, base_score in _CONTROLS_90D:
            # Gradual improvement: ~65% at day 0 -> ~82% at day 89
            # Linear trend: +0.19 per day ≈ +17 over 90 days
            trend = day_index * 0.19

            # Periodic dips: every 10-15 days, drop 2-3%
            dip = 0.0
            if day_index % 12 in (0,) and day_index > 0:
                dip = -random.uniform(2.0, 3.5)
            elif day_index % 17 == 0 and day_index > 0:
                dip = -random.uniform(1.5, 3.0)

            # Per-control noise
            noise = random.uniform(-2.0, 2.0)

            score = base_score + trend + dip + noise
            score = max(0.0, min(100.0, round(score, 1)))

            if score >= 80:
                status = "compliant"
            elif score >= 50:
                status = "partial"
            else:
                status = "non_compliant"

            total = random.randint(3, 12)
            compliant_count = max(0, int(total * score / 100))
            non_compliant_count = total - compliant_count
            sufficiency = min(100.0, max(0.0, score + random.uniform(-10, 10)))

            snapshots.append(
                PostureSnapshot(
                    id=_uuid(),
                    snapshot_date=snapshot_date,
                    framework=framework,
                    control_id=control_id,
                    status=status,
                    posture_score=score,
                    total_findings=total,
                    compliant_findings=compliant_count,
                    non_compliant_findings=non_compliant_count,
                    partial_findings=0,
                    not_assessed_findings=0,
                    evidence_sources=_EVIDENCE_SOURCES.get(framework, ["aws"]),
                    evidence_freshness_hours=round(random.uniform(1.0, 24.0), 1),
                    sufficiency_score=round(sufficiency, 1),
                    sufficiency_details={
                        "source_count": random.randint(2, 4),
                        "evidence_types": ["config", "telemetry", "process"],
                    },
                    system_profile_id=None,
                    uptime_pct=round(max(50.0, min(100.0, score + random.uniform(-5, 5))), 1),
                    mttr_hours=round(max(0.5, (100 - score) / 10 + random.uniform(-1, 2)), 1),
                    drift_count=random.randint(0, 3) if score < 70 else random.randint(0, 1),
                    created_at=snapshot_date,
                )
            )

    session.add_all(snapshots)
    session.flush()
    return len(snapshots)


# ---------------------------------------------------------------------------
# 2. Pipeline runs — 90 days of daily scheduled runs
# ---------------------------------------------------------------------------

_FAILED_DAYS = {12, 47, 73}


def _seed_pipeline_runs_90d(session: Session) -> int:
    """Create 90 PipelineRun records, one per day over the last 90 days.

    87 completed runs, 3 failed runs on days 12, 47, 73. Connector counts
    gradually increase from 341 to 351 over the period.
    """
    existing = session.query(PipelineRun).count()
    if existing >= 30:
        return 0  # Already expanded; skip

    random.seed(91)
    now = _utcnow()
    runs: list[PipelineRun] = []

    for day_offset in range(90, 0, -1):
        day_index = 90 - day_offset  # 0..89
        started_at = (now - timedelta(days=day_offset)).replace(
            hour=2, minute=0, second=0, microsecond=0
        )

        is_failed = day_offset in _FAILED_DAYS
        duration = random.uniform(90.0, 120.0) if is_failed else random.uniform(30.0, 90.0)
        completed_at = started_at + timedelta(seconds=duration)

        # Gradually increase from 341 to 351 connectors
        connectors_succeeded = min(351, 155 + int(day_index * 10 / 89))

        if is_failed:
            status = "failed"
            connectors_failed = 5
            connectors_succeeded = connectors_succeeded - 5
            raw_events = random.randint(200, 350)
            findings = 0
            controls = 0
            errors = [
                "Timeout on tenable_io connector",
                "Auth failure on okta_iam",
                "Rate limit exceeded on crowdstrike_edr",
            ]
        else:
            status = "completed"
            connectors_failed = 0
            raw_events = random.randint(550, 590)
            findings = random.randint(5200, 5480)
            controls = random.randint(370000, 373852)
            errors = []

        runs.append(
            PipelineRun(
                id=_uuid(),
                status=status,
                connectors_succeeded=connectors_succeeded,
                connectors_failed=connectors_failed,
                raw_events_collected=raw_events,
                findings_normalized=findings,
                controls_mapped=controls,
                errors=errors,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=round(duration, 1),
                triggered_by="scheduler",
            )
        )

    session.add_all(runs)
    session.flush()
    return len(runs)


# ---------------------------------------------------------------------------
# 3. Backdate findings across 90 days
# ---------------------------------------------------------------------------


def _backdate_findings_90d(session: Session) -> int:
    """Spread existing Finding.observed_at across 90 days.

    The FindingData.sha256 property hashes (observation_type, detail,
    resource_id, resource_type) — NOT observed_at — so backdating is safe
    and does not break the hash chain.

    Distribution:
      ~200 findings: 60-90 days ago
      ~500 findings: 30-60 days ago
      ~1000 findings: 7-30 days ago
      Remainder: leave at current date
    """
    random.seed(92)
    now = _utcnow()
    total_updated = 0

    # Batch 1: oldest findings (60-90 days ago)
    batch1 = session.query(Finding).order_by(Finding.id).offset(0).limit(200).all()
    for f in batch1:
        days_back = random.randint(60, 90)
        f.observed_at = now - timedelta(
            days=days_back,
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
    total_updated += len(batch1)

    # Batch 2: mid-range findings (30-60 days ago)
    batch2 = session.query(Finding).order_by(Finding.id).offset(200).limit(500).all()
    for f in batch2:
        days_back = random.randint(30, 59)
        f.observed_at = now - timedelta(
            days=days_back,
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
    total_updated += len(batch2)

    # Batch 3: recent findings (7-30 days ago)
    batch3 = session.query(Finding).order_by(Finding.id).offset(700).limit(1000).all()
    for f in batch3:
        days_back = random.randint(7, 29)
        f.observed_at = now - timedelta(
            days=days_back,
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
    total_updated += len(batch3)

    # Remainder: leave at current date (no update needed)

    session.flush()
    return total_updated


# ---------------------------------------------------------------------------
# 4. Compliance drift events — expand from 10 to 30
# ---------------------------------------------------------------------------

_DRIFT_EVENTS = [
    # (framework, control_id, prev_status, new_status, direction, days_ago, summary)
    (
        "nist_800_53",
        "AC-2",
        "compliant",
        "partial",
        "degraded",
        85,
        "IAM role permissions expanded without approval",
    ),
    (
        "nist_800_53",
        "AU-2",
        "partial",
        "compliant",
        "improved",
        80,
        "CloudTrail logging enabled across all regions",
    ),
    (
        "soc2",
        "CC6.1",
        "compliant",
        "non_compliant",
        "degraded",
        75,
        "MFA disabled for service accounts during migration",
    ),
    (
        "hipaa",
        "164.312(a)(1)",
        "partial",
        "compliant",
        "improved",
        72,
        "Access controls remediated after audit finding",
    ),
    (
        "iso_27001",
        "A.8.5",
        "compliant",
        "partial",
        "degraded",
        68,
        "Authentication bypass found in legacy API",
    ),
    (
        "nist_800_53",
        "SC-7",
        "partial",
        "compliant",
        "improved",
        63,
        "Network segmentation rules deployed to production",
    ),
    (
        "soc2",
        "CC7.2",
        "non_compliant",
        "partial",
        "improved",
        58,
        "Incident response playbooks updated and tested",
    ),
    (
        "hipaa",
        "164.312(e)(1)",
        "compliant",
        "partial",
        "degraded",
        52,
        "TLS 1.0 endpoint discovered in partner integration",
    ),
    (
        "nist_800_53",
        "IA-2",
        "partial",
        "compliant",
        "improved",
        47,
        "FIDO2 hardware keys rolled out to all admins",
    ),
    (
        "iso_27001",
        "A.8.9",
        "compliant",
        "partial",
        "degraded",
        42,
        "Configuration drift detected in firewall rules",
    ),
    (
        "soc2",
        "CC8.1",
        "partial",
        "compliant",
        "improved",
        38,
        "Change management process formalized with approval gates",
    ),
    (
        "hipaa",
        "164.312(d)",
        "non_compliant",
        "partial",
        "improved",
        33,
        "Person/entity authentication added to patient portal",
    ),
    (
        "nist_800_53",
        "AC-2",
        "partial",
        "compliant",
        "improved",
        28,
        "Automated account provisioning/deprovisioning deployed",
    ),
    (
        "nist_800_53",
        "AU-2",
        "compliant",
        "partial",
        "degraded",
        22,
        "Log retention policy reduced below 90-day requirement",
    ),
    (
        "soc2",
        "CC6.1",
        "non_compliant",
        "partial",
        "improved",
        18,
        "MFA re-enabled for all accounts post-migration",
    ),
    (
        "hipaa",
        "164.312(a)(1)",
        "compliant",
        "partial",
        "degraded",
        14,
        "Unauthorized access attempt from compromised credential",
    ),
    (
        "iso_27001",
        "A.8.5",
        "partial",
        "compliant",
        "improved",
        10,
        "Legacy API authentication bypass patched",
    ),
    (
        "nist_800_53",
        "SC-7",
        "compliant",
        "partial",
        "degraded",
        7,
        "New microservice deployed without network policy",
    ),
    (
        "soc2",
        "CC7.2",
        "partial",
        "compliant",
        "improved",
        4,
        "Tabletop exercise completed with updated runbook",
    ),
    (
        "hipaa",
        "164.312(e)(1)",
        "partial",
        "compliant",
        "improved",
        2,
        "TLS 1.0 endpoint decommissioned and verified",
    ),
]


def _seed_drift_events_90d(session: Session) -> int:
    """Create 20 additional ComplianceDrift events spread across 90 days."""
    existing = session.query(ComplianceDrift).count()
    if existing >= 30:
        return 0  # Already expanded

    random.seed(93)
    now = _utcnow()

    # Grab some change event IDs for correlation
    change_events = session.query(ChangeEvent).limit(20).all()
    ce_ids = [ce.id for ce in change_events]

    drifts: list[ComplianceDrift] = []
    for (
        framework,
        control_id,
        prev_status,
        new_status,
        direction,
        days_back,
        summary,
    ) in _DRIFT_EVENTS:
        prev_score = {"compliant": 85.0, "partial": 65.0, "non_compliant": 35.0}[prev_status]
        new_score = {"compliant": 85.0, "partial": 65.0, "non_compliant": 35.0}[new_status]

        # Correlate 1-3 change events if available
        correlated = random.sample(ce_ids, min(random.randint(1, 3), len(ce_ids))) if ce_ids else []

        drifts.append(
            ComplianceDrift(
                id=_uuid(),
                framework=framework,
                control_id=control_id,
                system_profile_id=None,
                previous_status=prev_status,
                new_status=new_status,
                drift_direction=direction,
                previous_posture_score=prev_score + random.uniform(-5, 5),
                new_posture_score=new_score + random.uniform(-5, 5),
                correlated_change_event_ids=correlated,
                root_cause_summary=summary,
                correlation_confidence=round(random.uniform(0.6, 0.95), 2),
                detected_at=now - timedelta(days=days_back),
                snapshot_id=None,
            )
        )

    session.add_all(drifts)
    session.flush()
    return len(drifts)


# ---------------------------------------------------------------------------
# 5. Change events — expand from 40 to 100
# ---------------------------------------------------------------------------

_CHANGE_EVENT_TEMPLATES: list[dict[str, Any]] = [
    # Infrastructure changes
    {
        "source": "cloudtrail",
        "source_type": "cloud_audit",
        "event_type": "iam_role_modified",
        "actor": "admin@acme.com",
        "action": "UpdateRole",
        "resource_type": "iam_role",
        "detail_template": {"change": "Added S3 full access policy"},
    },
    {
        "source": "cloudtrail",
        "source_type": "cloud_audit",
        "event_type": "security_group_modified",
        "actor": "devops@acme.com",
        "action": "AuthorizeSecurityGroupIngress",
        "resource_type": "security_group",
        "detail_template": {"port": 443, "cidr": "0.0.0.0/0"},
    },
    {
        "source": "cloudtrail",
        "source_type": "cloud_audit",
        "event_type": "firewall_rule_updated",
        "actor": "netops@acme.com",
        "action": "UpdateFirewallRule",
        "resource_type": "network_firewall",
        "detail_template": {"rule": "Allow inbound HTTPS from partner CIDR"},
    },
    {
        "source": "cloudtrail",
        "source_type": "cloud_audit",
        "event_type": "s3_bucket_policy_changed",
        "actor": "data-eng@acme.com",
        "action": "PutBucketPolicy",
        "resource_type": "s3_bucket",
        "detail_template": {"change": "Added cross-account access for analytics"},
    },
    {
        "source": "cloudtrail",
        "source_type": "cloud_audit",
        "event_type": "kms_key_rotated",
        "actor": "security@acme.com",
        "action": "RotateKey",
        "resource_type": "kms_key",
        "detail_template": {"rotation": "annual", "algorithm": "AES-256"},
    },
    # Code changes
    {
        "source": "github",
        "source_type": "ci_cd",
        "event_type": "pull_request_merged",
        "actor": "dev1@acme.com",
        "action": "MergePullRequest",
        "resource_type": "repository",
        "detail_template": {"repo": "acme/platform", "pr": 1234},
    },
    {
        "source": "github",
        "source_type": "ci_cd",
        "event_type": "dependency_update",
        "actor": "dependabot[bot]",
        "action": "UpdateDependency",
        "resource_type": "repository",
        "detail_template": {"package": "cryptography", "from": "41.0.0", "to": "42.0.1"},
    },
    {
        "source": "github",
        "source_type": "ci_cd",
        "event_type": "branch_protection_changed",
        "actor": "admin@acme.com",
        "action": "UpdateBranchProtection",
        "resource_type": "repository",
        "detail_template": {"branch": "main", "required_reviews": 2},
    },
    {
        "source": "github",
        "source_type": "ci_cd",
        "event_type": "secret_scanning_alert",
        "actor": "github-actions[bot]",
        "action": "CreateAlert",
        "resource_type": "repository",
        "detail_template": {"type": "aws_access_key", "status": "open"},
    },
    # Config changes
    {
        "source": "cloudtrail",
        "source_type": "cloud_audit",
        "event_type": "dns_record_updated",
        "actor": "platform@acme.com",
        "action": "ChangeResourceRecordSets",
        "resource_type": "route53_record",
        "detail_template": {"record": "api.acme.com", "type": "CNAME"},
    },
    {
        "source": "cloudtrail",
        "source_type": "cloud_audit",
        "event_type": "ssl_cert_renewed",
        "actor": "certbot@acme.com",
        "action": "ImportCertificate",
        "resource_type": "acm_certificate",
        "detail_template": {"domain": "*.acme.com", "expiry": "2027-03-25"},
    },
    {
        "source": "terraform",
        "source_type": "iac",
        "event_type": "infrastructure_plan_applied",
        "actor": "ci-pipeline@acme.com",
        "action": "ApplyPlan",
        "resource_type": "terraform_state",
        "detail_template": {"resources_changed": 12, "workspace": "production"},
    },
    # Personnel changes
    {
        "source": "okta",
        "source_type": "iam",
        "event_type": "user_onboarded",
        "actor": "hr@acme.com",
        "action": "CreateUser",
        "resource_type": "okta_user",
        "detail_template": {"department": "Engineering", "role": "developer"},
    },
    {
        "source": "okta",
        "source_type": "iam",
        "event_type": "user_offboarded",
        "actor": "hr@acme.com",
        "action": "DeactivateUser",
        "resource_type": "okta_user",
        "detail_template": {"department": "Sales", "reason": "voluntary_departure"},
    },
    {
        "source": "okta",
        "source_type": "iam",
        "event_type": "role_changed",
        "actor": "hr@acme.com",
        "action": "UpdateUserProfile",
        "resource_type": "okta_user",
        "detail_template": {"from_role": "developer", "to_role": "tech_lead"},
    },
]

# Realistic resource IDs per type
_RESOURCE_IDS = {
    "iam_role": [f"arn:aws:iam::123456789012:role/svc-role-{i}" for i in range(10)],
    "security_group": [f"sg-0abc{i:04d}def" for i in range(10)],
    "network_firewall": [f"fw-prod-{i:02d}" for i in range(5)],
    "s3_bucket": [
        f"acme-data-{suf}" for suf in ("raw", "processed", "analytics", "backup", "logs")
    ],
    "kms_key": [f"arn:aws:kms:us-east-1:123456789012:key/key-{i}" for i in range(3)],
    "repository": ["acme/platform", "acme/api", "acme/infra", "acme/frontend"],
    "route53_record": ["api.acme.com", "app.acme.com", "admin.acme.com"],
    "acm_certificate": ["arn:aws:acm:us-east-1:123456789012:certificate/cert-001"],
    "terraform_state": ["s3://acme-tfstate/production/terraform.tfstate"],
    "okta_user": [f"user-{i:04d}@acme.com" for i in range(20)],
}


def _seed_change_events_90d(session: Session) -> int:
    """Create 60 additional ChangeEvent records spread across 90 days."""
    existing = session.query(ChangeEvent).count()
    if existing >= 100:
        return 0  # Already expanded

    random.seed(94)
    now = _utcnow()
    events: list[ChangeEvent] = []

    for i in range(60):
        template = random.choice(_CHANGE_EVENT_TEMPLATES)
        days_back = random.randint(1, 89)
        occurred_at = now - timedelta(
            days=days_back,
            hours=random.randint(6, 22),
            minutes=random.randint(0, 59),
        )

        resource_type = template["resource_type"]
        resource_ids = _RESOURCE_IDS.get(resource_type, [f"{resource_type}-{i}"])
        resource_id = random.choice(resource_ids)

        detail = dict(template["detail_template"])
        detail["event_index"] = i

        data_for_hash = {
            "source": template["source"],
            "event_type": template["event_type"],
            "resource_id": resource_id,
            "occurred_at": str(occurred_at),
            "index": i,
        }

        events.append(
            ChangeEvent(
                id=_uuid(),
                source=template["source"],
                source_type=template["source_type"],
                event_type=template["event_type"],
                actor=template["actor"],
                action=template["action"],
                resource_id=resource_id,
                resource_type=resource_type,
                detail=detail,
                occurred_at=occurred_at,
                ingested_at=occurred_at + timedelta(seconds=random.randint(5, 300)),
                sha256=_sha256(data_for_hash),
            )
        )

    session.add_all(events)
    session.flush()
    return len(events)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def seed_phase3(session: Session) -> dict[str, int]:
    """Create 90 days of historical data for time-series commands.

    Args:
        session: Active SQLAlchemy session with schema already created
            and main seed data committed.

    Returns:
        Dict mapping entity name to count of records created/updated.
    """
    results: dict[str, int] = {}

    results["posture_snapshots"] = _seed_posture_snapshots_90d(session)
    results["pipeline_runs"] = _seed_pipeline_runs_90d(session)
    results["findings_backdated"] = _backdate_findings_90d(session)
    results["compliance_drifts"] = _seed_drift_events_90d(session)
    results["change_events"] = _seed_change_events_90d(session)

    session.commit()
    return results
