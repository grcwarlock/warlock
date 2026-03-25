"""Phase 3: Time depth — expand history to 90 days."""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

NOW = datetime.now(timezone.utc)


def seed_phase3(session) -> dict:
    """Expand time-series data to 90 days for trends and history."""
    from warlock.db.models import (
        ChangeEvent,
        ComplianceDrift,
        Finding,
        PipelineRun,
        PostureSnapshot,
    )
    from sqlalchemy import func

    counts: dict[str, int] = {}

    # --- 3.1: Posture snapshots (90 days, if not already present) ---
    existing_snaps = session.query(PostureSnapshot).count()
    if existing_snaps < 100:
        # Get distinct framework/control pairs from existing results
        from warlock.db.models import ControlResult

        pairs = (
            session.query(ControlResult.framework, ControlResult.control_id)
            .group_by(ControlResult.framework, ControlResult.control_id)
            .limit(16)  # 16 representative controls
            .all()
        )

        snap_count = 0
        for day_offset in range(90):
            snap_date = NOW - timedelta(days=day_offset)
            for fw, ctrl in pairs:
                # Simulate gradual improvement with noise
                base_score = 0.3 + (day_offset / 90) * 0.1  # starts low, improves
                noise = random.uniform(-0.05, 0.05)
                score = max(0.1, min(1.0, base_score + noise))

                session.add(
                    PostureSnapshot(
                        id=str(uuid.uuid4()),
                        framework=fw,
                        control_id=ctrl,
                        snapshot_date=snap_date,
                        status="compliant" if score > 0.5 else "non_compliant",
                        posture_score=round(score, 3),
                        sufficiency_score=round(score * 0.9, 3),
                        evidence_sources=["tenable", "aws", "okta"][:random.randint(1, 3)],
                        evidence_freshness_hours=random.uniform(2, 72),
                        uptime_pct=round(random.uniform(85, 100), 1),
                        mttr_hours=round(random.uniform(1, 48), 1),
                        drift_count=random.randint(0, 3),
                    )
                )
                snap_count += 1

        counts["posture_snapshots"] = snap_count
    else:
        counts["posture_snapshots"] = 0

    # --- 3.2: Pipeline runs (90 days, if not already present) ---
    existing_runs = session.query(PipelineRun).count()
    if existing_runs < 30:
        run_count = 0
        for day_offset in range(90):
            run_date = NOW - timedelta(days=day_offset, hours=random.randint(0, 6))
            duration = random.randint(25, 120)
            status = "success" if random.random() > 0.03 else "failed"
            base_findings = 5400 + day_offset * 2
            session.add(
                PipelineRun(
                    id=str(uuid.uuid4()),
                    status=status,
                    started_at=run_date,
                    completed_at=run_date + timedelta(seconds=duration),
                    duration_seconds=duration,
                    raw_event_count=580 + random.randint(-10, 10),
                    finding_count=base_findings + random.randint(-50, 50),
                    control_result_count=370000 + random.randint(-5000, 5000),
                    connector_count=165,
                    error_count=0 if status == "success" else random.randint(1, 3),
                )
            )
            run_count += 1
        counts["pipeline_runs"] = run_count
    else:
        counts["pipeline_runs"] = 0

    # --- 3.3: Backdate findings across 90 days ---
    # Check if findings are already spread out
    f_min = session.query(func.min(Finding.observed_at)).scalar()
    f_max = session.query(func.max(Finding.observed_at)).scalar()
    if f_min and f_max:
        spread_days = (f_max - f_min).days
    else:
        spread_days = 0

    if spread_days < 30:
        # Spread findings across 90 days
        findings = session.query(Finding).all()
        total = len(findings)
        for i, finding in enumerate(findings):
            # Distribute: recent findings more common
            # Use exponential distribution biased toward recent
            pct = i / total
            if pct < 0.04:
                days_ago = random.randint(60, 90)
            elif pct < 0.13:
                days_ago = random.randint(30, 60)
            elif pct < 0.33:
                days_ago = random.randint(7, 30)
            else:
                days_ago = random.randint(0, 7)

            finding.observed_at = NOW - timedelta(
                days=days_ago,
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
            )
        counts["findings_backdated"] = total
    else:
        counts["findings_backdated"] = 0

    # --- 3.4: Compliance drift and change events ---
    existing_drift = session.query(ComplianceDrift).count()
    if existing_drift < 10:
        frameworks = ["nist_800_53", "soc2", "hipaa", "pci_dss", "iso_27001", "cmmc_l2"]
        controls = ["AC-2", "SC-7", "SI-4", "AU-2", "IA-2", "CM-7", "CC6.1", "CC7.2", "164.312(b)"]
        drift_count = 0
        for _ in range(20):
            fw = random.choice(frameworks)
            ctrl = random.choice(controls)
            direction = random.choice(["DEGRADED", "IMPROVED"])
            if direction == "DEGRADED":
                prev, new = "compliant", "non_compliant"
            else:
                prev, new = "non_compliant", "compliant"

            session.add(
                ComplianceDrift(
                    id=str(uuid.uuid4()),
                    framework=fw,
                    control_id=ctrl,
                    drift_direction=direction,
                    previous_status=prev,
                    new_status=new,
                    detected_at=NOW - timedelta(days=random.randint(1, 90)),
                    correlated_change_event_ids=[],
                )
            )
            drift_count += 1
        counts["compliance_drifts"] = drift_count
    else:
        counts["compliance_drifts"] = 0

    existing_changes = session.query(ChangeEvent).count()
    if existing_changes < 30:
        change_types = [
            ("infrastructure", "IAM role trust policy modified"),
            ("infrastructure", "Security group ingress rule added"),
            ("infrastructure", "S3 bucket policy updated"),
            ("infrastructure", "VPC peering connection created"),
            ("code", "PR merged: update authentication middleware"),
            ("code", "PR merged: disable TLS 1.0 support"),
            ("code", "Dependency update: openssl 3.1.0 -> 3.2.1"),
            ("config", "Firewall rule modified: allow port 8443"),
            ("config", "DNS record changed: api.acme.com"),
            ("vendor", "New vendor onboarded: DataDog"),
            ("vendor", "Vendor contract renewed: CrowdStrike"),
            ("personnel", "New hire: SOC analyst"),
        ]
        ce_count = 0
        for _ in range(60):
            ct, desc = random.choice(change_types)
            session.add(
                ChangeEvent(
                    id=str(uuid.uuid4()),
                    change_type=ct,
                    description=desc,
                    source=random.choice(["cloudtrail", "github", "servicenow", "manual"]),
                    detected_at=NOW - timedelta(days=random.randint(1, 90)),
                    risk_level=random.choice(["low", "medium", "high"]),
                )
            )
            ce_count += 1
        counts["change_events"] = ce_count
    else:
        counts["change_events"] = 0

    session.commit()
    return counts
