"""Audit management workflows: sampling, workpapers, continuous auditing, evidence validity, certification packages.

AUD-2:  Workpaper management with sign-off workflow
AUD-5:  Continuous auditing (scheduled tests, drift detection)
AUD-6:  Statistical sampling methodology
AUD-9:  Evidence validity rules (freshness, type requirements)
AUD-10: Certification package assembly
"""

from __future__ import annotations

import logging
import math
import random
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import (
    AuditEngagement,
    ControlResult,
    Finding,
)
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# Z-scores for common confidence levels
_Z_SCORES: dict[float, float] = {
    0.90: 1.645,
    0.95: 1.960,
    0.99: 2.576,
}

# Valid workpaper statuses and transitions
_WORKPAPER_STATUSES = ("draft", "reviewed", "signed_off")
_WORKPAPER_TEMPLATES = ("test_of_design", "test_of_effectiveness", "walkthrough")


class AuditManager:
    """Encapsulates audit workflow operations: sampling, workpapers, continuous tests,
    evidence validity checks, and certification package assembly."""

    # ------------------------------------------------------------------
    # AUD-6: Statistical sampling
    # ------------------------------------------------------------------

    def select_sample(
        self,
        session: Session,
        engagement_id: str,
        confidence_level: float = 0.95,
        margin_error: float = 0.05,
        seed: int | None = 42,
    ) -> dict:
        """Calculate a statistically significant sample from the control population
        and return selected control IDs.

        Uses the formula: n = (Z^2 * p * (1-p)) / E^2
        where Z = z-score for confidence level, p = 0.5 (max variance), E = margin of error.

        For finite populations, applies finite population correction:
        n_adj = n / (1 + (n - 1) / N)

        Args:
            session: SQLAlchemy session.
            engagement_id: Engagement to sample from.
            confidence_level: Confidence level (0.90, 0.95, or 0.99).
            margin_error: Acceptable margin of error (e.g. 0.05 = 5%).
            seed: Random seed for reproducibility.

        Returns:
            Dict with keys: engagement_id, population_size, sample_size,
            confidence_level, margin_error, selected_control_ids.
        """
        eng = session.query(AuditEngagement).filter(AuditEngagement.id == engagement_id).first()
        if not eng:
            raise ValueError(f"Engagement not found: {engagement_id}")

        # Get the control population for this engagement's framework
        controls_q = (
            session.query(ControlResult.control_id)
            .filter(ControlResult.framework == eng.framework)
            .distinct()
        )

        # Respect engagement scoping
        in_scope = eng.in_scope_controls or []
        excluded = eng.excluded_controls or []
        if in_scope:
            controls_q = controls_q.filter(ControlResult.control_id.in_(in_scope))
        if excluded:
            controls_q = controls_q.filter(~ControlResult.control_id.in_(excluded))

        all_control_ids = sorted({row[0] for row in controls_q.all()})
        population_size = len(all_control_ids)

        if population_size == 0:
            return {
                "engagement_id": engagement_id,
                "population_size": 0,
                "sample_size": 0,
                "confidence_level": confidence_level,
                "margin_error": margin_error,
                "selected_control_ids": [],
            }

        # Look up Z-score (default to 0.95 if not in table)
        z = _Z_SCORES.get(confidence_level)
        if z is None:
            # Fall back to closest known level
            closest = min(_Z_SCORES.keys(), key=lambda k: abs(k - confidence_level))
            z = _Z_SCORES[closest]
            log.warning(
                "Confidence level %.2f not in Z-score table; using %.2f (Z=%.3f)",
                confidence_level,
                closest,
                z,
            )

        # Sample size formula: n = (Z^2 * p * (1-p)) / E^2
        p = 0.5  # maximum variance assumption
        n_infinite = (z**2 * p * (1 - p)) / (margin_error**2)

        # Finite population correction
        n_adjusted = n_infinite / (1 + (n_infinite - 1) / population_size)
        sample_size = min(math.ceil(n_adjusted), population_size)

        # Deterministic random selection
        rng = random.Random(seed)
        selected = sorted(rng.sample(all_control_ids, sample_size))

        return {
            "engagement_id": engagement_id,
            "population_size": population_size,
            "sample_size": sample_size,
            "confidence_level": confidence_level,
            "margin_error": margin_error,
            "selected_control_ids": selected,
        }

    # ------------------------------------------------------------------
    # AUD-2: Workpaper management
    # ------------------------------------------------------------------

    def create_workpaper(
        self,
        session: Session,
        engagement_id: str,
        control_id: str,
        template_type: str,
        reviewer: str,
        actor: str = "cli@warlock",
    ) -> dict:
        """Create a structured workpaper for a control within an engagement.

        Args:
            session: SQLAlchemy session.
            engagement_id: Parent engagement ID.
            control_id: Control this workpaper covers.
            template_type: One of test_of_design, test_of_effectiveness, walkthrough.
            reviewer: Assigned reviewer identity.
            actor: Actor for audit trail.

        Returns:
            Workpaper dict with id, status, template, and metadata.
        """
        if template_type not in _WORKPAPER_TEMPLATES:
            raise ValueError(
                f"Invalid template_type '{template_type}'. "
                f"Must be one of: {', '.join(_WORKPAPER_TEMPLATES)}"
            )

        eng = session.query(AuditEngagement).filter(AuditEngagement.id == engagement_id).first()
        if not eng:
            raise ValueError(f"Engagement not found: {engagement_id}")

        workpaper_id = str(uuid4())
        now = datetime.now(timezone.utc)

        workpaper = {
            "id": workpaper_id,
            "engagement_id": engagement_id,
            "framework": eng.framework,
            "control_id": control_id,
            "template_type": template_type,
            "status": "draft",
            "reviewer": reviewer,
            "notes": "",
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "review_history": [],
        }

        # Record in audit trail
        audit = AuditTrail(session)
        audit.record(
            action="workpaper_created",
            entity_type="workpaper",
            entity_id=workpaper_id,
            actor=actor,
            metadata={
                "engagement_id": engagement_id,
                "control_id": control_id,
                "template_type": template_type,
                "reviewer": reviewer,
            },
        )

        log.info(
            "Workpaper %s created for control %s in engagement %s",
            workpaper_id[:8],
            control_id,
            engagement_id[:8],
        )
        return workpaper

    def review_workpaper(
        self,
        session: Session,
        workpaper_id: str,
        reviewer: str,
        status: str,
        notes: str = "",
        actor: str = "cli@warlock",
    ) -> dict:
        """Record a review or sign-off on a workpaper.

        Args:
            session: SQLAlchemy session.
            workpaper_id: Workpaper to review.
            reviewer: Person performing the review.
            status: Target status (reviewed or signed_off).
            notes: Review notes.
            actor: Actor for audit trail.

        Returns:
            Review record dict.
        """
        if status not in ("reviewed", "signed_off"):
            raise ValueError(
                f"Invalid review status '{status}'. Must be 'reviewed' or 'signed_off'."
            )

        now = datetime.now(timezone.utc)
        review_record = {
            "workpaper_id": workpaper_id,
            "reviewer": reviewer,
            "status": status,
            "notes": notes,
            "reviewed_at": now.isoformat(),
        }

        # Record in audit trail
        audit = AuditTrail(session)
        audit.record(
            action=f"workpaper_{status}",
            entity_type="workpaper",
            entity_id=workpaper_id,
            actor=actor,
            metadata={
                "reviewer": reviewer,
                "status": status,
                "notes": notes,
            },
        )

        log.info(
            "Workpaper %s %s by %s",
            workpaper_id[:8],
            status,
            reviewer,
        )
        return review_record

    # ------------------------------------------------------------------
    # AUD-5: Continuous auditing
    # ------------------------------------------------------------------

    def schedule_continuous_test(
        self,
        session: Session,
        engagement_id: str,
        frequency_days: int,
        test_type: str,
    ) -> dict:
        """Define an automated test schedule between formal audits.

        Args:
            session: SQLAlchemy session.
            engagement_id: Engagement to attach the schedule to.
            frequency_days: How often to run (e.g. 7 = weekly, 30 = monthly).
            test_type: Type of test (drift_detection, evidence_freshness, control_status).

        Returns:
            Schedule definition dict.
        """
        valid_test_types = ("drift_detection", "evidence_freshness", "control_status")
        if test_type not in valid_test_types:
            raise ValueError(
                f"Invalid test_type '{test_type}'. Must be one of: {', '.join(valid_test_types)}"
            )

        eng = session.query(AuditEngagement).filter(AuditEngagement.id == engagement_id).first()
        if not eng:
            raise ValueError(f"Engagement not found: {engagement_id}")

        schedule_id = str(uuid4())
        now = datetime.now(timezone.utc)

        schedule = {
            "id": schedule_id,
            "engagement_id": engagement_id,
            "framework": eng.framework,
            "frequency_days": frequency_days,
            "test_type": test_type,
            "created_at": now.isoformat(),
            "last_run": None,
            "next_run": now.isoformat(),
            "enabled": True,
        }

        log.info(
            "Continuous test scheduled: %s every %d days for engagement %s",
            test_type,
            frequency_days,
            engagement_id[:8],
        )
        return schedule

    def run_continuous_tests(
        self,
        session: Session,
        engagement_id: str,
    ) -> dict:
        """Execute continuous tests for an engagement: check for drift and stale evidence.

        Scans control results in the engagement's framework for:
        - Status drift: controls that changed status since last assessment
        - Evidence staleness: controls not reassessed recently

        Args:
            session: SQLAlchemy session.
            engagement_id: Engagement to test.

        Returns:
            Dict with drift_detected (list), stale_controls (list), summary.
        """
        eng = session.query(AuditEngagement).filter(AuditEngagement.id == engagement_id).first()
        if not eng:
            raise ValueError(f"Engagement not found: {engagement_id}")

        now = datetime.now(timezone.utc)

        # Get all control results for this framework within the engagement period
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == eng.framework,
                ControlResult.assessed_at >= eng.period_start,
            )
            .order_by(ControlResult.control_id, ControlResult.assessed_at.desc())
            .all()
        )

        # Group by control_id, detect drift (multiple statuses) and staleness
        controls: dict[str, list[ControlResult]] = {}
        for r in results:
            controls.setdefault(r.control_id, []).append(r)

        drift_detected: list[dict] = []
        stale_controls: list[dict] = []
        stale_threshold_days = 30

        for ctrl_id, ctrl_results in controls.items():
            # Drift: check if status changed across assessments
            statuses = list(dict.fromkeys(r.status for r in ctrl_results))
            if len(statuses) > 1:
                drift_detected.append(
                    {
                        "control_id": ctrl_id,
                        "statuses": statuses,
                        "assessment_count": len(ctrl_results),
                    }
                )

            # Staleness: check latest assessment age
            latest = ctrl_results[0]
            latest_at = ensure_aware(latest.assessed_at)
            if latest_at is not None:
                age_days = (now - latest_at).days
                if age_days > stale_threshold_days:
                    stale_controls.append(
                        {
                            "control_id": ctrl_id,
                            "last_assessed": latest_at.isoformat(),
                            "age_days": age_days,
                            "status": latest.status,
                        }
                    )

        return {
            "engagement_id": engagement_id,
            "framework": eng.framework,
            "controls_checked": len(controls),
            "drift_detected": drift_detected,
            "stale_controls": stale_controls,
            "summary": {
                "drift_count": len(drift_detected),
                "stale_count": len(stale_controls),
                "healthy_count": len(controls) - len(drift_detected) - len(stale_controls),
            },
        }

    # ------------------------------------------------------------------
    # AUD-9: Evidence validity rules
    # ------------------------------------------------------------------

    def define_validity_rules(
        self,
        session: Session,
        framework: str,
        control_id: str,
        max_age_days: int = 90,
        required_types: list[str] | None = None,
    ) -> dict:
        """Define evidence freshness and type requirements for a control.

        Args:
            session: SQLAlchemy session (for future persistence).
            framework: Framework ID (e.g. 'soc2').
            control_id: Control ID (e.g. 'CC6.1').
            max_age_days: Maximum acceptable evidence age in days.
            required_types: List of required evidence types (e.g. ['configuration', 'scan']).

        Returns:
            Rule definition dict.
        """
        rule_id = str(uuid4())
        rule = {
            "id": rule_id,
            "framework": framework,
            "control_id": control_id,
            "max_age_days": max_age_days,
            "required_types": required_types or [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        log.info(
            "Evidence validity rule defined: %s/%s max_age=%d days, required_types=%s",
            framework,
            control_id,
            max_age_days,
            required_types or [],
        )
        return rule

    def check_evidence_validity(
        self,
        session: Session,
        engagement_id: str,
        max_age_days: int = 90,
    ) -> dict:
        """Scan evidence for an engagement and flag stale or missing items.

        Checks each control in the engagement's framework for:
        - Stale evidence: findings older than max_age_days
        - Missing evidence: controls with no findings at all

        Args:
            session: SQLAlchemy session.
            engagement_id: Engagement to check.
            max_age_days: Default maximum evidence age.

        Returns:
            Dict with stale (list), missing (list), valid (list), summary.
        """
        eng = session.query(AuditEngagement).filter(AuditEngagement.id == engagement_id).first()
        if not eng:
            raise ValueError(f"Engagement not found: {engagement_id}")

        now = datetime.now(timezone.utc)

        # Get all controls that have results in this framework
        control_results = (
            session.query(
                ControlResult.control_id,
                ControlResult.assessed_at,
                ControlResult.status,
                ControlResult.evidence_ids,
            )
            .filter(ControlResult.framework == eng.framework)
            .order_by(ControlResult.control_id, ControlResult.assessed_at.desc())
            .all()
        )

        # Get all controls expected from engagement scope
        in_scope = eng.in_scope_controls or []

        # If no explicit scope, get all distinct controls from results
        if in_scope:
            expected_controls = set(in_scope)
        else:
            # Fall back to all controls that have any result
            expected_controls = {r[0] for r in control_results}

        excluded = set(eng.excluded_controls or [])
        expected_controls -= excluded

        # Build latest assessment per control
        latest_per_control: dict[str, tuple] = {}
        for ctrl_id, assessed_at, status, evidence_ids in control_results:
            if ctrl_id not in latest_per_control:
                latest_per_control[ctrl_id] = (assessed_at, status, evidence_ids)

        stale: list[dict] = []
        missing: list[dict] = []
        valid: list[dict] = []

        for ctrl_id in sorted(expected_controls):
            if ctrl_id not in latest_per_control:
                missing.append(
                    {
                        "control_id": ctrl_id,
                        "reason": "no_evidence",
                    }
                )
                continue

            assessed_at, status, evidence_ids = latest_per_control[ctrl_id]
            assessed_aware = ensure_aware(assessed_at)
            age_days = (now - assessed_aware).days if assessed_aware else 999

            if age_days > max_age_days:
                stale.append(
                    {
                        "control_id": ctrl_id,
                        "last_assessed": assessed_aware.isoformat()
                        if assessed_aware
                        else "unknown",
                        "age_days": age_days,
                        "status": status,
                    }
                )
            else:
                valid.append(
                    {
                        "control_id": ctrl_id,
                        "last_assessed": assessed_aware.isoformat()
                        if assessed_aware
                        else "unknown",
                        "age_days": age_days,
                        "status": status,
                    }
                )

        return {
            "engagement_id": engagement_id,
            "framework": eng.framework,
            "max_age_days": max_age_days,
            "stale": stale,
            "missing": missing,
            "valid": valid,
            "summary": {
                "total_controls": len(expected_controls),
                "valid_count": len(valid),
                "stale_count": len(stale),
                "missing_count": len(missing),
            },
        }

    # ------------------------------------------------------------------
    # AUD-10: Certification package assembly
    # ------------------------------------------------------------------

    def assemble_package(
        self,
        session: Session,
        engagement_id: str,
    ) -> dict:
        """Gather all evidence, workpapers, test results, and attestations into
        a structured certification package.

        Args:
            session: SQLAlchemy session.
            engagement_id: Engagement to package.

        Returns:
            Package dict with sections: engagement, control_results, findings,
            evidence_validity, audit_trail_summary.
        """
        eng = session.query(AuditEngagement).filter(AuditEngagement.id == engagement_id).first()
        if not eng:
            raise ValueError(f"Engagement not found: {engagement_id}")

        now = datetime.now(timezone.utc)

        # Collect control results for the framework within period
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == eng.framework,
                ControlResult.assessed_at >= eng.period_start,
            )
            .order_by(ControlResult.control_id)
            .all()
        )

        # Summarize by status
        status_counts: dict[str, int] = {}
        control_details: list[dict] = []
        for r in results:
            status_counts[r.status] = status_counts.get(r.status, 0) + 1
            control_details.append(
                {
                    "control_id": r.control_id,
                    "status": r.status,
                    "severity": r.severity,
                    "assessed_at": ensure_aware(r.assessed_at).isoformat()
                    if r.assessed_at
                    else None,
                    "assessor": r.assessor,
                    "assertion_name": r.assertion_name,
                    "evidence_ids": r.evidence_ids or [],
                }
            )

        # Collect unique findings linked to these results
        finding_ids = set()
        for r in results:
            if r.finding_id:
                finding_ids.add(r.finding_id)

        findings_summary: list[dict] = []
        if finding_ids:
            findings = session.query(Finding).filter(Finding.id.in_(list(finding_ids)[:500])).all()
            for f in findings:
                findings_summary.append(
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity,
                        "observation_type": f.observation_type,
                        "source": f.source,
                    }
                )

        # Evidence validity check
        validity = self.check_evidence_validity(session, engagement_id)

        # Audit trail entries for this engagement
        from warlock.db.models import AuditEntry

        audit_entries = (
            session.query(AuditEntry)
            .filter(AuditEntry.entity_id == engagement_id)
            .order_by(AuditEntry.sequence.desc())
            .limit(100)
            .all()
        )
        trail_summary = [
            {
                "sequence": e.sequence,
                "action": e.action,
                "actor": e.actor,
                "created_at": ensure_aware(e.created_at).isoformat() if e.created_at else None,
            }
            for e in audit_entries
        ]

        # Verify chain integrity
        audit = AuditTrail(session)
        chain_valid, chain_errors = audit.verify_chain()

        package = {
            "package_id": str(uuid4()),
            "assembled_at": now.isoformat(),
            "engagement": {
                "id": eng.id,
                "name": eng.name,
                "framework": eng.framework,
                "status": eng.status,
                "period_start": ensure_aware(eng.period_start).isoformat()
                if eng.period_start
                else None,
                "period_end": ensure_aware(eng.period_end).isoformat() if eng.period_end else None,
                "auditor_name": eng.auditor_name,
                "auditor_firm": eng.auditor_firm,
            },
            "control_results": {
                "total": len(results),
                "by_status": status_counts,
                "details": control_details,
            },
            "findings": {
                "total": len(findings_summary),
                "details": findings_summary,
            },
            "evidence_validity": validity["summary"],
            "audit_trail": {
                "entries": len(trail_summary),
                "chain_valid": chain_valid,
                "chain_errors": chain_errors[:10] if chain_errors else [],
                "recent_entries": trail_summary[:20],
            },
        }

        log.info(
            "Certification package assembled for engagement %s: %d results, %d findings",
            engagement_id[:8],
            len(results),
            len(findings_summary),
        )
        return package
