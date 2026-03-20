"""Control posture aggregation and evidence sufficiency scoring.

Aggregates individual ControlResult rows into per-control posture scores.
Evaluates whether collected evidence is sufficient for an audit.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import distinct
from sqlalchemy.orm import Session

from warlock.db.models import (
    AuditEngagement,
    ControlResult,
    Finding,
    PostureSnapshot,
)
from datetime import timedelta

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ControlPosture:
    framework: str
    control_id: str
    status: str
    posture_score: float
    total_findings: int
    compliant_count: int
    non_compliant_count: int
    partial_count: int
    not_assessed_count: int
    evidence_sources: list[str]
    evidence_freshness_hours: float | None
    oldest_evidence_hours: float | None = None
    assessed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SufficiencyScore:
    framework: str
    control_id: str
    score: float  # 0-100
    evidence_volume: float
    evidence_freshness: float
    evidence_diversity: float
    assertion_coverage: float
    gaps: list[str]


@dataclass
class FrameworkSufficiency:
    framework: str
    overall_score: float
    control_scores: list[SufficiencyScore]
    controls_scored: int
    controls_sufficient: int  # score >= 60
    controls_insufficient: int
    common_gaps: list[str]


@dataclass
class EngagementSufficiency:
    engagement_id: str
    engagement_name: str
    framework: str
    period_start: datetime
    period_end: datetime
    overall_score: float
    control_scores: list[SufficiencyScore]
    controls_in_scope: int
    controls_sufficient: int
    controls_insufficient: int
    common_gaps: list[str]


# ---------------------------------------------------------------------------
# Severity weights for posture scoring
#
# Rationale: Weights follow CVSS severity tiers (Critical > High > Medium >
# Low > Informational) with a 5:1 ratio between critical and info. This
# ensures a single critical non-compliance outweighs five informational
# findings in the posture score. The 50% weight for "partial" compliance
# reflects that partial implementations provide some risk reduction.
#
# These weights are used by PostureAggregator.aggregate_control() to compute
# a weighted compliance percentage (0-100). A posture score of 100 means all
# assessed controls are fully compliant weighted by severity.
#
# To customize: override via framework-specific config or system profile
# settings in a future release. Current values are aligned with common
# GRC scoring methodologies (NIST CSF, CIS RAM).
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 5.0,
    "high": 4.0,
    "medium": 3.0,
    "low": 2.0,
    "info": 1.0,
}


def _severity_weight(severity: str) -> float:
    return _SEVERITY_WEIGHTS.get(severity.lower().strip(), 1.0)


# ---------------------------------------------------------------------------
# PostureAggregator
# ---------------------------------------------------------------------------


class PostureAggregator:
    """Aggregates ControlResult rows into per-control posture scores."""

    def aggregate_control(
        self,
        session: Session,
        framework: str,
        control_id: str,
    ) -> ControlPosture:
        """Query all ControlResults for a control, compute posture.

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier (e.g. "soc2", "nist_800_53").
            control_id: Control identifier (e.g. "CC6.1", "AC-2").

        Returns:
            ControlPosture with aggregated metrics.
        """
        results: list[ControlResult] = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.control_id == control_id,
            )
            .all()
        )

        if not results:
            return ControlPosture(
                framework=framework,
                control_id=control_id,
                status="not_assessed",
                posture_score=0.0,
                total_findings=0,
                compliant_count=0,
                non_compliant_count=0,
                partial_count=0,
                not_assessed_count=0,
                evidence_sources=[],
                evidence_freshness_hours=None,
                oldest_evidence_hours=None,
            )

        # Count statuses
        compliant = 0
        non_compliant = 0
        partial = 0
        not_assessed = 0
        weighted_compliant = 0.0
        weighted_total = 0.0

        for r in results:
            weight = _severity_weight(r.severity)
            weighted_total += weight
            if r.status == "compliant":
                compliant += 1
                weighted_compliant += weight
            elif r.status == "non_compliant":
                non_compliant += 1
            elif r.status == "partial":
                partial += 1
                weighted_compliant += weight * 0.5
            elif r.status == "not_assessed":
                not_assessed += 1
            # not_applicable is excluded from scoring

        # Posture score: weighted % compliant (0-100)
        posture_score = (
            round((weighted_compliant / weighted_total) * 100, 2) if weighted_total > 0 else 0.0
        )

        # Worst-case rollup for status
        if non_compliant > 0:
            status = "non_compliant"
        elif partial > 0:
            status = "partial"
        elif compliant > 0:
            status = "compliant"
        else:
            status = "not_assessed"

        # Evidence sources — unique providers from related findings
        finding_ids = [r.finding_id for r in results]
        sources: list[str] = []
        if finding_ids:
            provider_rows = (
                session.query(distinct(Finding.provider)).filter(Finding.id.in_(finding_ids)).all()
            )
            sources = sorted([row[0] for row in provider_rows if row[0]])

        # Evidence freshness — hours since newest and oldest evidence
        assessed_times = [r.assessed_at for r in results if r.assessed_at]
        now = datetime.now(timezone.utc)
        freshness_hours: float | None = None
        oldest_hours: float | None = None
        if assessed_times:
            newest = max(assessed_times)
            oldest = min(assessed_times)
            # Ensure timezone-aware comparison
            if newest.tzinfo is None:
                newest = newest.replace(tzinfo=timezone.utc)
            if oldest.tzinfo is None:
                oldest = oldest.replace(tzinfo=timezone.utc)
            freshness_hours = round((now - newest).total_seconds() / 3600, 2)
            oldest_hours = round((now - oldest).total_seconds() / 3600, 2)

        return ControlPosture(
            framework=framework,
            control_id=control_id,
            status=status,
            posture_score=posture_score,
            total_findings=len(results),
            compliant_count=compliant,
            non_compliant_count=non_compliant,
            partial_count=partial,
            not_assessed_count=not_assessed,
            evidence_sources=sources,
            evidence_freshness_hours=freshness_hours,
            oldest_evidence_hours=oldest_hours,
        )

    def aggregate_framework(
        self,
        session: Session,
        framework: str,
    ) -> list[ControlPosture]:
        """Aggregate all controls in a framework using batch queries."""
        # Single query: all results for this framework
        results: list[ControlResult] = (
            session.query(ControlResult).filter(ControlResult.framework == framework).all()
        )

        if not results:
            return []

        # Group by control_id
        by_control: dict[str, list[ControlResult]] = {}
        for r in results:
            by_control.setdefault(r.control_id, []).append(r)

        # Batch fetch provider diversity for all findings at once
        all_finding_ids = list({r.finding_id for r in results})
        provider_map: dict[str, set[str]] = {}  # finding_id -> set of providers
        if all_finding_ids:
            # Query in chunks to avoid SQLite variable limit
            chunk_size = 500
            for i in range(0, len(all_finding_ids), chunk_size):
                chunk = all_finding_ids[i : i + chunk_size]
                rows = (
                    session.query(Finding.id, Finding.provider).filter(Finding.id.in_(chunk)).all()
                )
                for fid, provider in rows:
                    if provider:
                        provider_map.setdefault(fid, set()).add(provider)

        # Compute posture per control
        now = datetime.now(timezone.utc)
        postures = []
        for control_id in sorted(by_control.keys()):
            ctrl_results = by_control[control_id]
            compliant = non_compliant = partial = not_assessed = 0
            weighted_compliant = 0.0
            weighted_total = 0.0

            for r in ctrl_results:
                weight = _severity_weight(r.severity)
                weighted_total += weight
                if r.status == "compliant":
                    compliant += 1
                    weighted_compliant += weight
                elif r.status == "non_compliant":
                    non_compliant += 1
                elif r.status == "partial":
                    partial += 1
                    weighted_compliant += weight * 0.5
                elif r.status == "not_assessed":
                    not_assessed += 1

            posture_score = (
                round((weighted_compliant / weighted_total) * 100, 2) if weighted_total > 0 else 0.0
            )

            if non_compliant > 0:
                status = "non_compliant"
            elif partial > 0:
                status = "partial"
            elif compliant > 0:
                status = "compliant"
            else:
                status = "not_assessed"

            # Evidence sources from batch map
            sources = set()
            for r in ctrl_results:
                if r.finding_id in provider_map:
                    sources.update(provider_map[r.finding_id])

            # Evidence freshness
            assessed_times = [r.assessed_at for r in ctrl_results if r.assessed_at]
            freshness_hours = None
            oldest_hours = None
            if assessed_times:
                newest = max(assessed_times)
                oldest = min(assessed_times)
                if newest.tzinfo is None:
                    newest = newest.replace(tzinfo=timezone.utc)
                if oldest.tzinfo is None:
                    oldest = oldest.replace(tzinfo=timezone.utc)
                freshness_hours = round((now - newest).total_seconds() / 3600, 2)
                oldest_hours = round((now - oldest).total_seconds() / 3600, 2)

            postures.append(
                ControlPosture(
                    framework=framework,
                    control_id=control_id,
                    status=status,
                    posture_score=posture_score,
                    total_findings=len(ctrl_results),
                    compliant_count=compliant,
                    non_compliant_count=non_compliant,
                    partial_count=partial,
                    not_assessed_count=not_assessed,
                    evidence_sources=sorted(sources),
                    evidence_freshness_hours=freshness_hours,
                    oldest_evidence_hours=oldest_hours,
                )
            )

        return postures

    def aggregate_all(
        self,
        session: Session,
    ) -> dict[str, list[ControlPosture]]:
        """Aggregate all frameworks.

        Returns:
            Dict mapping framework name to list of ControlPosture.
        """
        framework_rows = session.query(distinct(ControlResult.framework)).all()
        frameworks = sorted([row[0] for row in framework_rows])

        result: dict[str, list[ControlPosture]] = {}
        for fw in frameworks:
            result[fw] = self.aggregate_framework(session, fw)
        return result

    def take_snapshot(
        self,
        session: Session,
        framework: str | None = None,
    ) -> list[PostureSnapshot]:
        """Create PostureSnapshot rows from current aggregation.

        Args:
            session: SQLAlchemy session.
            framework: If set, only snapshot this framework. Otherwise all.

        Returns:
            List of created PostureSnapshot rows.
        """
        now = datetime.now(timezone.utc)
        scorer = EvidenceSufficiencyScorer()

        if framework:
            postures_by_fw = {framework: self.aggregate_framework(session, framework)}
        else:
            postures_by_fw = self.aggregate_all(session)

        snapshots: list[PostureSnapshot] = []
        for fw, postures in postures_by_fw.items():
            for posture in postures:
                # Compute sufficiency for the snapshot
                sufficiency = scorer.score_control(session, fw, posture.control_id)

                snapshot = PostureSnapshot(
                    snapshot_date=now,
                    framework=fw,
                    control_id=posture.control_id,
                    status=posture.status,
                    posture_score=posture.posture_score,
                    total_findings=posture.total_findings,
                    compliant_findings=posture.compliant_count,
                    non_compliant_findings=posture.non_compliant_count,
                    partial_findings=posture.partial_count,
                    not_assessed_findings=posture.not_assessed_count,
                    evidence_sources=posture.evidence_sources,
                    evidence_freshness_hours=posture.evidence_freshness_hours,
                    sufficiency_score=sufficiency.score,
                    sufficiency_details={
                        "evidence_volume": sufficiency.evidence_volume,
                        "evidence_freshness": sufficiency.evidence_freshness,
                        "evidence_diversity": sufficiency.evidence_diversity,
                        "assertion_coverage": sufficiency.assertion_coverage,
                        "gaps": sufficiency.gaps,
                    },
                )
                session.add(snapshot)
                snapshots.append(snapshot)

        session.flush()
        log.info(
            "Created %d posture snapshots%s",
            len(snapshots),
            f" for {framework}" if framework else "",
        )
        return snapshots


# ---------------------------------------------------------------------------
# EvidenceSufficiencyScorer
# ---------------------------------------------------------------------------


class EvidenceSufficiencyScorer:
    """Scores whether collected evidence is sufficient for an audit."""

    def score_control(
        self,
        session: Session,
        framework: str,
        control_id: str,
    ) -> SufficiencyScore:
        """Score evidence sufficiency for a single control.

        Scoring breakdown (0-100):
          - evidence_volume: 0-40 points (count of findings, logarithmic scale)
          - evidence_freshness: 0-25 points (hours since newest finding)
          - evidence_diversity: 0-20 points (unique source providers)
          - assertion_coverage: 0-15 points (deterministic assertion exists)

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier.
            control_id: Control identifier.

        Returns:
            SufficiencyScore with detailed breakdown and gaps.
        """
        results: list[ControlResult] = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.control_id == control_id,
            )
            .all()
        )

        gaps: list[str] = []

        if not results:
            return SufficiencyScore(
                framework=framework,
                control_id=control_id,
                score=0.0,
                evidence_volume=0.0,
                evidence_freshness=0.0,
                evidence_diversity=0.0,
                assertion_coverage=0.0,
                gaps=["No evidence collected for this control"],
            )

        # --- Evidence volume (0-40 points, logarithmic) ---
        count = len(results)
        # log2 scale: 1→10, 2→16, 4→22, 8→28, 16→34, 32→40
        if count >= 32:
            volume_score = 40.0
        elif count >= 1:
            volume_score = min(40.0, round(10 + 6 * math.log2(count), 2))
        else:
            volume_score = 0.0

        if count < 3:
            gaps.append(f"Low evidence volume: only {count} finding(s)")

        # --- Evidence freshness (0-25 points) ---
        assessed_times = [r.assessed_at for r in results if r.assessed_at]
        freshness_score = 0.0
        if assessed_times:
            now = datetime.now(timezone.utc)
            newest = max(assessed_times)
            if newest.tzinfo is None:
                newest = newest.replace(tzinfo=timezone.utc)
            hours_since = (now - newest).total_seconds() / 3600

            if hours_since <= 24:
                freshness_score = 25.0
            elif hours_since <= 168:  # 7 days
                freshness_score = 15.0
            elif hours_since <= 720:  # 30 days
                freshness_score = 5.0
            else:
                freshness_score = 0.0
                gaps.append(
                    f"Last evidence is {int(hours_since / 24)} days old ({int(hours_since)} hours)"
                )
        else:
            gaps.append("No timestamped evidence available")

        # --- Evidence diversity (0-20 points) ---
        finding_ids = [r.finding_id for r in results]
        unique_providers: list[str] = []
        if finding_ids:
            provider_rows = (
                session.query(distinct(Finding.provider)).filter(Finding.id.in_(finding_ids)).all()
            )
            unique_providers = [row[0] for row in provider_rows if row[0]]

        provider_count = len(unique_providers)
        if provider_count >= 3:
            diversity_score = 20.0
        elif provider_count == 2:
            diversity_score = 10.0
        elif provider_count == 1:
            diversity_score = 5.0
        else:
            diversity_score = 0.0

        if provider_count < 2:
            if provider_count == 0:
                gaps.append("No identifiable evidence sources")
            else:
                gaps.append(
                    f"Evidence from only 1 source ({unique_providers[0]}); "
                    "consider additional providers for corroboration"
                )

        # Check for common source type gaps
        source_types: set[str] = set()
        if finding_ids:
            type_rows = (
                session.query(distinct(Finding.source_type))
                .filter(Finding.id.in_(finding_ids))
                .all()
            )
            source_types = {row[0] for row in type_rows if row[0]}

        if "iam" not in source_types and source_types:
            gaps.append("No evidence from IAM sources")

        # --- Assertion coverage (0-15 points) ---
        has_assertion = any(r.assertion_name and r.assertion_name.strip() for r in results)
        assertion_score = 15.0 if has_assertion else 0.0
        if not has_assertion:
            gaps.append("No deterministic assertion covers this control")

        # --- Total ---
        total = round(volume_score + freshness_score + diversity_score + assertion_score, 2)

        return SufficiencyScore(
            framework=framework,
            control_id=control_id,
            score=total,
            evidence_volume=volume_score,
            evidence_freshness=freshness_score,
            evidence_diversity=diversity_score,
            assertion_coverage=assertion_score,
            gaps=gaps,
        )

    def score_framework(
        self,
        session: Session,
        framework: str,
    ) -> FrameworkSufficiency:
        """Aggregate sufficiency scores across all controls in a framework.

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier.

        Returns:
            FrameworkSufficiency with per-control scores and summary.
        """
        control_rows = (
            session.query(distinct(ControlResult.control_id))
            .filter(ControlResult.framework == framework)
            .all()
        )
        control_ids = sorted([row[0] for row in control_rows])

        scores: list[SufficiencyScore] = []
        for cid in control_ids:
            scores.append(self.score_control(session, framework, cid))

        sufficient = sum(1 for s in scores if s.score >= 60)
        insufficient = len(scores) - sufficient

        # Find most common gaps
        gap_counts: dict[str, int] = {}
        for s in scores:
            for gap in s.gaps:
                # Normalize gap text for aggregation
                key = gap.split(":")[0].strip() if ":" in gap else gap
                gap_counts[key] = gap_counts.get(key, 0) + 1
        common_gaps = sorted(gap_counts, key=gap_counts.get, reverse=True)[:5]  # type: ignore[arg-type]

        overall = round(sum(s.score for s in scores) / len(scores), 2) if scores else 0.0

        return FrameworkSufficiency(
            framework=framework,
            overall_score=overall,
            control_scores=scores,
            controls_scored=len(scores),
            controls_sufficient=sufficient,
            controls_insufficient=insufficient,
            common_gaps=common_gaps,
        )

    def score_engagement(
        self,
        session: Session,
        engagement_id: str,
    ) -> EngagementSufficiency:
        """Score evidence sufficiency for an audit engagement period.

        Scopes scoring to the engagement's framework and date range.

        Args:
            session: SQLAlchemy session.
            engagement_id: ID of the AuditEngagement.

        Returns:
            EngagementSufficiency with scoped scores.

        Raises:
            ValueError: If engagement not found.
        """
        engagement: AuditEngagement | None = (
            session.query(AuditEngagement).filter(AuditEngagement.id == engagement_id).first()
        )
        if not engagement:
            raise ValueError(f"Engagement not found: {engagement_id}")

        framework = engagement.framework
        period_start = engagement.period_start
        period_end = engagement.period_end

        # Get controls in scope
        in_scope = engagement.in_scope_controls or []
        excluded = engagement.excluded_controls or []

        # Query control results within the engagement period
        query = session.query(distinct(ControlResult.control_id)).filter(
            ControlResult.framework == framework,
            ControlResult.assessed_at >= period_start,
            ControlResult.assessed_at <= period_end,
        )
        if in_scope:
            query = query.filter(ControlResult.control_id.in_(in_scope))
        if excluded:
            query = query.filter(~ControlResult.control_id.in_(excluded))

        control_ids = sorted([row[0] for row in query.all()])

        # Score each control (using all evidence, not just period-scoped,
        # since sufficiency is about what we have now)
        scores: list[SufficiencyScore] = []
        for cid in control_ids:
            scores.append(self.score_control(session, framework, cid))

        # Also count controls in scope that have NO results at all
        controls_in_scope = len(in_scope) if in_scope else len(control_ids)
        sufficient = sum(1 for s in scores if s.score >= 60)
        insufficient = controls_in_scope - sufficient

        gap_counts: dict[str, int] = {}
        for s in scores:
            for gap in s.gaps:
                key = gap.split(":")[0].strip() if ":" in gap else gap
                gap_counts[key] = gap_counts.get(key, 0) + 1
        common_gaps = sorted(gap_counts, key=gap_counts.get, reverse=True)[:5]  # type: ignore[arg-type]

        overall = round(sum(s.score for s in scores) / len(scores), 2) if scores else 0.0

        return EngagementSufficiency(
            engagement_id=engagement_id,
            engagement_name=engagement.name,
            framework=framework,
            period_start=period_start,
            period_end=period_end,
            overall_score=overall,
            control_scores=scores,
            controls_in_scope=controls_in_scope,
            controls_sufficient=sufficient,
            controls_insufficient=insufficient,
            common_gaps=common_gaps,
        )


# ---------------------------------------------------------------------------
# Posture Time-Series
# ---------------------------------------------------------------------------


@dataclass
class PostureTimeSeriesPoint:
    date: datetime
    status: str
    posture_score: float
    sufficiency_score: float
    evidence_freshness_hours: float | None


@dataclass
class PostureTimeSeries:
    framework: str
    control_id: str
    points: list[PostureTimeSeriesPoint]
    trend: str  # improving, stable, degrading
    trend_slope: float  # posture_score change per day


class PostureTimeSeriesQuery:
    """Query PostureSnapshot history for trend analysis."""

    def query_control(
        self,
        session: Session,
        framework: str,
        control_id: str,
        days: int = 90,
    ) -> PostureTimeSeries:
        """Get time-series data for a single control."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        snapshots = (
            session.query(PostureSnapshot)
            .filter(
                PostureSnapshot.framework == framework,
                PostureSnapshot.control_id == control_id,
                PostureSnapshot.snapshot_date >= cutoff,
            )
            .order_by(PostureSnapshot.snapshot_date)
            .all()
        )

        points = [
            PostureTimeSeriesPoint(
                date=s.snapshot_date,
                status=s.status,
                posture_score=s.posture_score,
                sufficiency_score=s.sufficiency_score or 0.0,
                evidence_freshness_hours=s.evidence_freshness_hours,
            )
            for s in snapshots
        ]

        slope = self._compute_slope(points)
        if slope > 0.05:
            trend = "improving"
        elif slope < -0.05:
            trend = "degrading"
        else:
            trend = "stable"

        return PostureTimeSeries(
            framework=framework,
            control_id=control_id,
            points=points,
            trend=trend,
            trend_slope=round(slope, 4),
        )

    def query_framework(
        self,
        session: Session,
        framework: str,
        days: int = 90,
    ) -> list[PostureTimeSeries]:
        """Get time-series for all controls in a framework."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        control_rows = (
            session.query(distinct(PostureSnapshot.control_id))
            .filter(
                PostureSnapshot.framework == framework,
                PostureSnapshot.snapshot_date >= cutoff,
            )
            .all()
        )
        control_ids = sorted([row[0] for row in control_rows])
        return [self.query_control(session, framework, cid, days) for cid in control_ids]

    @staticmethod
    def _compute_slope(points: list[PostureTimeSeriesPoint]) -> float:
        """Simple linear regression slope on posture_score over time.

        Returns change in posture_score per day.
        """
        if len(points) < 2:
            return 0.0

        base_time = points[0].date
        if base_time.tzinfo is None:
            base_time = base_time.replace(tzinfo=timezone.utc)

        xs: list[float] = []
        ys: list[float] = []
        for p in points:
            t = p.date
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            day_offset = (t - base_time).total_seconds() / 86400.0
            xs.append(day_offset)
            ys.append(p.posture_score)

        n = len(xs)
        sum_x = sum(xs)
        sum_y = sum(ys)
        sum_xy = sum(x * y for x, y in zip(xs, ys))
        sum_x2 = sum(x * x for x in xs)

        denom = n * sum_x2 - sum_x * sum_x
        if abs(denom) < 1e-10:
            return 0.0

        return (n * sum_xy - sum_x * sum_y) / denom
