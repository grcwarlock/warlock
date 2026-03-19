"""Tests for Phase 1: Continuous monitoring cadence, evidence sufficiency, posture time-series."""

from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from warlock.db.models import Base, ControlMapping, ControlResult, Finding, RawEvent, ConnectorRun, PostureSnapshot


@pytest.fixture
def session():
    """Create an in-memory database with schema."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    yield s
    s.close()


@pytest.fixture
def seeded_session(session):
    """Session with sample data for testing."""
    now = datetime.now(timezone.utc)

    # Create a connector run
    run = ConnectorRun(
        id="run-1",
        connector_name="aws",
        source="aws",
        source_type="cloud",
        provider="aws",
        status="success",
    )
    session.add(run)

    # Create raw events
    for i in range(3):
        session.add(RawEvent(
            id=f"raw-{i}",
            connector_run_id="run-1",
            source="aws",
            source_type="cloud",
            provider="aws",
            event_type="iam_credential_report",
            raw_data={"test": True},
            sha256=f"abc{i}",
        ))

    # Create findings
    for i in range(3):
        session.add(Finding(
            id=f"finding-{i}",
            raw_event_id=f"raw-{i}",
            observation_type="misconfiguration",
            title=f"Test finding {i}",
            detail={"test": True},
            resource_type="iam_user",
            source="aws",
            source_type="cloud",
            provider="aws",
            severity="high",
            observed_at=now - timedelta(hours=i * 12),
            sha256=f"def{i}",
        ))

    # Create control mappings with monitoring_frequency
    for i in range(3):
        session.add(ControlMapping(
            id=f"mapping-{i}",
            finding_id=f"finding-{i}",
            framework="nist_800_53",
            control_id="AC-2",
            control_family="AC",
            mapping_method="explicit",
            confidence=1.0,
            monitoring_frequency="daily",
        ))

    # Create control results
    for i in range(3):
        session.add(ControlResult(
            id=f"result-{i}",
            finding_id=f"finding-{i}",
            control_mapping_id=f"mapping-{i}",
            framework="nist_800_53",
            control_id="AC-2",
            status="compliant" if i < 2 else "non_compliant",
            severity="high",
            assessor="assertion:mfa_check",
            assessed_at=now - timedelta(hours=i * 12),
        ))

    # Also create a monthly control that's old
    session.add(ControlMapping(
        id="mapping-pe",
        finding_id="finding-0",
        framework="nist_800_53",
        control_id="PE-1",
        control_family="PE",
        mapping_method="explicit",
        confidence=1.0,
        monitoring_frequency="annual",
    ))
    session.add(ControlResult(
        id="result-pe",
        finding_id="finding-0",
        control_mapping_id="mapping-pe",
        framework="nist_800_53",
        control_id="PE-1",
        status="compliant",
        severity="low",
        assessor="manual",
        assessed_at=now - timedelta(days=30),
    ))

    session.flush()
    return session


# ---------------------------------------------------------------------------
# Phase 1a: Cadence Tests
# ---------------------------------------------------------------------------

class TestCadenceChecker:

    def test_fresh_daily_control(self, seeded_session):
        from warlock.assessors.cadence import CadenceChecker

        checker = CadenceChecker()
        cadence = checker.check_control(seeded_session, "nist_800_53", "AC-2")

        assert cadence.required_frequency == "daily"
        assert cadence.required_hours == 24.0
        assert cadence.last_evidence_at is not None
        assert cadence.hours_since is not None
        assert cadence.hours_since < 1.0  # Just created
        assert cadence.is_stale is False
        assert cadence.staleness_ratio < 1.0

    def test_annual_control_fresh_at_30_days(self, seeded_session):
        from warlock.assessors.cadence import CadenceChecker

        checker = CadenceChecker()
        cadence = checker.check_control(seeded_session, "nist_800_53", "PE-1")

        assert cadence.required_frequency == "annual"
        assert cadence.required_hours == 8760.0
        assert cadence.is_stale is False
        # 30 days old / 8760 hours required = small ratio
        assert cadence.staleness_ratio < 0.1

    def test_check_framework(self, seeded_session):
        from warlock.assessors.cadence import CadenceChecker

        checker = CadenceChecker()
        cadences = checker.check_framework(seeded_session, "nist_800_53")

        assert len(cadences) == 2  # AC-2 and PE-1
        control_ids = {c.control_id for c in cadences}
        assert "AC-2" in control_ids
        assert "PE-1" in control_ids

    def test_stale_controls_empty_when_fresh(self, seeded_session):
        from warlock.assessors.cadence import CadenceChecker

        checker = CadenceChecker()
        stale = checker.get_stale_controls(seeded_session)
        assert len(stale) == 0

    def test_no_evidence_is_stale(self, seeded_session):
        from warlock.assessors.cadence import CadenceChecker

        checker = CadenceChecker()
        # Check a control that doesn't exist - should be stale
        cadence = checker.check_control(seeded_session, "nist_800_53", "FAKE-1")
        assert cadence.is_stale is True
        assert cadence.staleness_ratio == float("inf")

    def test_check_all(self, seeded_session):
        from warlock.assessors.cadence import CadenceChecker

        checker = CadenceChecker()
        all_cadences = checker.check_all(seeded_session)

        assert "nist_800_53" in all_cadences
        assert len(all_cadences["nist_800_53"]) == 2


# ---------------------------------------------------------------------------
# Phase 1b: Sufficiency Tests
# ---------------------------------------------------------------------------

class TestEvidenceSufficiency:

    def test_score_control_with_evidence(self, seeded_session):
        from warlock.assessors.posture import EvidenceSufficiencyScorer

        scorer = EvidenceSufficiencyScorer()
        score = scorer.score_control(seeded_session, "nist_800_53", "AC-2")

        assert score.score > 0
        assert score.evidence_volume > 0
        assert score.evidence_freshness > 0
        assert score.evidence_diversity > 0  # At least one source
        assert score.framework == "nist_800_53"
        assert score.control_id == "AC-2"

    def test_score_control_no_evidence(self, seeded_session):
        from warlock.assessors.posture import EvidenceSufficiencyScorer

        scorer = EvidenceSufficiencyScorer()
        score = scorer.score_control(seeded_session, "nist_800_53", "FAKE-1")

        assert score.score == 0.0
        assert len(score.gaps) > 0
        assert "No evidence" in score.gaps[0]

    def test_score_framework(self, seeded_session):
        from warlock.assessors.posture import EvidenceSufficiencyScorer

        scorer = EvidenceSufficiencyScorer()
        result = scorer.score_framework(seeded_session, "nist_800_53")

        assert result.controls_scored == 2  # AC-2 and PE-1
        assert result.overall_score > 0

    def test_take_snapshot(self, seeded_session):
        from warlock.assessors.posture import PostureAggregator

        aggregator = PostureAggregator()
        snapshots = aggregator.take_snapshot(seeded_session, framework="nist_800_53")

        assert len(snapshots) == 2  # AC-2 and PE-1
        for snap in snapshots:
            assert snap.sufficiency_score > 0
            assert snap.sufficiency_details is not None


# ---------------------------------------------------------------------------
# Phase 1c: Time-Series Tests
# ---------------------------------------------------------------------------

class TestPostureTimeSeries:

    def test_query_control_with_snapshots(self, seeded_session):
        from warlock.assessors.posture import PostureAggregator, PostureTimeSeriesQuery

        # Create snapshots first
        aggregator = PostureAggregator()
        aggregator.take_snapshot(seeded_session, framework="nist_800_53")
        seeded_session.flush()

        tsq = PostureTimeSeriesQuery()
        ts = tsq.query_control(seeded_session, "nist_800_53", "AC-2", days=90)

        assert ts.framework == "nist_800_53"
        assert ts.control_id == "AC-2"
        assert len(ts.points) == 1  # One snapshot
        assert ts.trend == "stable"  # Single point can't have slope
        assert ts.points[0].posture_score >= 0

    def test_query_control_no_snapshots(self, seeded_session):
        from warlock.assessors.posture import PostureTimeSeriesQuery

        tsq = PostureTimeSeriesQuery()
        ts = tsq.query_control(seeded_session, "nist_800_53", "AC-2", days=90)

        assert len(ts.points) == 0
        assert ts.trend == "stable"

    def test_trend_computation(self):
        from warlock.assessors.posture import PostureTimeSeriesQuery, PostureTimeSeriesPoint

        now = datetime.now(timezone.utc)
        # Simulate improving trend
        points = [
            PostureTimeSeriesPoint(
                date=now - timedelta(days=30),
                status="partial",
                posture_score=50.0,
                sufficiency_score=40.0,
                evidence_freshness_hours=None,
            ),
            PostureTimeSeriesPoint(
                date=now - timedelta(days=15),
                status="partial",
                posture_score=70.0,
                sufficiency_score=50.0,
                evidence_freshness_hours=None,
            ),
            PostureTimeSeriesPoint(
                date=now,
                status="compliant",
                posture_score=90.0,
                sufficiency_score=60.0,
                evidence_freshness_hours=None,
            ),
        ]

        slope = PostureTimeSeriesQuery._compute_slope(points)
        assert slope > 0.05  # Should be improving (~1.33/day)

    def test_trend_stable(self):
        from warlock.assessors.posture import PostureTimeSeriesQuery, PostureTimeSeriesPoint

        now = datetime.now(timezone.utc)
        points = [
            PostureTimeSeriesPoint(
                date=now - timedelta(days=30),
                status="compliant",
                posture_score=80.0,
                sufficiency_score=60.0,
                evidence_freshness_hours=None,
            ),
            PostureTimeSeriesPoint(
                date=now,
                status="compliant",
                posture_score=80.0,
                sufficiency_score=60.0,
                evidence_freshness_hours=None,
            ),
        ]

        slope = PostureTimeSeriesQuery._compute_slope(points)
        assert abs(slope) < 0.05  # Should be stable

    def test_query_framework(self, seeded_session):
        from warlock.assessors.posture import PostureAggregator, PostureTimeSeriesQuery

        aggregator = PostureAggregator()
        aggregator.take_snapshot(seeded_session, framework="nist_800_53")
        seeded_session.flush()

        tsq = PostureTimeSeriesQuery()
        series = tsq.query_framework(seeded_session, "nist_800_53", days=90)

        assert len(series) == 2  # AC-2 and PE-1
        control_ids = {s.control_id for s in series}
        assert "AC-2" in control_ids
        assert "PE-1" in control_ids


# ---------------------------------------------------------------------------
# Schema / Migration Tests
# ---------------------------------------------------------------------------

class TestSchema:

    def test_control_mapping_has_monitoring_frequency(self, session):
        """Verify the monitoring_frequency column exists on ControlMapping."""
        from sqlalchemy import inspect
        inspector = inspect(session.bind)
        columns = {c["name"] for c in inspector.get_columns("control_mappings")}
        assert "monitoring_frequency" in columns

    def test_monitoring_frequency_persists(self, session):
        """Verify monitoring_frequency can be written and read."""
        run = ConnectorRun(
            id="test-run",
            connector_name="test",
            source="test",
            source_type="test",
            provider="test",
        )
        session.add(run)
        session.add(RawEvent(
            id="test-raw",
            connector_run_id="test-run",
            source="test",
            source_type="test",
            provider="test",
            event_type="test",
            raw_data={},
            sha256="test",
        ))
        session.add(Finding(
            id="test-finding",
            raw_event_id="test-raw",
            observation_type="test",
            title="test",
            detail={},
            source="test",
            source_type="test",
            provider="test",
            severity="low",
            observed_at=datetime.now(timezone.utc),
            sha256="test",
        ))
        mapping = ControlMapping(
            id="test-mapping",
            finding_id="test-finding",
            framework="test",
            control_id="TEST-1",
            mapping_method="explicit",
            confidence=1.0,
            monitoring_frequency="weekly",
        )
        session.add(mapping)
        session.flush()

        loaded = session.query(ControlMapping).filter_by(id="test-mapping").one()
        assert loaded.monitoring_frequency == "weekly"


# ---------------------------------------------------------------------------
# Mapper Tests
# ---------------------------------------------------------------------------

class TestControlMapperFrequency:

    def test_mapper_propagates_frequency(self):
        """Verify ControlMapper sets monitoring_frequency from YAML config."""
        from warlock.mappers.control_mapper import ControlMapper
        from warlock.normalizers.base import FindingData

        mapper = ControlMapper()
        config = {
            "control_families": {
                "AC": {
                    "controls": {
                        "AC-2": {
                            "monitoring_frequency": "daily",
                            "checks": [{
                                "id": "test",
                                "event_types": ["iam_users"],
                                "resource_types": ["iam_user"],
                            }],
                        },
                    },
                },
            },
        }
        mapper.load_framework_yaml("nist_800_53", config)

        finding = FindingData(
            id="f1",
            raw_event_id="raw-1",
            observation_type="iam_users",
            title="Test",
            detail={},
            resource_type="iam_user",
            source="aws",
            source_type="cloud",
            provider="aws",
            severity="high",
            observed_at=datetime.now(timezone.utc).isoformat(),
        )

        result = mapper.map(finding)
        assert len(result.mappings) > 0
        for m in result.mappings:
            if m.framework == "nist_800_53" and m.control_id == "AC-2":
                assert m.monitoring_frequency == "daily"
                break
        else:
            pytest.fail("AC-2 mapping not found")


# ---------------------------------------------------------------------------
# Scheduler Tests
# ---------------------------------------------------------------------------

class TestScheduler:

    def test_scheduler_creates_with_schedules(self):
        from warlock.pipeline.scheduler import PipelineScheduler

        sched = PipelineScheduler(interval_minutes=30)
        status = sched.status

        assert status["running"] is False
        assert "schedules" in status
        assert "pipeline_collect" in status["schedules"]
        assert "posture_snapshot" in status["schedules"]
        assert "cadence_check" in status["schedules"]
        assert status["schedules"]["pipeline_collect"]["interval_minutes"] == 30
        assert status["schedules"]["posture_snapshot"]["interval_minutes"] == 1440

    def test_scheduler_backward_compat(self):
        from warlock.pipeline.scheduler import PipelineScheduler

        sched = PipelineScheduler(interval_minutes=60)
        status = sched.status

        # Old-style top-level fields still present
        assert "interval_minutes" in status
        assert "last_run" in status
        assert "run_count" in status
