"""Tests for OLTP thinning."""

from datetime import datetime, timezone, timedelta


# Required non-nullable FK placeholders — SQLite in-memory doesn't enforce FK constraints
_FINDING_ID = "finding-test-01"
_MAPPING_ID = "mapping-test-01"
_ASSESSOR = "assertion:test"


def _make_result(id: str, days_ago: int, now: datetime, **kwargs):
    """Helper: create a minimal ControlResult for test use."""
    from warlock.db.models import ControlResult

    defaults = dict(
        id=id,
        finding_id=_FINDING_ID,
        control_mapping_id=_MAPPING_ID,
        framework="nist_800_53",
        control_id="AC-2",
        status="compliant",
        severity="high",
        assessor=_ASSESSOR,
        assessed_at=now - timedelta(days=days_ago),
    )
    defaults.update(kwargs)
    return ControlResult(**defaults)


class TestOLTPThin:
    def test_dry_run_counts_only(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from warlock.db.models import Base, ControlResult
        from warlock.lake.oltp_thin import thin_oltp

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)

        with Session(engine) as session:
            # Add 3 results for same control — only latest should be kept
            now = datetime.now(timezone.utc)
            for i in range(3):
                session.add(_make_result(f"cr-{i}", days_ago=i, now=now))
            session.flush()

            stats = thin_oltp(session, dry_run=True)
            assert stats.control_results_kept == 1
            assert stats.control_results_removed == 2
            # Verify nothing was actually deleted
            assert session.query(ControlResult).count() == 3

    def test_actual_thin_removes_old(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from warlock.db.models import Base, ControlResult
        from warlock.lake.oltp_thin import thin_oltp

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)

        with Session(engine) as session:
            now = datetime.now(timezone.utc)
            for i in range(3):
                session.add(_make_result(f"cr-{i}", days_ago=i, now=now))
            session.flush()

            stats = thin_oltp(session, dry_run=False)
            assert stats.control_results_kept == 1
            assert stats.control_results_removed == 2
            assert session.query(ControlResult).count() == 1

    def test_current_state_projection(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from warlock.db.models import Base
        from warlock.lake.oltp_thin import current_state_projection

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)

        with Session(engine) as session:
            now = datetime.now(timezone.utc)
            session.add(_make_result("cr-old", days_ago=1, now=now, status="non_compliant"))
            session.add(_make_result("cr-new", days_ago=0, now=now, status="compliant"))
            session.flush()

            projection = current_state_projection(session, framework="nist_800_53")
            assert len(projection) == 1
            assert projection[0]["status"] == "compliant"

    def test_empty_db(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from warlock.db.models import Base
        from warlock.lake.oltp_thin import thin_oltp

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)

        with Session(engine) as session:
            stats = thin_oltp(session, dry_run=True)
            assert stats.control_results_kept == 0
            assert stats.total_removed == 0
