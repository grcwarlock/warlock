"""Shared test fixtures for Warlock test suite.

H-10: Unified DB setup — replaces 8+ duplicate patterns across test files.
New tests should use these fixtures instead of creating their own engines.
Existing tests are NOT refactored to avoid risky churn.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, StaticPool
from sqlalchemy.orm import sessionmaker

# Set env vars BEFORE any warlock imports — Settings reads these once.
os.environ.setdefault("WLK_JWT_SECRET", "test-secret-key-that-is-at-least-32-characters-long")
os.environ.setdefault("WLK_ENV", "development")
os.environ.setdefault("WLK_DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("WLK_GDPR_HMAC_SECRET", "test-gdpr-hmac-secret-at-least-32-chars-long")

from warlock.db.models import (  # noqa: E402
    Base,
    ConnectorRun,
    ControlMapping,
    ControlResult,
    Finding,
    RawEvent,
    SystemProfile,
    User,
)


def _uuid() -> str:
    return str(uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Core DB fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def db_engine():
    """Session-scoped in-memory SQLite engine.

    Using StaticPool so the same connection is reused across threads,
    which is required for SQLite in-memory databases.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine):
    """Function-scoped DB session with rollback for per-test isolation.

    Each test gets a clean session that rolls back on teardown,
    so tests don't pollute each other.
    """
    connection = db_engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


# ---------------------------------------------------------------------------
# CLI fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def cli_db(tmp_path, monkeypatch):
    """Set up a file-based test DB for CLI commands.

    CLI commands use warlock.db.engine internally (not dependency injection),
    so we must monkeypatch the engine globals to point at a test DB.

    Returns the db path for reference.
    """
    import warlock.db.engine as eng

    db_path = tmp_path / "test.db"
    monkeypatch.setenv("WLK_DATABASE_URL", f"sqlite:///{db_path}")

    # Reset engine globals so they re-initialize with test URL
    eng._engine = None
    eng._read_engine = None
    eng._session_factory = None
    eng._read_session_factory = None

    # Create all tables
    eng.init_db()

    yield db_path

    # Cleanup globals
    eng._engine = None
    eng._read_engine = None
    eng._session_factory = None
    eng._read_session_factory = None


@pytest.fixture
def cli_runner():
    """Click CliRunner for invoking CLI commands."""
    from click.testing import CliRunner

    return CliRunner()


# ---------------------------------------------------------------------------
# Data seeding helpers
# ---------------------------------------------------------------------------


def seed_system_profile(session, name="Production") -> SystemProfile:
    """Insert a minimal SystemProfile."""
    sp = SystemProfile(
        id=_uuid(),
        name=name,
        description=f"{name} environment",
    )
    session.add(sp)
    session.flush()
    return sp


def seed_connector_run(session, connector_name="aws_iam", status="success") -> ConnectorRun:
    """Insert a minimal ConnectorRun."""
    run = ConnectorRun(
        id=_uuid(),
        connector_name=connector_name,
        source="aws",
        source_type="cloud",
        provider="aws_iam",
        status=status,
        event_count=1,
        started_at=_utcnow(),
        completed_at=_utcnow(),
        errors=[],
    )
    session.add(run)
    session.flush()
    return run


def seed_raw_event(session, connector_run=None, source="aws", event_type="iam_user") -> RawEvent:
    """Insert a minimal RawEvent."""
    import hashlib

    if connector_run is None:
        connector_run = seed_connector_run(session)
    raw_data = {"test": True, "event_type": event_type}
    event = RawEvent(
        id=_uuid(),
        connector_run_id=connector_run.id,
        source=source,
        source_type="cloud",
        provider="aws_iam",
        event_type=event_type,
        raw_data=raw_data,
        sha256=hashlib.sha256(str(raw_data).encode()).hexdigest(),
        ingested_at=_utcnow(),
    )
    session.add(event)
    session.flush()
    return event


def seed_finding(
    session,
    raw_event=None,
    source="aws",
    severity="high",
    title="Test finding",
) -> Finding:
    """Insert a minimal Finding."""
    import hashlib

    if raw_event is None:
        raw_event = seed_raw_event(session, source=source)
    detail = {"description": "Test finding for unit tests"}
    finding = Finding(
        id=_uuid(),
        raw_event_id=raw_event.id,
        source=source,
        source_type="cloud",
        provider="aws_iam",
        severity=severity,
        title=title,
        detail=detail,
        observation_type="misconfiguration",
        observed_at=_utcnow(),
        ingested_at=_utcnow(),
        sha256=hashlib.sha256(str(detail).encode()).hexdigest(),
    )
    session.add(finding)
    session.flush()
    return finding


def seed_control_mapping(
    session,
    finding=None,
    framework="nist_800_53",
    control_id="AC-2",
) -> ControlMapping:
    """Insert a minimal ControlMapping."""
    if finding is None:
        finding = seed_finding(session)
    mapping = ControlMapping(
        id=_uuid(),
        finding_id=finding.id,
        framework=framework,
        control_id=control_id,
        mapping_method="explicit",
        confidence=0.95,
        created_at=_utcnow(),
    )
    session.add(mapping)
    session.flush()
    return mapping


def seed_control_result(
    session,
    finding=None,
    mapping=None,
    status="compliant",
    system_profile_id=None,
) -> ControlResult:
    """Insert a minimal ControlResult."""
    if finding is None:
        finding = seed_finding(session)
    if mapping is None:
        mapping = seed_control_mapping(session, finding=finding)
    result = ControlResult(
        id=_uuid(),
        finding_id=finding.id,
        control_mapping_id=mapping.id,
        system_profile_id=system_profile_id or _uuid(),
        framework=mapping.framework,
        control_id=mapping.control_id,
        status=status,
        severity="high",
        assessed_at=_utcnow(),
        assessor="assertion:test_check",
    )
    session.add(result)
    session.flush()
    return result


def seed_user(session, email="test@warlock.dev", name="Test User", role="analyst") -> User:
    """Insert a minimal User."""
    from warlock.api.auth import hash_password

    user = User(
        id=_uuid(),
        email=email,
        name=name,
        role=role,
        hashed_password=hash_password("testpass123"),
        is_active=True,
        created_at=_utcnow(),
    )
    session.add(user)
    session.flush()
    return user


def seed_full_chain(session):
    """Seed a complete FK chain: ConnectorRun → RawEvent → Finding → Mapping → Result.

    Returns a dict with all created objects for test assertions.
    """
    sp = seed_system_profile(session)
    run = seed_connector_run(session)
    event = seed_raw_event(session, connector_run=run)
    finding = seed_finding(session, raw_event=event)
    mapping = seed_control_mapping(session, finding=finding)
    result = seed_control_result(session, finding=finding, mapping=mapping, system_profile_id=sp.id)
    return {
        "system_profile": sp,
        "connector_run": run,
        "raw_event": event,
        "finding": finding,
        "mapping": mapping,
        "result": result,
    }
