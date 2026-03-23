"""Tests for domain services: controls, issues, evidence."""

from datetime import datetime, timezone, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from warlock.db.models import (
    Base,
    ConnectorRun,
    RawEvent,
    Finding,
    ControlMapping,
    ControlResult,
    POAM,
    Issue,
)
from warlock.domains.base import QueryFilters

import pytest


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _seed_full_chain(
    session, framework="soc2", control_id="CC6.1", status="non_compliant", severity="high"
):
    """Build full FK chain: ConnectorRun → RawEvent → Finding → ControlMapping → ControlResult."""
    now = datetime.now(timezone.utc)

    cr_run = ConnectorRun(
        connector_name="demo-test",
        source="test-source",
        source_type="cloud",
        provider="test",
        started_at=now,
        status="success",
    )
    session.add(cr_run)
    session.flush()

    raw = RawEvent(
        connector_run_id=cr_run.id,
        source="test",
        source_type="cloud",
        provider="test",
        event_type="test_event",
        raw_data={"test": True},
        sha256="testhash",
        ingested_at=now,
    )
    session.add(raw)
    session.flush()

    finding = Finding(
        raw_event_id=raw.id,
        observation_type="configuration",
        title="Test finding",
        detail={"test": True},
        source="test",
        source_type="cloud",
        provider="test",
        severity=severity,
        confidence=1.0,
        observed_at=now,
        ingested_at=now,
        sha256="findinghash",
    )
    session.add(finding)
    session.flush()

    mapping = ControlMapping(
        finding_id=finding.id,
        framework=framework,
        control_id=control_id,
        mapping_method="explicit",
        confidence=1.0,
    )
    session.add(mapping)
    session.flush()

    result = ControlResult(
        finding_id=finding.id,
        control_mapping_id=mapping.id,
        framework=framework,
        control_id=control_id,
        status=status,
        severity=severity,
        assessor="assertion:test_assertion",
        assessed_at=now,
    )
    session.add(result)
    session.commit()

    return {
        "connector_run": cr_run,
        "raw_event": raw,
        "finding": finding,
        "mapping": mapping,
        "result": result,
    }


class TestControlsDomainService:
    def test_domain_name(self):
        from warlock.domains.controls import ControlsDomainService

        svc = ControlsDomainService.__new__(ControlsDomainService)
        assert svc.domain_name == "controls"

    def test_get_related_to_control(self, db_session):
        from warlock.domains.controls import ControlsDomainService

        _seed_full_chain(db_session, control_id="CC6.1", status="non_compliant")
        # Also add a POAM
        poam = POAM(
            framework="soc2",
            control_id="CC6.1",
            severity="high",
            status="open",
            weakness_description="MFA not enforced",
            created_by="admin@acme.com",
        )
        db_session.add(poam)
        db_session.commit()

        svc = ControlsDomainService(db_session)
        related = svc.get_related_to("control", "CC6.1")
        assert len(related) >= 2  # control_status + poam
        types = [r.entity_type for r in related]
        assert "control_status" in types
        assert "poam" in types

    def test_get_urgent_items_finds_non_compliant(self, db_session):
        from warlock.domains.controls import ControlsDomainService

        _seed_full_chain(db_session, control_id="CC6.1", status="non_compliant")
        svc = ControlsDomainService(db_session)
        items = svc.get_urgent_items(QueryFilters(frameworks=["soc2"]))
        assert len(items) > 0
        assert any("CC6.1" in item.summary for item in items)

    def test_get_urgent_items_filters_by_framework(self, db_session):
        from warlock.domains.controls import ControlsDomainService

        _seed_full_chain(db_session, framework="soc2", control_id="CC6.1", status="non_compliant")
        svc = ControlsDomainService(db_session)
        items = svc.get_urgent_items(QueryFilters(frameworks=["soc2"]))
        assert len(items) > 0
        items = svc.get_urgent_items(QueryFilters(frameworks=["hipaa"]))
        assert len(items) == 0

    def test_get_related_returns_empty_for_non_control(self, db_session):
        from warlock.domains.controls import ControlsDomainService

        svc = ControlsDomainService(db_session)
        assert svc.get_related_to("person", "eve@acme.com") == []


def _seed_issue_data(session):
    now = datetime.now(timezone.utc)
    poam = POAM(
        framework="nist_800_53",
        control_id="AC-2",
        severity="critical",
        status="open",
        weakness_description="Root account access keys active",
        created_by="admin@acme.com",
        scheduled_completion=now - timedelta(days=5),
    )
    session.add(poam)
    issue = Issue(
        framework="soc2",
        control_id="CC6.1",
        title="MFA not enforced",
        status="open",
        priority="high",
    )
    session.add(issue)
    session.commit()
    return {"poam": poam, "issue": issue}


class TestIssuesDomainService:
    def test_domain_name(self):
        from warlock.domains.issues import IssuesDomainService

        svc = IssuesDomainService.__new__(IssuesDomainService)
        assert svc.domain_name == "issues"

    def test_get_urgent_items_includes_overdue_poams(self, db_session):
        from warlock.domains.issues import IssuesDomainService

        _seed_issue_data(db_session)
        svc = IssuesDomainService(db_session)
        items = svc.get_urgent_items(QueryFilters())
        assert len(items) >= 1
        overdue = [i for i in items if "overdue" in i.summary.lower() or "AC-2" in i.summary]
        assert len(overdue) >= 1

    def test_get_related_to_control(self, db_session):
        from warlock.domains.issues import IssuesDomainService

        _seed_issue_data(db_session)
        svc = IssuesDomainService(db_session)
        related = svc.get_related_to("control", "AC-2")
        assert len(related) >= 1
        assert related[0].entity_type in ("poam", "issue")

    def test_get_urgent_items_filters_framework(self, db_session):
        from warlock.domains.issues import IssuesDomainService

        _seed_issue_data(db_session)
        svc = IssuesDomainService(db_session)
        items = svc.get_urgent_items(QueryFilters(frameworks=["soc2"]))
        for item in items:
            assert item.framework == "soc2"


class TestEvidenceDomainService:
    def test_domain_name(self):
        from warlock.domains.evidence import EvidenceDomainService

        svc = EvidenceDomainService.__new__(EvidenceDomainService)
        assert svc.domain_name == "evidence"

    def test_get_related_to_control(self, db_session):
        from warlock.domains.evidence import EvidenceDomainService

        _seed_full_chain(db_session, control_id="CC6.1")
        svc = EvidenceDomainService(db_session)
        related = svc.get_related_to("control", "CC6.1")
        assert len(related) >= 1
        assert any(r.entity_type == "evidence_summary" for r in related)

    def test_get_urgent_items_finds_stale_evidence(self, db_session):
        from warlock.domains.evidence import EvidenceDomainService
        from warlock.db.models import ControlResult

        _seed_full_chain(db_session, control_id="CC6.1")
        # Make the assessed_at old
        result = db_session.query(ControlResult).first()
        result.assessed_at = datetime.now(timezone.utc) - timedelta(days=100)
        db_session.commit()

        svc = EvidenceDomainService(db_session, stale_threshold_days=90)
        items = svc.get_urgent_items(QueryFilters())
        assert len(items) >= 1
        assert any("stale" in item.summary.lower() for item in items)

    def test_get_related_returns_empty_for_unknown(self, db_session):
        from warlock.domains.evidence import EvidenceDomainService

        svc = EvidenceDomainService(db_session)
        assert svc.get_related_to("control", "FAKE-99") == []
