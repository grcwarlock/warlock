"""Tests for policy engine: models, CRUD, resolution."""

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from warlock.db.models import Base

import pytest


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


class TestPolicyModel:
    def test_create_policy(self, db_session):
        from warlock.db.models import Policy
        p = Policy(
            policy_type="sla",
            scope={"severity": ["critical"]},
            rules={"remediation_days": 14, "escalate_after": 7},
            created_by="admin@acme.com",
            description="Critical SLA",
        )
        db_session.add(p)
        db_session.commit()
        result = db_session.query(Policy).first()
        assert result.policy_type == "sla"
        assert result.rules["remediation_days"] == 14
        assert result.enabled is True
        assert result.priority == 0

    def test_create_policy_history(self, db_session):
        from warlock.db.models import Policy, PolicyHistory
        p = Policy(
            policy_type="retention",
            scope={},
            rules={"days": 365},
            created_by="admin@acme.com",
        )
        db_session.add(p)
        db_session.commit()
        h = PolicyHistory(
            policy_id=p.id,
            action="created",
            new_rules={"days": 365},
            actor="admin@acme.com",
        )
        db_session.add(h)
        db_session.commit()
        result = db_session.query(PolicyHistory).first()
        assert result.action == "created"
        assert result.policy_id == p.id


class TestAssetModel:
    def test_create_asset(self, db_session):
        from warlock.db.models import Asset
        a = Asset(
            resource_id="prod-db-01",
            resource_type="database",
            resource_name="Production PostgreSQL",
            classification="critical",
            criticality=9,
        )
        db_session.add(a)
        db_session.commit()
        result = db_session.query(Asset).first()
        assert result.resource_id == "prod-db-01"
        assert result.classification == "critical"
        assert result.status == "active"


class TestVendorModel:
    def test_create_vendor(self, db_session):
        from warlock.db.models import Vendor
        v = Vendor(
            name="Cloudflare",
            tier="critical",
            risk_score=82.0,
        )
        db_session.add(v)
        db_session.commit()
        result = db_session.query(Vendor).first()
        assert result.name == "Cloudflare"
        assert result.tier == "critical"
        assert result.risk_score == 82.0
