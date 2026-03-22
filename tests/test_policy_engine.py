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


class TestPolicyEngine:
    def test_set_and_get_policy(self, db_session):
        from warlock.domains.policy_engine import PolicyEngine
        engine = PolicyEngine(db_session)
        engine.set_policy(
            policy_type="sla",
            scope={"severity": ["critical"]},
            rules={"remediation_days": 14},
            actor="admin@acme.com",
        )
        result = engine.get("sla", severity="critical")
        assert result is not None
        assert result.rules["remediation_days"] == 14

    def test_get_returns_none_when_no_match(self, db_session):
        from warlock.domains.policy_engine import PolicyEngine
        engine = PolicyEngine(db_session)
        result = engine.get("sla", severity="critical")
        assert result is None

    def test_specific_scope_beats_global(self, db_session):
        from warlock.domains.policy_engine import PolicyEngine
        engine = PolicyEngine(db_session)
        engine.set_policy(
            policy_type="sla", scope={},
            rules={"remediation_days": 30}, actor="admin@acme.com",
        )
        engine.set_policy(
            policy_type="sla", scope={"severity": ["critical"]},
            rules={"remediation_days": 14}, actor="admin@acme.com",
        )
        result = engine.get("sla", severity="critical")
        assert result.rules["remediation_days"] == 14
        result = engine.get("sla", severity="low")
        assert result.rules["remediation_days"] == 30

    def test_higher_priority_wins(self, db_session):
        from warlock.domains.policy_engine import PolicyEngine
        engine = PolicyEngine(db_session)
        engine.set_policy(
            policy_type="retention",
            scope={"frameworks": ["pci_dss"]},
            rules={"days": 365}, actor="admin@acme.com", priority=0,
        )
        engine.set_policy(
            policy_type="retention",
            scope={"frameworks": ["pci_dss"]},
            rules={"days": 2555}, actor="compliance@acme.com", priority=10,
        )
        result = engine.get("retention", framework="pci_dss")
        assert result.rules["days"] == 2555

    def test_disabled_policies_excluded(self, db_session):
        from warlock.db.models import Policy
        from warlock.domains.policy_engine import PolicyEngine
        engine = PolicyEngine(db_session)
        engine.set_policy(
            policy_type="sla", scope={},
            rules={"remediation_days": 14}, actor="admin@acme.com",
        )
        p = db_session.query(Policy).first()
        p.enabled = False
        db_session.commit()
        result = engine.get("sla")
        assert result is None

    def test_set_policy_creates_history(self, db_session):
        from warlock.db.models import PolicyHistory
        from warlock.domains.policy_engine import PolicyEngine
        engine = PolicyEngine(db_session)
        engine.set_policy(
            policy_type="retention", scope={},
            rules={"days": 365}, actor="admin@acme.com",
        )
        history = db_session.query(PolicyHistory).all()
        assert len(history) == 1
        assert history[0].action == "created"
        assert history[0].actor == "admin@acme.com"

    def test_list_policies(self, db_session):
        from warlock.domains.policy_engine import PolicyEngine
        engine = PolicyEngine(db_session)
        engine.set_policy("sla", {}, {"days": 14}, "admin@acme.com")
        engine.set_policy("retention", {}, {"days": 365}, "admin@acme.com")
        all_policies = engine.list_policies()
        assert len(all_policies) == 2
        sla_only = engine.list_policies(policy_type="sla")
        assert len(sla_only) == 1
