"""GAP-071: Tests for critical paths — hash chain, POA&M state machine,
GDPR erasure, and ABAC.

Uses in-memory SQLite with the init_db pattern from existing tests.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, StaticPool
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("WLK_JWT_SECRET", "test-secret-key-that-is-at-least-32-characters-long")
os.environ.setdefault("WLK_ENV", "development")
os.environ.setdefault("WLK_DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("WLK_GDPR_HMAC_SECRET", "test-gdpr-hmac-secret-at-least-32-chars-long")

from warlock.db.models import (  # noqa: E402
    Base,
    POAM,
    User,
)


def _uuid() -> str:
    return str(uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()


# ---------------------------------------------------------------------------
# Hash Chain Integrity
# ---------------------------------------------------------------------------


class TestHashChainIntegrity:
    """Verify the audit trail hash chain is tamper-evident."""

    def test_genesis_entry(self, db_session):
        """First entry has previous_hash='genesis'."""
        from warlock.db.audit import AuditTrail

        trail = AuditTrail(db_session)
        entry = trail.record(
            action="test_action",
            entity_type="test",
            entity_id="id-1",
            actor="test",
        )

        assert entry.previous_hash == "genesis"
        assert entry.sequence == 1
        assert entry.entry_hash  # non-empty

    def test_chain_links_correctly(self, db_session):
        """Second entry's previous_hash matches first entry's entry_hash."""
        from warlock.db.audit import AuditTrail

        trail = AuditTrail(db_session)
        first = trail.record(
            action="action_1",
            entity_type="test",
            entity_id="id-1",
            actor="test",
        )
        second = trail.record(
            action="action_2",
            entity_type="test",
            entity_id="id-2",
            actor="test",
        )

        assert second.previous_hash == first.entry_hash
        assert second.sequence == 2

    def test_hash_is_deterministic(self, db_session):
        """Entry hash can be recomputed from stored fields."""
        from warlock.db.audit import AuditTrail

        trail = AuditTrail(db_session)
        entry = trail.record(
            action="deterministic_test",
            entity_type="finding",
            entity_id="f-1",
            actor="pipeline",
            evidence_sha256="abc123",
        )

        content = json.dumps(
            {
                "sequence": entry.sequence,
                "previous_hash": entry.previous_hash,
                "action": entry.action,
                "entity_type": entry.entity_type,
                "entity_id": entry.entity_id,
                "actor": entry.actor,
                "evidence_sha256": entry.evidence_sha256 or "",
            },
            sort_keys=True,
        )
        expected_hash = hashlib.sha256(content.encode()).hexdigest()
        assert entry.entry_hash == expected_hash

    def test_three_entry_chain(self, db_session):
        """Three entries form a valid chain."""
        from warlock.db.audit import AuditTrail

        trail = AuditTrail(db_session)
        entries = []
        for i in range(3):
            e = trail.record(
                action=f"action_{i}",
                entity_type="test",
                entity_id=f"id-{i}",
                actor="test",
            )
            entries.append(e)

        assert entries[0].previous_hash == "genesis"
        assert entries[1].previous_hash == entries[0].entry_hash
        assert entries[2].previous_hash == entries[1].entry_hash


# ---------------------------------------------------------------------------
# POA&M State Machine
# ---------------------------------------------------------------------------


class TestPOAMStateMachine:
    """Verify POA&M transitions follow the state machine rules."""

    def _create_poam(self, session, status="draft") -> POAM:
        poam = POAM(
            id=_uuid(),
            framework="nist_800_53",
            control_id="AC-2",
            weakness_description="Test weakness",
            severity="high",
            status=status,
            scheduled_completion=_utcnow() + timedelta(days=60),
        )
        session.add(poam)
        session.flush()
        return poam

    def test_valid_transition_draft_to_open(self, db_session):
        from warlock.workflows.poam import POAMManager

        poam = self._create_poam(db_session, status="draft")
        mgr = POAMManager()
        result = mgr.transition(db_session, poam.id, "open", actor="test")
        assert result.status == "open"

    def test_valid_transition_chain(self, db_session):
        from warlock.workflows.poam import POAMManager

        poam = self._create_poam(db_session, status="draft")
        mgr = POAMManager()

        # Walk the full happy path
        mgr.transition(db_session, poam.id, "open", actor="test")
        mgr.transition(db_session, poam.id, "in_progress", actor="test")
        mgr.transition(db_session, poam.id, "remediated", actor="test")
        mgr.transition(db_session, poam.id, "verified", actor="test")
        mgr.transition(db_session, poam.id, "completed", actor="test")
        assert poam.status == "completed"

    def test_invalid_transition_raises(self, db_session):
        from warlock.workflows.poam import POAMManager

        poam = self._create_poam(db_session, status="draft")
        mgr = POAMManager()

        # draft -> completed is not valid
        with pytest.raises(ValueError, match="Cannot transition"):
            mgr.transition(db_session, poam.id, "completed", actor="test")

    def test_any_state_target_risk_accepted(self, db_session):
        from warlock.workflows.poam import POAMManager

        poam = self._create_poam(db_session, status="in_progress")
        mgr = POAMManager()

        # risk_accepted is reachable from any state
        result = mgr.transition(db_session, poam.id, "risk_accepted", actor="ao")
        assert result.status == "risk_accepted"

    def test_any_state_target_cancelled(self, db_session):
        from warlock.workflows.poam import POAMManager

        poam = self._create_poam(db_session, status="open")
        mgr = POAMManager()
        result = mgr.transition(db_session, poam.id, "cancelled", actor="test")
        assert result.status == "cancelled"

    def test_nonexistent_poam_raises(self, db_session):
        from warlock.workflows.poam import POAMManager

        mgr = POAMManager()
        with pytest.raises(ValueError, match="not found"):
            mgr.transition(db_session, "nonexistent-id", "open", actor="test")


# ---------------------------------------------------------------------------
# GDPR Erasure
# ---------------------------------------------------------------------------


class TestGDPRErasure:
    """Verify GDPR anonymization replaces PII with REDACTED tokens."""

    def _seed_user(self, session, email="victim@example.com") -> User:
        from warlock.api.auth import hash_password

        user = User(
            id=_uuid(),
            email=email,
            name="Victim User",
            role="viewer",
            hashed_password=hash_password("testpass123"),
            is_active=True,
            created_at=_utcnow(),
        )
        session.add(user)
        session.flush()
        return user

    def test_erasure_anonymizes_user_fields(self, db_session):
        from warlock.workflows.gdpr import GDPRManager

        user = self._seed_user(db_session)
        original_email = user.email

        mgr = GDPRManager()
        result = mgr.erase_subject_data(db_session, original_email, erased_by="test")

        # User should be anonymized
        assert "user" in result["affected"]
        assert user.email.startswith("[REDACTED-")
        assert user.name.startswith("[REDACTED-")
        assert user.is_active is False
        assert user.email != original_email

    def test_erasure_is_idempotent(self, db_session):
        from warlock.workflows.gdpr import GDPRManager

        user = self._seed_user(db_session)
        email = user.email

        mgr = GDPRManager()
        mgr.erase_subject_data(db_session, email, erased_by="test")
        # Second call with the same email finds no match (already anonymized)
        result2 = mgr.erase_subject_data(db_session, email, erased_by="test")

        # Second result should have no new affected records
        assert result2["affected"] == {} or result2.get("idempotent") is True


# ---------------------------------------------------------------------------
# ABAC / Policy Gate
# ---------------------------------------------------------------------------


class TestABAC:
    """Test ABAC role-permission checks from the policy gate."""

    def test_health_endpoints_bypass_policy(self):
        from warlock.api.policy_gate import _is_health_endpoint

        assert _is_health_endpoint("/health") is True
        assert _is_health_endpoint("/healthz") is True
        assert _is_health_endpoint("/readyz") is True
        assert _is_health_endpoint("/api/v1/health") is True  # ends with /health
        assert _is_health_endpoint("/api/v1/findings") is False

    def test_policy_gate_fail_closed_default(self):
        from warlock.api.policy_gate import PolicyGate

        gate = PolicyGate(opa_url="http://localhost:9999/v1/data/warlock/allow")
        assert gate.fail_mode == "closed"
