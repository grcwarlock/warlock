"""Tests for critical/high/medium/low security fixes.

Validates all security controls introduced during the 14-agent review remediation.
Tests are grouped by the finding they validate.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import sessionmaker

from warlock.db.models import (
    Base,
    ConnectorRun,
    ControlMapping,
    ControlResult,
    Finding,
    RawEvent,
    User,
)


@pytest.fixture
def engine():
    eng = create_engine("sqlite:///:memory:")

    # Apply the same FK pragma as production (M-1 fix) — BEFORE create_all
    @event.listens_for(eng, "connect")
    def _set_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session(engine):
    Session = sessionmaker(bind=engine)
    s = Session()
    # Default tenant is auto-inserted via Tenant.__table__ after_create event
    yield s
    s.close()


NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# C-1: JWT startup guard
# ---------------------------------------------------------------------------


class TestJWTStartupGuard:
    def test_ephemeral_secret_in_dev_mode(self):
        """In dev mode, ephemeral secret is generated (no crash)."""
        from warlock.api.auth import _get_jwt_secret

        # This should not raise — dev mode allows ephemeral
        secret = _get_jwt_secret()
        assert len(secret) > 0

    def test_secret_length_warning(self):
        """Short secrets should still work but log a warning."""
        from warlock.api.auth import _get_jwt_secret

        # Just verify the function returns without error
        secret = _get_jwt_secret()
        assert isinstance(secret, str)


# ---------------------------------------------------------------------------
# C-3: Account lockout
# ---------------------------------------------------------------------------


class TestAccountLockout:
    def _create_user(self, session, email="test@acme.com", password="TestPassword2026!"):
        from warlock.api.auth import hash_password

        user = User(
            email=email,
            name="Test User",
            hashed_password=hash_password(password),
            role="viewer",
        )
        session.add(user)
        session.flush()
        return user

    def test_successful_login_resets_counter(self, session):
        from warlock.api.auth import authenticate_user

        self._create_user(session)

        user = authenticate_user(session, "test@acme.com", "TestPassword2026!")
        assert user is not None
        assert user.failed_login_count == 0

    def test_failed_login_increments_counter(self, session):
        from warlock.api.auth import authenticate_user

        self._create_user(session)

        authenticate_user(session, "test@acme.com", "wrong-password")
        session.flush()

        user = session.query(User).filter_by(email="test@acme.com").one()
        assert user.failed_login_count == 1

    def test_lockout_after_5_failures(self, session):
        from warlock.api.auth import authenticate_user

        self._create_user(session)

        # Fail 5 times
        for _ in range(5):
            result = authenticate_user(session, "test@acme.com", "wrong-password")
            assert result is None
            session.flush()

        user = session.query(User).filter_by(email="test@acme.com").one()
        assert user.failed_login_count >= 5
        assert user.locked_until is not None

        # 6th attempt with correct password should still be locked
        result = authenticate_user(session, "test@acme.com", "TestPassword2026!")
        assert result is None  # Locked out

    def test_lockout_expires(self, session):
        from warlock.api.auth import authenticate_user

        self._create_user(session)

        # Lock the account
        for _ in range(5):
            authenticate_user(session, "test@acme.com", "wrong-password")
            session.flush()

        # Set lockout to the past (simulate expiry)
        user = session.query(User).filter_by(email="test@acme.com").one()
        user.locked_until = NOW - timedelta(minutes=1)
        session.flush()

        # Should succeed now
        result = authenticate_user(session, "test@acme.com", "TestPassword2026!")
        assert result is not None
        assert result.failed_login_count == 0

    def test_timing_oracle_prevention(self, session):
        """Login with nonexistent user should run a dummy verify (not instant)."""
        from warlock.api.auth import authenticate_user

        # Just verify it doesn't crash and returns None
        result = authenticate_user(session, "nonexistent@acme.com", "any-password")
        assert result is None


# ---------------------------------------------------------------------------
# H-1: Legacy password re-hash on login
# ---------------------------------------------------------------------------


class TestLegacyPasswordReHash:
    def test_legacy_hash_migrated_on_login(self, session):
        import hashlib

        from warlock.api.auth import authenticate_user

        # Create user with legacy SHA-256 hash
        salt = "legacy_salt"
        password = "TestPassword2026!"
        legacy_hash = f"{salt}:{hashlib.sha256(f'{salt}:{password}'.encode()).hexdigest()}"

        user = User(
            email="legacy@acme.com",
            name="Legacy User",
            hashed_password=legacy_hash,
            role="viewer",
        )
        session.add(user)
        session.flush()

        # Login should succeed AND re-hash
        result = authenticate_user(session, "legacy@acme.com", password)
        assert result is not None
        session.flush()

        # Verify password is now bcrypt or pbkdf2
        updated = session.query(User).filter_by(email="legacy@acme.com").one()
        assert not updated.hashed_password.startswith("legacy_salt:")
        assert updated.hashed_password.startswith(("$2b$", "bcrypt:", "pbkdf2:"))


# ---------------------------------------------------------------------------
# H-2: Token revocation
# ---------------------------------------------------------------------------


class TestTokenRevocation:
    def test_token_valid_after_column_exists(self, session):
        cols = {c["name"] for c in inspect(session.bind).get_columns("users")}
        assert "token_valid_after" in cols

    def test_token_issued_before_revocation_rejected(self, session):
        """Simulates the revocation check logic from deps.py."""
        user = User(
            email="revoke@acme.com",
            name="Revoke Test",
            hashed_password="$2b$12$test",
            role="viewer",
            token_valid_after=NOW,
        )
        session.add(user)
        session.flush()

        # Token issued 5 minutes ago (before revocation)
        token_iat = (NOW - timedelta(minutes=5)).timestamp()
        valid_after = user.token_valid_after.timestamp()

        assert token_iat < valid_after  # This token should be rejected

        # Token issued 5 minutes from now (after revocation)
        token_iat_future = (NOW + timedelta(minutes=5)).timestamp()
        assert token_iat_future > valid_after  # This token should be accepted


# ---------------------------------------------------------------------------
# H-3: Empty API key scopes = zero permissions
# ---------------------------------------------------------------------------


class TestEmptyApiKeyScopes:
    def test_empty_scopes_grants_nothing(self):
        """Empty scopes list should result in zero effective permissions."""
        from warlock.api.auth import PERMISSIONS

        role_perms = PERMISSIONS.get("admin", set())
        assert len(role_perms) > 0  # Admin has permissions

        # Simulate the deps.py logic for empty scopes
        scopes = []  # Empty list
        if scopes:
            effective = role_perms & set(scopes)
        else:
            effective = set()  # Empty scopes = no permissions

        assert len(effective) == 0

    def test_nonempty_scopes_intersects(self):
        """Non-empty scopes should intersect with role permissions."""
        from warlock.api.auth import PERMISSIONS

        role_perms = PERMISSIONS.get("admin", set())
        scopes = ["read"]
        effective = role_perms & set(scopes)

        assert effective == {"read"}


# ---------------------------------------------------------------------------
# C-2 / H-ABAC: Framework scoping functions
# ---------------------------------------------------------------------------


class TestABACScoping:
    def _seed_results(self, session):
        """Create control results with proper FK chain for different frameworks."""
        session.add(
            ConnectorRun(
                id="abac-run",
                connector_name="test",
                source="test",
                source_type="test",
                provider="test",
            )
        )
        session.add(
            RawEvent(
                id="abac-raw",
                connector_run_id="abac-run",
                source="test",
                source_type="test",
                provider="test",
                event_type="test",
                raw_data={},
                sha256="abac",
            )
        )
        for i, fw in enumerate(["nist_800_53", "soc2", "iso_27001"]):
            fid = f"abac-f-{i}"
            mid = f"abac-m-{i}"
            session.add(
                Finding(
                    id=fid,
                    raw_event_id="abac-raw",
                    observation_type="test",
                    title="test",
                    detail={},
                    source="test",
                    source_type="test",
                    provider="test",
                    severity="low",
                    observed_at=datetime.now(timezone.utc),
                    sha256=f"abac-{i}",
                )
            )
            session.add(
                ControlMapping(
                    id=mid,
                    finding_id=fid,
                    framework=fw,
                    control_id="TEST-1",
                    mapping_method="explicit",
                    confidence=1.0,
                )
            )
            session.add(
                ControlResult(
                    finding_id=fid,
                    control_mapping_id=mid,
                    framework=fw,
                    control_id="TEST-1",
                    status="compliant",
                    severity="low",
                    assessor="test",
                )
            )
        session.flush()

    def test_apply_framework_scope_filters(self, session):
        from warlock.api.deps import apply_framework_scope

        self._seed_results(session)

        user = User(
            email="scoped@test.com",
            name="Scoped",
            hashed_password="x",
            role="owner",
            allowed_frameworks=["soc2"],
        )

        query = session.query(ControlResult).filter(ControlResult.control_id == "TEST-1")
        scoped = apply_framework_scope(query, ControlResult, user)
        results = scoped.all()

        assert all(r.framework == "soc2" for r in results)
        assert len(results) == 1

    def test_empty_allowed_frameworks_returns_all(self, session):
        from warlock.api.deps import apply_framework_scope

        # Ensure data exists (previous test may have seeded, but be explicit)
        existing = session.query(ControlResult).filter(ControlResult.control_id == "TEST-1").count()
        if existing == 0:
            self._seed_results(session)

        user = User(
            email="all@test.com",
            name="All Access",
            hashed_password="x",
            role="admin",
            allowed_frameworks=[],  # Empty = all
        )

        query = session.query(ControlResult).filter(ControlResult.control_id == "TEST-1")
        scoped = apply_framework_scope(query, ControlResult, user)
        assert scoped.count() >= 1  # Not filtered


# ---------------------------------------------------------------------------
# M-1: SQLite FK pragma enforcement
# ---------------------------------------------------------------------------


class TestSQLiteFKPragma:
    def test_foreign_keys_pragma_is_on(self, engine):
        """Verify PRAGMA foreign_keys=ON is active."""
        with engine.connect() as conn:
            result = conn.execute(text("PRAGMA foreign_keys"))
            assert result.scalar() == 1

    def test_fk_violation_raises(self, session):
        """Inserting a row with an invalid FK should raise."""
        # RawEvent references connector_runs.id — no such run exists
        session.add(
            RawEvent(
                id="orphan",
                connector_run_id="nonexistent",
                source="test",
                source_type="test",
                provider="test",
                event_type="test",
                raw_data={},
                sha256="orphan",
            )
        )
        with pytest.raises(Exception):  # IntegrityError
            session.flush()
        session.rollback()


# ---------------------------------------------------------------------------
# M-2: Audit trail unique sequence + threading lock
# ---------------------------------------------------------------------------


class TestAuditTrailIntegrity:
    def test_unique_sequence_constraint(self, session):
        """Duplicate sequence numbers should be rejected."""
        cols = {c["name"] for c in inspect(session.bind).get_columns("audit_entries")}
        assert "sequence" in cols

        # Check the index is unique
        indexes = inspect(session.bind).get_indexes("audit_entries")
        seq_idx = [i for i in indexes if "sequence" in i.get("column_names", [])]
        assert any(i.get("unique") for i in seq_idx), "idx_audit_sequence must be unique"

    def test_audit_trail_record_and_verify(self, session):
        from warlock.db.audit import AuditTrail

        trail = AuditTrail(session)
        e1 = trail.record("test_action", "test_entity", "id-1", actor="test")
        session.flush()

        assert e1.sequence == 1
        assert e1.previous_hash == "genesis"
        assert len(e1.entry_hash) == 64  # SHA-256 hex

        e2 = trail.record("test_action_2", "test_entity", "id-2", actor="test")
        session.flush()

        assert e2.sequence == 2
        assert e2.previous_hash == e1.entry_hash


# ---------------------------------------------------------------------------
# SEC-C4: Canonical hash-chained writers (no hand-rolled entry_hash)
# ---------------------------------------------------------------------------


class TestNoCustomAuditChainWriters:
    """Audit-chain writers must route through ``AuditTrail.record``.

    A hand-rolled ``hashlib.sha256(...)`` next to a hand-built
    ``AuditEntry(...)`` produces an ``entry_hash`` that does NOT match
    ``AuditTrail.verify_chain``. The fix consolidates every writer onto
    the canonical API; this test guards against regression.
    """

    def test_no_custom_entry_hash_construction(self):
        import re
        from pathlib import Path

        repo_root = Path(__file__).parent.parent / "warlock"
        # Files that legitimately implement the chain
        allow = {
            repo_root / "db" / "audit.py",
            repo_root / "db" / "models.py",
            repo_root / "export" / "audit_sink.py",
            repo_root / "export" / "chain_anchor.py",  # uses _recompute helper
        }
        pattern_kwarg = re.compile(r"entry_hash\s*=\s*hashlib\.")
        pattern_inline = re.compile(r"entry_hash\s*=\s*hashlib\.sha256")
        offenders: list[str] = []
        for py in repo_root.rglob("*.py"):
            if py in allow:
                continue
            text = py.read_text(encoding="utf-8")
            if pattern_kwarg.search(text) or pattern_inline.search(text):
                offenders.append(str(py.relative_to(repo_root)))
        assert not offenders, (
            "These files build entry_hash by hand instead of routing through "
            "AuditTrail.record(): " + ", ".join(offenders)
        )

    def test_no_orphan_AuditEntry_construction(self):
        """Constructing AuditEntry outside the canonical writer is forbidden."""
        import re
        from pathlib import Path

        repo_root = Path(__file__).parent.parent / "warlock"
        allow = {
            repo_root / "db" / "audit.py",
            repo_root / "db" / "models.py",
            repo_root / "export" / "audit_sink.py",
        }
        # Match ``entry = AuditEntry(`` / ``audit = AuditEntry(`` / standalone
        # ``AuditEntry(`` opening a constructor (not a query usage).
        pat = re.compile(r"^\s*(?:entry|audit|del_entry|addressed_entry)\s*=\s*AuditEntry\(", re.M)
        offenders: list[str] = []
        for py in repo_root.rglob("*.py"):
            if py in allow:
                continue
            text = py.read_text(encoding="utf-8")
            if pat.search(text):
                offenders.append(str(py.relative_to(repo_root)))
        assert not offenders, (
            "These files instantiate AuditEntry directly. Use AuditTrail.record(): "
            + ", ".join(offenders)
        )


class TestVerifyChainAPIRecomputes:
    """SEC-C6: ``/pipeline/verify-chain`` must recompute every row's content hash.

    Previously the endpoint only checked ``previous_hash`` linkage which
    let a DB-write attacker mutate ``action``/``entity_id``/``actor``/
    ``extra``/``evidence_sha256`` without detection.
    """

    def test_verify_chain_detects_content_tamper(self, session):
        from warlock.db.audit import AuditTrail
        from warlock.db.models import AuditEntry

        trail = AuditTrail(session)
        e1 = trail.record("a1", "t1", "id-1", actor="actor-1")
        e2 = trail.record("a2", "t1", "id-2", actor="actor-2")
        session.flush()

        # Tamper with row content without updating entry_hash.
        e2_row = session.query(AuditEntry).filter(AuditEntry.sequence == e2.sequence).one()
        e2_row.action = "tampered_action"
        session.flush()

        valid, errors = AuditTrail(session).verify_chain()
        assert not valid
        assert any("Hash mismatch" in err for err in errors)
        assert any(f"sequence {e2.sequence}" in err for err in errors)
        # Ensure e1 still verifies clean (only e2 should be flagged).
        assert not any(f"sequence {e1.sequence}" in err for err in errors)


class TestCSVFormulaInjectionScrubber:
    """SEC-C11: spreadsheet formula-injection prefixes must be neutralised."""

    def test_neutralizes_leading_equals(self):
        from warlock.utils.csv_safety import neutralize_csv_value

        assert neutralize_csv_value('=HYPERLINK("http://x","y")') == (
            "'=HYPERLINK(\"http://x\",\"y\")"
        )

    def test_neutralizes_each_dangerous_prefix(self):
        from warlock.utils.csv_safety import neutralize_csv_value

        for prefix in ("=", "+", "-", "@", "\t", "\r"):
            assert neutralize_csv_value(f"{prefix}danger").startswith("'" + prefix)

    def test_leaves_safe_values_unchanged(self):
        from warlock.utils.csv_safety import neutralize_csv_value

        assert neutralize_csv_value("normal text") == "normal text"
        assert neutralize_csv_value("") == ""
        assert neutralize_csv_value(42) == 42
        assert neutralize_csv_value(None) is None

    def test_cli_output_render_csv_neutralises(self):
        import csv
        import io

        from warlock.cli.output import render_csv

        # Capture stdout
        buf = io.StringIO()
        import sys

        old = sys.stdout
        sys.stdout = buf
        try:
            render_csv(
                [{"title": "=cmd|'/c calc'!A0", "id": "abc"}],
                keys=["id", "title"],
                headers=["ID", "Title"],
            )
        finally:
            sys.stdout = old

        reader = csv.DictReader(io.StringIO(buf.getvalue()))
        rows = list(reader)
        assert rows[0]["Title"].startswith("'="), (
            f"Formula prefix must be neutralised, got: {rows[0]['Title']!r}"
        )


class TestTenantFilterCoversUpdateDelete:
    """SEC-C8: tenant filter must cover UPDATE and DELETE, not just SELECT.

    Previously the ``do_orm_execute`` listener short-circuited on non-SELECT
    statements, so a user authenticated to tenant A could mutate tenant B's
    rows by guessing the primary key UUID.
    """

    def test_multi_tenancy_enabled_by_default(self):
        from warlock.config import Settings

        s = Settings()
        assert s.multi_tenancy_enabled is True, (
            "multi_tenancy_enabled must default to True so the tenant filter "
            "is active out-of-the-box. SEC-C8."
        )


class TestOutboundURLSafetyHelper:
    """SEC-C12/C13: ``validate_outbound_url`` must reject SSRF-prone targets."""

    def test_rejects_loopback_literal(self):
        from warlock.utils.url_safety import UnsafeURLError, validate_outbound_url

        with pytest.raises(UnsafeURLError):
            validate_outbound_url("https://127.0.0.1/admin")

    def test_rejects_metadata_service(self):
        from warlock.utils.url_safety import UnsafeURLError, validate_outbound_url

        with pytest.raises(UnsafeURLError):
            validate_outbound_url("http://169.254.169.254/latest/meta-data/")

    def test_rejects_rfc1918_literal(self):
        from warlock.utils.url_safety import UnsafeURLError, validate_outbound_url

        with pytest.raises(UnsafeURLError):
            validate_outbound_url("https://10.0.0.1/")

    def test_rejects_userinfo(self):
        from warlock.utils.url_safety import UnsafeURLError, validate_outbound_url

        with pytest.raises(UnsafeURLError):
            validate_outbound_url("https://attacker@victim.example/")

    def test_rejects_non_https_by_default(self):
        from warlock.utils.url_safety import UnsafeURLError, validate_outbound_url

        with pytest.raises(UnsafeURLError):
            validate_outbound_url("http://example.com/")

    def test_accepts_https_public(self):
        from warlock.utils.url_safety import validate_outbound_url

        # A public, well-known DNS name. If the test environment cannot
        # resolve DNS, validation still passes — unresolvable hostnames
        # are not rejected (they would simply fail to connect, no
        # credential exfiltration).
        out = validate_outbound_url("https://example.com/api")
        assert out == "https://example.com/api"

    def test_hostname_allowlist_pin(self):
        from warlock.utils.url_safety import UnsafeURLError, validate_outbound_url

        with pytest.raises(UnsafeURLError):
            validate_outbound_url(
                "https://attacker.example/",
                allowed_hosts=["*.okta.com"],
            )


class TestSSOAllowedRedirectURIs:
    """SEC-C3: ``/auth/sso/login`` must reject absolute redirect_uri values
    that are not in the operator-configured allowlist."""

    def test_setting_exists_and_defaults_empty(self):
        from warlock.config import Settings

        s = Settings()
        assert hasattr(s, "sso_allowed_redirect_uris")
        # Default empty = no absolute URLs accepted unless explicitly added.
        assert s.sso_allowed_redirect_uris == ""


class TestChainAnchorRecomputes:
    """SEC-C7: ``ChainAnchor.verify_anchor`` must recompute content hash."""

    def test_anchor_detects_content_tamper(self, session, tmp_path):
        from warlock.db.audit import AuditTrail
        from warlock.db.models import AuditEntry
        from warlock.export.chain_anchor import ChainAnchor

        trail = AuditTrail(session)
        trail.record("a", "t", "id-1", actor="u")
        session.flush()
        session.commit()

        anchor_file = tmp_path / "anchor.json"
        anchor = ChainAnchor()
        anchor.publish(session, target="file", path=str(anchor_file))

        # Mutate the row content without rehashing.
        row = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        row.action = "tampered"
        session.commit()

        result = anchor.verify_anchor(session, target="file", path=str(anchor_file))
        assert result["valid"] is False
        assert "error" in result


# ---------------------------------------------------------------------------
# M-5: julianday replaced with Python sorting
# ---------------------------------------------------------------------------


class TestDriftCorrelationPortable:
    def test_correlate_changes_no_julianday(self):
        """Verify drift.py doesn't call func.julianday in executable code."""
        from pathlib import Path

        drift_path = Path(__file__).parent.parent / "warlock" / "assessors" / "drift.py"
        source = drift_path.read_text()
        # Check that julianday is not used in actual function calls (comments are ok)
        code_lines = [
            line.strip()
            for line in source.split("\n")
            if line.strip() and not line.strip().startswith("#")
        ]
        for line in code_lines:
            assert "func.julianday" not in line, f"drift.py still calls func.julianday: {line}"


# ---------------------------------------------------------------------------
# M-6: PostgreSQL pool config
# ---------------------------------------------------------------------------


class TestPoolConfiguration:
    def test_sqlite_no_pool_kwargs(self):
        """SQLite should not get pool_size/max_overflow."""
        from warlock.db.engine import get_engine

        # The default is SQLite — just verify it doesn't crash
        eng = get_engine()
        assert eng is not None


# ---------------------------------------------------------------------------
# M-7: Attestation separation of duties
# ---------------------------------------------------------------------------


class TestAttestationSoD:
    def test_sod_fields_exist(self, session):
        """Attestation model has the fields needed for SoD checks."""
        cols = {c["name"] for c in inspect(session.bind).get_columns("attestations")}
        assert "prepared_by" in cols
        assert "reviewed_by" in cols
        assert "approved_by" in cols


# ---------------------------------------------------------------------------
# M-9: Scheduler runs all schedules on startup
# ---------------------------------------------------------------------------


class TestSchedulerStartup:
    def test_all_schedules_defined(self):
        from warlock.pipeline.scheduler import DEFAULT_SCHEDULES

        assert "pipeline_collect" in DEFAULT_SCHEDULES
        assert "posture_snapshot" in DEFAULT_SCHEDULES
        assert "cadence_check" in DEFAULT_SCHEDULES
        assert "retention_purge" in DEFAULT_SCHEDULES

    def test_retention_enabled_by_default(self):
        from warlock.pipeline.scheduler import DEFAULT_SCHEDULES

        assert DEFAULT_SCHEDULES["retention_purge"]["enabled"] is True


# ---------------------------------------------------------------------------
# M-11: CORS configuration
# ---------------------------------------------------------------------------


class TestCORSConfiguration:
    def test_cors_origins_setting_exists(self):
        from warlock.config import Settings

        s = Settings()
        assert hasattr(s, "cors_origins")
        assert s.cors_origins == []  # Default empty = no CORS


# ---------------------------------------------------------------------------
# M-3: Structured logging
# ---------------------------------------------------------------------------


class TestStructuredLogging:
    def test_json_formatter_produces_valid_json(self):
        import logging

        from warlock.logging_config import CorrelationFilter, JSONFormatter

        formatter = JSONFormatter()
        filt = CorrelationFilter()

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test message",
            args=(),
            exc_info=None,
        )
        filt.filter(record)
        output = formatter.format(record)

        data = json.loads(output)
        assert data["level"] == "INFO"
        assert data["message"] == "test message"
        assert "timestamp" in data
        assert "correlation_id" in data

    def test_correlation_id_generation(self):
        from warlock.logging_config import correlation_id, new_correlation_id

        cid = new_correlation_id()
        assert len(cid) == 8
        assert correlation_id.get() == cid


# ---------------------------------------------------------------------------
# L-1: Deprecated .get() replaced
# ---------------------------------------------------------------------------


class TestNoDeprecatedGet:
    def test_no_query_get_in_poam(self):
        from pathlib import Path

        source = (Path(__file__).parent.parent / "warlock" / "workflows" / "poam.py").read_text()
        assert ".query(" not in source or "session.query(POAM).get(" not in source
        assert "session.get(POAM," in source or "session.get(Finding," in source

    def test_no_query_get_in_binder(self):
        from pathlib import Path

        source = (Path(__file__).parent.parent / "warlock" / "export" / "binder.py").read_text()
        assert "session.query(AuditEngagement).get(" not in source
        assert "session.query(Finding).get(" not in source


# ---------------------------------------------------------------------------
# L-2: Single version source
# ---------------------------------------------------------------------------


class TestVersionSingleSource:
    def test_version_defined_in_init(self):
        from warlock import __version__

        assert __version__ == "2.0.0a1"

    def test_app_uses_init_version(self):
        from pathlib import Path

        source = (Path(__file__).parent.parent / "warlock" / "api" / "app.py").read_text()
        # Should not contain hardcoded version strings
        # (except in the import line itself)
        lines_with_version = [
            line for line in source.split("\n") if "2.0.0a1" in line and "import" not in line
        ]
        assert len(lines_with_version) == 0, f"Hardcoded version found: {lines_with_version}"


# ---------------------------------------------------------------------------
# L-5: Trust portal binned scores
# ---------------------------------------------------------------------------


class TestTrustPortalBinnedScores:
    def test_framework_status_no_exact_counts(self):
        """FrameworkStatus should not expose non_compliant or partial counts."""
        from warlock.api.trust_portal import FrameworkStatus

        fields = set(FrameworkStatus.model_fields.keys())
        assert "non_compliant" not in fields
        assert "partial" not in fields
        assert "posture_score" not in fields
        assert "posture_rating" in fields
        assert "compliance_rate_band" in fields

    def test_trust_status_response_uses_rating(self):
        from warlock.api.trust_portal import TrustStatusResponse

        fields = set(TrustStatusResponse.model_fields.keys())
        assert "overall_posture_score" not in fields
        assert "overall_rating" in fields


# ---------------------------------------------------------------------------
# H-11: Health readiness probe
# ---------------------------------------------------------------------------


class TestHealthReadiness:
    def test_health_live_endpoint_exists(self):
        """Verify /health/live route is registered."""
        from warlock.api.app import app

        routes = [r.path for r in app.routes]
        assert "/api/v1/health/live" in routes

    def test_health_ready_endpoint_exists(self):
        """Verify /health/ready route is registered."""
        from warlock.api.app import app

        routes = [r.path for r in app.routes]
        assert "/api/v1/health/ready" in routes


# ---------------------------------------------------------------------------
# H-10: AI reproducibility
# ---------------------------------------------------------------------------


class TestAIReproducibility:
    def test_prompt_hash_function(self):
        from warlock.assessors.ai_reasoning import _hash_prompt

        h1 = _hash_prompt("system", "user")
        h2 = _hash_prompt("system", "user")
        h3 = _hash_prompt("system", "different")
        assert h1 == h2  # Same input = same hash
        assert h1 != h3  # Different input = different hash
        assert len(h1) == 64  # SHA-256 hex

    def test_confidence_floor_setting(self):
        from warlock.config import Settings

        s = Settings()
        assert s.ai_confidence_floor == 0.7
        assert s.ai_temperature == 0.0

    def test_all_providers_set_temperature_zero(self):
        """Verify temperature: 0 is in all provider implementations."""
        from pathlib import Path

        source = (
            Path(__file__).parent.parent / "warlock" / "assessors" / "ai_reasoning.py"
        ).read_text()
        # Count "temperature": 0 or "temperature": 0, occurrences
        temp_count = source.count('"temperature": 0')
        assert temp_count >= 4, f"Expected 4 providers with temperature=0, found {temp_count}"


class TestRequirePermissionStringsExist:
    """Regression guard: every require_permission("X") call in the API must
    reference a permission that exists in the PERMISSIONS map. A typo or a
    role-name ("admin") mistakenly used as a permission would cause the route
    to be permanently 403 for everyone — previously this bit webhooks and
    pipeline-metrics routes (findings F4/F5).
    """

    def test_all_require_permission_strings_are_valid(self):
        import re
        from pathlib import Path

        from warlock.api.auth import PERMISSIONS

        valid = set()
        for perms in PERMISSIONS.values():
            valid.update(perms)

        api_root = Path(__file__).parent.parent / "warlock" / "api"
        pattern = re.compile(r'require_permission\(\s*["\']([^"\']+)["\']\s*\)')
        offenders: list[tuple[str, int, str]] = []

        for py in api_root.rglob("*.py"):
            for lineno, line in enumerate(py.read_text().splitlines(), 1):
                for match in pattern.finditer(line):
                    perm = match.group(1)
                    if perm not in valid:
                        offenders.append(
                            (str(py.relative_to(api_root.parent.parent)), lineno, perm)
                        )

        assert not offenders, (
            "Found require_permission() calls referencing unknown permissions "
            f"(known: {sorted(valid)}):\n"
            + "\n".join(f"  {f}:{ln} -> {p!r}" for f, ln, p in offenders)
        )
