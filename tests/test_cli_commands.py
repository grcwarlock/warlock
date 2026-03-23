"""CLI command smoke tests.

H-10: Verifies that CLI command groups invoke without crashing against
a seeded test database. These are NOT deep behavioral tests — they verify
that imports resolve, DB queries execute, and output renders without
exceptions.

Groups with invoke_without_command=True show a default summary view.
Groups without it show help text. Both should exit 0.

Subcommands that require arguments are tested with minimal valid inputs.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from warlock.cli import cli


@pytest.fixture(autouse=True)
def _test_db(tmp_path, monkeypatch):
    """Set up a file-based test DB with seeded data for all CLI tests."""
    import warlock.db.engine as eng

    db_path = tmp_path / "test.db"
    monkeypatch.setenv("WLK_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("WLK_JWT_SECRET", "test-secret-key-that-is-at-least-32-characters-long")
    monkeypatch.setenv("WLK_GDPR_HMAC_SECRET", "test-gdpr-hmac-secret-at-least-32-chars-long")
    monkeypatch.setenv("WLK_ENV", "development")

    eng._engine = None
    eng._read_engine = None
    eng._session_factory = None
    eng._read_session_factory = None
    eng.init_db()

    # Seed minimal data so commands that query the DB don't crash on empty tables
    from warlock.db.engine import get_session
    from tests.conftest import seed_full_chain, seed_user

    with get_session() as session:
        seed_full_chain(session)
        # Only seed user if init_db() didn't already create one
        from warlock.db.models import User

        if not session.query(User).filter_by(email="admin@test.com").first():
            seed_user(session, email="admin@test.com", name="Admin", role="admin")
        session.commit()

    yield

    eng._engine = None
    eng._read_engine = None
    eng._session_factory = None
    eng._read_session_factory = None


@pytest.fixture
def runner():
    return CliRunner()


# ---------------------------------------------------------------------------
# Top-level command: warlock (no subcommand shows help)
# ---------------------------------------------------------------------------


class TestTopLevel:
    def test_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Warlock" in result.output


# ---------------------------------------------------------------------------
# Groups with invoke_without_command=True (show default summary)
# ---------------------------------------------------------------------------


class TestGroupsWithDefaults:
    """Groups that show a useful summary when invoked without a subcommand."""

    @pytest.mark.parametrize(
        "group",
        [
            "findings",
            "connectors",
            "assertions",
            "attestations",
            "training",
            "exceptions",
            "sod",
            "risk",
            "ai",
        ],
    )
    def test_group_default_view(self, runner, group):
        result = runner.invoke(cli, [group])
        # Should exit 0 and produce output (not crash)
        assert result.exit_code == 0, (
            f"{group} failed: {result.output}\n{result.stderr if hasattr(result, 'stderr') else ''}"
        )


# ---------------------------------------------------------------------------
# Groups that show help when invoked without subcommand
# ---------------------------------------------------------------------------


class TestGroupsShowHelp:
    """Groups that show help text when invoked without a subcommand."""

    @pytest.mark.parametrize(
        "group",
        [
            "pipeline",
            "lake",
            "issues",
            "poams",
            "incidents",
            "evidence",
            "privacy",
            "calendar",
        ],
    )
    def test_group_help(self, runner, group):
        result = runner.invoke(cli, [group, "--help"])
        assert result.exit_code == 0
        assert "Usage" in result.output


# ---------------------------------------------------------------------------
# Core commands — functional smoke tests
# ---------------------------------------------------------------------------


class TestCoreCommands:
    """Test core commands that every user runs."""

    def test_results(self, runner):
        result = runner.invoke(cli, ["results", "--limit", "5"])
        assert result.exit_code == 0

    def test_coverage(self, runner):
        result = runner.invoke(cli, ["coverage"])
        assert result.exit_code == 0

    def test_findings_default(self, runner):
        """findings group with invoke_without_command shows summary."""
        result = runner.invoke(cli, ["findings"])
        assert result.exit_code == 0

    def test_connectors_default(self, runner):
        result = runner.invoke(cli, ["connectors"])
        assert result.exit_code == 0

    def test_assertions_default(self, runner):
        result = runner.invoke(cli, ["assertions"])
        assert result.exit_code == 0

    def test_frameworks_help(self, runner):
        result = runner.invoke(cli, ["frameworks", "--help"])
        assert result.exit_code == 0

    def test_audit_trail_help(self, runner):
        result = runner.invoke(cli, ["audit-trail", "--help"])
        assert result.exit_code == 0

    def test_users_help(self, runner):
        result = runner.invoke(cli, ["users", "--help"])
        assert result.exit_code == 0

    def test_reports_help(self, runner):
        result = runner.invoke(cli, ["reports", "--help"])
        assert result.exit_code == 0

    def test_vendors_help(self, runner):
        result = runner.invoke(cli, ["vendors", "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Workflow CLI modules
# ---------------------------------------------------------------------------


class TestWorkflowCommands:
    """Test Phase 2 workflow commands."""

    @pytest.mark.parametrize(
        "group",
        [
            "access-review",
            "control-tests",
            "bcp",
            "audit-trail",
            "compensating-controls",
            "risk-acceptances",
        ],
    )
    def test_workflow_group_help(self, runner, group):
        result = runner.invoke(cli, [group, "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Phase 3 expansion commands
# ---------------------------------------------------------------------------


class TestExpansionCommands:
    """Test Phase 3 CLI expansion modules."""

    @pytest.mark.parametrize(
        "group",
        [
            "policies",
            "oscal",
            "vulns",
            "conmon",
            "poam",
            "terraform",
            "integrations",
            "frameworks",
            "users",
            "vendors",
            "reports",
        ],
    )
    def test_expansion_group_help(self, runner, group):
        result = runner.invoke(cli, [group, "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Analytics / AI / Automation commands
# ---------------------------------------------------------------------------


class TestAnalyticsCommands:
    """Test Phase 3+ analytics and automation commands."""

    @pytest.mark.parametrize(
        "group",
        [
            "correlate",
            "risk-engine",
            "comply",
            "lake-analytics",
            "dashboard",
            "ai-ops",
            "automation",
            "investigate",
        ],
    )
    def test_analytics_group_help(self, runner, group):
        result = runner.invoke(cli, [group, "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Interactive workflow commands
# ---------------------------------------------------------------------------


class TestInteractiveWorkflows:
    """Test interactive workflow commands (help only — they prompt for input)."""

    @pytest.mark.parametrize(
        "group",
        [
            "vendor-mgmt",
            "incident-response",
            "privacy-ops",
            "audit-prep",
            "risk-review",
            "daily",
            "onboard-system",
            "change-submit",
            "training-drive",
            "exception-review",
            "conmon-monthly",
            "evidence-collection",
        ],
    )
    def test_interactive_workflow_help(self, runner, group):
        result = runner.invoke(cli, [group, "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Standalone commands (not groups)
# ---------------------------------------------------------------------------


class TestStandaloneCommands:
    """Test standalone top-level commands."""

    def test_briefing(self, runner):
        result = runner.invoke(cli, ["briefing"])
        assert result.exit_code == 0

    def test_control_hub_help(self, runner):
        # control-hub requires a control_id argument
        result = runner.invoke(cli, ["control-hub", "--help"])
        assert result.exit_code == 0

    def test_policy_list(self, runner):
        result = runner.invoke(cli, ["policy", "list"])
        assert result.exit_code == 0
