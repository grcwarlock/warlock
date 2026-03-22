"""CLI integration tests for domain commands."""

from click.testing import CliRunner
from warlock.cli import cli
import pytest


@pytest.fixture(autouse=True)
def _use_test_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("WLK_DATABASE_URL", f"sqlite:///{db_path}")
    import warlock.db.engine as eng
    eng._engine = None
    eng._read_engine = None
    eng._session_factory = None
    eng._read_session_factory = None
    from warlock.db.engine import init_db
    init_db()
    yield
    eng._engine = None
    eng._read_engine = None
    eng._session_factory = None
    eng._read_session_factory = None


class TestPolicyCLI:
    def test_policy_list_empty(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["policy", "list"])
        assert result.exit_code == 0

    def test_policy_set_sla(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "policy", "set", "sla",
            "--severity", "critical",
            "--remediation-days", "14",
            "--escalate-after", "7",
        ])
        assert result.exit_code == 0
        assert "created" in result.output.lower() or "policy" in result.output.lower()
        result = runner.invoke(cli, ["policy", "list"])
        assert "sla" in result.output.lower()

    def test_policy_set_retention(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "policy", "set", "retention",
            "--framework", "pci_dss",
            "--days", "2555",
        ])
        assert result.exit_code == 0

    def test_policy_history(self):
        runner = CliRunner()
        runner.invoke(cli, ["policy", "set", "sla", "--severity", "critical", "--remediation-days", "14"])
        result = runner.invoke(cli, ["policy", "history"])
        assert result.exit_code == 0
        assert "created" in result.output.lower()
