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
        result = runner.invoke(
            cli,
            [
                "policy",
                "set",
                "sla",
                "--severity",
                "critical",
                "--remediation-days",
                "14",
                "--escalate-after",
                "7",
            ],
        )
        assert result.exit_code == 0
        assert "created" in result.output.lower() or "policy" in result.output.lower()
        result = runner.invoke(cli, ["policy", "list"])
        assert "sla" in result.output.lower()

    def test_policy_set_retention(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "policy",
                "set",
                "retention",
                "--framework",
                "pci_dss",
                "--days",
                "2555",
            ],
        )
        assert result.exit_code == 0

    def test_policy_history(self):
        runner = CliRunner()
        runner.invoke(
            cli, ["policy", "set", "sla", "--severity", "critical", "--remediation-days", "14"]
        )
        result = runner.invoke(cli, ["policy", "history"])
        assert result.exit_code == 0
        assert "created" in result.output.lower()


class TestBriefingCLI:
    def test_briefing_runs(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["briefing"])
        assert result.exit_code == 0
        assert "briefing" in result.output.lower() or "warlock" in result.output.lower()

    def test_briefing_with_framework_filter(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["briefing", "-f", "soc2"])
        assert result.exit_code == 0

    def test_briefing_with_mode(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["briefing", "--mode", "audit-prep"])
        assert result.exit_code == 0


class TestControlHubCLI:
    def test_control_hub_runs(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["control-hub", "AC-2", "-f", "nist_800_53"])
        assert result.exit_code == 0

    def test_control_hub_no_data(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["control-hub", "FAKE-99", "-f", "fake"])
        assert result.exit_code == 0


class TestCrossDomainIntegration:
    """End-to-end: seed data, then use cross-domain commands."""

    def _seed_test_data(self):
        """Seed minimal data for integration testing."""
        from warlock.db.engine import get_session
        from warlock.db.models import (
            ConnectorRun,
            RawEvent,
            Finding,
            ControlMapping,
            ControlResult,
            POAM,
            Issue,
        )
        from datetime import datetime, timezone, timedelta

        now = datetime.now(timezone.utc)
        with get_session() as session:
            # Build full FK chain for a non-compliant control
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
                sha256="rawhash1",
                ingested_at=now,
            )
            session.add(raw)
            session.flush()

            finding = Finding(
                raw_event_id=raw.id,
                observation_type="configuration",
                title="MFA not enforced",
                detail={"test": True},
                source="test",
                source_type="cloud",
                provider="test",
                severity="critical",
                confidence=1.0,
                observed_at=now,
                ingested_at=now,
                sha256="findhash1",
            )
            session.add(finding)
            session.flush()

            mapping = ControlMapping(
                finding_id=finding.id,
                framework="soc2",
                control_id="CC6.1",
                mapping_method="explicit",
                confidence=1.0,
            )
            session.add(mapping)
            session.flush()

            result = ControlResult(
                finding_id=finding.id,
                control_mapping_id=mapping.id,
                framework="soc2",
                control_id="CC6.1",
                status="non_compliant",
                severity="critical",
                assessor="assertion:mfa_enabled",
                assessed_at=now,
            )
            session.add(result)

            # Overdue POAM
            poam = POAM(
                framework="soc2",
                control_id="CC6.1",
                severity="critical",
                status="open",
                weakness_description="MFA not enforced for privileged users",
                created_by="admin@acme.com",
                scheduled_completion=now - timedelta(days=3),
            )
            session.add(poam)

            # Open issue
            issue = Issue(
                framework="soc2",
                control_id="CC6.1",
                title="Enforce MFA for all users",
                status="open",
                priority="critical",
            )
            session.add(issue)
            session.commit()

    def test_full_workflow(self):
        """Seed → briefing → control-hub → policy set → policy list."""
        self._seed_test_data()
        runner = CliRunner()

        # 1. Briefing shows urgent items
        result = runner.invoke(cli, ["briefing", "-f", "soc2"])
        assert result.exit_code == 0, f"briefing failed: {result.output}"
        assert "CC6.1" in result.output

        # 2. Control hub shows cross-domain data
        result = runner.invoke(cli, ["control-hub", "CC6.1", "-f", "soc2"])
        assert result.exit_code == 0, f"control-hub failed: {result.output}"
        assert "CC6.1" in result.output

        # 3. Set an SLA policy
        result = runner.invoke(
            cli,
            [
                "policy",
                "set",
                "sla",
                "--severity",
                "critical",
                "--remediation-days",
                "14",
                "--escalate-after",
                "7",
            ],
        )
        assert result.exit_code == 0, f"policy set failed: {result.output}"

        # 4. Policy appears in list
        result = runner.invoke(cli, ["policy", "list"])
        assert result.exit_code == 0, f"policy list failed: {result.output}"
        assert "sla" in result.output.lower()

        # 5. Policy history recorded
        result = runner.invoke(cli, ["policy", "history"])
        assert result.exit_code == 0, f"policy history failed: {result.output}"
        assert "created" in result.output.lower()
