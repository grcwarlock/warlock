"""Tests for curated zone domain writers (domains 2-10)."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pyarrow")

import pyarrow.parquet as pq

from warlock.lake.domains import (
    write_entity_facts,
    write_evidence_facts,
    write_governance_facts,
    write_incident_facts,
    write_pipeline_health_facts,
    write_privacy_facts,
    write_risk_facts,
    write_supply_chain_facts,
    write_temporal_facts,
)


@pytest.fixture
def lake_dir(tmp_path):
    """Provide a temporary lake directory."""
    return str(tmp_path / "lake")


RUN_ID = "test-run-001"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _parquet_row_count(lake_dir: str, table_name: str) -> int:
    """Count total rows across all Parquet files for a curated table."""
    curated = Path(lake_dir) / "curated" / table_name
    if not curated.exists():
        return 0
    total = 0
    for pf in curated.rglob("*.parquet"):
        total += pq.read_table(str(pf)).num_rows
    return total


# ---------------------------------------------------------------------------
# Domain 2 — Temporal Facts
# ---------------------------------------------------------------------------


class TestTemporalFacts:
    def test_posture_snapshots(self, lake_dir):
        rows = [
            {
                "id": "1",
                "framework": "nist_800_53",
                "control_id": "AC-1",
                "system_profile_id": "sp-1",
                "snapshot_date": "2026-03-21",
                "posture_score": "0.85",
                "status": "compliant",
            },
        ]
        count = write_temporal_facts(lake_dir, RUN_ID, posture_snapshots=rows)
        assert count == 1
        assert _parquet_row_count(lake_dir, "posture_snapshots") == 1

    def test_compliance_drifts(self, lake_dir):
        rows = [
            {
                "id": "1",
                "framework": "soc2",
                "control_id": "CC6.1",
                "previous_status": "compliant",
                "new_status": "non_compliant",
                "drift_direction": "regression",
                "detected_at": "2026-03-21T00:00:00Z",
            },
        ]
        count = write_temporal_facts(lake_dir, RUN_ID, compliance_drifts=rows)
        assert count == 1
        assert _parquet_row_count(lake_dir, "compliance_drift") == 1

    def test_regulatory_deadlines(self, lake_dir):
        rows = [
            {
                "id": "1",
                "regulation": "GDPR",
                "deadline_type": "dsar_response",
                "deadline_at": "2026-04-20",
                "days_remaining": "30",
                "status": "pending",
                "linked_control_ids": "PR-1,PR-2",
            },
        ]
        count = write_temporal_facts(lake_dir, RUN_ID, regulatory_deadlines=rows)
        assert count == 1

    def test_empty_inputs(self, lake_dir):
        assert write_temporal_facts(lake_dir, RUN_ID) == 0


# ---------------------------------------------------------------------------
# Domain 3 — Risk Facts
# ---------------------------------------------------------------------------


class TestRiskFacts:
    def test_risk_simulations(self, lake_dir):
        rows = [
            {
                "id": "1",
                "framework": "nist_800_53",
                "scenario_name": "ransomware",
                "mean_ale": "500000",
                "var_95": "1200000",
                "var_99": "2000000",
                "control_effectiveness": "0.72",
                "created_at": "2026-03-21",
            },
        ]
        count = write_risk_facts(lake_dir, RUN_ID, risk_simulations=rows)
        assert count == 1

    def test_vulnerability_lifecycle(self, lake_dir):
        rows = [
            {
                "id": "1",
                "vuln_id": "CVE-2026-1234",
                "cvss_score": "9.8",
                "epss_score": "0.95",
                "status": "remediated",
                "remediated_at": "2026-03-15",
                "sla_target_days": "7",
                "sla_met": "True",
            },
        ]
        count = write_risk_facts(lake_dir, RUN_ID, vulnerability_lifecycle=rows)
        assert count == 1

    def test_control_effectiveness(self, lake_dir):
        rows = [
            {
                "id": "1",
                "control_id": "AC-2",
                "framework": "nist_800_53",
                "effectiveness_rate": "0.91",
                "trend": "improving",
                "measurement_window": "90d",
            },
        ]
        count = write_risk_facts(lake_dir, RUN_ID, control_effectiveness=rows)
        assert count == 1

    def test_empty_inputs(self, lake_dir):
        assert write_risk_facts(lake_dir, RUN_ID) == 0


# ---------------------------------------------------------------------------
# Domain 4 — Entity Facts
# ---------------------------------------------------------------------------


class TestEntityFacts:
    def test_resources(self, lake_dir):
        rows = [
            {
                "id": "1",
                "resource_type": "ec2",
                "resource_id": "i-abc123",
                "account_id": "111222333",
                "region": "us-east-1",
                "tags": "{}",
                "valid_from": "2026-01-01",
                "valid_to": "",
                "is_current": "True",
            },
        ]
        count = write_entity_facts(lake_dir, RUN_ID, resources=rows)
        assert count == 1

    def test_personnel(self, lake_dir):
        rows = [
            {
                "id": "1",
                "email": "j@example.com",
                "department": "eng",
                "hr_status": "active",
                "mfa_enabled": "True",
                "risk_score": "0.1",
                "valid_from": "2026-01-01",
                "valid_to": "",
                "is_current": "True",
            },
        ]
        count = write_entity_facts(lake_dir, RUN_ID, personnel=rows)
        assert count == 1

    def test_all_entity_tables(self, lake_dir):
        """Write one row to every entity table at once."""
        count = write_entity_facts(
            lake_dir,
            RUN_ID,
            resources=[{"id": "1", "resource_type": "s3"}],
            systems=[{"id": "1", "name": "core"}],
            personnel=[{"id": "1", "email": "a@b.com"}],
            vendors=[{"id": "1", "name": "Acme"}],
            data_silos=[{"id": "1", "name": "warehouse"}],
            software_components=[{"id": "1", "name": "openssl", "version": "3.0"}],
        )
        assert count == 6

    def test_empty_inputs(self, lake_dir):
        assert write_entity_facts(lake_dir, RUN_ID) == 0


# ---------------------------------------------------------------------------
# Domain 5 — Governance Facts
# ---------------------------------------------------------------------------


class TestGovernanceFacts:
    def test_poams(self, lake_dir):
        rows = [
            {
                "id": "1",
                "framework": "nist_800_53",
                "control_id": "AC-2",
                "status": "open",
                "milestone": "Deploy MFA",
                "owner": "security-team",
                "created_at": "2026-03-01",
            },
        ]
        count = write_governance_facts(lake_dir, RUN_ID, poams=rows)
        assert count == 1

    def test_audit_entries(self, lake_dir):
        rows = [
            {
                "id": "1",
                "sequence": "100",
                "action": "create",
                "entity_type": "ControlResult",
                "entity_id": "cr-1",
                "actor": "system",
                "entry_hash": "abc123",
                "created_at": "2026-03-21T12:00:00Z",
            },
        ]
        count = write_governance_facts(lake_dir, RUN_ID, audit_entries=rows)
        assert count == 1

    def test_all_governance_tables(self, lake_dir):
        count = write_governance_facts(
            lake_dir,
            RUN_ID,
            poams=[{"id": "1", "framework": "soc2", "status": "open"}],
            issues=[{"id": "1", "framework": "iso_27001", "title": "Gap"}],
            attestations=[{"id": "1", "framework": "soc2", "status": "pending"}],
            audit_entries=[{"id": "1", "action": "update"}],
            policy_documents=[{"id": "1", "policy_id": "P-1"}],
            exceptions=[{"id": "1", "policy_id": "P-1", "reason": "legacy"}],
            legal_holds=[{"id": "1", "trigger_event": "litigation"}],
        )
        assert count == 7

    def test_empty_inputs(self, lake_dir):
        assert write_governance_facts(lake_dir, RUN_ID) == 0


# ---------------------------------------------------------------------------
# Domain 6 — Evidence Facts
# ---------------------------------------------------------------------------


class TestEvidenceFacts:
    def test_evidence_artifacts(self, lake_dir):
        rows = [
            {
                "id": "1",
                "source_connector": "aws_config",
                "collected_at": "2026-03-21",
                "artifact_type": "screenshot",
                "storage_ref": "s3://bucket/key",
                "hash": "sha256:abc",
                "pipeline_run_id": "run-1",
            },
        ]
        count = write_evidence_facts(lake_dir, RUN_ID, evidence_artifacts=rows)
        assert count == 1

    def test_evidence_control_bindings(self, lake_dir):
        rows = [
            {
                "evidence_id": "1",
                "control_id": "AC-1",
                "framework": "nist_800_53",
                "sufficiency_score": "0.9",
            },
        ]
        count = write_evidence_facts(lake_dir, RUN_ID, evidence_control_bindings=rows)
        assert count == 1

    def test_empty_inputs(self, lake_dir):
        assert write_evidence_facts(lake_dir, RUN_ID) == 0


# ---------------------------------------------------------------------------
# Domain 7 — Privacy Facts
# ---------------------------------------------------------------------------


class TestPrivacyFacts:
    def test_processing_activities(self, lake_dir):
        rows = [
            {
                "id": "1",
                "purpose": "marketing",
                "legal_basis": "consent",
                "data_categories": "email,name",
                "recipients": "CRM vendor",
                "retention_period": "365d",
            },
        ]
        count = write_privacy_facts(lake_dir, RUN_ID, processing_activities=rows)
        assert count == 1

    def test_dsars(self, lake_dir):
        rows = [
            {
                "id": "1",
                "request_type": "access",
                "received_at": "2026-03-01",
                "deadline_at": "2026-03-31",
                "completed_at": "",
                "status": "in_progress",
            },
        ]
        count = write_privacy_facts(lake_dir, RUN_ID, dsars=rows)
        assert count == 1

    def test_breach_register(self, lake_dir):
        rows = [
            {
                "id": "1",
                "discovered_at": "2026-03-20",
                "reported_at": "2026-03-21",
                "affected_subjects_count": "1500",
                "notification_status": "notified",
            },
        ]
        count = write_privacy_facts(lake_dir, RUN_ID, breach_register=rows)
        assert count == 1

    def test_empty_inputs(self, lake_dir):
        assert write_privacy_facts(lake_dir, RUN_ID) == 0


# ---------------------------------------------------------------------------
# Domain 8 — Incident Facts
# ---------------------------------------------------------------------------


class TestIncidentFacts:
    def test_security_events(self, lake_dir):
        rows = [
            {
                "id": "1",
                "source_connector": "crowdstrike",
                "event_type": "malware",
                "severity": "critical",
                "detected_at": "2026-03-21T08:00:00Z",
            },
        ]
        count = write_incident_facts(lake_dir, RUN_ID, security_events=rows)
        assert count == 1

    def test_incidents(self, lake_dir):
        rows = [
            {
                "id": "1",
                "classification": "data_breach",
                "severity": "high",
                "status": "investigating",
                "commander": "ciso",
                "detected_at": "2026-03-21",
            },
        ]
        count = write_incident_facts(lake_dir, RUN_ID, incidents=rows)
        assert count == 1

    def test_tabletop_exercises(self, lake_dir):
        rows = [
            {
                "id": "1",
                "scenario": "ransomware",
                "participants": "exec-team",
                "findings": "slow response",
                "action_items": "update runbook",
            },
        ]
        count = write_incident_facts(lake_dir, RUN_ID, tabletop_exercises=rows)
        assert count == 1

    def test_empty_inputs(self, lake_dir):
        assert write_incident_facts(lake_dir, RUN_ID) == 0


# ---------------------------------------------------------------------------
# Domain 9 — Pipeline Health Facts
# ---------------------------------------------------------------------------


class TestPipelineHealthFacts:
    def test_pipeline_runs(self, lake_dir):
        rows = [
            {
                "id": "1",
                "run_id": "run-42",
                "raw_events_collected": "222",
                "findings_normalized": "646",
                "controls_mapped": "32817",
                "results_assessed": "32817",
                "duration_seconds": "12.5",
                "hash_chain_valid": "True",
            },
        ]
        count = write_pipeline_health_facts(lake_dir, RUN_ID, pipeline_runs=rows)
        assert count == 1

    def test_data_freshness(self, lake_dir):
        rows = [
            {
                "id": "1",
                "connector_id": "aws_config",
                "last_successful_run": "2026-03-21T06:00:00Z",
                "hours_since_last_success": "2",
                "freshness_status": "fresh",
            },
        ]
        count = write_pipeline_health_facts(lake_dir, RUN_ID, data_freshness=rows)
        assert count == 1

    def test_coverage_metrics(self, lake_dir):
        rows = [
            {
                "id": "1",
                "total_connectors": "57",
                "healthy": "55",
                "degraded": "2",
                "failed": "0",
                "pct_controls_with_evidence": "0.87",
            },
        ]
        count = write_pipeline_health_facts(lake_dir, RUN_ID, coverage_metrics=rows)
        assert count == 1

    def test_empty_inputs(self, lake_dir):
        assert write_pipeline_health_facts(lake_dir, RUN_ID) == 0


# ---------------------------------------------------------------------------
# Domain 10 — Supply Chain Facts
# ---------------------------------------------------------------------------


class TestSupplyChainFacts:
    def test_sbom_components(self, lake_dir):
        rows = [
            {
                "id": "1",
                "component_name": "openssl",
                "version": "3.0.13",
                "sbom_format": "CycloneDX",
                "license": "Apache-2.0",
                "known_cves": "0",
                "slsa_level": "3",
            },
        ]
        count = write_supply_chain_facts(lake_dir, RUN_ID, sbom_components=rows)
        assert count == 1

    def test_supplier_assessments(self, lake_dir):
        rows = [
            {
                "id": "1",
                "supplier_id": "vendor-1",
                "assessed_at": "2026-03-01",
                "rating_source": "bitsight",
                "score": "740",
            },
        ]
        count = write_supply_chain_facts(lake_dir, RUN_ID, supplier_assessments=rows)
        assert count == 1

    def test_concentration_risk(self, lake_dir):
        rows = [
            {
                "id": "1",
                "supplier_id": "aws",
                "dependent_systems": "12",
                "single_point_of_failure": "True",
            },
        ]
        count = write_supply_chain_facts(lake_dir, RUN_ID, concentration_risk=rows)
        assert count == 1

    def test_provenance_attestations(self, lake_dir):
        rows = [
            {
                "id": "1",
                "artifact_id": "pkg-1",
                "slsa_level": "2",
                "signer": "ci-bot",
                "signature_verified": "True",
            },
        ]
        count = write_supply_chain_facts(lake_dir, RUN_ID, provenance_attestations=rows)
        assert count == 1

    def test_empty_inputs(self, lake_dir):
        assert write_supply_chain_facts(lake_dir, RUN_ID) == 0


# ---------------------------------------------------------------------------
# Cross-domain tests
# ---------------------------------------------------------------------------


class TestCrossDomain:
    def test_multiple_rows(self, lake_dir):
        """Verify multi-row writes produce correct Parquet row counts."""
        rows = [
            {
                "id": str(i),
                "framework": "soc2",
                "control_id": f"CC{i}.1",
                "status": "open",
                "milestone": "",
                "owner": "",
                "created_at": "2026-03-21",
            }
            for i in range(1, 11)
        ]
        count = write_governance_facts(lake_dir, RUN_ID, poams=rows)
        assert count == 10
        assert _parquet_row_count(lake_dir, "poams") == 10

    def test_framework_partitioning(self, lake_dir):
        """Rows with different frameworks should land in different directories."""
        rows = [
            {
                "id": "1",
                "framework": "nist_800_53",
                "control_id": "AC-1",
                "system_profile_id": "sp-1",
                "snapshot_date": "2026-03-21",
                "posture_score": "0.85",
                "status": "compliant",
            },
            {
                "id": "2",
                "framework": "soc2",
                "control_id": "CC6.1",
                "system_profile_id": "sp-1",
                "snapshot_date": "2026-03-21",
                "posture_score": "0.9",
                "status": "compliant",
            },
        ]
        count = write_temporal_facts(lake_dir, RUN_ID, posture_snapshots=rows)
        assert count == 2
        # Check both framework partitions exist
        curated = Path(lake_dir) / "curated" / "posture_snapshots"
        frameworks = {p.name for p in curated.iterdir() if p.is_dir()}
        assert "nist_800_53" in frameworks
        assert "soc2" in frameworks


# ---------------------------------------------------------------------------
# Domain CLI Tests
# ---------------------------------------------------------------------------


class TestDomainCLI:
    def test_evidence_list_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lake", "evidence", "list", "--path", "/tmp/empty-lake"])
        assert result.exit_code == 0

    def test_evidence_freshness_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lake", "evidence", "freshness", "--path", "/tmp/empty-lake"])
        assert result.exit_code == 0

    def test_incidents_list_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lake", "incidents", "list", "--path", "/tmp/empty-lake"])
        assert result.exit_code == 0

    def test_incidents_events_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lake", "incidents", "events", "--path", "/tmp/empty-lake"])
        assert result.exit_code == 0

    def test_privacy_dsars_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lake", "privacy", "dsars", "--path", "/tmp/empty-lake"])
        assert result.exit_code == 0

    def test_privacy_processing_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lake", "privacy", "processing", "--path", "/tmp/empty-lake"])
        assert result.exit_code == 0

    def test_privacy_transfers_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lake", "privacy", "transfers", "--path", "/tmp/empty-lake"])
        assert result.exit_code == 0

    def test_supply_chain_sbom_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lake", "supply-chain", "sbom", "--path", "/tmp/empty-lake"])
        assert result.exit_code == 0

    def test_supply_chain_suppliers_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(
            cli, ["lake", "supply-chain", "suppliers", "--path", "/tmp/empty-lake"]
        )
        assert result.exit_code == 0

    def test_supply_chain_concentration_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(
            cli, ["lake", "supply-chain", "concentration", "--path", "/tmp/empty-lake"]
        )
        assert result.exit_code == 0

    def test_analytics_trends_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lake", "analytics", "trends", "--path", "/tmp/empty-lake"])
        assert result.exit_code == 0

    def test_analytics_heatmap_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lake", "analytics", "heatmap", "--path", "/tmp/empty-lake"])
        assert result.exit_code == 0

    def test_health_runs_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lake", "health", "runs", "--path", "/tmp/empty-lake"])
        assert result.exit_code == 0

    def test_health_freshness_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lake", "health", "freshness", "--path", "/tmp/empty-lake"])
        assert result.exit_code == 0

    def test_health_coverage_no_data(self):
        from click.testing import CliRunner

        from warlock.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lake", "health", "coverage", "--path", "/tmp/empty-lake"])
        assert result.exit_code == 0
