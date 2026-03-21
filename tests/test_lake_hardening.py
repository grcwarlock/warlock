"""Tests for lake hardening — posture readers, ABAC, legal holds, etc."""

from datetime import datetime, timezone
from pathlib import Path
import pytest


@pytest.fixture
def lake_with_posture(tmp_path):
    """Seed lake with posture snapshot data."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    date = "2026-03-21"
    snapshots = {
        "id": ["ps-1", "ps-2", "ps-3"],
        "framework": ["nist_800_53", "nist_800_53", "soc2"],
        "control_id": ["AC-2", "AC-3", "CC6.1"],
        "system_profile_id": ["sys-1", "sys-1", "sys-1"],
        "snapshot_date": [date, date, date],
        "posture_score": ["85.0", "72.0", "91.0"],
        "status": ["compliant", "partial", "compliant"],
        "run_id": ["run-1", "run-1", "run-1"],
    }
    for fw in ["nist_800_53", "soc2"]:
        d = Path(tmp_path) / "curated" / "posture_snapshots" / fw / date
        d.mkdir(parents=True, exist_ok=True)
        fw_data = {k: [v for v, f in zip(snapshots[k], snapshots["framework"]) if f == fw]
                   for k in snapshots}
        pq.write_table(pa.table(fw_data), str(d / "run-1.parquet"))
    return str(tmp_path)


class TestPostureReaders:
    def test_latest_snapshot_date_returns_date(self, lake_with_posture):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(lake_with_posture)
        result = readers.latest_snapshot_date()
        assert result is not None
        readers.close()

    def test_latest_snapshot_date_empty_lake(self, tmp_path):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(str(tmp_path))
        result = readers.latest_snapshot_date()
        assert result is None
        readers.close()

    def test_framework_avg_scores(self, lake_with_posture):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(lake_with_posture)
        result = readers.framework_avg_scores_at()
        assert len(result) == 2  # nist_800_53 and soc2
        # Check it returns (framework, float) tuples
        for fw, score in result:
            assert isinstance(fw, str)
            assert isinstance(score, float)
        readers.close()

    def test_effectiveness_latest_all(self, lake_with_posture):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(lake_with_posture)
        result = readers.effectiveness_latest()
        assert len(result) == 3
        readers.close()

    def test_effectiveness_latest_filtered(self, lake_with_posture):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(lake_with_posture)
        result = readers.effectiveness_latest(framework="soc2")
        assert len(result) == 1
        assert result[0]["framework"] == "soc2"
        readers.close()


class TestLegalHoldChecking:
    def test_expire_blocked_by_legal_hold(self):
        from warlock.lake.maintenance import expire_snapshots_safe
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from warlock.db.models import Base, LegalHold
        from datetime import datetime, timezone

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            session.add(LegalHold(
                id="lh-1",
                reason="Litigation hold for investigation",
                start_date=datetime.now(timezone.utc),
                is_active=True,
            ))
            session.flush()
            result = expire_snapshots_safe(session, "/tmp/empty-lake")
            assert result.get("blocked_by_hold") is True

    def test_expire_proceeds_without_hold(self):
        from warlock.lake.maintenance import expire_snapshots_safe
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from warlock.db.models import Base

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            result = expire_snapshots_safe(session, "/tmp/empty-lake")
            assert result.get("blocked_by_hold") is not True

    def test_thin_blocked_by_legal_hold(self):
        from warlock.lake.oltp_thin import thin_oltp_safe
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from warlock.db.models import Base, LegalHold
        from datetime import datetime, timezone

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            session.add(LegalHold(
                id="lh-1",
                reason="Litigation hold for investigation",
                start_date=datetime.now(timezone.utc),
                is_active=True,
            ))
            session.flush()
            stats = thin_oltp_safe(session, dry_run=True)
            assert stats.total_removed == 0
            assert any("legal hold" in e.lower() for e in stats.errors)

    def test_thin_proceeds_without_hold(self):
        from warlock.lake.oltp_thin import thin_oltp_safe
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from warlock.db.models import Base

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            stats = thin_oltp_safe(session, dry_run=True)
            assert not stats.errors or not any("legal hold" in e.lower() for e in stats.errors)


class TestHashReconciliation:
    def test_matching_hashes(self):
        from warlock.lake.reconciliation import sample_hashes
        oltp_hashes = {"evt-1": "abc123", "evt-2": "def456"}
        lake_hashes = {"evt-1": "abc123", "evt-2": "def456"}
        mismatches = sample_hashes(oltp_hashes, lake_hashes)
        assert len(mismatches) == 0

    def test_mismatched_hashes(self):
        from warlock.lake.reconciliation import sample_hashes
        oltp_hashes = {"evt-1": "abc123", "evt-2": "def456"}
        lake_hashes = {"evt-1": "abc123", "evt-2": "WRONG"}
        mismatches = sample_hashes(oltp_hashes, lake_hashes)
        assert len(mismatches) == 1
        assert mismatches[0]["id"] == "evt-2"
        assert mismatches[0]["reason"] == "hash_mismatch"

    def test_missing_in_lake(self):
        from warlock.lake.reconciliation import sample_hashes
        oltp_hashes = {"evt-1": "abc123", "evt-2": "def456"}
        lake_hashes = {"evt-1": "abc123"}
        mismatches = sample_hashes(oltp_hashes, lake_hashes)
        assert len(mismatches) == 1
        assert mismatches[0]["reason"] == "missing_in_lake"

    def test_empty_hashes(self):
        from warlock.lake.reconciliation import sample_hashes
        mismatches = sample_hashes({}, {})
        assert len(mismatches) == 0


# ── ABAC scope filtering tests ──────────────────────────────────────


@pytest.fixture
def lake_for_abac(tmp_path):
    """Seed lake with multi-framework data for ABAC testing."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    date = "2026-03-21"
    cr = {
        "id": ["cr-1", "cr-2", "cr-3"],
        "finding_id": ["f-1", "f-2", "f-3"],
        "control_mapping_id": ["cm-1", "cm-2", "cm-3"],
        "framework": ["nist_800_53", "soc2", "iso_27001"],
        "control_id": ["AC-2", "CC6.1", "A.9.1"],
        "status": ["compliant", "non_compliant", "compliant"],
        "severity": ["high", "critical", "medium"],
        "system_profile_id": ["sys-prod", "sys-prod", "sys-staging"],
        "assertion_name": ["mfa", "encrypt", "access"],
        "assertion_passed": [True, False, True],
        "assessed_at": [datetime.now(timezone.utc).isoformat()] * 3,
        "run_id": ["run-1"] * 3,
    }
    for fw in ["nist_800_53", "soc2", "iso_27001"]:
        d = Path(tmp_path) / "curated" / "control_results" / fw / date
        d.mkdir(parents=True, exist_ok=True)
        fw_data = {
            k: [v for v, f in zip(cr[k], cr["framework"]) if f == fw] for k in cr
        }
        pq.write_table(pa.table(fw_data), str(d / "run-1.parquet"))

    # Control mappings
    cm = {
        "id": ["cm-1", "cm-2", "cm-3"],
        "finding_id": ["f-1", "f-2", "f-3"],
        "framework": ["nist_800_53", "soc2", "iso_27001"],
        "control_id": ["AC-2", "CC6.1", "A.9.1"],
        "control_family": ["AC", "CC6", "A.9"],
        "mapping_method": ["explicit", "explicit", "keyword"],
        "confidence": [1.0, 1.0, 0.8],
        "created_at": [datetime.now(timezone.utc).isoformat()] * 3,
        "run_id": ["run-1"] * 3,
    }
    d = Path(tmp_path) / "curated" / "control_mappings" / date
    d.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.table(cm), str(d / "run-1.parquet"))

    return str(tmp_path)


class TestABACLakeReaders:
    def test_dashboard_framework_scope(self, lake_for_abac):
        from warlock.lake.readers import LakeReaders

        readers = LakeReaders(lake_for_abac)
        result = readers.dashboard_framework_summary(allowed_frameworks=["soc2"])
        assert all(r[0] == "soc2" for r in result)
        assert len(result) > 0
        readers.close()

    def test_dashboard_system_profile_scope(self, lake_for_abac):
        from warlock.lake.readers import LakeReaders

        readers = LakeReaders(lake_for_abac)
        result = readers.dashboard_framework_summary(
            allowed_system_profiles=["sys-prod"]
        )
        # sys-prod has nist_800_53 and soc2 (not iso_27001 which is sys-staging)
        frameworks = {r[0] for r in result}
        assert "iso_27001" not in frameworks
        readers.close()

    def test_dashboard_no_scope_returns_all(self, lake_for_abac):
        from warlock.lake.readers import LakeReaders

        readers = LakeReaders(lake_for_abac)
        result = readers.dashboard_framework_summary()
        frameworks = {r[0] for r in result}
        assert len(frameworks) == 3
        readers.close()

    def test_coverage_with_framework_scope(self, lake_for_abac):
        from warlock.lake.readers import LakeReaders

        readers = LakeReaders(lake_for_abac)
        result = readers.coverage_by_status(allowed_frameworks=["nist_800_53"])
        assert all(r[0] == "nist_800_53" for r in result)
        readers.close()

    def test_distinct_frameworks_scoped(self, lake_for_abac):
        from warlock.lake.readers import LakeReaders

        readers = LakeReaders(lake_for_abac)
        result = readers.distinct_frameworks(
            allowed_frameworks=["soc2", "iso_27001"]
        )
        assert "nist_800_53" not in result
        assert "soc2" in result
        readers.close()

    def test_list_frameworks_scoped(self, lake_for_abac):
        from warlock.lake.readers import LakeReaders

        readers = LakeReaders(lake_for_abac)
        result = readers.list_frameworks(allowed_frameworks=["nist_800_53"])
        assert len(result) == 1
        assert result[0][0] == "nist_800_53"
        readers.close()

    def test_list_controls_scoped(self, lake_for_abac):
        from warlock.lake.readers import LakeReaders

        readers = LakeReaders(lake_for_abac)
        # Request controls for nist_800_53 but ABAC only allows soc2 → empty
        result = readers.list_controls(
            "nist_800_53", allowed_frameworks=["soc2"]
        )
        assert len(result) == 0
        readers.close()

    def test_top_non_compliant_risks_scoped(self, lake_for_abac):
        from warlock.lake.readers import LakeReaders

        readers = LakeReaders(lake_for_abac)
        # Only soc2 has a non_compliant row
        result = readers.top_non_compliant_risks(allowed_frameworks=["soc2"])
        assert len(result) == 1
        assert result[0]["framework"] == "soc2"
        readers.close()

    def test_top_non_compliant_risks_no_match(self, lake_for_abac):
        from warlock.lake.readers import LakeReaders

        readers = LakeReaders(lake_for_abac)
        # nist_800_53 has only compliant rows
        result = readers.top_non_compliant_risks(
            allowed_frameworks=["nist_800_53"]
        )
        assert len(result) == 0
        readers.close()

    def test_last_assessed_at_scoped(self, lake_for_abac):
        from warlock.lake.readers import LakeReaders

        readers = LakeReaders(lake_for_abac)
        result = readers.last_assessed_at(allowed_frameworks=["soc2"])
        assert result is not None
        readers.close()

    def test_combined_framework_and_profile_scope(self, lake_for_abac):
        from warlock.lake.readers import LakeReaders

        readers = LakeReaders(lake_for_abac)
        # nist_800_53 is sys-prod, iso_27001 is sys-staging
        # Filter to nist_800_53 + sys-prod → should get 1 result
        result = readers.dashboard_framework_summary(
            allowed_frameworks=["nist_800_53"],
            allowed_system_profiles=["sys-prod"],
        )
        assert len(result) == 1
        assert result[0][0] == "nist_800_53"
        readers.close()

    def test_profile_scope_excludes_staging(self, lake_for_abac):
        from warlock.lake.readers import LakeReaders

        readers = LakeReaders(lake_for_abac)
        # sys-prod only → iso_27001 (sys-staging) excluded
        result = readers.coverage_by_status(
            allowed_system_profiles=["sys-prod"]
        )
        frameworks = {r[0] for r in result}
        assert "iso_27001" not in frameworks
        assert len(frameworks) == 2
        readers.close()


class TestBridgeTables:
    def test_write_crosswalk(self, tmp_path):
        from warlock.lake.bridges import write_bridge_tables
        from warlock.lake.query import LakeQueryEngine
        crosswalks = [
            {"source_framework": "nist_800_53", "source_control": "AC-2",
             "target_framework": "iso_27001", "target_control": "A.9.2.1",
             "confidence": 0.95},
        ]
        count = write_bridge_tables(str(tmp_path), "run-1", crosswalks=crosswalks)
        assert count == 1
        engine = LakeQueryEngine(str(tmp_path))
        result = engine.query(f"SELECT * FROM read_parquet('{tmp_path}/curated/bridge_control_crosswalk/**/*.parquet')")
        assert len(result) == 1
        assert result[0]["source_framework"] == "nist_800_53"
        engine.close()

    def test_write_entity_relationships(self, tmp_path):
        from warlock.lake.bridges import write_bridge_tables
        relationships = [
            {"source_entity": "user-1", "target_entity": "laptop-1",
             "relationship_type": "owns", "effective_date": "2026-03-21"},
        ]
        count = write_bridge_tables(str(tmp_path), "run-1", entity_relationships=relationships)
        assert count == 1

    def test_write_incident_bridges(self, tmp_path):
        from warlock.lake.bridges import write_bridge_tables
        controls = [{"incident_id": "inc-1", "control_id": "AC-2",
                      "framework": "nist_800_53", "failure_type": "bypassed"}]
        entities = [{"incident_id": "inc-1", "entity_id": "srv-1",
                      "entity_type": "server", "impact": "compromised"}]
        count = write_bridge_tables(str(tmp_path), "run-1",
                                     incident_controls=controls, incident_entities=entities)
        assert count == 2

    def test_write_data_flow(self, tmp_path):
        from warlock.lake.bridges import write_bridge_tables
        flows = [{"source_entity": "app-1", "destination_entity": "db-1",
                   "data_classification": "PII", "transfer_mechanism": "TLS",
                   "legal_basis": "consent", "cross_border_flag": False}]
        count = write_bridge_tables(str(tmp_path), "run-1", data_flows=flows)
        assert count == 1

    def test_write_boundary_membership(self, tmp_path):
        from warlock.lake.bridges import write_bridge_tables
        memberships = [{"entity_id": "srv-1", "boundary_id": "fedramp-moderate",
                         "inclusion_type": "in_boundary"}]
        count = write_bridge_tables(str(tmp_path), "run-1", boundary_memberships=memberships)
        assert count == 1

    def test_empty_bridge_tables(self, tmp_path):
        from warlock.lake.bridges import write_bridge_tables
        count = write_bridge_tables(str(tmp_path), "run-1")
        assert count == 0


class TestTypedParquetColumns:
    def test_numeric_fields_stored_as_numbers(self, tmp_path):
        """Numeric fields should be stored as numbers, not strings."""
        from warlock.lake.domains import write_risk_facts
        from warlock.lake.query import LakeQueryEngine

        risk_sims = [{"id": "rs-1", "framework": "nist_800_53", "scenario_name": "breach",
                       "mean_ale": 500000.0, "var_95": 1200000.0, "var_99": 2500000.0,
                       "control_effectiveness": 0.85, "created_at": "2026-03-21"}]
        write_risk_facts(str(tmp_path), "run-1", risk_simulations=risk_sims)

        engine = LakeQueryEngine(str(tmp_path))
        result = engine.query(
            f"SELECT mean_ale, typeof(mean_ale) as t FROM read_parquet('{tmp_path}/curated/risk_simulations/**/*.parquet')"
        )
        assert result[0]["t"] != "VARCHAR", f"mean_ale stored as {result[0]['t']}, expected numeric"
        engine.close()

    def test_boolean_fields_stored_as_bool(self, tmp_path):
        from warlock.lake.domains import write_entity_facts
        from warlock.lake.query import LakeQueryEngine

        resources = [{"id": "r-1", "resource_type": "server", "is_current": True,
                       "resource_id": "srv-1", "account_id": "acc-1"}]
        write_entity_facts(str(tmp_path), "run-1", resources=resources)

        engine = LakeQueryEngine(str(tmp_path))
        result = engine.query(
            f"SELECT is_current, typeof(is_current) as t FROM read_parquet('{tmp_path}/curated/resources/**/*.parquet')"
        )
        assert result[0]["t"] == "BOOLEAN", f"is_current stored as {result[0]['t']}"
        engine.close()

    def test_integer_fields_stored_as_int(self, tmp_path):
        from warlock.lake.domains import write_pipeline_health_facts
        from warlock.lake.query import LakeQueryEngine

        runs = [{"id": "pr-1", "run_id": "run-1", "raw_events_collected": 100,
                  "findings_normalized": 50, "controls_mapped": 200, "results_assessed": 200,
                  "duration_seconds": 5.2, "hash_chain_valid": True}]
        write_pipeline_health_facts(str(tmp_path), "run-1", pipeline_runs=runs)

        engine = LakeQueryEngine(str(tmp_path))
        result = engine.query(
            f"SELECT raw_events_collected, typeof(raw_events_collected) as t FROM read_parquet('{tmp_path}/curated/pipeline_runs/**/*.parquet')"
        )
        assert result[0]["t"] in ("INTEGER", "BIGINT"), f"raw_events_collected stored as {result[0]['t']}"
        engine.close()

    def test_string_fields_still_work(self, tmp_path):
        from warlock.lake.domains import write_governance_facts
        from warlock.lake.query import LakeQueryEngine

        issues = [{"id": "iss-1", "title": "Fix AC-2", "status": "open",
                    "priority": "high", "assigned_to": "alice"}]
        write_governance_facts(str(tmp_path), "run-1", issues=issues)

        engine = LakeQueryEngine(str(tmp_path))
        result = engine.query(
            f"SELECT title, typeof(title) as t FROM read_parquet('{tmp_path}/curated/issues/**/*.parquet')"
        )
        assert result[0]["t"] == "VARCHAR"
        assert result[0]["title"] == "Fix AC-2"
        engine.close()


class TestSCDType2:
    def test_new_entity(self):
        from warlock.lake.scd import apply_scd_type2
        existing = []
        incoming = [{"id": "p-1", "email": "alice@co.com", "department": "eng"}]
        result = apply_scd_type2(existing, incoming, key_fields=["id"])
        assert len(result) == 1
        assert result[0]["is_current"] == "true"
        assert result[0]["valid_to"] == "9999-12-31"

    def test_unchanged_entity(self):
        from warlock.lake.scd import apply_scd_type2
        existing = [{"id": "p-1", "email": "alice@co.com", "department": "eng",
                     "valid_from": "2026-01-01", "valid_to": "9999-12-31", "is_current": "true"}]
        incoming = [{"id": "p-1", "email": "alice@co.com", "department": "eng"}]
        result = apply_scd_type2(existing, incoming, key_fields=["id"])
        assert len(result) == 1  # No new version needed
        assert result[0]["is_current"] == "true"

    def test_changed_entity_closes_old(self):
        from warlock.lake.scd import apply_scd_type2
        existing = [{"id": "p-1", "email": "alice@co.com", "department": "eng",
                     "valid_from": "2026-01-01", "valid_to": "9999-12-31", "is_current": "true"}]
        incoming = [{"id": "p-1", "email": "alice@co.com", "department": "security"}]
        result = apply_scd_type2(existing, incoming, key_fields=["id"],
                                  change_date="2026-03-21")
        assert len(result) == 2
        old = next(r for r in result if r["department"] == "eng")
        assert old["is_current"] == "false"
        assert old["valid_to"] == "2026-03-21"
        new = next(r for r in result if r["department"] == "security")
        assert new["is_current"] == "true"
        assert new["valid_from"] == "2026-03-21"

    def test_multiple_entities(self):
        from warlock.lake.scd import apply_scd_type2
        existing = [
            {"id": "p-1", "name": "Alice", "dept": "eng", "valid_from": "2026-01-01",
             "valid_to": "9999-12-31", "is_current": "true"},
            {"id": "p-2", "name": "Bob", "dept": "sales", "valid_from": "2026-01-01",
             "valid_to": "9999-12-31", "is_current": "true"},
        ]
        incoming = [
            {"id": "p-1", "name": "Alice", "dept": "security"},  # changed
            {"id": "p-2", "name": "Bob", "dept": "sales"},  # unchanged
            {"id": "p-3", "name": "Charlie", "dept": "eng"},  # new
        ]
        result = apply_scd_type2(existing, incoming, key_fields=["id"])
        assert len(result) == 4  # 2 existing + 1 closed + 1 new version + 1 new entity... wait
        # p-1: old (closed) + new (current) = 2
        # p-2: unchanged = 1
        # p-3: new = 1
        # Total: 4
        current_records = [r for r in result if str(r.get("is_current", "")).lower() == "true"]
        assert len(current_records) == 3

    def test_empty_inputs(self):
        from warlock.lake.scd import apply_scd_type2
        result = apply_scd_type2([], [], key_fields=["id"])
        assert result == []


class TestLakeRAG:
    @pytest.fixture
    def seeded_lake_for_rag(self, tmp_path):
        import pyarrow as pa
        import pyarrow.parquet as pq

        date = "2026-03-21"

        # Control results
        cr = {"id": ["cr-1", "cr-2"], "finding_id": ["f-1", "f-2"],
              "control_mapping_id": ["cm-1", "cm-2"],
              "framework": ["nist_800_53", "soc2"],
              "control_id": ["AC-2", "CC6.1"],
              "status": ["compliant", "non_compliant"],
              "severity": ["high", "critical"],
              "assertion_name": ["mfa_check", "encryption_check"],
              "assertion_passed": [True, False],
              "assessed_at": [datetime.now(timezone.utc).isoformat()] * 2,
              "run_id": ["run-1"] * 2}
        for fw in ["nist_800_53", "soc2"]:
            d = Path(tmp_path) / "curated" / "control_results" / fw / date
            d.mkdir(parents=True, exist_ok=True)
            fw_data = {k: [v for v, f in zip(cr[k], cr["framework"]) if f == fw] for k in cr}
            pq.write_table(pa.table(fw_data), str(d / "run-1.parquet"))

        # Findings
        f = {"id": ["f-1", "f-2"], "title": ["No MFA enabled", "Disk unencrypted"],
             "severity": ["high", "critical"], "source": ["aws", "aws"],
             "observation_type": ["iam_user", "ebs_volume"],
             "raw_event_id": ["r-1", "r-2"], "detail": ["", ""],
             "resource_id": ["u-1", "v-1"], "resource_type": ["user", "volume"],
             "source_type": ["cloud", "cloud"], "provider": ["aws", "aws"],
             "confidence": [1.0, 1.0],
             "observed_at": [datetime.now(timezone.utc).isoformat()] * 2,
             "ingested_at": [datetime.now(timezone.utc).isoformat()] * 2,
             "sha256": ["abc", "def"], "run_id": ["run-1"] * 2}
        d = Path(tmp_path) / "enrichment" / "aws" / date
        d.mkdir(parents=True, exist_ok=True)
        pq.write_table(pa.table(f), str(d / "run-1.parquet"))

        # Control mappings
        cm = {"id": ["cm-1", "cm-2"], "finding_id": ["f-1", "f-2"],
              "framework": ["nist_800_53", "soc2"],
              "control_id": ["AC-2", "CC6.1"],
              "control_family": ["AC", "CC6"],
              "mapping_method": ["explicit", "explicit"],
              "confidence": [1.0, 1.0],
              "created_at": [datetime.now(timezone.utc).isoformat()] * 2,
              "run_id": ["run-1"] * 2}
        d = Path(tmp_path) / "curated" / "control_mappings" / date
        d.mkdir(parents=True, exist_ok=True)
        pq.write_table(pa.table(cm), str(d / "run-1.parquet"))

        return str(tmp_path)

    def test_index_builds(self, seeded_lake_for_rag):
        from warlock.lake.rag import LakeRAG
        rag = LakeRAG(seeded_lake_for_rag)
        count = rag.index()
        assert count > 0
        assert rag.document_count > 0

    def test_query_returns_results(self, seeded_lake_for_rag):
        from warlock.lake.rag import LakeRAG
        rag = LakeRAG(seeded_lake_for_rag)
        rag.index()
        results = rag.query("access control compliance")
        assert len(results) > 0
        assert results[0].score > 0

    def test_query_relevance(self, seeded_lake_for_rag):
        from warlock.lake.rag import LakeRAG
        rag = LakeRAG(seeded_lake_for_rag)
        rag.index()
        results = rag.query("MFA authentication")
        # Should find the MFA-related control
        found_mfa = any("mfa" in r.document.content.lower() for r in results)
        assert found_mfa

    def test_empty_lake(self, tmp_path):
        from warlock.lake.rag import LakeRAG
        rag = LakeRAG(str(tmp_path))
        count = rag.index()
        assert count == 0
        results = rag.query("anything")
        assert results == []

    def test_empty_query(self, seeded_lake_for_rag):
        from warlock.lake.rag import LakeRAG
        rag = LakeRAG(seeded_lake_for_rag)
        rag.index()
        results = rag.query("")
        assert results == []


class TestIcebergWiring:
    def test_register_table(self, tmp_path):
        from warlock.lake.catalog import create_catalog, register_table, ensure_namespace
        from warlock.lake.schema import generate_iceberg_schema
        from warlock.db.models import ControlResult

        catalog = create_catalog("sqlite", str(tmp_path / "catalog.db"))
        ensure_namespace(catalog, "warlock")
        schema = generate_iceberg_schema(ControlResult)
        table = register_table(
            catalog, "warlock", "control_results", schema,
            location=str(tmp_path / "curated" / "control_results"),
        )
        assert table is not None

    def test_register_table_idempotent(self, tmp_path):
        from warlock.lake.catalog import create_catalog, register_table, ensure_namespace
        from warlock.lake.schema import generate_iceberg_schema
        from warlock.db.models import ControlResult

        catalog = create_catalog("sqlite", str(tmp_path / "catalog.db"))
        ensure_namespace(catalog, "warlock")
        schema = generate_iceberg_schema(ControlResult)
        location = str(tmp_path / "curated" / "control_results")

        table1 = register_table(catalog, "warlock", "control_results", schema, location=location)
        table2 = register_table(catalog, "warlock", "control_results", schema, location=location)
        assert table1 is not None
        assert table2 is not None

    def test_get_pyarrow_schema(self):
        import pyarrow as pa
        from warlock.lake.schema import get_pyarrow_schema
        from warlock.db.models import ControlResult

        schema = get_pyarrow_schema(ControlResult)
        assert isinstance(schema, pa.Schema)
        field_names = [f.name for f in schema]
        assert "id" in field_names
        assert "framework" in field_names
        assert "status" in field_names

    def test_register_pipeline_tables(self, tmp_path):
        from warlock.lake.catalog import register_pipeline_tables

        results = register_pipeline_tables(str(tmp_path))
        assert len(results) > 0
        # At least some should register
        assert any(v == "registered" for v in results.values())
