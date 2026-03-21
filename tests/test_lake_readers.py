"""Tests for lake reader methods with seeded Parquet data."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

pytest.importorskip("pyarrow")

import pyarrow as pa
import pyarrow.parquet as pq

from warlock.lake.readers import LakeReaders


@pytest.fixture
def seeded_lake(tmp_path):
    """Create a lake directory with sample Parquet data across all zones."""
    lake = tmp_path / "lake"

    # --- Control results (curated/control_results/) ---
    cr_dir = lake / "curated" / "control_results" / "2026-03-21"
    cr_dir.mkdir(parents=True)
    cr_table = pa.table(
        {
            "framework": ["nist_800_53", "nist_800_53", "soc2", "soc2", "iso_27001"],
            "control_id": ["AC-2", "AC-3", "CC6.1", "CC6.2", "A.5.1"],
            "status": [
                "compliant",
                "non_compliant",
                "compliant",
                "non_compliant",
                "compliant",
            ],
            "severity": ["high", "critical", "medium", "high", "low"],
            "assessed_at": [
                datetime(2026, 3, 20, 10, 0, tzinfo=timezone.utc),
                datetime(2026, 3, 21, 12, 0, tzinfo=timezone.utc),
                datetime(2026, 3, 19, 8, 0, tzinfo=timezone.utc),
                datetime(2026, 3, 21, 11, 0, tzinfo=timezone.utc),
                datetime(2026, 3, 18, 9, 0, tzinfo=timezone.utc),
            ],
        }
    )
    pq.write_table(cr_table, str(cr_dir / "data.parquet"))

    # --- Findings (enrichment/) ---
    findings_dir = lake / "enrichment" / "2026-03-21"
    findings_dir.mkdir(parents=True)
    findings_table = pa.table(
        {
            "id": ["f1", "f2", "f3"],
            "severity": ["high", "critical", "medium"],
            "source": ["aws", "aws", "aws"],
            "title": ["S3 bucket public", "IAM root key", "SG open port"],
            "observed_at": [
                datetime(2026, 3, 21, 10, 0, tzinfo=timezone.utc),
                datetime(2026, 3, 21, 11, 0, tzinfo=timezone.utc),
                datetime(2026, 3, 20, 9, 0, tzinfo=timezone.utc),
            ],
        }
    )
    pq.write_table(findings_table, str(findings_dir / "data.parquet"))

    # --- Control mappings (curated/control_mappings/) ---
    cm_dir = lake / "curated" / "control_mappings" / "2026-03-21"
    cm_dir.mkdir(parents=True)
    cm_table = pa.table(
        {
            "framework": ["nist_800_53", "nist_800_53", "soc2", "soc2", "iso_27001"],
            "control_id": ["AC-2", "AC-3", "CC6.1", "CC6.2", "A.5.1"],
            "control_family": [
                "Access Control",
                "Access Control",
                "Common Criteria",
                "Common Criteria",
                "Policies",
            ],
            "mapping_method": [
                "keyword",
                "keyword",
                "keyword",
                "semantic",
                "keyword",
            ],
        }
    )
    pq.write_table(cm_table, str(cm_dir / "data.parquet"))

    # --- Connector runs (curated/connector_runs/) ---
    conn_dir = lake / "curated" / "connector_runs" / "2026-03-21"
    conn_dir.mkdir(parents=True)
    conn_table = pa.table(
        {
            "connector_name": ["aws_config", "okta"],
            "provider": ["aws", "okta"],
            "event_count": [150, 72],
            "started_at": [
                datetime(2026, 3, 21, 10, 0, tzinfo=timezone.utc),
                datetime(2026, 3, 21, 10, 5, tzinfo=timezone.utc),
            ],
            "status": ["success", "success"],
        }
    )
    pq.write_table(conn_table, str(conn_dir / "data.parquet"))

    readers = LakeReaders(str(lake))
    yield readers
    readers.close()


class TestDashboardFrameworkSummary:
    def test_returns_framework_status_count_tuples(self, seeded_lake):
        result = seeded_lake.dashboard_framework_summary()
        assert len(result) > 0
        # Each entry is (framework, status, count)
        for row in result:
            assert len(row) == 3
            assert isinstance(row[0], str)
            assert isinstance(row[1], str)
            assert isinstance(row[2], int)

    def test_correct_counts(self, seeded_lake):
        result = seeded_lake.dashboard_framework_summary()
        lookup = {(fw, st): cnt for fw, st, cnt in result}
        assert lookup[("nist_800_53", "compliant")] == 1
        assert lookup[("nist_800_53", "non_compliant")] == 1
        assert lookup[("soc2", "compliant")] == 1
        assert lookup[("soc2", "non_compliant")] == 1
        assert lookup[("iso_27001", "compliant")] == 1


class TestCoverageByStatus:
    def test_all_frameworks(self, seeded_lake):
        result = seeded_lake.coverage_by_status()
        assert len(result) == 5  # 3 frameworks * ~2 statuses (5 unique combos)
        frameworks = {r[0] for r in result}
        assert frameworks == {"nist_800_53", "soc2", "iso_27001"}

    def test_filter_by_framework(self, seeded_lake):
        result = seeded_lake.coverage_by_status(framework="soc2")
        assert all(r[0] == "soc2" for r in result)
        assert len(result) == 2  # compliant + non_compliant


class TestDistinctFrameworks:
    def test_returns_all_three(self, seeded_lake):
        result = seeded_lake.distinct_frameworks()
        assert result == ["iso_27001", "nist_800_53", "soc2"]


class TestListFrameworks:
    def test_returns_framework_control_count(self, seeded_lake):
        result = seeded_lake.list_frameworks()
        assert len(result) == 3
        lookup = dict(result)
        assert lookup["nist_800_53"] == 2
        assert lookup["soc2"] == 2
        assert lookup["iso_27001"] == 1

    def test_limit_offset(self, seeded_lake):
        result = seeded_lake.list_frameworks(limit=1, offset=0)
        assert len(result) == 1
        assert result[0][0] == "iso_27001"  # alphabetical first


class TestListControls:
    def test_filters_by_framework(self, seeded_lake):
        result = seeded_lake.list_controls("nist_800_53")
        assert len(result) == 2
        control_ids = [r[0] for r in result]
        assert "AC-2" in control_ids
        assert "AC-3" in control_ids

    def test_tuple_structure(self, seeded_lake):
        result = seeded_lake.list_controls("soc2")
        # (control_id, control_family, mapping_method, mapping_count)
        for row in result:
            assert len(row) == 4


class TestTotalEventCount:
    def test_sums_events(self, seeded_lake):
        assert seeded_lake.total_event_count() == 222  # 150 + 72


class TestLatestPerConnector:
    def test_one_row_per_connector(self, seeded_lake):
        result = seeded_lake.latest_per_connector()
        assert len(result) == 2
        names = [r["connector_name"] for r in result]
        assert "aws_config" in names
        assert "okta" in names


class TestLatestPerProvider:
    def test_one_row_per_provider(self, seeded_lake):
        result = seeded_lake.latest_per_provider()
        assert len(result) == 2
        providers = [r["provider"] for r in result]
        assert "aws" in providers
        assert "okta" in providers


class TestFindingsBySeverity:
    def test_filters_high(self, seeded_lake):
        result = seeded_lake.findings_by_severity("high")
        assert len(result) == 1
        assert result[0]["severity"] == "high"

    def test_filters_critical(self, seeded_lake):
        result = seeded_lake.findings_by_severity("critical")
        assert len(result) == 1
        assert result[0]["id"] == "f2"

    def test_no_results_for_low(self, seeded_lake):
        result = seeded_lake.findings_by_severity("low")
        assert len(result) == 0


class TestFindingsBySource:
    def test_filters_aws(self, seeded_lake):
        result = seeded_lake.findings_by_source("aws")
        assert len(result) == 3

    def test_no_results_for_unknown(self, seeded_lake):
        result = seeded_lake.findings_by_source("gcp")
        assert len(result) == 0


class TestTopNonCompliantRisks:
    def test_only_non_compliant(self, seeded_lake):
        result = seeded_lake.top_non_compliant_risks()
        assert len(result) == 2  # AC-3 and CC6.2
        for row in result:
            # These came from non_compliant rows
            assert row["framework"] in ("nist_800_53", "soc2")


class TestLastAssessedAt:
    def test_returns_latest_datetime(self, seeded_lake):
        result = seeded_lake.last_assessed_at()
        assert result is not None
        # Latest is 2026-03-21 12:00 UTC
        assert result.year == 2026
        assert result.month == 3
        assert result.day == 21


class TestPlaceholderMethods:
    def test_latest_snapshot_date(self, seeded_lake):
        assert seeded_lake.latest_snapshot_date() is None

    def test_framework_avg_scores_at(self, seeded_lake):
        assert seeded_lake.framework_avg_scores_at() == []

    def test_effectiveness_latest(self, seeded_lake):
        assert seeded_lake.effectiveness_latest() == []


@pytest.fixture
def seeded_lake_path(tmp_path):
    """Create a lake directory with sample Parquet data and return the path string."""
    lake = tmp_path / "lake"

    # --- Control results (curated/control_results/) ---
    cr_dir = lake / "curated" / "control_results" / "2026-03-21"
    cr_dir.mkdir(parents=True)
    cr_table = pa.table(
        {
            "framework": ["nist_800_53", "nist_800_53", "soc2", "soc2", "iso_27001"],
            "control_id": ["AC-2", "AC-3", "CC6.1", "CC6.2", "A.5.1"],
            "status": [
                "compliant",
                "non_compliant",
                "compliant",
                "non_compliant",
                "compliant",
            ],
            "severity": ["high", "critical", "medium", "high", "low"],
            "assessed_at": [
                datetime(2026, 3, 20, 10, 0, tzinfo=timezone.utc),
                datetime(2026, 3, 21, 12, 0, tzinfo=timezone.utc),
                datetime(2026, 3, 19, 8, 0, tzinfo=timezone.utc),
                datetime(2026, 3, 21, 11, 0, tzinfo=timezone.utc),
                datetime(2026, 3, 18, 9, 0, tzinfo=timezone.utc),
            ],
        }
    )
    pq.write_table(cr_table, str(cr_dir / "data.parquet"))

    # --- Control mappings (curated/control_mappings/) ---
    cm_dir = lake / "curated" / "control_mappings" / "2026-03-21"
    cm_dir.mkdir(parents=True)
    cm_table = pa.table(
        {
            "framework": ["nist_800_53", "nist_800_53", "soc2", "soc2", "iso_27001"],
            "control_id": ["AC-2", "AC-3", "CC6.1", "CC6.2", "A.5.1"],
            "control_family": [
                "Access Control",
                "Access Control",
                "Common Criteria",
                "Common Criteria",
                "Policies",
            ],
            "mapping_method": [
                "keyword",
                "keyword",
                "keyword",
                "semantic",
                "keyword",
            ],
        }
    )
    pq.write_table(cm_table, str(cm_dir / "data.parquet"))

    yield str(lake)


class TestAggregations:
    def test_refresh_framework_posture(self, seeded_lake_path):
        from warlock.lake.aggregations import refresh_aggregations
        from warlock.lake.query import LakeQueryEngine

        counts = refresh_aggregations(seeded_lake_path)
        assert "agg_framework_posture" in counts
        assert counts["agg_framework_posture"] > 0

        engine = LakeQueryEngine(seeded_lake_path)
        result = engine.query(
            f"SELECT * FROM read_parquet('{seeded_lake_path}/curated/agg_framework_posture/*.parquet')"
        )
        assert len(result) > 0
        assert "framework" in result[0]
        assert "compliant_count" in result[0]
        assert "compliance_pct" in result[0]
        engine.close()

    def test_refresh_control_family_posture(self, seeded_lake_path):
        from warlock.lake.aggregations import refresh_aggregations
        from warlock.lake.query import LakeQueryEngine

        counts = refresh_aggregations(seeded_lake_path)
        assert "agg_control_family_posture" in counts

        engine = LakeQueryEngine(seeded_lake_path)
        result = engine.query(
            f"SELECT * FROM read_parquet('{seeded_lake_path}/curated/agg_control_family_posture/*.parquet')"
        )
        assert len(result) > 0
        assert "control_family" in result[0]
        engine.close()

    def test_refresh_empty_lake(self, tmp_path):
        from warlock.lake.aggregations import refresh_aggregations
        counts = refresh_aggregations(str(tmp_path))
        assert counts == {}
