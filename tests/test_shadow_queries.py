"""Tests for shadow query comparator."""
import pytest


class TestCompareResults:
    def test_matching_results(self):
        from warlock.lake.shadow import compare_results
        oltp = [(1, "a"), (2, "b")]
        lake = [(1, "a"), (2, "b")]
        result = compare_results("test_query", oltp, lake)
        assert result.match is True
        assert result.discrepancies == []

    def test_mismatched_values(self):
        from warlock.lake.shadow import compare_results
        oltp = [(1, "a"), (2, "b")]
        lake = [(1, "a"), (2, "c")]
        result = compare_results("test_query", oltp, lake)
        assert result.match is False
        assert len(result.discrepancies) > 0

    def test_count_mismatch(self):
        from warlock.lake.shadow import compare_results
        oltp = [(1, "a")]
        lake = [(1, "a"), (2, "b")]
        result = compare_results("test_query", oltp, lake)
        assert result.match is False
        assert "Row count" in result.discrepancies[0]

    def test_empty_results_match(self):
        from warlock.lake.shadow import compare_results
        result = compare_results("test", [], [])
        assert result.match is True

    def test_none_results(self):
        from warlock.lake.shadow import compare_results
        result = compare_results("test", None, None)
        assert result.match is True


class TestShadowQueryRunner:
    def test_compare_matching(self):
        from warlock.lake.shadow import ShadowQueryRunner
        runner = ShadowQueryRunner()
        result = runner.compare("test", lambda: [(1,)], lambda: [(1,)])
        assert result.match is True
        assert runner.all_match is True

    def test_compare_mismatch(self):
        from warlock.lake.shadow import ShadowQueryRunner
        runner = ShadowQueryRunner()
        result = runner.compare("test", lambda: [(1,)], lambda: [(2,)])
        assert result.match is False
        assert runner.all_match is False
        assert len(runner.mismatches) == 1

    def test_lake_failure_graceful(self):
        from warlock.lake.shadow import ShadowQueryRunner
        runner = ShadowQueryRunner()
        def fail(): raise RuntimeError("DuckDB crashed")
        result = runner.compare("test", lambda: [(1,)], fail)
        assert result.match is False
        assert "Lake query failed" in result.discrepancies[0]

    def test_timing_recorded(self):
        from warlock.lake.shadow import ShadowQueryRunner
        runner = ShadowQueryRunner()
        result = runner.compare("test", lambda: [], lambda: [])
        assert result.oltp_ms >= 0
        assert result.lake_ms >= 0
