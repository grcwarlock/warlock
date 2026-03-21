"""Tests for lake maintenance jobs."""
from pathlib import Path
import pytest


class TestCompaction:
    def test_compact_merges_small_files(self, tmp_path):
        import pyarrow as pa
        import pyarrow.parquet as pq
        from warlock.lake.maintenance import compact

        # Create multiple small files in a zone dir
        zone = tmp_path / "curated" / "control_results" / "nist_800_53" / "2026-03-21"
        zone.mkdir(parents=True)
        for i in range(5):
            t = pa.table({"id": [f"r-{i}"], "status": ["compliant"]})
            pq.write_table(t, str(zone / f"run-{i}.parquet"))

        stats = compact(str(tmp_path))
        assert len(stats) > 0
        # Should have merged into one file
        remaining = list(zone.glob("*.parquet"))
        assert len(remaining) == 1

    def test_compact_no_action_single_file(self, tmp_path):
        import pyarrow as pa
        import pyarrow.parquet as pq
        from warlock.lake.maintenance import compact

        zone = tmp_path / "raw" / "aws" / "2026-03-21"
        zone.mkdir(parents=True)
        pq.write_table(pa.table({"id": ["r-1"]}), str(zone / "run-1.parquet"))

        stats = compact(str(tmp_path))
        assert stats == {}

    def test_compact_empty_lake(self, tmp_path):
        from warlock.lake.maintenance import compact

        stats = compact(str(tmp_path))
        assert stats == {}


class TestExpiry:
    def test_expire_old_files(self, tmp_path):
        import os
        import time

        import pyarrow as pa
        import pyarrow.parquet as pq
        from warlock.lake.maintenance import expire_snapshots

        zone = tmp_path / "raw" / "aws" / "2026-01-01"
        zone.mkdir(parents=True)
        f = zone / "old.parquet"
        pq.write_table(pa.table({"id": ["r-1"]}), str(f))
        # Set mtime to 30 days ago
        old_time = time.time() - (30 * 86400)
        os.utime(str(f), (old_time, old_time))

        stats = expire_snapshots(str(tmp_path), raw_days=7)
        assert "raw" in stats
        assert stats["raw"] == 1
        assert not f.exists()

    def test_expire_keeps_recent(self, tmp_path):
        import pyarrow as pa
        import pyarrow.parquet as pq
        from warlock.lake.maintenance import expire_snapshots

        zone = tmp_path / "raw" / "aws" / "2026-03-21"
        zone.mkdir(parents=True)
        f = zone / "recent.parquet"
        pq.write_table(pa.table({"id": ["r-1"]}), str(f))

        stats = expire_snapshots(str(tmp_path), raw_days=7)
        assert stats == {}
        assert f.exists()


class TestOrphanCleanup:
    def test_cleanup_empty_dirs(self, tmp_path):
        from warlock.lake.maintenance import cleanup_orphans

        empty = tmp_path / "raw" / "aws" / "2026-01-01"
        empty.mkdir(parents=True)

        stats = cleanup_orphans(str(tmp_path))
        assert "raw" in stats
        assert not empty.exists()

    def test_cleanup_preserves_dirs_with_files(self, tmp_path):
        import pyarrow as pa
        import pyarrow.parquet as pq
        from warlock.lake.maintenance import cleanup_orphans

        zone = tmp_path / "raw" / "aws" / "2026-03-21"
        zone.mkdir(parents=True)
        pq.write_table(pa.table({"id": ["r-1"]}), str(zone / "data.parquet"))

        stats = cleanup_orphans(str(tmp_path))
        assert zone.exists()


class TestRunAll:
    def test_run_all_empty(self, tmp_path):
        from warlock.lake.maintenance import run_all_maintenance

        results = run_all_maintenance(str(tmp_path))
        assert "compaction" in results
        assert "expiry" in results
        assert "orphan_cleanup" in results
