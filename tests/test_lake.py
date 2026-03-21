"""Tests for data lake infrastructure."""

import os
import tempfile
from pathlib import Path
import pytest


class TestLakeConfig:
    def test_lake_disabled_by_default(self):
        from warlock.config import get_settings
        s = get_settings()
        assert s.lake_enabled is False

    def test_lake_path_default(self):
        from warlock.config import get_settings
        s = get_settings()
        assert s.lake_path == "lake"

    def test_lake_catalog_type_default(self):
        from warlock.config import get_settings
        s = get_settings()
        assert s.lake_catalog_type == "sqlite"


class TestLocalStorage:
    def test_put_and_get(self, tmp_path):
        from warlock.lake.storage import LocalStorage
        store = LocalStorage(str(tmp_path))
        store.put("test/data.parquet", b"fake parquet data")
        result = store.get("test/data.parquet")
        assert result == b"fake parquet data"

    def test_list_prefix(self, tmp_path):
        from warlock.lake.storage import LocalStorage
        store = LocalStorage(str(tmp_path))
        store.put("raw/aws/2026-03-21/events.parquet", b"data1")
        store.put("raw/aws/2026-03-21/events2.parquet", b"data2")
        store.put("raw/okta/2026-03-21/events.parquet", b"data3")
        files = store.list("raw/aws/")
        assert len(files) == 2

    def test_delete(self, tmp_path):
        from warlock.lake.storage import LocalStorage
        store = LocalStorage(str(tmp_path))
        store.put("test/file.parquet", b"data")
        store.delete("test/file.parquet")
        files = store.list("test/")
        assert len(files) == 0

    def test_get_nonexistent_raises(self, tmp_path):
        from warlock.lake.storage import LocalStorage
        store = LocalStorage(str(tmp_path))
        with pytest.raises(FileNotFoundError):
            store.get("nonexistent.parquet")

    def test_exists(self, tmp_path):
        from warlock.lake.storage import LocalStorage
        store = LocalStorage(str(tmp_path))
        assert store.exists("nope") is False
        store.put("yes", b"data")
        assert store.exists("yes") is True


class TestDuckDBQuery:
    def test_query_parquet_file(self, tmp_path):
        import pyarrow as pa
        import pyarrow.parquet as pq
        from warlock.lake.query import LakeQueryEngine

        # Create a sample parquet file
        table = pa.table({
            "framework": ["nist_800_53", "nist_800_53", "soc2"],
            "status": ["compliant", "non_compliant", "compliant"],
            "count": [10, 5, 8],
        })
        pq.write_table(table, str(tmp_path / "results.parquet"))

        engine = LakeQueryEngine(str(tmp_path))
        result = engine.query(
            "SELECT framework, SUM(count) as total FROM read_parquet(?) GROUP BY framework ORDER BY framework",
            [str(tmp_path / "results.parquet")],
        )
        assert len(result) == 2
        assert result[0]["framework"] == "nist_800_53"
        assert result[0]["total"] == 15

    def test_query_returns_dicts(self, tmp_path):
        import pyarrow as pa
        import pyarrow.parquet as pq
        from warlock.lake.query import LakeQueryEngine

        table = pa.table({"id": ["a", "b"], "value": [1, 2]})
        pq.write_table(table, str(tmp_path / "test.parquet"))

        engine = LakeQueryEngine(str(tmp_path))
        result = engine.query(
            "SELECT * FROM read_parquet(?)",
            [str(tmp_path / "test.parquet")],
        )
        assert isinstance(result[0], dict)
        assert result[0]["id"] == "a"
