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


class TestSchemaGenerator:
    def test_generates_schema_for_control_result(self):
        from warlock.lake.schema import generate_iceberg_schema
        from warlock.db.models import ControlResult
        schema = generate_iceberg_schema(ControlResult)
        field_names = [f.name for f in schema.fields]
        assert "id" in field_names
        assert "framework" in field_names
        assert "status" in field_names
        assert "assessed_at" in field_names

    def test_generates_schema_for_finding(self):
        from warlock.lake.schema import generate_iceberg_schema
        from warlock.db.models import Finding
        schema = generate_iceberg_schema(Finding)
        field_names = [f.name for f in schema.fields]
        assert "id" in field_names
        assert "severity" in field_names
        assert "observed_at" in field_names

    def test_maps_sqlalchemy_types_correctly(self):
        from warlock.lake.schema import generate_iceberg_schema
        from warlock.db.models import ControlResult
        schema = generate_iceberg_schema(ControlResult)
        id_field = next(f for f in schema.fields if f.name == "id")
        assert id_field.field_type.__class__.__name__ == "StringType"


class TestIcebergCatalog:
    def test_sqlite_catalog_creates_db(self, tmp_path):
        from warlock.lake.catalog import create_catalog
        catalog = create_catalog("sqlite", str(tmp_path / "catalog.db"))
        assert catalog is not None

    def test_catalog_factory_validates_type(self):
        from warlock.lake.catalog import create_catalog
        with pytest.raises(ValueError, match="Unknown catalog type"):
            create_catalog("invalid", "")


class TestNATSBackend:
    def test_nats_backend_registered_in_factory(self):
        """Verify the factory recognizes 'nats' as a valid backend."""
        from warlock.pipeline.queue import _BACKEND_MAP
        # The backend map should include "nats"
        assert "nats" in _BACKEND_MAP, "NATS backend not registered in _BACKEND_MAP"


class TestLakeDemo:
    def test_init_creates_lake_directory(self, tmp_path):
        from warlock.lake.demo import init_lake
        lake_path = str(tmp_path / "lake")
        init_lake(lake_path)
        assert (tmp_path / "lake").exists()
        assert (tmp_path / "lake" / "raw").exists()
        assert (tmp_path / "lake" / "enrichment").exists()
        assert (tmp_path / "lake" / "curated").exists()

    def test_write_sample_parquet(self, tmp_path):
        from warlock.lake.demo import write_sample_parquet
        lake_path = str(tmp_path / "lake")
        write_sample_parquet(lake_path, "test_table", {"id": ["a"], "value": [1]})
        from warlock.lake.query import LakeQueryEngine
        engine = LakeQueryEngine(lake_path)
        result = engine.query(
            f"SELECT * FROM read_parquet('{tmp_path}/lake/curated/test_table/*.parquet')"
        )
        assert len(result) == 1
