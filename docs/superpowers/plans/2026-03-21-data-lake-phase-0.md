# Data Lake Phase 0: Foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the foundational infrastructure for the GRC data lake — storage abstraction, DuckDB feasibility validation, Iceberg catalog, local-dev lake story, and repository pattern completion — so that Phase 1 (lake writer) can proceed with confidence.

**Architecture:** Phase 0 is purely additive. No existing functionality changes. The pipeline continues writing to OLTP exactly as it does today. We add new abstractions alongside existing code, validate DuckDB can serve our hardest queries, and complete the repository pattern to create clean seams for Phase 2's query migration.

**Tech Stack:** DuckDB, PyArrow, PyIceberg, existing SQLAlchemy/FastAPI/Click

**Spec:** `docs/superpowers/specs/2026-03-21-grc-data-lake-design.md`

**Acceptance criteria:** Demo seed passes unchanged. All 295+ tests pass. QA gate green. DuckDB feasibility spike produces latency measurements. Local lake directory created with sample Parquet files.

---

## File Structure

### New Files

| File | Responsibility |
|---|---|
| `warlock/lake/__init__.py` | Lake package init |
| `warlock/lake/storage.py` | Object storage abstraction — Protocol + 3 backends (local, S3, Azure) |
| `warlock/lake/catalog.py` | Iceberg catalog abstraction — SQLite (dev) and REST (cloud) |
| `warlock/lake/query.py` | DuckDB query engine wrapper — read Parquet/Iceberg tables |
| `warlock/lake/config.py` | Lake configuration settings (extends `warlock/config.py`) |
| `warlock/lake/schema.py` | Generate Iceberg schemas from SQLAlchemy model metadata |
| `tests/test_lake.py` | Tests for storage, catalog, query, and schema modules |
| `tests/test_duckdb_feasibility.py` | DuckDB feasibility spike — 5 hardest queries benchmarked |
| `tests/test_repository_migration.py` | Verify routers use repositories, not raw session.query() |

### Modified Files

| File | What Changes |
|---|---|
| `pyproject.toml` | Add duckdb, pyarrow, pyiceberg to optional `lake` extra |
| `warlock/config.py` | Add lake settings (WLK_LAKE_ENABLED, WLK_LAKE_PATH, WLK_LAKE_CATALOG_TYPE) |
| `warlock/api/routers/compliance.py` | Migrate 24 raw db.query() calls to repository methods |
| `warlock/api/routers/risk.py` | Migrate raw db.query() calls to repository methods |
| `warlock/api/routers/admin.py` | Migrate 16 raw db.query() calls to repository methods |
| `warlock/api/routers/export.py` | Migrate 3 raw db.query() calls to repository methods |
| `warlock/api/routers/pipeline.py` | Migrate 4 raw db.query() calls to repository methods |
| `warlock/pipeline/queue.py` | Add NATS JetStream backend for durable event bus |
| `warlock/db/repository.py` | Add missing repository methods needed by routers |
| `scripts/qa.sh` | Add lake validation when WLK_LAKE_ENABLED=true |

---

## Task 1: Add Lake Dependencies

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add lake optional dependencies**

In `pyproject.toml`, add a new `lake` extra after the existing `monitoring` extra:

```toml
lake = ["duckdb>=1.1", "pyarrow>=17.0", "pyiceberg[pyarrow]>=0.7"]
```

- [ ] **Step 2: Install and verify**

Run: `pip install -e ".[dev,lake]"`
Expected: Installs duckdb, pyarrow, pyiceberg without conflicts

- [ ] **Step 3: Verify no JVM dependency**

Run: `python -c "import duckdb; import pyarrow; import pyiceberg; print('All lake deps OK')"`
Expected: `All lake deps OK` — no Java errors

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "feat: add duckdb, pyarrow, pyiceberg as optional lake dependencies"
```

---

## Task 2: Lake Configuration Settings

**Files:**
- Modify: `warlock/config.py`
- Test: `tests/test_lake.py`

- [ ] **Step 1: Write failing test for lake config**

Create `tests/test_lake.py`:

```python
"""Tests for data lake infrastructure."""

import os
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_lake.py::TestLakeConfig -v`
Expected: FAIL — `lake_enabled` attribute not found on Settings

- [ ] **Step 3: Add lake settings to config.py**

In `warlock/config.py`, add to the `Settings` class after the existing fields:

```python
    # --- Data Lake ---
    lake_enabled: bool = False
    lake_path: str = "lake"  # Local filesystem path or object store prefix
    lake_catalog_type: str = "sqlite"  # "sqlite" (dev) or "rest" (cloud)
    lake_catalog_url: str = ""  # REST catalog URL (cloud only)
    lake_storage_backend: str = "local"  # "local", "s3", "azure"
    lake_storage_url: str = ""  # S3 bucket URL or Azure container URL
    lake_storage_region: str = ""  # For S3-compatible stores
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_lake.py::TestLakeConfig -v`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -x -q`
Expected: 295+ passed

- [ ] **Step 6: Commit**

```bash
git add warlock/config.py tests/test_lake.py
git commit -m "feat: add lake configuration settings to Settings class"
```

---

## Task 3: Object Storage Abstraction

**Files:**
- Create: `warlock/lake/__init__.py`
- Create: `warlock/lake/storage.py`
- Test: `tests/test_lake.py`

- [ ] **Step 1: Create lake package**

Create `warlock/lake/__init__.py`:

```python
"""Warlock GRC Data Lake infrastructure."""
```

- [ ] **Step 2: Write failing tests for storage abstraction**

Add to `tests/test_lake.py`:

```python
import tempfile
from pathlib import Path


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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_lake.py::TestLocalStorage -v`
Expected: FAIL — `LocalStorage` not found

- [ ] **Step 4: Implement storage abstraction**

Create `warlock/lake/storage.py`:

```python
"""Cloud-agnostic object storage abstraction.

Supports:
- Local filesystem (dev/on-prem)
- S3-compatible API (AWS, GCS, Alibaba, DigitalOcean, MinIO, OVH, etc.)
- Azure Blob Storage

The interface is intentionally minimal: put, get, list, delete, exists.
Parquet files don't care where they live.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Protocol, runtime_checkable

log = logging.getLogger(__name__)


@runtime_checkable
class ObjectStorage(Protocol):
    """Protocol for cloud-agnostic object storage."""

    def put(self, path: str, data: bytes) -> None: ...
    def get(self, path: str) -> bytes: ...
    def list(self, prefix: str) -> list[str]: ...
    def delete(self, path: str) -> None: ...
    def exists(self, path: str) -> bool: ...


class LocalStorage:
    """Local filesystem storage backend for dev and on-prem."""

    def __init__(self, base_path: str) -> None:
        self._base = Path(base_path)
        self._base.mkdir(parents=True, exist_ok=True)

    def put(self, path: str, data: bytes) -> None:
        full = self._base / path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(data)

    def get(self, path: str) -> bytes:
        full = self._base / path
        if not full.exists():
            raise FileNotFoundError(f"Object not found: {path}")
        return full.read_bytes()

    def list(self, prefix: str) -> list[str]:
        target = self._base / prefix
        if not target.exists():
            return []
        results = []
        for p in target.rglob("*"):
            if p.is_file():
                results.append(str(p.relative_to(self._base)))
        return sorted(results)

    def delete(self, path: str) -> None:
        full = self._base / path
        if full.exists():
            full.unlink()

    def exists(self, path: str) -> bool:
        return (self._base / path).exists()


class S3Storage:
    """S3-compatible object storage backend.

    Works with: AWS S3, GCS (interop), Alibaba OSS, DigitalOcean Spaces,
    MinIO, OVH, Huawei OBS, and any S3-compatible API.
    """

    def __init__(self, bucket_url: str, region: str = "") -> None:
        import boto3

        self._bucket_url = bucket_url
        # Parse bucket name from URL (s3://bucket-name/prefix)
        parts = bucket_url.replace("s3://", "").split("/", 1)
        self._bucket = parts[0]
        self._prefix = parts[1] if len(parts) > 1 else ""
        kwargs: dict = {}
        if region:
            kwargs["region_name"] = region
        # Support custom endpoints for S3-compatible services
        endpoint = os.environ.get("WLK_S3_ENDPOINT_URL", "")
        if endpoint:
            kwargs["endpoint_url"] = endpoint
        self._client = boto3.client("s3", **kwargs)

    def _full_key(self, path: str) -> str:
        return f"{self._prefix}/{path}" if self._prefix else path

    def put(self, path: str, data: bytes) -> None:
        self._client.put_object(Bucket=self._bucket, Key=self._full_key(path), Body=data)

    def get(self, path: str) -> bytes:
        try:
            resp = self._client.get_object(Bucket=self._bucket, Key=self._full_key(path))
            return resp["Body"].read()
        except self._client.exceptions.NoSuchKey:
            raise FileNotFoundError(f"Object not found: {path}")

    def list(self, prefix: str) -> list[str]:
        full_prefix = self._full_key(prefix)
        results = []
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket, Prefix=full_prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if self._prefix:
                    key = key[len(self._prefix) + 1 :]
                results.append(key)
        return sorted(results)

    def delete(self, path: str) -> None:
        self._client.delete_object(Bucket=self._bucket, Key=self._full_key(path))

    def exists(self, path: str) -> bool:
        try:
            self._client.head_object(Bucket=self._bucket, Key=self._full_key(path))
            return True
        except Exception:
            return False


class AzureBlobStorage:
    """Azure Blob Storage backend."""

    def __init__(self, container_url: str) -> None:
        from azure.storage.blob import ContainerClient

        self._client = ContainerClient.from_container_url(container_url)

    def put(self, path: str, data: bytes) -> None:
        self._client.upload_blob(path, data, overwrite=True)

    def get(self, path: str) -> bytes:
        try:
            blob = self._client.download_blob(path)
            return blob.readall()
        except Exception:
            raise FileNotFoundError(f"Object not found: {path}")

    def list(self, prefix: str) -> list[str]:
        return sorted(b.name for b in self._client.list_blobs(name_starts_with=prefix))

    def delete(self, path: str) -> None:
        self._client.delete_blob(path)

    def exists(self, path: str) -> bool:
        try:
            self._client.get_blob_properties(path)
            return True
        except Exception:
            return False


def create_storage(backend: str, path: str = "lake", url: str = "", region: str = "") -> ObjectStorage:
    """Factory for creating storage backends from config."""
    if backend == "local":
        return LocalStorage(path)
    elif backend == "s3":
        if not url:
            raise ValueError("WLK_LAKE_STORAGE_URL required for S3 backend")
        return S3Storage(url, region)
    elif backend == "azure":
        if not url:
            raise ValueError("WLK_LAKE_STORAGE_URL required for Azure backend")
        return AzureBlobStorage(url)
    else:
        raise ValueError(f"Unknown storage backend: {backend}")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_lake.py::TestLocalStorage -v`
Expected: All 5 PASS

- [ ] **Step 6: Run full test suite**

Run: `pytest tests/ -x -q`
Expected: 295+ passed (existing tests unaffected)

- [ ] **Step 7: Commit**

```bash
git add warlock/lake/__init__.py warlock/lake/storage.py tests/test_lake.py
git commit -m "feat: add cloud-agnostic object storage abstraction with local, S3, Azure backends"
```

---

## Task 4: DuckDB Query Engine Wrapper

**Files:**
- Create: `warlock/lake/query.py`
- Test: `tests/test_lake.py`

- [ ] **Step 1: Write failing test for DuckDB query wrapper**

Add to `tests/test_lake.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_lake.py::TestDuckDBQuery -v`
Expected: FAIL — `LakeQueryEngine` not found

- [ ] **Step 3: Implement DuckDB query wrapper**

Create `warlock/lake/query.py`:

```python
"""DuckDB query engine for reading Parquet/Iceberg data from the lake.

DuckDB runs in-process (no server). It reads Parquet files directly
from local filesystem or object storage. No JVM dependency.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


class LakeQueryEngine:
    """Embedded DuckDB query engine for analytical queries over the lake."""

    def __init__(self, lake_path: str = "lake") -> None:
        import duckdb

        self._lake_path = lake_path
        self._conn = duckdb.connect()
        # httpfs extension only needed for S3/HTTP reads, not local filesystem
        if lake_path.startswith("s3://") or lake_path.startswith("http"):
            try:
                self._conn.execute("INSTALL httpfs; LOAD httpfs;")
            except Exception:
                log.warning("Failed to load httpfs extension — S3/HTTP reads unavailable")
        log.info("DuckDB lake query engine initialized (lake_path=%s)", lake_path)

    def query(self, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        """Execute a SQL query and return results as a list of dicts."""
        result = self._conn.execute(sql, params or [])
        columns = [desc[0] for desc in result.description]
        return [dict(zip(columns, row)) for row in result.fetchall()]

    def query_df(self, sql: str, params: list[Any] | None = None):
        """Execute a SQL query and return a PyArrow Table."""
        result = self._conn.execute(sql, params or [])
        return result.fetch_arrow_table()

    def close(self) -> None:
        """Close the DuckDB connection."""
        self._conn.close()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_lake.py::TestDuckDBQuery -v`
Expected: All 2 PASS

- [ ] **Step 5: Commit**

```bash
git add warlock/lake/query.py tests/test_lake.py
git commit -m "feat: add DuckDB query engine wrapper for lake reads"
```

---

## Task 5: Iceberg Schema Generator

**Files:**
- Create: `warlock/lake/schema.py`
- Test: `tests/test_lake.py`

- [ ] **Step 1: Write failing test for schema generation**

Add to `tests/test_lake.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_lake.py::TestSchemaGenerator -v`
Expected: FAIL — `generate_iceberg_schema` not found

- [ ] **Step 3: Implement schema generator**

Create `warlock/lake/schema.py`:

```python
"""Generate Iceberg schemas from SQLAlchemy model metadata.

Keeps Parquet/Iceberg schemas in sync with the ORM. Run as part of CI
to prevent schema divergence between OLTP and lake.
"""

from __future__ import annotations

import logging
from typing import Any

from pyiceberg.schema import Schema
from pyiceberg.types import (
    BooleanType,
    DateType,
    DoubleType,
    FloatType,
    IntegerType,
    LongType,
    NestedField,
    StringType,
    TimestampType,
    TimestamptzType,
)
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import DeclarativeBase

log = logging.getLogger(__name__)

# Map SQLAlchemy type names to Iceberg types
_TYPE_MAP: dict[str, Any] = {
    "VARCHAR": StringType,
    "TEXT": StringType,
    "STRING": StringType,
    "NVARCHAR": StringType,
    "INTEGER": IntegerType,
    "BIGINT": LongType,
    "SMALLINT": IntegerType,
    "FLOAT": FloatType,
    "DOUBLE": DoubleType,
    "DOUBLE_PRECISION": DoubleType,
    "NUMERIC": DoubleType,
    "BOOLEAN": BooleanType,
    "DATE": DateType,
    "DATETIME": TimestamptzType,
    "TIMESTAMP": TimestamptzType,
    "JSON": StringType,  # Stored as JSON string in Parquet; parsed at query time
    "JSONB": StringType,
}


def generate_iceberg_schema(model_class: type) -> Schema:
    """Generate an Iceberg Schema from a SQLAlchemy model class."""
    mapper = sa_inspect(model_class)
    fields = []
    field_id = 1

    for column in mapper.columns:
        type_name = type(column.type).__name__.upper()
        # Handle parameterized types (e.g., String(36) -> STRING)
        iceberg_type_cls = _TYPE_MAP.get(type_name, StringType)
        fields.append(
            NestedField(
                field_id=field_id,
                name=column.name,
                field_type=iceberg_type_cls(),
                required=not column.nullable,
            )
        )
        field_id += 1

    return Schema(*fields)


def generate_all_schemas() -> dict[str, Schema]:
    """Generate Iceberg schemas for all pipeline models."""
    from warlock.db.models import (
        ConnectorRun,
        ControlMapping,
        ControlResult,
        Finding,
        RawEvent,
        PostureSnapshot,
        ComplianceDrift,
        AuditEntry,
    )

    models = {
        "connector_runs": ConnectorRun,
        "raw_events": RawEvent,
        "findings": Finding,
        "control_mappings": ControlMapping,
        "control_results": ControlResult,
        "posture_snapshots": PostureSnapshot,
        "compliance_drifts": ComplianceDrift,
        "audit_entries": AuditEntry,
    }

    return {name: generate_iceberg_schema(model) for name, model in models.items()}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_lake.py::TestSchemaGenerator -v`
Expected: All 3 PASS

- [ ] **Step 5: Commit**

```bash
git add warlock/lake/schema.py tests/test_lake.py
git commit -m "feat: generate Iceberg schemas from SQLAlchemy model metadata"
```

---

## Task 5b: Iceberg Catalog Abstraction

**Files:**
- Create: `warlock/lake/catalog.py`
- Test: `tests/test_lake.py`

- [ ] **Step 1: Write failing test for catalog abstraction**

Add to `tests/test_lake.py`:

```python
class TestIcebergCatalog:
    def test_sqlite_catalog_creates_db(self, tmp_path):
        from warlock.lake.catalog import create_catalog
        catalog = create_catalog("sqlite", str(tmp_path / "catalog.db"))
        assert catalog is not None

    def test_catalog_factory_validates_type(self):
        from warlock.lake.catalog import create_catalog
        with pytest.raises(ValueError, match="Unknown catalog type"):
            create_catalog("invalid", "")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_lake.py::TestIcebergCatalog -v`
Expected: FAIL — `create_catalog` not found

- [ ] **Step 3: Implement catalog abstraction**

Create `warlock/lake/catalog.py`:

```python
"""Iceberg catalog abstraction.

Supports:
- SQLite catalog (dev/on-prem) — PyIceberg native, no server needed
- REST catalog (cloud) — connects to any Iceberg REST catalog service
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


def create_catalog(catalog_type: str, uri: str, **kwargs: Any):
    """Factory for creating Iceberg catalog instances.

    Args:
        catalog_type: "sqlite" or "rest"
        uri: SQLite DB path (for sqlite) or REST catalog URL (for rest)
    """
    from pyiceberg.catalog import load_catalog

    if catalog_type == "sqlite":
        return load_catalog(
            "warlock",
            **{
                "type": "sql",
                "uri": f"sqlite:///{uri}",
                **kwargs,
            },
        )
    elif catalog_type == "rest":
        if not uri:
            raise ValueError("REST catalog URL required")
        return load_catalog(
            "warlock",
            **{
                "type": "rest",
                "uri": uri,
                **kwargs,
            },
        )
    else:
        raise ValueError(f"Unknown catalog type: {catalog_type}. Use 'sqlite' or 'rest'.")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_lake.py::TestIcebergCatalog -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add warlock/lake/catalog.py tests/test_lake.py
git commit -m "feat: add Iceberg catalog abstraction — SQLite (dev) and REST (cloud)"
```

---

## Task 5c: NATS JetStream Event Bus Backend

**Files:**
- Modify: `warlock/pipeline/queue.py`
- Test: `tests/test_lake.py`

NATS JetStream provides a lightweight durable event bus for self-hosted deployments. No JVM, no Kafka cluster — single binary. This is new work not yet in queue.py.

- [ ] **Step 1: Write failing test for NATS backend factory**

Add to `tests/test_lake.py`:

```python
class TestNATSBackend:
    def test_nats_backend_registered_in_factory(self):
        """Verify the factory recognizes 'nats' as a valid backend."""
        from warlock.pipeline.queue import QueueConfig, create_bus
        config = QueueConfig(backend="nats", url="nats://localhost:4222")
        # Should not raise ValueError for unknown backend
        # Will raise ConnectionError since no NATS server is running, which is OK
        try:
            bus = create_bus(config)
        except Exception as e:
            # Connection errors are expected (no NATS server in test)
            # ValueError("Unknown backend") is NOT expected
            assert "Unknown" not in str(e), f"NATS backend not registered: {e}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_lake.py::TestNATSBackend -v`
Expected: FAIL — "Unknown" backend error

- [ ] **Step 3: Implement NATS JetStream backend**

Add to `warlock/pipeline/queue.py` — a `NATSBus` class following the same pattern as `RedisStreamBus` and `KafkaBus`. Uses `nats-py` package (pure Python, no JVM).

Key methods:
- `subscribe(event_type, handler)` — create JetStream consumer
- `publish(event)` — publish to JetStream subject
- `subscribe_all(handler)` — subscribe to wildcard subject `warlock.>`

Update `create_bus()` factory to recognize `backend="nats"`.

- [ ] **Step 4: Add nats-py to optional dependencies**

In `pyproject.toml`, add to the `lake` extra:

```toml
lake = ["duckdb>=1.1", "pyarrow>=17.0", "pyiceberg[pyarrow]>=0.7", "nats-py>=2.7"]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_lake.py::TestNATSBackend -v`
Expected: PASS (connection error is acceptable, not "Unknown backend")

- [ ] **Step 6: Commit**

```bash
git add warlock/pipeline/queue.py pyproject.toml tests/test_lake.py
git commit -m "feat: add NATS JetStream event bus backend for durable self-hosted deployments"
```

---

## Task 6: DuckDB Feasibility Spike

**Files:**
- Create: `tests/test_duckdb_feasibility.py`

This task validates that DuckDB can serve the 5 hardest compliance queries from the API. We generate Parquet files at 10x demo scale (5,470 findings, 292,070 control results) and measure query latency.

- [ ] **Step 1: Write the feasibility benchmarks**

Create `tests/test_duckdb_feasibility.py`:

```python
"""DuckDB Feasibility Spike — Phase 0 Validation.

Generates Parquet files at 10x demo scale and benchmarks the 5 hardest
compliance queries. Target: all queries < 500ms.
"""

import time
import uuid
from datetime import datetime, timezone, timedelta
import pytest

FRAMEWORKS = [
    "nist_800_53", "iso_27001", "soc2", "hipaa", "fedramp",
    "pci_dss", "cmmc_l2", "gdpr", "iso_27701", "iso_42001",
    "ucf", "nist_csf", "eu_ai_act", "sec_cyber",
]
STATUSES = ["compliant", "non_compliant", "partial", "not_assessed", "not_applicable"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SCALE = 10  # 10x demo numbers


@pytest.fixture(scope="module")
def lake_parquet(tmp_path_factory):
    """Generate Parquet files at 10x demo scale."""
    import pyarrow as pa
    import pyarrow.parquet as pq
    import random

    random.seed(42)
    base = tmp_path_factory.mktemp("lake")
    now = datetime.now(timezone.utc)

    # Control results: ~29K per run * 10 = 290K rows
    n_results = 29_000 * SCALE
    results_data = {
        "id": [str(uuid.uuid4()) for _ in range(n_results)],
        "finding_id": [str(uuid.uuid4()) for _ in range(n_results)],
        "framework": [random.choice(FRAMEWORKS) for _ in range(n_results)],
        "control_id": [f"CTRL-{random.randint(1, 200)}" for _ in range(n_results)],
        "status": [random.choice(STATUSES) for _ in range(n_results)],
        "severity": [random.choice(SEVERITIES) for _ in range(n_results)],
        "assessed_at": [
            now - timedelta(days=random.randint(0, 180)) for _ in range(n_results)
        ],
        "assessor": [
            random.choice(["assertion:mfa_check", "opa:nist_800_53", "ai:gemini", "manual"])
            for _ in range(n_results)
        ],
    }
    pq.write_table(
        pa.table(results_data),
        str(base / "control_results.parquet"),
    )

    # Posture snapshots: ~8K per day * 180 days = ~1.4M rows
    n_snapshots = 8_000 * 180
    snapshots_data = {
        "id": [str(uuid.uuid4()) for _ in range(n_snapshots)],
        "framework": [random.choice(FRAMEWORKS) for _ in range(n_snapshots)],
        "control_id": [f"CTRL-{random.randint(1, 200)}" for _ in range(n_snapshots)],
        "snapshot_date": [
            (now - timedelta(days=random.randint(0, 180))).date() for _ in range(n_snapshots)
        ],
        "posture_score": [random.uniform(0, 100) for _ in range(n_snapshots)],
        "status": [random.choice(STATUSES) for _ in range(n_snapshots)],
    }
    pq.write_table(
        pa.table(snapshots_data),
        str(base / "posture_snapshots.parquet"),
    )

    # Findings: ~550 per run * 10 = 5,500 rows
    n_findings = 550 * SCALE
    findings_data = {
        "id": [str(uuid.uuid4()) for _ in range(n_findings)],
        "severity": [random.choice(SEVERITIES) for _ in range(n_findings)],
        "source": [random.choice(["aws", "okta", "crowdstrike", "tenable"]) for _ in range(n_findings)],
        "observed_at": [
            now - timedelta(days=random.randint(0, 90)) for _ in range(n_findings)
        ],
    }
    pq.write_table(
        pa.table(findings_data),
        str(base / "findings.parquet"),
    )

    return base


class TestDuckDBFeasibility:
    """Each query must complete in < 500ms at 10x demo scale."""

    MAX_MS = 500

    def test_query_1_dashboard_framework_status_groupby(self, lake_parquet):
        """Dashboard summary: GROUP BY framework, status with counts."""
        from warlock.lake.query import LakeQueryEngine
        engine = LakeQueryEngine(str(lake_parquet))
        path = str(lake_parquet / "control_results.parquet")

        start = time.perf_counter()
        result = engine.query(f"""
            SELECT framework, status, COUNT(*) as cnt
            FROM read_parquet('{path}')
            GROUP BY framework, status
            ORDER BY framework, cnt DESC
        """)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert len(result) > 0
        assert elapsed_ms < self.MAX_MS, f"Dashboard query took {elapsed_ms:.0f}ms (limit {self.MAX_MS}ms)"
        print(f"\n  Dashboard GROUP BY: {elapsed_ms:.1f}ms ({len(result)} rows)")

    def test_query_2_posture_trend_avg_by_framework(self, lake_parquet):
        """Posture trend: AVG score per framework per snapshot date."""
        from warlock.lake.query import LakeQueryEngine
        engine = LakeQueryEngine(str(lake_parquet))
        path = str(lake_parquet / "posture_snapshots.parquet")

        start = time.perf_counter()
        result = engine.query(f"""
            SELECT framework, snapshot_date, AVG(posture_score) as avg_score
            FROM read_parquet('{path}')
            GROUP BY framework, snapshot_date
            ORDER BY framework, snapshot_date
        """)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert len(result) > 0
        assert elapsed_ms < self.MAX_MS, f"Posture trend query took {elapsed_ms:.0f}ms (limit {self.MAX_MS}ms)"
        print(f"\n  Posture trend AVG: {elapsed_ms:.1f}ms ({len(result)} rows)")

    def test_query_3_coverage_summary_with_counts(self, lake_parquet):
        """Coverage summary: count by framework + status with percentage."""
        from warlock.lake.query import LakeQueryEngine
        engine = LakeQueryEngine(str(lake_parquet))
        path = str(lake_parquet / "control_results.parquet")

        start = time.perf_counter()
        result = engine.query(f"""
            WITH totals AS (
                SELECT framework, COUNT(*) as total
                FROM read_parquet('{path}')
                GROUP BY framework
            ),
            statuses AS (
                SELECT framework, status, COUNT(*) as cnt
                FROM read_parquet('{path}')
                GROUP BY framework, status
            )
            SELECT s.framework, s.status, s.cnt,
                   ROUND(s.cnt * 100.0 / t.total, 1) as pct
            FROM statuses s
            JOIN totals t ON s.framework = t.framework
            ORDER BY s.framework, s.cnt DESC
        """)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert len(result) > 0
        assert elapsed_ms < self.MAX_MS, f"Coverage summary took {elapsed_ms:.0f}ms (limit {self.MAX_MS}ms)"
        print(f"\n  Coverage CTE: {elapsed_ms:.1f}ms ({len(result)} rows)")

    def test_query_4_findings_with_window_pagination(self, lake_parquet):
        """Paginated findings with total count via window function (replaces COUNT+SELECT)."""
        from warlock.lake.query import LakeQueryEngine
        engine = LakeQueryEngine(str(lake_parquet))
        path = str(lake_parquet / "findings.parquet")

        start = time.perf_counter()
        result = engine.query(f"""
            SELECT *, COUNT(*) OVER() as total
            FROM read_parquet('{path}')
            WHERE severity IN ('critical', 'high')
            ORDER BY observed_at DESC
            LIMIT 100 OFFSET 0
        """)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert len(result) <= 100
        assert "total" in result[0]
        assert elapsed_ms < self.MAX_MS, f"Windowed pagination took {elapsed_ms:.0f}ms (limit {self.MAX_MS}ms)"
        print(f"\n  Window pagination: {elapsed_ms:.1f}ms ({len(result)} rows, total={result[0]['total']})")

    def test_query_5_cross_framework_drift_detection(self, lake_parquet):
        """Drift detection: compare latest two snapshot dates per framework."""
        from warlock.lake.query import LakeQueryEngine
        engine = LakeQueryEngine(str(lake_parquet))
        path = str(lake_parquet / "posture_snapshots.parquet")

        start = time.perf_counter()
        result = engine.query(f"""
            WITH ranked AS (
                SELECT framework, control_id, status, posture_score, snapshot_date,
                       ROW_NUMBER() OVER (PARTITION BY framework, control_id ORDER BY snapshot_date DESC) as rn
                FROM read_parquet('{path}')
            ),
            current AS (SELECT * FROM ranked WHERE rn = 1),
            previous AS (SELECT * FROM ranked WHERE rn = 2)
            SELECT c.framework, c.control_id,
                   p.status as prev_status, c.status as curr_status,
                   p.posture_score as prev_score, c.posture_score as curr_score
            FROM current c
            JOIN previous p ON c.framework = p.framework AND c.control_id = p.control_id
            WHERE c.status != p.status
            ORDER BY c.framework, c.control_id
        """)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < self.MAX_MS, f"Drift detection took {elapsed_ms:.0f}ms (limit {self.MAX_MS}ms)"
        print(f"\n  Drift detection: {elapsed_ms:.1f}ms ({len(result)} drifted controls)")
```

- [ ] **Step 2: Run the feasibility spike**

Run: `pytest tests/test_duckdb_feasibility.py -v -s`
Expected: All 5 PASS with timing output. All queries < 500ms.

- [ ] **Step 3: Record results**

Document the latency numbers in a comment at the top of the test file. These become the Phase 2 migration baseline.

- [ ] **Step 4: Commit**

```bash
git add tests/test_duckdb_feasibility.py
git commit -m "feat: DuckDB feasibility spike — 5 hardest queries benchmarked at 10x scale"
```

---

## Task 7: Repository Pattern Migration — Compliance Router

**Files:**
- Modify: `warlock/db/repository.py` — add missing methods
- Modify: `warlock/api/routers/compliance.py` — replace raw session.query() with repository calls
- Test: `tests/test_repository_migration.py`

This is the largest task. The compliance router has 24 raw `session.query()` calls. We migrate them to use the existing `ControlResultRepository`, `FindingRepository`, and `PostureSnapshotRepository`.

- [ ] **Step 1: Write test that verifies no raw session.query() in compliance router**

Create `tests/test_repository_migration.py`:

```python
"""Verify API routers use repository pattern, not raw session.query()."""

import ast
import pytest
from pathlib import Path

ROUTERS_DIR = Path("warlock/api/routers")

# These routers should have zero raw session.query() calls after migration
MIGRATED_ROUTERS = [
    "compliance.py",
    "risk.py",
    "admin.py",
    "export.py",
    "pipeline.py",
]

# These routers are allowed to keep raw session.query() (OLTP-only permanently)
EXEMPT_ROUTERS = ["auth_routes.py", "health.py", "ai_routes.py", "governance.py"]


class TestRepositoryMigration:
    @pytest.mark.parametrize("router_file", MIGRATED_ROUTERS)
    def test_no_raw_db_query(self, router_file):
        """Verify migrated routers don't use raw db.query() — use repository methods."""
        source = (ROUTERS_DIR / router_file).read_text()
        tree = ast.parse(source)
        # Find all method calls where the method name is "query" and the object
        # is "db" or "session" (the SQLAlchemy session variables used in routers)
        raw_query_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "query" and isinstance(node.func.value, ast.Name):
                    if node.func.value.id in ("db", "session"):
                        raw_query_calls.append(node.lineno)
        assert len(raw_query_calls) == 0, (
            f"{router_file} has {len(raw_query_calls)} raw db.query()/session.query() calls "
            f"at lines {raw_query_calls[:10]}. Use repository methods instead.\n"
            + "\n".join(f"  line {l}" for l in raw_query_calls[:5])
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_repository_migration.py::TestRepositoryMigration::test_no_raw_session_query[compliance.py] -v`
Expected: FAIL — compliance.py has 24 raw .query() calls

- [ ] **Step 3: Add missing repository methods**

Read `warlock/api/routers/compliance.py` to identify which queries need new repository methods. Add methods to `warlock/db/repository.py` that match the existing query patterns. Do NOT change query logic — just move it behind the repository interface.

Key methods to add to `ControlResultRepository`:
- `dashboard_summary(user)` — the GROUP BY framework, status query
- `list_filtered(framework, control_id, status, severity, assessor, date_range, offset, limit, user)` — paginated with ABAC
- `sufficiency_scores(framework, user)` — evidence sufficiency per control

Key methods to add to `FindingRepository`:
- `list_filtered(framework, severity, source, date_range, offset, limit, user)` — paginated with ABAC and optional framework JOIN

Key methods to add to `PostureSnapshotRepository`:
- `posture_trend(framework, control_id, days, user)` — time-series query
- `drift_events(framework, days, user)` — compliance drift

- [ ] **Step 4: Migrate compliance.py to use repository methods**

Replace each raw `db.query(...)` call with the corresponding repository method call. Use `get_repos(db)` to get the repository factory.

Example migration pattern:
```python
# Before:
fw_rows = db.query(ControlResult.framework, ControlResult.status, func.count(ControlResult.id)).group_by(...)

# After:
repos = get_repos(db)
fw_rows = repos.control_results.dashboard_summary(current_user)
```

- [ ] **Step 5: Run compliance tests**

Run: `pytest tests/test_api.py -v -k "compliance or dashboard or coverage or finding or result"`
Expected: All compliance-related API tests pass

- [ ] **Step 6: Run migration test**

Run: `pytest tests/test_repository_migration.py::TestRepositoryMigration::test_no_raw_session_query[compliance.py] -v`
Expected: PASS

- [ ] **Step 7: Run full test suite + demo seed**

Run: `pytest tests/ -x -q && rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/python scripts/demo_seed.py 2>&1 | grep -E "Connectors succeeded|failed"`
Expected: 295+ passed. 57 connectors succeeded, 0 failed.

- [ ] **Step 8: Commit**

```bash
git add warlock/db/repository.py warlock/api/routers/compliance.py tests/test_repository_migration.py
git commit -m "refactor: migrate compliance router from raw session.query() to repository pattern"
```

---

## Task 8: Repository Pattern Migration — Remaining Routers

**Files:**
- Modify: `warlock/db/repository.py` — add missing methods
- Modify: `warlock/api/routers/risk.py`
- Modify: `warlock/api/routers/admin.py` — 16 calls
- Modify: `warlock/api/routers/export.py` — 3 calls
- Modify: `warlock/api/routers/pipeline.py` — 4 calls
- Test: `tests/test_repository_migration.py`

Same pattern as Task 7, repeated for each router. Do one router at a time, test after each.

- [ ] **Step 1: Migrate risk.py**

Add needed repository methods. Replace raw queries. Run tests.

- [ ] **Step 2: Verify risk migration**

Run: `pytest tests/test_repository_migration.py::TestRepositoryMigration::test_no_raw_session_query[risk.py] -v`
Expected: PASS

- [ ] **Step 3: Migrate admin.py (16 calls)**

Add needed repository methods. Replace raw queries. Run tests.

- [ ] **Step 4: Verify admin migration**

Run: `pytest tests/test_repository_migration.py::TestRepositoryMigration::test_no_raw_session_query[admin.py] -v`
Expected: PASS

- [ ] **Step 5: Migrate export.py (3 calls) and pipeline.py (4 calls)**

Smaller files — migrate both, test both.

- [ ] **Step 6: Run all migration tests**

Run: `pytest tests/test_repository_migration.py -v`
Expected: All 5 PASS (all migrated routers clean)

- [ ] **Step 7: Run full QA gate**

Run: `./scripts/qa.sh --quick`
Expected: ALL CHECKS PASSED

- [ ] **Step 8: Commit**

```bash
git add warlock/db/repository.py warlock/api/routers/risk.py warlock/api/routers/admin.py warlock/api/routers/export.py warlock/api/routers/pipeline.py
git commit -m "refactor: migrate risk, admin, export, pipeline routers to repository pattern"
```

---

## Task 9: Local-Dev Lake Story

**Files:**
- Create: `warlock/lake/demo.py` — demo seed lake extension
- Modify: `scripts/qa.sh` — add lake validation
- Test: `tests/test_lake.py`

- [ ] **Step 1: Write test for lake demo initialization**

Add to `tests/test_lake.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_lake.py::TestLakeDemo -v`
Expected: FAIL

- [ ] **Step 3: Implement lake demo helpers**

Create `warlock/lake/demo.py`:

```python
"""Local development lake initialization.

Creates the lake directory structure and writes sample Parquet files.
Used by demo_seed.py when WLK_LAKE_ENABLED=true.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def init_lake(lake_path: str) -> None:
    """Create the lake directory structure."""
    base = Path(lake_path)
    for zone in ("raw", "enrichment", "curated"):
        (base / zone).mkdir(parents=True, exist_ok=True)
    log.info("Lake initialized at %s", lake_path)


def write_sample_parquet(
    lake_path: str, table_name: str, data: dict[str, list[Any]]
) -> None:
    """Write a dict of columns as a Parquet file to the curated zone."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    base = Path(lake_path) / "curated" / table_name
    base.mkdir(parents=True, exist_ok=True)
    table = pa.table(data)
    pq.write_table(table, str(base / "data.parquet"))
    log.info("Wrote %d rows to %s", len(next(iter(data.values()))), base)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_lake.py::TestLakeDemo -v`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -x -q`
Expected: 295+ passed

- [ ] **Step 6: Commit**

```bash
git add warlock/lake/demo.py tests/test_lake.py
git commit -m "feat: local-dev lake initialization and Parquet write helpers"
```

---

## Task 10: Final QA Gate + Phase 0 Completion

- [ ] **Step 1: Run the full QA gate**

Run: `./scripts/qa.sh --quick`
Expected: ALL CHECKS PASSED

- [ ] **Step 2: Run demo seed**

Run: `rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/python scripts/demo_seed.py 2>&1 | grep -E "Connectors succeeded|failed|Raw events|Findings|Controls mapped"`
Expected: 57 connectors succeeded, 0 failed (unchanged from before Phase 0)

- [ ] **Step 3: Run DuckDB feasibility results**

Run: `pytest tests/test_duckdb_feasibility.py -v -s`
Expected: All 5 queries < 500ms

- [ ] **Step 4: Verify all new tests pass**

Run: `pytest tests/test_lake.py tests/test_duckdb_feasibility.py tests/test_repository_migration.py -v`
Expected: All pass

- [ ] **Step 5: List all changes for review**

Run: `git diff --stat main`
Review file list and change summary.

- [ ] **Step 6: Commit any remaining changes**

Ask: "Ready to push?"

---

## Phase 0 Completion Criteria

All of the following must be true before starting Phase 1:

- [ ] DuckDB, PyArrow, PyIceberg install cleanly (no JVM)
- [ ] All 5 DuckDB feasibility queries run < 500ms at 10x demo scale
- [ ] Object storage abstraction works for local filesystem
- [ ] Iceberg schema generator produces correct schemas from SQLAlchemy models
- [ ] Zero raw `db.query()` calls in compliance, risk, admin, export, pipeline routers
- [ ] Iceberg catalog abstraction works for SQLite (dev) and REST (cloud)
- [ ] NATS JetStream backend implemented in queue.py
- [ ] Local lake directory structure can be created and queried
- [ ] Demo seed produces identical output (57 connectors, 0 failures)
- [ ] All 295+ existing tests pass
- [ ] QA gate passes
