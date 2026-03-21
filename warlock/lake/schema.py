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
    TimestamptzType,
)
from sqlalchemy import inspect as sa_inspect

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


def get_pyarrow_schema(model_class: type) -> Any:
    """Generate a PyArrow schema from a SQLAlchemy model class.

    Useful for writing strongly-typed Parquet files.
    """
    import pyarrow as pa

    mapper = sa_inspect(model_class)
    fields = []

    _PA_TYPE_MAP = {
        "VARCHAR": pa.string(),
        "TEXT": pa.string(),
        "STRING": pa.string(),
        "INTEGER": pa.int64(),
        "BIGINT": pa.int64(),
        "SMALLINT": pa.int32(),
        "FLOAT": pa.float64(),
        "DOUBLE": pa.float64(),
        "BOOLEAN": pa.bool_(),
        "DATETIME": pa.timestamp("us", tz="UTC"),
        "TIMESTAMP": pa.timestamp("us", tz="UTC"),
        "DATE": pa.date32(),
        "JSON": pa.string(),
        "JSONB": pa.string(),
    }

    for column in mapper.columns:
        type_name = type(column.type).__name__.upper()
        pa_type = _PA_TYPE_MAP.get(type_name, pa.string())
        fields.append(pa.field(column.name, pa_type, nullable=column.nullable))

    return pa.schema(fields)
