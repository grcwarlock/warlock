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


def register_table(catalog, namespace: str, table_name: str, schema, location: str):
    """Register or update a table in the Iceberg catalog.

    If the table already exists, returns it. Otherwise creates it.
    """
    from pyiceberg.exceptions import NoSuchTableError

    identifier = (namespace, table_name)
    try:
        return catalog.load_table(identifier)
    except NoSuchTableError:
        return catalog.create_table(identifier, schema=schema, location=location)


def ensure_namespace(catalog, namespace: str) -> None:
    """Create a namespace if it doesn't exist."""
    from pyiceberg.exceptions import NamespaceAlreadyExistsError

    try:
        catalog.create_namespace(namespace)
    except (NamespaceAlreadyExistsError, Exception):
        pass  # Already exists or not supported by catalog type


def register_pipeline_tables(
    lake_path: str,
    catalog_type: str = "sqlite",
    catalog_uri: str = "",
) -> dict[str, str]:
    """Register all pipeline tables with the Iceberg catalog.

    Creates the catalog, namespace, and registers each table that has
    Parquet files in the lake directory.

    Returns dict of {table_name: status} where status is 'registered' or 'failed: ...'.
    """
    from pathlib import Path

    from warlock.lake.schema import generate_all_schemas

    base = Path(lake_path)

    # Default catalog URI for SQLite
    if not catalog_uri:
        catalog_uri = str(base / "catalog.db")

    catalog = create_catalog(catalog_type, catalog_uri)
    ensure_namespace(catalog, "warlock")

    schemas = generate_all_schemas()
    results: dict[str, str] = {}

    # Map schema names to their lake locations
    table_locations = {
        "raw_events": str(base / "raw"),
        "findings": str(base / "enrichment"),
        "control_results": str(base / "curated" / "control_results"),
        "control_mappings": str(base / "curated" / "control_mappings"),
        "connector_runs": str(base / "curated" / "connector_runs"),
        "posture_snapshots": str(base / "curated" / "posture_snapshots"),
        "compliance_drifts": str(base / "curated" / "compliance_drift"),
        "audit_entries": str(base / "curated" / "audit_entries"),
    }

    for table_name, schema in schemas.items():
        location = table_locations.get(table_name, str(base / "curated" / table_name))
        try:
            register_table(catalog, "warlock", table_name, schema, location)
            results[table_name] = "registered"
        except Exception as exc:
            log.warning("Failed to register table %s: %s", table_name, exc)
            results[table_name] = f"failed: {exc}"

    return results
