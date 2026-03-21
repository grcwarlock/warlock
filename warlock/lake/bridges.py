"""Bridge table writers for cross-domain relationships.

Bridge tables connect entities across curated zone domains:
- Crosswalks: framework-to-framework control mappings
- Entity relationships: graph model for blast radius analysis
- Data flows: data classification and transfer tracking
- Boundary membership: FedRAMP authorization boundaries
- Incident bridges: which controls/entities were affected
"""

from __future__ import annotations

import logging
from typing import Any

from warlock.lake.utils import today_partition, ensure_dir

log = logging.getLogger(__name__)


def write_bridge_tables(
    lake_path: str,
    run_id: str,
    crosswalks: list[dict] | None = None,
    entity_relationships: list[dict] | None = None,
    data_flows: list[dict] | None = None,
    boundary_memberships: list[dict] | None = None,
    incident_controls: list[dict] | None = None,
    incident_entities: list[dict] | None = None,
) -> int:
    """Write bridge tables to the curated zone. Returns total row count."""
    total = 0

    if crosswalks:
        total += _write_bridge(lake_path, "bridge_control_crosswalk", crosswalks, run_id)
    if entity_relationships:
        total += _write_bridge(lake_path, "bridge_entity_relationship", entity_relationships, run_id)
    if data_flows:
        total += _write_bridge(lake_path, "fact_data_flow", data_flows, run_id)
    if boundary_memberships:
        total += _write_bridge(lake_path, "fact_boundary_membership", boundary_memberships, run_id)
    if incident_controls:
        total += _write_bridge(lake_path, "bridge_incident_control", incident_controls, run_id)
    if incident_entities:
        total += _write_bridge(lake_path, "bridge_incident_entity", incident_entities, run_id)

    return total


def _write_bridge(lake_path: str, table_name: str, rows: list[dict], run_id: str) -> int:
    """Write a single bridge table to Parquet."""
    if not rows:
        return 0

    import pyarrow as pa
    import pyarrow.parquet as pq
    from pathlib import Path

    date_part = today_partition()

    # Build columns preserving types
    columns: dict[str, list] = {}
    for key in rows[0]:
        values = [r.get(key) for r in rows]
        sample = next((v for v in values if v is not None), "")
        if isinstance(sample, bool):
            columns[key] = [bool(v) if v is not None else False for v in values]
        elif isinstance(sample, (int, float)):
            columns[key] = [float(v) if v is not None else 0.0 for v in values]
        else:
            columns[key] = [str(v) if v is not None else "" for v in values]
    columns["run_id"] = [run_id] * len(rows)

    table = pa.table(columns)
    out_dir = Path(lake_path) / "curated" / table_name / date_part
    ensure_dir(out_dir)
    out_file = out_dir / f"{run_id}.parquet"
    pq.write_table(table, str(out_file))
    log.info("Wrote %d rows to %s", len(rows), out_file)
    return len(rows)
