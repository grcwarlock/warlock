"""Zone writers — serialize pipeline data to Parquet in lake zones.

Three zones:
- Raw: immutable append-only raw events, partitioned by source/date
- Enrichment: normalized findings, partitioned by source/date
- Curated: control results, mappings, posture snapshots, partitioned by framework/date
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def _ensure_dir(path: Path) -> None:
    """Create directory and parents if they don't exist."""
    path.mkdir(parents=True, exist_ok=True)


def _today_partition() -> str:
    """Return today's date as YYYY-MM-DD for partitioning."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _serialize_json_field(value: Any) -> str:
    """Serialize a JSON-capable field to a deterministic string.

    Uses sort_keys=True and default=str to preserve SHA-256 hash integrity
    across OLTP and lake representations.
    """
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, sort_keys=True, default=str)


def write_raw_zone(lake_path: str, run_id: str, raw_events: list[dict]) -> int:
    """Write raw events to raw zone as Parquet. Returns row count.

    Partitions by source/date. Each pipeline run produces one file per source.
    """
    import pyarrow as pa
    import pyarrow.parquet as pq

    if not raw_events:
        return 0

    date_part = _today_partition()

    # Group events by source for partitioning
    by_source: dict[str, list[dict]] = {}
    for evt in raw_events:
        source = evt.get("source", "unknown")
        by_source.setdefault(source, []).append(evt)

    total = 0
    for source, events in by_source.items():
        rows = {
            "id": [],
            "connector_run_id": [],
            "source": [],
            "source_type": [],
            "provider": [],
            "event_type": [],
            "raw_data": [],
            "sha256": [],
            "ingested_at": [],
            "run_id": [],
        }
        for evt in events:
            rows["id"].append(str(evt.get("id", "")))
            rows["connector_run_id"].append(str(evt.get("connector_run_id", "")))
            rows["source"].append(str(evt.get("source", "")))
            rows["source_type"].append(str(evt.get("source_type", "")))
            rows["provider"].append(str(evt.get("provider", "")))
            rows["event_type"].append(str(evt.get("event_type", "")))
            rows["raw_data"].append(_serialize_json_field(evt.get("raw_data")))
            rows["sha256"].append(str(evt.get("sha256", "")))
            rows["ingested_at"].append(str(evt.get("ingested_at", "")))
            rows["run_id"].append(run_id)

        table = pa.table(rows)
        out_dir = Path(lake_path) / "raw" / source / date_part
        _ensure_dir(out_dir)
        out_file = out_dir / f"{run_id}.parquet"
        pq.write_table(table, str(out_file))
        total += len(events)
        log.info("Wrote %d raw events to %s", len(events), out_file)

    return total


def write_enrichment_zone(lake_path: str, run_id: str, findings: list[dict]) -> int:
    """Write normalized findings to enrichment zone. Returns row count.

    Partitions by source/date.
    """
    import pyarrow as pa
    import pyarrow.parquet as pq

    if not findings:
        return 0

    date_part = _today_partition()

    # Group by source
    by_source: dict[str, list[dict]] = {}
    for f in findings:
        source = f.get("source", "unknown")
        by_source.setdefault(source, []).append(f)

    total = 0
    for source, items in by_source.items():
        rows = {
            "id": [],
            "raw_event_id": [],
            "observation_type": [],
            "title": [],
            "detail": [],
            "resource_id": [],
            "resource_type": [],
            "source": [],
            "source_type": [],
            "provider": [],
            "severity": [],
            "confidence": [],
            "observed_at": [],
            "ingested_at": [],
            "sha256": [],
            "run_id": [],
        }
        for f in items:
            rows["id"].append(str(f.get("id", "")))
            rows["raw_event_id"].append(str(f.get("raw_event_id", "")))
            rows["observation_type"].append(str(f.get("observation_type", "")))
            rows["title"].append(str(f.get("title", "")))
            rows["detail"].append(_serialize_json_field(f.get("detail")))
            rows["resource_id"].append(str(f.get("resource_id", "")))
            rows["resource_type"].append(str(f.get("resource_type", "")))
            rows["source"].append(str(f.get("source", "")))
            rows["source_type"].append(str(f.get("source_type", "")))
            rows["provider"].append(str(f.get("provider", "")))
            rows["severity"].append(str(f.get("severity", "")))
            rows["confidence"].append(float(f.get("confidence", 1.0)))
            rows["observed_at"].append(str(f.get("observed_at", "")))
            rows["ingested_at"].append(str(f.get("ingested_at", "")))
            rows["sha256"].append(str(f.get("sha256", "")))
            rows["run_id"].append(run_id)

        table = pa.table(rows)
        out_dir = Path(lake_path) / "enrichment" / source / date_part
        _ensure_dir(out_dir)
        out_file = out_dir / f"{run_id}.parquet"
        pq.write_table(table, str(out_file))
        total += len(items)
        log.info("Wrote %d findings to %s", len(items), out_file)

    return total


def write_curated_zone(
    lake_path: str,
    run_id: str,
    control_results: list[dict],
    control_mappings: list[dict],
    connector_runs: list[dict],
) -> int:
    """Write control results, mappings, and connector runs to curated zone.

    Returns total row count across all tables.
    Control results partitioned by framework/date.
    Mappings and connector runs partitioned by date.
    """
    import pyarrow as pa
    import pyarrow.parquet as pq

    date_part = _today_partition()
    total = 0

    # --- Control results (partitioned by framework/date) ---
    if control_results:
        by_framework: dict[str, list[dict]] = {}
        for cr in control_results:
            fw = cr.get("framework", "unknown")
            by_framework.setdefault(fw, []).append(cr)

        for framework, items in by_framework.items():
            rows = {
                "id": [],
                "finding_id": [],
                "control_mapping_id": [],
                "framework": [],
                "control_id": [],
                "status": [],
                "severity": [],
                "assertion_name": [],
                "assertion_passed": [],
                "assessed_at": [],
                "run_id": [],
            }
            for cr in items:
                rows["id"].append(str(cr.get("id", "")))
                rows["finding_id"].append(str(cr.get("finding_id", "")))
                rows["control_mapping_id"].append(str(cr.get("control_mapping_id", "")))
                rows["framework"].append(str(cr.get("framework", "")))
                rows["control_id"].append(str(cr.get("control_id", "")))
                rows["status"].append(str(cr.get("status", "")))
                rows["severity"].append(str(cr.get("severity", "")))
                rows["assertion_name"].append(str(cr.get("assertion_name", "")))
                rows["assertion_passed"].append(bool(cr.get("assertion_passed", False)))
                rows["assessed_at"].append(str(cr.get("assessed_at", "")))
                rows["run_id"].append(run_id)

            table = pa.table(rows)
            out_dir = Path(lake_path) / "curated" / "control_results" / framework / date_part
            _ensure_dir(out_dir)
            out_file = out_dir / f"{run_id}.parquet"
            pq.write_table(table, str(out_file))
            total += len(items)
            log.info("Wrote %d control results (%s) to %s", len(items), framework, out_file)

    # --- Control mappings (partitioned by date) ---
    if control_mappings:
        rows = {
            "id": [],
            "finding_id": [],
            "framework": [],
            "control_id": [],
            "control_family": [],
            "mapping_method": [],
            "confidence": [],
            "created_at": [],
            "run_id": [],
        }
        for cm in control_mappings:
            rows["id"].append(str(cm.get("id", "")))
            rows["finding_id"].append(str(cm.get("finding_id", "")))
            rows["framework"].append(str(cm.get("framework", "")))
            rows["control_id"].append(str(cm.get("control_id", "")))
            rows["control_family"].append(str(cm.get("control_family", "")))
            rows["mapping_method"].append(str(cm.get("mapping_method", "")))
            rows["confidence"].append(float(cm.get("confidence", 0.0)))
            rows["created_at"].append(str(cm.get("created_at", "")))
            rows["run_id"].append(run_id)

        table = pa.table(rows)
        out_dir = Path(lake_path) / "curated" / "control_mappings" / date_part
        _ensure_dir(out_dir)
        out_file = out_dir / f"{run_id}.parquet"
        pq.write_table(table, str(out_file))
        total += len(control_mappings)
        log.info("Wrote %d control mappings to %s", len(control_mappings), out_file)

    # --- Connector runs (partitioned by date) ---
    if connector_runs:
        rows = {
            "id": [],
            "connector_name": [],
            "source": [],
            "source_type": [],
            "provider": [],
            "status": [],
            "event_count": [],
            "error_count": [],
            "started_at": [],
            "completed_at": [],
            "duration_seconds": [],
            "run_id": [],
        }
        for cr in connector_runs:
            rows["id"].append(str(cr.get("id", "")))
            rows["connector_name"].append(str(cr.get("connector_name", "")))
            rows["source"].append(str(cr.get("source", "")))
            rows["source_type"].append(str(cr.get("source_type", "")))
            rows["provider"].append(str(cr.get("provider", "")))
            rows["status"].append(str(cr.get("status", "")))
            rows["event_count"].append(int(cr.get("event_count", 0)))
            rows["error_count"].append(int(cr.get("error_count", 0)))
            rows["started_at"].append(str(cr.get("started_at", "")))
            rows["completed_at"].append(str(cr.get("completed_at", "")))
            rows["duration_seconds"].append(float(cr.get("duration_seconds", 0.0)))
            rows["run_id"].append(run_id)

        table = pa.table(rows)
        out_dir = Path(lake_path) / "curated" / "connector_runs" / date_part
        _ensure_dir(out_dir)
        out_file = out_dir / f"{run_id}.parquet"
        pq.write_table(table, str(out_file))
        total += len(connector_runs)
        log.info("Wrote %d connector runs to %s", len(connector_runs), out_file)

    return total
