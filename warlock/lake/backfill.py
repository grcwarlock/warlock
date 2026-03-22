"""Backfill existing OLTP historical data to the lake.

Reads all pipeline data from OLTP (raw events, findings, control mappings,
control results, connector runs) and writes to lake zones as Parquet.

This is a one-time (or periodic) operation for bootstrapping the lake with
data that was collected before the lake writer was enabled.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from warlock.lake.utils import model_to_dict

log = logging.getLogger(__name__)


@dataclass
class BackfillStats:
    """Statistics from a backfill operation."""

    raw_events: int = 0
    findings: int = 0
    control_mappings: int = 0
    control_results: int = 0
    connector_runs: int = 0
    posture_snapshots: int = 0
    compliance_drifts: int = 0
    audit_entries: int = 0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (
            self.raw_events
            + self.findings
            + self.control_mappings
            + self.control_results
            + self.connector_runs
            + self.posture_snapshots
            + self.compliance_drifts
            + self.audit_entries
        )


def backfill(session: Any, lake_path: str, batch_size: int = 10000) -> BackfillStats:
    """Backfill all OLTP pipeline data to lake.

    Reads tables in batches and writes to the appropriate lake zones.
    Returns BackfillStats with counts per table.

    Parameters
    ----------
    session:
        SQLAlchemy session with access to OLTP data.
    lake_path:
        Root path for the lake directory structure.
    batch_size:
        Number of rows to process per batch (for memory efficiency).
    """
    from warlock.db.models import (
        AuditEntry,
        ComplianceDrift,
        ConnectorRun,
        ControlMapping,
        ControlResult,
        Finding,
        PostureSnapshot,
        RawEvent,
    )
    from warlock.lake.domains import write_governance_facts, write_temporal_facts
    from warlock.lake.zones import (
        write_curated_zone,
        write_enrichment_zone,
        write_raw_zone,
    )

    start = time.monotonic()
    stats = BackfillStats()
    run_id = "backfill"

    # --- Raw events ---
    try:
        offset = 0
        while True:
            batch = (
                session.query(RawEvent).order_by(RawEvent.id).offset(offset).limit(batch_size).all()
            )
            if not batch:
                break
            dicts = [model_to_dict(r) for r in batch]
            written = write_raw_zone(lake_path, run_id, dicts)
            stats.raw_events += written
            offset += batch_size
            log.info("Backfilled %d raw events (offset=%d)", written, offset)
    except Exception as exc:
        msg = f"Raw event backfill failed: {exc}"
        log.exception(msg)
        stats.errors.append(msg)

    # --- Findings ---
    try:
        offset = 0
        while True:
            batch = (
                session.query(Finding).order_by(Finding.id).offset(offset).limit(batch_size).all()
            )
            if not batch:
                break
            dicts = [model_to_dict(r) for r in batch]
            written = write_enrichment_zone(lake_path, run_id, dicts)
            stats.findings += written
            offset += batch_size
            log.info("Backfilled %d findings (offset=%d)", written, offset)
    except Exception as exc:
        msg = f"Finding backfill failed: {exc}"
        log.exception(msg)
        stats.errors.append(msg)

    # --- Control results, mappings, connector runs (curated zone) ---
    try:
        cr_dicts: list[dict] = []
        offset = 0
        while True:
            batch = (
                session.query(ControlResult)
                .order_by(ControlResult.id)
                .offset(offset)
                .limit(batch_size)
                .all()
            )
            if not batch:
                break
            cr_dicts.extend(model_to_dict(r) for r in batch)
            offset += batch_size

        cm_dicts: list[dict] = []
        offset = 0
        while True:
            batch = (
                session.query(ControlMapping)
                .order_by(ControlMapping.id)
                .offset(offset)
                .limit(batch_size)
                .all()
            )
            if not batch:
                break
            cm_dicts.extend(model_to_dict(r) for r in batch)
            offset += batch_size

        conn_dicts: list[dict] = []
        offset = 0
        while True:
            batch = (
                session.query(ConnectorRun)
                .order_by(ConnectorRun.id)
                .offset(offset)
                .limit(batch_size)
                .all()
            )
            if not batch:
                break
            conn_dicts.extend(model_to_dict(r) for r in batch)
            offset += batch_size

        if cr_dicts or cm_dicts or conn_dicts:
            write_curated_zone(lake_path, run_id, cr_dicts, cm_dicts, conn_dicts)
            stats.control_results = len(cr_dicts)
            stats.control_mappings = len(cm_dicts)
            stats.connector_runs = len(conn_dicts)
            log.info(
                "Backfilled curated zone: %d results, %d mappings, %d connector runs",
                stats.control_results,
                stats.control_mappings,
                stats.connector_runs,
            )
    except Exception as exc:
        msg = f"Curated zone backfill failed: {exc}"
        log.exception(msg)
        stats.errors.append(msg)

    # --- Posture snapshots (temporal domain) ---
    try:
        offset = 0
        snapshot_dicts: list[dict] = []
        while True:
            batch = (
                session.query(PostureSnapshot)
                .order_by(PostureSnapshot.id)
                .offset(offset)
                .limit(batch_size)
                .all()
            )
            if not batch:
                break
            snapshot_dicts.extend(model_to_dict(r) for r in batch)
            offset += batch_size

        if snapshot_dicts:
            written = write_temporal_facts(lake_path, run_id, posture_snapshots=snapshot_dicts)
            stats.posture_snapshots = written
            log.info("Backfilled %d posture snapshots", written)
    except Exception as exc:
        msg = f"Posture snapshot backfill failed: {exc}"
        log.exception(msg)
        stats.errors.append(msg)

    # --- Compliance drifts (temporal domain) ---
    try:
        offset = 0
        drift_dicts: list[dict] = []
        while True:
            batch = (
                session.query(ComplianceDrift)
                .order_by(ComplianceDrift.id)
                .offset(offset)
                .limit(batch_size)
                .all()
            )
            if not batch:
                break
            drift_dicts.extend(model_to_dict(r) for r in batch)
            offset += batch_size

        if drift_dicts:
            written = write_temporal_facts(lake_path, run_id, compliance_drifts=drift_dicts)
            stats.compliance_drifts = written
            log.info("Backfilled %d compliance drifts", written)
    except Exception as exc:
        msg = f"Compliance drift backfill failed: {exc}"
        log.exception(msg)
        stats.errors.append(msg)

    # --- Audit entries (governance domain) ---
    try:
        offset = 0
        audit_dicts: list[dict] = []
        while True:
            batch = (
                session.query(AuditEntry)
                .order_by(AuditEntry.id)
                .offset(offset)
                .limit(batch_size)
                .all()
            )
            if not batch:
                break
            audit_dicts.extend(model_to_dict(r) for r in batch)
            offset += batch_size

        if audit_dicts:
            written = write_governance_facts(lake_path, run_id, audit_entries=audit_dicts)
            stats.audit_entries = written
            log.info("Backfilled %d audit entries", written)
    except Exception as exc:
        msg = f"Audit entry backfill failed: {exc}"
        log.exception(msg)
        stats.errors.append(msg)

    stats.duration_seconds = time.monotonic() - start
    log.info(
        "Backfill complete: %d total rows in %.2fs",
        stats.total,
        stats.duration_seconds,
    )
    return stats
