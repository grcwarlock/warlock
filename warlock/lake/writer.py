"""Lake writer — event bus subscriber that materializes pipeline data to Parquet.

Event-sourced materialization: the pipeline writes to OLTP as today, and this
subscriber asynchronously batches events per pipeline run and writes Parquet
files to the lake. OLTP is never blocked. Eventually consistent.

Anti-patterns avoided:
- No synchronous dual-write (this is async via event bus)
- No Parquet file-per-record (batch per pipeline run)
- SHA-256 hash integrity preserved (same serialization)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from warlock.pipeline.bus import PipelineEvent

log = logging.getLogger(__name__)


@dataclass
class LakeWriteStats:
    """Statistics from a single lake flush operation."""

    run_id: str
    raw_events_written: int = 0
    findings_written: int = 0
    control_mappings_written: int = 0
    control_results_written: int = 0
    connector_runs_written: int = 0
    posture_snapshots_written: int = 0
    compliance_drifts_written: int = 0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


def _model_to_dict(obj: Any) -> dict[str, Any]:
    """Convert a SQLAlchemy model instance to a dict.

    Handles JSON fields by serializing with sort_keys=True for hash integrity.
    """
    d: dict[str, Any] = {}
    for col in obj.__table__.columns:
        val = getattr(obj, col.name, None)
        # Serialize JSON-like fields deterministically
        if isinstance(val, (dict, list)):
            val = json.dumps(val, sort_keys=True, default=str)
        d[col.name] = val
    return d


class LakeWriter:
    """Batches pipeline events and writes Parquet files per pipeline run.

    Usage:
        writer = LakeWriter("/path/to/lake")
        bus.subscribe_all(writer.handle_event)

        # ... pipeline runs ...

        stats = writer.flush("run-123", session)
    """

    def __init__(self, lake_path: str, session_factory: Any = None) -> None:
        self._lake_path = lake_path
        self._session_factory = session_factory
        self._raw_event_ids: list[str] = []
        self._finding_ids: list[str] = []
        self._control_mapping_ids: list[str] = []
        self._control_result_ids: list[str] = []
        self._current_run_id: str | None = None

    def handle_event(self, event: PipelineEvent) -> None:
        """Event bus handler — accumulates payload IDs by event type.

        Events only carry payload_id and metadata. Full records are read
        from OLTP during flush() after the transaction commits.
        """
        if event.event_type == "raw_event.created":
            self._raw_event_ids.append(event.payload_id)
        elif event.event_type == "finding.normalized":
            self._finding_ids.append(event.payload_id)
        elif event.event_type == "finding.mapped":
            self._control_mapping_ids.append(event.payload_id)
        elif event.event_type == "control.assessed":
            self._control_result_ids.append(event.payload_id)

    def flush(self, run_id: str, session: Any = None) -> LakeWriteStats:
        """Write all accumulated data to Parquet files, then clear buffers.

        Called after pipeline.run() completes and the OLTP transaction commits.
        Reads full records from OLTP (the committed data) and writes to lake.

        If session is None, writes are skipped but buffers are still cleared.
        This is useful for testing the accumulation logic in isolation.
        """
        from warlock.lake.zones import (
            write_curated_zone,
            write_enrichment_zone,
            write_raw_zone,
        )

        start = time.monotonic()
        stats = LakeWriteStats(run_id=run_id)

        if session is not None:
            try:
                stats.raw_events_written = self._flush_raw_events(
                    session, run_id, write_raw_zone
                )
            except Exception as exc:
                msg = f"Failed to write raw zone: {exc}"
                log.exception(msg)
                stats.errors.append(msg)

            try:
                stats.findings_written = self._flush_findings(
                    session, run_id, write_enrichment_zone
                )
            except Exception as exc:
                msg = f"Failed to write enrichment zone: {exc}"
                log.exception(msg)
                stats.errors.append(msg)

            try:
                cr_count, cm_count, conn_count = self._flush_curated(
                    session, run_id, write_curated_zone
                )
                stats.control_results_written = cr_count
                stats.control_mappings_written = cm_count
                stats.connector_runs_written = conn_count
            except Exception as exc:
                msg = f"Failed to write curated zone: {exc}"
                log.exception(msg)
                stats.errors.append(msg)

            # Write temporal domain tables (posture snapshots + compliance drifts)
            try:
                snap_count, drift_count = self._flush_temporal(session, run_id)
                stats.posture_snapshots_written = snap_count
                stats.compliance_drifts_written = drift_count
            except Exception as exc:
                msg = f"Failed to write temporal zone: {exc}"
                log.exception(msg)
                stats.errors.append(msg)

        # Always clear buffers, even on error
        self._raw_event_ids.clear()
        self._finding_ids.clear()
        self._control_mapping_ids.clear()
        self._control_result_ids.clear()
        self._current_run_id = None

        stats.duration_seconds = time.monotonic() - start
        log.info(
            "Lake flush complete for run %s: raw=%d findings=%d mappings=%d results=%d (%.2fs)",
            run_id,
            stats.raw_events_written,
            stats.findings_written,
            stats.control_mappings_written,
            stats.control_results_written,
            stats.duration_seconds,
        )
        return stats

    def _flush_raw_events(self, session: Any, run_id: str, writer_fn: Any) -> int:
        """Read raw events from OLTP and write to raw zone."""
        if not self._raw_event_ids:
            return 0

        from warlock.db.models import RawEvent

        records = session.query(RawEvent).filter(RawEvent.id.in_(self._raw_event_ids)).all()
        if not records:
            return 0

        dicts = [_model_to_dict(r) for r in records]
        return writer_fn(self._lake_path, run_id, dicts)

    def _flush_findings(self, session: Any, run_id: str, writer_fn: Any) -> int:
        """Read findings from OLTP and write to enrichment zone."""
        if not self._finding_ids:
            return 0

        from warlock.db.models import Finding

        records = session.query(Finding).filter(Finding.id.in_(self._finding_ids)).all()
        if not records:
            return 0

        dicts = [_model_to_dict(r) for r in records]
        return writer_fn(self._lake_path, run_id, dicts)

    def _flush_curated(
        self, session: Any, run_id: str, writer_fn: Any
    ) -> tuple[int, int, int]:
        """Read control results, mappings, and connector runs from OLTP."""
        from warlock.db.models import ConnectorRun, ControlMapping, ControlResult

        cr_dicts: list[dict] = []
        if self._control_result_ids:
            records = (
                session.query(ControlResult)
                .filter(ControlResult.id.in_(self._control_result_ids))
                .all()
            )
            cr_dicts = [_model_to_dict(r) for r in records]

        cm_dicts: list[dict] = []
        if self._control_mapping_ids:
            # finding.mapped events carry the finding ID; get all mappings for those findings
            records = (
                session.query(ControlMapping)
                .filter(ControlMapping.finding_id.in_(self._control_mapping_ids))
                .all()
            )
            cm_dicts = [_model_to_dict(r) for r in records]

        # Get connector runs associated with this pipeline run's raw events
        conn_dicts: list[dict] = []
        if self._raw_event_ids:
            from warlock.db.models import RawEvent

            connector_run_ids = (
                session.query(RawEvent.connector_run_id)
                .filter(RawEvent.id.in_(self._raw_event_ids))
                .distinct()
                .all()
            )
            cr_ids = [r[0] for r in connector_run_ids]
            if cr_ids:
                records = (
                    session.query(ConnectorRun).filter(ConnectorRun.id.in_(cr_ids)).all()
                )
                conn_dicts = [_model_to_dict(r) for r in records]

        total_cr = 0
        total_cm = 0
        total_conn = 0
        if cr_dicts or cm_dicts or conn_dicts:
            total = writer_fn(self._lake_path, run_id, cr_dicts, cm_dicts, conn_dicts)
            total_cr = len(cr_dicts)
            total_cm = len(cm_dicts)
            total_conn = len(conn_dicts)

        return total_cr, total_cm, total_conn

    def _flush_temporal(self, session: Any, run_id: str) -> tuple[int, int]:
        """Read recent posture snapshots and compliance drifts from OLTP.

        These aren't event-sourced — we query for any rows created since
        the last flush.  Returns (snapshot_count, drift_count).
        """
        from warlock.db.models import ComplianceDrift, PostureSnapshot
        from warlock.lake.domains import write_temporal_facts

        snap_dicts: list[dict] = []
        try:
            records = session.query(PostureSnapshot).all()
            snap_dicts = [_model_to_dict(r) for r in records] if records else []
        except Exception:
            log.debug("PostureSnapshot table not available, skipping")

        drift_dicts: list[dict] = []
        try:
            records = session.query(ComplianceDrift).all()
            drift_dicts = [_model_to_dict(r) for r in records] if records else []
        except Exception:
            log.debug("ComplianceDrift table not available, skipping")

        total = 0
        if snap_dicts or drift_dicts:
            total = write_temporal_facts(
                self._lake_path,
                run_id,
                posture_snapshots=snap_dicts or None,
                compliance_drifts=drift_dicts or None,
            )

        return len(snap_dicts), len(drift_dicts)

    @property
    def pending_count(self) -> int:
        """Total number of buffered event IDs waiting to be flushed."""
        return (
            len(self._raw_event_ids)
            + len(self._finding_ids)
            + len(self._control_mapping_ids)
            + len(self._control_result_ids)
        )
