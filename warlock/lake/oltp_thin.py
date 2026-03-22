"""OLTP thinning — keep only current-state projections in OLTP.

When the lake holds all historical data, OLTP only needs:
- Latest result per control per framework (current-state projection)
- Active governance items (POA&Ms, issues, attestations)
- Auth/sessions, configuration
- Hash-chained audit trail

This module removes historical records from OLTP pipeline tables
(control_results, control_mappings, findings, raw_events) while
preserving the latest state.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class ThinStats:
    """Statistics from an OLTP thinning operation."""

    control_results_kept: int = 0
    control_results_removed: int = 0
    control_mappings_removed: int = 0
    findings_removed: int = 0
    raw_events_removed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total_removed(self) -> int:
        return (
            self.control_results_removed
            + self.control_mappings_removed
            + self.findings_removed
            + self.raw_events_removed
        )


def thin_oltp(session: Any, dry_run: bool = True) -> ThinStats:
    """Thin OLTP by removing historical records, keeping latest per control.

    IMPORTANT: Only run this after confirming lake has all data (reconciliation passed).

    Preserves:
    - Latest ControlResult per (framework, control_id) — current-state projection
    - All ControlMappings referenced by kept ControlResults
    - All Findings referenced by kept ControlResults
    - All RawEvents referenced by kept Findings
    - All AuditEntries (never thinned — hash chain)
    - All governance items (POA&Ms, issues, attestations, etc.)

    Parameters
    ----------
    session: SQLAlchemy session
    dry_run: If True, count but don't delete
    """
    from sqlalchemy import func

    from warlock.db.models import ControlMapping, ControlResult, Finding, RawEvent

    stats = ThinStats()

    # Step 1: Find latest ControlResult ID per (framework, control_id)
    subq = (
        session.query(
            ControlResult.framework,
            ControlResult.control_id,
            func.max(ControlResult.assessed_at).label("max_assessed"),
        )
        .group_by(ControlResult.framework, ControlResult.control_id)
        .subquery()
    )

    latest_ids_query = session.query(ControlResult.id).join(
        subq,
        (ControlResult.framework == subq.c.framework)
        & (ControlResult.control_id == subq.c.control_id)
        & (ControlResult.assessed_at == subq.c.max_assessed),
    )
    latest_ids = {r[0] for r in latest_ids_query.all()}
    stats.control_results_kept = len(latest_ids)

    # Step 2: Count historical ControlResults
    total_results = session.query(func.count(ControlResult.id)).scalar() or 0
    stats.control_results_removed = total_results - stats.control_results_kept

    if dry_run:
        log.info(
            "OLTP thin (dry run): would keep %d, remove %d control results",
            stats.control_results_kept,
            stats.control_results_removed,
        )
        return stats

    if stats.control_results_removed == 0:
        log.info("OLTP thin: nothing to remove")
        return stats

    # Step 3: Delete historical ControlResults (not in latest set)
    # Get finding_ids and mapping_ids referenced by historical results
    historical_results = (
        session.query(ControlResult).filter(~ControlResult.id.in_(latest_ids)).all()
    )

    historical_finding_ids = {r.finding_id for r in historical_results if r.finding_id}
    historical_mapping_ids = {
        r.control_mapping_id for r in historical_results if r.control_mapping_id
    }

    # Delete historical results
    for r in historical_results:
        session.delete(r)
    session.flush()

    # Step 4: Delete orphaned ControlMappings (not referenced by any remaining result)
    kept_mapping_ids = {
        r.control_mapping_id
        for r in session.query(ControlResult.control_mapping_id).all()
        if r.control_mapping_id
    }
    orphan_mappings = historical_mapping_ids - kept_mapping_ids
    if orphan_mappings:
        deleted = (
            session.query(ControlMapping)
            .filter(ControlMapping.id.in_(orphan_mappings))
            .delete(synchronize_session="fetch")
        )
        stats.control_mappings_removed = deleted

    # Step 5: Delete orphaned Findings (not referenced by any remaining mapping)
    kept_finding_ids = {
        r.finding_id for r in session.query(ControlMapping.finding_id).all() if r.finding_id
    }
    orphan_findings = historical_finding_ids - kept_finding_ids
    if orphan_findings:
        deleted = (
            session.query(Finding)
            .filter(Finding.id.in_(orphan_findings))
            .delete(synchronize_session="fetch")
        )
        stats.findings_removed = deleted

    # Step 6: Delete orphaned RawEvents (not referenced by any remaining finding)
    kept_raw_ids = {
        r.raw_event_id for r in session.query(Finding.raw_event_id).all() if r.raw_event_id
    }
    all_raw_ids = {r[0] for r in session.query(RawEvent.id).all()}
    orphan_raws = all_raw_ids - kept_raw_ids
    if orphan_raws:
        deleted = (
            session.query(RawEvent)
            .filter(RawEvent.id.in_(orphan_raws))
            .delete(synchronize_session="fetch")
        )
        stats.raw_events_removed = deleted

    session.flush()
    log.info(
        "OLTP thin: kept %d results, removed %d results + %d mappings + %d findings + %d raw events",
        stats.control_results_kept,
        stats.control_results_removed,
        stats.control_mappings_removed,
        stats.findings_removed,
        stats.raw_events_removed,
    )
    return stats


def thin_oltp_safe(session: Any, dry_run: bool = True) -> ThinStats:
    """thin_oltp with legal hold checking.

    Checks for active legal holds before thinning OLTP.
    If any hold is active, returns ThinStats with error.
    """
    from warlock.db.models import LegalHold

    active_holds = session.query(LegalHold).filter(LegalHold.is_active.is_(True)).count()
    if active_holds > 0:
        stats = ThinStats()
        stats.errors.append(f"Blocked by {active_holds} active legal hold(s)")
        log.warning("OLTP thinning blocked: %d active legal hold(s)", active_holds)
        return stats
    return thin_oltp(session, dry_run=dry_run)


def current_state_projection(session: Any, framework: str = None) -> list[dict]:
    """Return the latest control result per (framework, control_id).

    This is the current-state view that OLTP maintains after thinning.
    """
    from sqlalchemy import func

    from warlock.db.models import ControlResult

    subq = session.query(
        ControlResult.framework,
        ControlResult.control_id,
        func.max(ControlResult.assessed_at).label("max_assessed"),
    ).group_by(ControlResult.framework, ControlResult.control_id)
    if framework:
        subq = subq.filter(ControlResult.framework == framework)
    subq = subq.subquery()

    results = (
        session.query(ControlResult)
        .join(
            subq,
            (ControlResult.framework == subq.c.framework)
            & (ControlResult.control_id == subq.c.control_id)
            & (ControlResult.assessed_at == subq.c.max_assessed),
        )
        .order_by(ControlResult.framework, ControlResult.control_id)
        .all()
    )

    return [
        {
            "framework": r.framework,
            "control_id": r.control_id,
            "status": r.status,
            "severity": r.severity,
            "assessed_at": str(r.assessed_at),
        }
        for r in results
    ]
