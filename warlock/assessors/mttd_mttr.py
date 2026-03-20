"""MTTD/MTTR tracking from compliance drift data.

Computes Mean Time to Detect (MTTD) and Mean Time to Remediate (MTTR)
for compliance drifts, using ComplianceDrift and correlated ChangeEvent
timestamps. Provides per-control and per-framework aggregate metrics.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import ChangeEvent, ComplianceDrift
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)


def compute_mttd(
    session: Session,
    framework: str | None = None,
) -> dict[str, Any]:
    """Compute mean time to detect compliance drifts.

    MTTD is measured as the time between the earliest correlated change
    event and the drift detection timestamp. If no change events are
    correlated, the drift is excluded from the calculation (we cannot
    measure detection latency without a known change time).

    Args:
        session: SQLAlchemy session.
        framework: If provided, filter to this framework only.

    Returns:
        Dict with ``framework_mttd_hours``, ``per_control`` breakdown,
        ``sample_size``, and ``excluded`` count.
    """
    query = session.query(ComplianceDrift)
    if framework:
        query = query.filter(ComplianceDrift.framework == framework)

    drifts = query.order_by(ComplianceDrift.detected_at).all()

    per_control: dict[str, list[float]] = {}
    excluded = 0

    for drift in drifts:
        change_ids = drift.correlated_change_event_ids or []
        if not change_ids:
            excluded += 1
            continue

        # Find the earliest correlated change event
        earliest_change = (
            session.query(func.min(ChangeEvent.occurred_at))
            .filter(ChangeEvent.id.in_(change_ids))
            .scalar()
        )
        if earliest_change is None:
            excluded += 1
            continue

        detected_at = ensure_aware(drift.detected_at)
        change_at = ensure_aware(earliest_change)
        if detected_at is None or change_at is None:
            excluded += 1
            continue

        delta_hours = (detected_at - change_at).total_seconds() / 3600.0
        if delta_hours < 0:
            # Change event recorded after detection — data anomaly, skip
            excluded += 1
            continue

        key = f"{drift.framework}:{drift.control_id}"
        per_control.setdefault(key, []).append(delta_hours)

    # Aggregate
    all_values: list[float] = []
    control_summary: dict[str, dict[str, float]] = {}

    for key, values in per_control.items():
        mean_val = sum(values) / len(values)
        control_summary[key] = {
            "mttd_hours": round(mean_val, 2),
            "sample_size": len(values),
            "min_hours": round(min(values), 2),
            "max_hours": round(max(values), 2),
        }
        all_values.extend(values)

    framework_mttd = round(sum(all_values) / len(all_values), 2) if all_values else 0.0

    return {
        "framework_mttd_hours": framework_mttd,
        "per_control": control_summary,
        "sample_size": len(all_values),
        "excluded": excluded,
    }


def compute_mttr(
    session: Session,
    framework: str | None = None,
) -> dict[str, Any]:
    """Compute mean time to remediate compliance drifts.

    MTTR is measured as the time between a degraded drift detection
    and the next improved drift for the same framework + control_id.
    Consecutive degraded drifts followed by an improved drift form a
    remediation cycle.

    Args:
        session: SQLAlchemy session.
        framework: If provided, filter to this framework only.

    Returns:
        Dict with ``framework_mttr_hours``, ``per_control`` breakdown,
        ``sample_size`` (remediation cycles found), and ``open_degradations``
        count (degraded drifts not yet remediated).
    """
    query = session.query(ComplianceDrift)
    if framework:
        query = query.filter(ComplianceDrift.framework == framework)

    drifts = query.order_by(
        ComplianceDrift.framework,
        ComplianceDrift.control_id,
        ComplianceDrift.detected_at,
    ).all()

    # Group by (framework, control_id)
    grouped: dict[str, list[ComplianceDrift]] = {}
    for drift in drifts:
        key = f"{drift.framework}:{drift.control_id}"
        grouped.setdefault(key, []).append(drift)

    per_control: dict[str, dict[str, Any]] = {}
    all_values: list[float] = []
    open_degradations = 0

    for key, control_drifts in grouped.items():
        remediation_times: list[float] = []
        pending_degraded: datetime | None = None

        for drift in control_drifts:
            if drift.drift_direction == "degraded":
                # Record the first degraded event in a sequence
                if pending_degraded is None:
                    pending_degraded = ensure_aware(drift.detected_at)
            elif drift.drift_direction == "improved" and pending_degraded is not None:
                # Remediation cycle complete
                improved_at = ensure_aware(drift.detected_at)
                if improved_at is not None and pending_degraded is not None:
                    delta_hours = (
                        (improved_at - pending_degraded).total_seconds() / 3600.0
                    )
                    if delta_hours >= 0:
                        remediation_times.append(delta_hours)
                pending_degraded = None

        if pending_degraded is not None:
            open_degradations += 1

        if remediation_times:
            mean_val = sum(remediation_times) / len(remediation_times)
            per_control[key] = {
                "mttr_hours": round(mean_val, 2),
                "sample_size": len(remediation_times),
                "min_hours": round(min(remediation_times), 2),
                "max_hours": round(max(remediation_times), 2),
            }
            all_values.extend(remediation_times)

    framework_mttr = round(sum(all_values) / len(all_values), 2) if all_values else 0.0

    return {
        "framework_mttr_hours": framework_mttr,
        "per_control": per_control,
        "sample_size": len(all_values),
        "open_degradations": open_degradations,
    }
