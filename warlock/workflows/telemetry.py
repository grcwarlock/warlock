"""Opt-in anonymous telemetry for industry benchmarking.

Collects aggregate compliance metrics (never PII or raw findings) for
anonymous industry benchmarking. Telemetry is strictly opt-in and
disabled by default.

Metrics collected (when opted in):
  - Framework names and compliance pass rates (percentages only)
  - Total control count (not individual control statuses)
  - Organization size tier (small/medium/large, not exact count)
  - Industry vertical (self-reported)

No PII, finding details, resource IDs, or customer data is ever collected.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Telemetry state file location
_STATE_FILE = Path.home() / ".warlock" / "telemetry.json"


@dataclass
class TelemetryState:
    """Telemetry opt-in state."""

    opted_in: bool = False
    opted_in_at: str | None = None
    opted_out_at: str | None = None
    instance_id: str = ""  # Anonymous hash, not reversible


def _load_state() -> TelemetryState:
    """Load telemetry state from disk."""
    if not _STATE_FILE.exists():
        return TelemetryState()
    try:
        with open(_STATE_FILE) as fh:
            data = json.load(fh)
        return TelemetryState(
            opted_in=data.get("opted_in", False),
            opted_in_at=data.get("opted_in_at"),
            opted_out_at=data.get("opted_out_at"),
            instance_id=data.get("instance_id", ""),
        )
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Failed to load telemetry state: %s", exc)
        return TelemetryState()


def _save_state(state: TelemetryState) -> None:
    """Save telemetry state to disk."""
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_STATE_FILE, "w") as fh:
        json.dump(
            {
                "opted_in": state.opted_in,
                "opted_in_at": state.opted_in_at,
                "opted_out_at": state.opted_out_at,
                "instance_id": state.instance_id,
            },
            fh,
            indent=2,
        )


def _generate_instance_id() -> str:
    """Generate an anonymous, non-reversible instance ID."""
    import uuid

    raw = f"warlock-{uuid.uuid4()}-{datetime.now(timezone.utc).isoformat()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def opt_in() -> TelemetryState:
    """Opt in to anonymous telemetry."""
    state = _load_state()
    state.opted_in = True
    state.opted_in_at = datetime.now(timezone.utc).isoformat()
    if not state.instance_id:
        state.instance_id = _generate_instance_id()
    _save_state(state)
    log.info("Telemetry opted in (instance_id=%s)", state.instance_id)
    return state


def opt_out() -> TelemetryState:
    """Opt out of anonymous telemetry."""
    state = _load_state()
    state.opted_in = False
    state.opted_out_at = datetime.now(timezone.utc).isoformat()
    _save_state(state)
    log.info("Telemetry opted out")
    return state


def get_status() -> TelemetryState:
    """Get current telemetry status."""
    return _load_state()


def collect_metrics() -> dict[str, Any] | None:
    """Collect anonymous aggregate metrics.

    Returns None if telemetry is not opted in.
    Metrics are aggregate only -- no PII, no raw findings.
    """
    state = _load_state()
    if not state.opted_in:
        return None

    # Collect aggregate stats from DB
    try:
        from warlock.db.engine import get_read_session, init_db
        from warlock.db.models import ControlResult

        init_db()
        with get_read_session() as session:
            total_controls = session.query(ControlResult).count()
            compliant = (
                session.query(ControlResult).filter(ControlResult.status == "compliant").count()
            )
            frameworks = session.query(ControlResult.framework).distinct().all()

            fw_rates: dict[str, float] = {}
            for (fw,) in frameworks:
                fw_total = (
                    session.query(ControlResult).filter(ControlResult.framework == fw).count()
                )
                fw_compliant = (
                    session.query(ControlResult)
                    .filter(
                        ControlResult.framework == fw,
                        ControlResult.status == "compliant",
                    )
                    .count()
                )
                if fw_total > 0:
                    fw_rates[fw] = round(fw_compliant / fw_total * 100, 1)

        # Size tier (anonymized)
        if total_controls < 1000:
            size_tier = "small"
        elif total_controls < 10000:
            size_tier = "medium"
        else:
            size_tier = "large"

        return {
            "instance_id": state.instance_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "size_tier": size_tier,
            "framework_count": len(frameworks),
            "framework_rates": fw_rates,
            "overall_pass_rate": round(compliant / total_controls * 100, 1)
            if total_controls
            else 0,
        }
    except Exception as exc:
        log.warning("Failed to collect telemetry metrics: %s", exc)
        return None
