"""AWS Lambda entry point for serverless pipeline execution.

Triggered by EventBridge, API Gateway, or direct invocation.

Environment variables:
    WLK_DATABASE_URL: Database connection string (must be Postgres for Lambda).
    WLK_ENCRYPTION_KEY: Optional field encryption key.
    WLK_LOG_LEVEL: Logging level (default: INFO).
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("warlock.lambda")


def _configure_logging() -> None:
    level = os.environ.get("WLK_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=getattr(logging, level, logging.INFO))


def _is_eventbridge_event(event: dict) -> bool:
    """Check if this looks like an EventBridge scheduled event."""
    return (
        (event.get("source") == "aws.events")
        or (event.get("detail-type") == "Scheduled Event")
        or (
            "source" in event
            and "detail-type" in event
            and event.get("source", "").startswith("aws.")
        )
    )


def _run_collect(sources: list[str] | None = None) -> dict[str, Any]:
    """Run the full pipeline collection."""
    from warlock.db.engine import get_session, init_db
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline

    init_db()
    bus = EventBus()
    pipeline = build_pipeline(bus, sources=sources or None)

    with get_session() as session:
        stats = pipeline.run(session)

    return {
        "raw_events": stats.raw_events_collected,
        "findings": stats.findings_normalized,
        "controls_mapped": stats.controls_mapped,
        "results_assessed": stats.results_assessed,
        "connectors_succeeded": stats.connectors_succeeded,
        "connectors_failed": stats.connectors_failed,
        "errors": stats.errors[:20] if stats.errors else [],
        "duration_seconds": round(stats.duration_seconds, 2) if stats.duration_seconds else None,
    }


def _run_posture_snapshot() -> dict[str, Any]:
    """Take a posture snapshot."""
    from warlock.db.engine import get_session, init_db

    init_db()

    # Import the snapshot logic
    try:
        from warlock.workflows.system_profile import SystemProfileManager

        mgr = SystemProfileManager()
    except ImportError:
        return {"error": "system_profile module not available"}

    with get_session() as session:
        profiles = mgr.list_active(session)
        snapshot_count = 0
        for profile in profiles:
            for fw in profile.frameworks or []:
                try:
                    mgr.posture_for_system(session, profile.id, fw)
                    snapshot_count += 1
                except Exception as exc:
                    log.warning("Snapshot failed for %s/%s: %s", profile.id, fw, exc)

    return {"snapshots_created": snapshot_count}


def _run_retention_purge(dry_run: bool = True) -> dict[str, Any]:
    """Run retention purge check."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.retention import RetentionManager

    init_db()
    mgr = RetentionManager()

    with get_session() as session:
        result = mgr.purge_expired(session, dry_run=dry_run)

    return result


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Main Lambda handler.

    Supports events:
    - ``{"action": "collect"}`` -- run full pipeline
    - ``{"action": "collect", "sources": ["aws"]}`` -- run specific connectors
    - ``{"action": "posture_snapshot"}`` -- take posture snapshot
    - ``{"action": "retention_purge", "dry_run": true}`` -- retention check
    - EventBridge scheduled event -- default to collect
    """
    _configure_logging()
    start = time.time()

    log.info("Lambda invoked: %s", json.dumps(event, default=str)[:500])

    # Determine the action
    if _is_eventbridge_event(event):
        # Scheduled event -- default to collect
        action = event.get("detail", {}).get("action", "collect")
        sources = event.get("detail", {}).get("sources")
    else:
        action = event.get("action", "collect")
        sources = event.get("sources")

    try:
        if action == "collect":
            result = _run_collect(sources=sources)
        elif action == "posture_snapshot":
            result = _run_posture_snapshot()
        elif action == "retention_purge":
            dry_run = event.get("dry_run", True)
            result = _run_retention_purge(dry_run=dry_run)
        else:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": f"Unknown action: {action}"}),
            }

        elapsed = round(time.time() - start, 2)
        log.info("Lambda completed in %.2fs: %s", elapsed, action)

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "action": action,
                    "result": result,
                    "execution_time_seconds": elapsed,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                default=str,
            ),
        }

    except Exception:
        log.exception("Lambda execution failed")
        elapsed = round(time.time() - start, 2)
        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "error": "Internal pipeline execution error",
                    "action": action,
                    "execution_time_seconds": elapsed,
                },
                default=str,
            ),
        }
