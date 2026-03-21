"""Pipeline and scheduler routes."""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, require_permission
from warlock.db.models import User
from warlock.db.repository import get_repos

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class PipelineStatusResponse(BaseModel):
    running: bool
    last_run_id: str | None = None
    last_status: str | None = None
    last_started: str | None = None
    last_completed: str | None = None
    raw_events: int = 0
    findings: int = 0
    results: int = 0


class PipelineCollectResponse(BaseModel):
    message: str
    run_id: str | None = None


class SchedulerStatusResponse(BaseModel):
    running: bool
    interval_minutes: int
    interval_seconds: int
    last_run: str | None
    next_run: str | None
    run_count: int
    last_error: str | None


class SchedulerStartRequest(BaseModel):
    interval_minutes: int = 60


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_pipeline_background(run_id: str, source: list[str] | None = None):
    """Execute the pipeline in a background thread.

    ConnectorRun rows written by the pipeline orchestrator track status;
    no in-memory flags are needed here.
    """
    try:
        from warlock.db.engine import get_session
        from warlock.connectors.base import registry as connector_registry
        from warlock.normalizers.base import NormalizerRegistry
        from warlock.mappers.control_mapper import ControlMapper
        from warlock.assessors.engine import Assessor
        from warlock.pipeline.bus import EventBus
        from warlock.pipeline.orchestrator import Pipeline

        bus = EventBus()
        normalizers = NormalizerRegistry()
        mapper = ControlMapper()
        assessor = Assessor()
        pipeline = Pipeline(
            connectors=connector_registry,
            normalizers=normalizers,
            mapper=mapper,
            assessor=assessor,
            bus=bus,
        )
        with get_session() as session:
            pipeline.run(session)
    except Exception:
        log.exception("Background pipeline run failed (run_id=%s)", run_id)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/pipeline/collect", status_code=202)
def pipeline_collect(
    background_tasks: BackgroundTasks,
    source: list[str] | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("run_pipeline")),
):
    """Trigger a full pipeline run in the background."""
    # Check for already-running pipeline via database (multi-worker safe)
    repos = get_repos(db)
    running = repos.connector_runs.find_running()
    if running:
        raise HTTPException(
            status_code=409,
            detail=f"Pipeline already running (run {running.id[:8]}, started {running.started_at})",
        )

    run_id = str(uuid.uuid4())
    background_tasks.add_task(_run_pipeline_background, run_id, source)
    return {"status": "started", "run_id": run_id}


@router.get("/pipeline/status")
def pipeline_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Pipeline run status."""
    repos = get_repos(db)
    latest_run = repos.connector_runs.latest_run()
    is_running = repos.connector_runs.is_running()

    # Use cached event_count from ConnectorRun records to avoid 3 full-table
    # COUNT queries on potentially large raw_events/findings/control_results tables.
    # Summing event_count across all runs is a cheap index scan on connector_runs.
    if latest_run is not None:
        raw_count = repos.connector_runs.total_event_count()
    else:
        raw_count = 0
    finding_count = 0
    result_count = 0

    return {
        "running": is_running,
        "last_run": {
            "id": latest_run.id if latest_run else None,
            "status": latest_run.status if latest_run else None,
            "started_at": latest_run.started_at.isoformat()
            if latest_run and latest_run.started_at
            else None,
            "completed_at": latest_run.completed_at.isoformat()
            if latest_run and latest_run.completed_at
            else None,
            "duration_seconds": latest_run.duration_seconds if latest_run else None,
        }
        if latest_run
        else None,
        "totals": {
            "raw_events": raw_count,
            "findings": finding_count,
            "control_results": result_count,
        },
    }


# =========================================================================
# Scheduler
# =========================================================================


@router.get("/scheduler/status", response_model=SchedulerStatusResponse)
def scheduler_status(
    current_user: User = Depends(require_permission("read")),
):
    from warlock.pipeline.scheduler import get_scheduler

    sched = get_scheduler()
    return SchedulerStatusResponse(**sched.status)


@router.post("/scheduler/start", response_model=SchedulerStatusResponse)
def scheduler_start(
    body: SchedulerStartRequest | None = None,
    current_user: User = Depends(require_permission("run_pipeline")),
):
    from warlock.pipeline.scheduler import get_scheduler

    interval = body.interval_minutes if body else 60
    sched = get_scheduler(interval_minutes=interval)
    sched.interval = interval * 60
    sched.start()
    return SchedulerStatusResponse(**sched.status)


@router.post("/scheduler/stop", response_model=SchedulerStatusResponse)
def scheduler_stop(
    current_user: User = Depends(require_permission("run_pipeline")),
):
    from warlock.pipeline.scheduler import get_scheduler

    sched = get_scheduler()
    sched.stop()
    return SchedulerStatusResponse(**sched.status)
