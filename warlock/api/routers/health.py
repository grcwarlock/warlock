"""Health check routes."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock import __version__ as _VERSION
from warlock.api.deps import get_db

router = APIRouter()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = _VERSION
    timestamp: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(
        status="ok",
        version=_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/health/live")
def health_live():
    """Liveness probe — process is alive."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get("/health/ready")
def health_ready(db: Session = Depends(get_db)):
    """Readiness probe — checks DB connectivity and scheduler state."""
    import logging

    from fastapi.responses import JSONResponse

    log = logging.getLogger(__name__)

    checks: dict[str, str] = {}
    all_ok = True

    # DB check
    try:
        from sqlalchemy import text

        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        # S-8: Don't leak internal error details in health probe response
        log.error("Readiness probe database check failed: %s", e)
        checks["database"] = "failed"
        all_ok = False

    # Scheduler check
    try:
        from warlock.pipeline.scheduler import get_scheduler

        sched = get_scheduler()
        sched_status = sched.status
        checks["scheduler"] = "running" if sched_status.get("running") else "stopped"
        if not sched_status.get("running"):
            all_ok = False
    except Exception:
        checks["scheduler"] = "unknown"

    status_code = 200 if all_ok else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ok" if all_ok else "degraded",
            "checks": checks,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )
