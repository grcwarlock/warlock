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
    """Readiness probe — checks DB, OPA, and scheduler connectivity."""
    import logging

    from fastapi.responses import JSONResponse

    log = logging.getLogger(__name__)

    checks: dict[str, str] = {}
    all_ok = True

    # DB check — execute a trivial query to verify connectivity
    try:
        from sqlalchemy import text

        db.execute(text("SELECT 1"))
        checks["db"] = "ok"
    except Exception as e:
        # S-8: Don't leak internal error details in health probe response
        log.error("Readiness probe database check failed: %s", e)
        checks["db"] = "failed"
        all_ok = False

    # OPA check — HTTP GET to OPA health endpoint (when configured)
    from warlock.config import get_settings

    settings = get_settings()
    if settings.opa_url:
        try:
            import urllib.request

            # Derive OPA health URL from the decision endpoint
            # e.g. http://localhost:8181/v1/data/... -> http://localhost:8181/health
            from urllib.parse import urlparse

            parsed = urlparse(settings.opa_url)
            opa_health_url = f"{parsed.scheme}://{parsed.netloc}/health"
            req = urllib.request.Request(opa_health_url, method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    checks["opa"] = "ok"
                else:
                    checks["opa"] = "degraded"
                    all_ok = False
        except Exception as e:
            log.error("Readiness probe OPA check failed: %s", e)
            checks["opa"] = "failed"
            all_ok = False
    else:
        checks["opa"] = "not_configured"

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
