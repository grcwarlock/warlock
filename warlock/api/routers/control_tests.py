"""Control testing routes: schedule, execute, and track test results.

Mirrors warlock/cli/control_tests_cmd.py using ControlResult model.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import (
    apply_framework_scope,
    get_db,
    get_pagination,
    require_permission,
)
from warlock.api.routers.schemas import PaginatedResponse, _dt_str
from warlock.db.models import ControlResult, User
from warlock.utils import ensure_aware

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ControlTestResponse(BaseModel):
    id: str
    framework: str
    control_id: str
    status: str
    assessor: str | None = None
    assessed_at: str | None = None
    examined_by: str | None = None
    examined_at: str | None = None


class ControlTestCreateRequest(BaseModel):
    framework: str
    control_id: str
    status: str = "not_assessed"
    notes: str | None = None


class ScheduleItemResponse(BaseModel):
    framework: str
    control_family: str
    controls_tested: int
    controls_untested: int
    last_tested: str | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/control-tests", response_model=PaginatedResponse)
def list_control_tests(
    framework: str | None = Query(None),
    status: str | None = Query(None),
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List control test results with pagination."""
    limit, offset = pagination
    q = db.query(ControlResult).order_by(ControlResult.assessed_at.desc())
    if framework:
        q = q.filter(ControlResult.framework == framework)
    if status:
        q = q.filter(ControlResult.status == status)
    q = apply_framework_scope(q, ControlResult, current_user)

    total = q.count()
    rows = q.offset(offset).limit(limit).all()

    items = [
        ControlTestResponse(
            id=r.id,
            framework=r.framework,
            control_id=r.control_id,
            status=r.status,
            assessor=r.assessor,
            assessed_at=_dt_str(r.assessed_at),
            examined_by=r.examined_by,
            examined_at=_dt_str(r.examined_at),
        ).model_dump()
        for r in rows
    ]

    return PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/control-tests",
    response_model=ControlTestResponse,
    status_code=201,
)
def record_control_test(
    req: ControlTestCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Record a control test result."""
    valid_statuses = [
        "compliant",
        "non_compliant",
        "partial",
        "not_assessed",
        "not_applicable",
    ]
    if req.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status: {req.status}. Valid: {valid_statuses}",
        )

    now = datetime.now(timezone.utc)
    result_id = str(uuid.uuid4())

    result = ControlResult(
        id=result_id,
        framework=req.framework,
        control_id=req.control_id,
        status=req.status,
        severity="medium",
        assessor=f"manual:{current_user.email}",
        assessed_at=now,
        examined_by=current_user.email,
        examined_at=now,
    )
    db.add(result)

    # SEC-C4: canonical hash-chained trail.
    from warlock.db.audit import AuditTrail

    actor = f"api:{current_user.email}"
    AuditTrail(db).record(
        action="control_tested",
        entity_type="control_result",
        entity_id=result_id,
        actor=actor,
        metadata={"notes": req.notes},
    )

    return ControlTestResponse(
        id=result.id,
        framework=result.framework,
        control_id=result.control_id,
        status=result.status,
        assessor=result.assessor,
        assessed_at=_dt_str(result.assessed_at),
        examined_by=result.examined_by,
        examined_at=_dt_str(result.examined_at),
    )


@router.get(
    "/control-tests/schedule",
    response_model=list[ScheduleItemResponse],
)
def control_test_schedule(
    framework: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Control test schedule: which families have been tested and when."""
    from collections import defaultdict

    q = db.query(
        ControlResult.framework,
        ControlResult.control_id,
        ControlResult.assessed_at,
        ControlResult.examined_at,
    )
    if framework:
        q = q.filter(ControlResult.framework == framework)
    q = apply_framework_scope(q, ControlResult, current_user)
    rows = q.limit(100_000).all()

    # Group by framework + family
    families: dict[tuple[str, str], dict] = defaultdict(
        lambda: {
            "tested": set(),
            "all": set(),
            "last_tested": None,
        }
    )
    for fw, ctrl_id, assessed_at, examined_at in rows:
        parts = ctrl_id.split("-", 1)
        family = parts[0] if len(parts) > 1 else ctrl_id.split(".")[0]
        key = (fw, family)
        families[key]["all"].add(ctrl_id)
        if examined_at:
            families[key]["tested"].add(ctrl_id)
            dt = ensure_aware(examined_at)
            if families[key]["last_tested"] is None or dt > families[key]["last_tested"]:
                families[key]["last_tested"] = dt

    schedule = []
    for (fw, family), data in sorted(families.items()):
        last = data["last_tested"]
        schedule.append(
            ScheduleItemResponse(
                framework=fw,
                control_family=family,
                controls_tested=len(data["tested"]),
                controls_untested=len(data["all"]) - len(data["tested"]),
                last_tested=last.isoformat() if last else None,
            )
        )

    return schedule
