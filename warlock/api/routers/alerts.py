"""Alert management routes: list, create, acknowledge, resolve, dismiss."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import apply_framework_scope, get_db, require_permission
from warlock.api.routers.schemas import PaginatedResponse, _dt_str
from warlock.db.models import Alert, User
from warlock.utils import ensure_aware

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class AlertCreateRequest(BaseModel):
    title: str
    description: str | None = None
    severity: str = "medium"
    category: str = "policy_violation"
    framework: str | None = None
    control_id: str | None = None
    connector_name: str | None = None
    finding_id: str | None = None
    control_result_id: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    rule_name: str | None = None
    rule_metadata: dict[str, Any] | None = None


class AlertAcknowledgeRequest(BaseModel):
    notes: str | None = None


class AlertResolveRequest(BaseModel):
    notes: str


class AlertDismissRequest(BaseModel):
    notes: str | None = None


class AlertResponse(BaseModel):
    id: str
    title: str
    description: str | None = None
    severity: str
    category: str
    finding_id: str | None = None
    control_result_id: str | None = None
    connector_name: str | None = None
    framework: str | None = None
    control_id: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    status: str
    acknowledged_by: str | None = None
    acknowledged_at: str | None = None
    resolved_by: str | None = None
    resolved_at: str | None = None
    resolution_notes: str | None = None
    rule_name: str | None = None
    rule_metadata: dict[str, Any] | None = None
    triggered_at: str
    created_at: str
    updated_at: str | None = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_CATEGORIES = {
    "control_drift",
    "new_finding",
    "connector_failure",
    "threshold_breach",
    "policy_violation",
}
_VALID_STATUSES = {"open", "acknowledged", "investigating", "resolved", "dismissed"}


def _alert_to_response(alert: Alert) -> AlertResponse:
    return AlertResponse(
        id=alert.id,
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        category=alert.category,
        finding_id=alert.finding_id,
        control_result_id=alert.control_result_id,
        connector_name=alert.connector_name,
        framework=alert.framework,
        control_id=alert.control_id,
        mitre_tactic=alert.mitre_tactic,
        mitre_technique=alert.mitre_technique,
        status=alert.status,
        acknowledged_by=alert.acknowledged_by,
        acknowledged_at=_dt_str(ensure_aware(alert.acknowledged_at)),
        resolved_by=alert.resolved_by,
        resolved_at=_dt_str(ensure_aware(alert.resolved_at)),
        resolution_notes=alert.resolution_notes,
        rule_name=alert.rule_name,
        rule_metadata=alert.rule_metadata,
        triggered_at=_dt_str(ensure_aware(alert.triggered_at)) or "",
        created_at=_dt_str(ensure_aware(alert.created_at)) or "",
        updated_at=_dt_str(ensure_aware(alert.updated_at)),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/alerts", response_model=PaginatedResponse)
def list_alerts(
    alert_status: str | None = Query(None, alias="status"),
    severity: str | None = Query(None),
    category: str | None = Query(None),
    framework: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List alerts with optional filters."""
    query = db.query(Alert)
    query = apply_framework_scope(query, Alert, current_user)

    if alert_status:
        if alert_status not in _VALID_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status: {alert_status}. Must be one of: {', '.join(sorted(_VALID_STATUSES))}",
            )
        query = query.filter(Alert.status == alert_status)
    if severity:
        if severity not in _VALID_SEVERITIES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity: {severity}. Must be one of: {', '.join(sorted(_VALID_SEVERITIES))}",
            )
        query = query.filter(Alert.severity == severity)
    if category:
        query = query.filter(Alert.category == category)
    if framework:
        query = query.filter(Alert.framework == framework)

    total = query.count()
    rows = query.order_by(Alert.triggered_at.desc()).offset(offset).limit(limit).all()
    items = [_alert_to_response(a) for a in rows]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Get a single alert by ID."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_to_response(alert)


@router.post("/alerts", response_model=AlertResponse, status_code=201)
def create_alert(
    body: AlertCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Create a manual alert."""
    if body.severity not in _VALID_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity: {body.severity}. Must be one of: {', '.join(sorted(_VALID_SEVERITIES))}",
        )
    if body.category not in _VALID_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category: {body.category}. Must be one of: {', '.join(sorted(_VALID_CATEGORIES))}",
        )

    now = datetime.now(timezone.utc)
    alert = Alert(
        title=body.title,
        description=body.description,
        severity=body.severity,
        category=body.category,
        framework=body.framework,
        control_id=body.control_id,
        connector_name=body.connector_name,
        finding_id=body.finding_id,
        control_result_id=body.control_result_id,
        mitre_tactic=body.mitre_tactic,
        mitre_technique=body.mitre_technique,
        rule_name=body.rule_name,
        rule_metadata=body.rule_metadata or {},
        triggered_at=now,
        status="open",
    )
    db.add(alert)
    db.flush()
    log.info(
        "Alert created: %s (severity=%s, category=%s)", alert.id, alert.severity, alert.category
    )
    return _alert_to_response(alert)


@router.patch("/alerts/{alert_id}/acknowledge", response_model=AlertResponse)
def acknowledge_alert(
    alert_id: str,
    body: AlertAcknowledgeRequest | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Acknowledge an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status not in ("open",):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot acknowledge alert in '{alert.status}' state (must be 'open')",
        )

    now = datetime.now(timezone.utc)
    alert.status = "acknowledged"
    alert.acknowledged_by = current_user.email
    alert.acknowledged_at = now
    if body and body.notes:
        alert.resolution_notes = body.notes
    db.flush()
    log.info("Alert acknowledged: %s by %s", alert_id, current_user.email)
    return _alert_to_response(alert)


@router.patch("/alerts/{alert_id}/resolve", response_model=AlertResponse)
def resolve_alert(
    alert_id: str,
    body: AlertResolveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Resolve an alert with notes."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status in ("resolved", "dismissed"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot resolve alert in '{alert.status}' state (already terminal)",
        )

    now = datetime.now(timezone.utc)
    alert.status = "resolved"
    alert.resolved_by = current_user.email
    alert.resolved_at = now
    alert.resolution_notes = body.notes
    db.flush()
    log.info("Alert resolved: %s by %s", alert_id, current_user.email)
    return _alert_to_response(alert)


@router.patch("/alerts/{alert_id}/dismiss", response_model=AlertResponse)
def dismiss_alert(
    alert_id: str,
    body: AlertDismissRequest | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Dismiss an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status in ("resolved", "dismissed"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot dismiss alert in '{alert.status}' state (already terminal)",
        )

    now = datetime.now(timezone.utc)
    alert.status = "dismissed"
    alert.resolved_by = current_user.email
    alert.resolved_at = now
    if body and body.notes:
        alert.resolution_notes = body.notes
    db.flush()
    log.info("Alert dismissed: %s by %s", alert_id, current_user.email)
    return _alert_to_response(alert)
