"""Export routes: OSCAL export and vendor questionnaires."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, require_permission
from warlock.api.routers.schemas import PaginatedResponse, _dt_str
from warlock.db.models import Questionnaire, QuestionnaireTemplate, User
from warlock.db.repository import get_repos

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models — OSCAL
# ---------------------------------------------------------------------------


class OSCALExportRequest(BaseModel):
    export_type: str = "ar"  # ar, ssp, poam
    framework: str | None = None
    system_name: str = "Warlock GRC System"
    description: str = "System assessed by Warlock GRC pipeline"


# ---------------------------------------------------------------------------
# Models — Questionnaires
# ---------------------------------------------------------------------------


class TemplateCreateRequest(BaseModel):
    name: str
    template_type: str
    questions: list[dict[str, Any]]
    description: str = ""
    version: str = "1.0"


class TemplateResponse(BaseModel):
    id: str
    name: str
    template_type: str
    version: str | None = None
    description: str | None = None
    total_questions: int = 0
    is_active: bool = True
    created_at: str

    model_config = {"from_attributes": True}


class QuestionnaireCreateRequest(BaseModel):
    template_id: str
    vendor_name: str
    vendor_email: str | None = None
    due_days: int = 30


class QuestionnaireResponseModel(BaseModel):
    id: str
    template_id: str
    vendor_name: str
    vendor_contact_email: str | None = None
    status: str
    completion_pct: float = 0.0
    risk_score: float | None = None
    risk_findings: list[dict[str, Any]] | None = None
    ai_suggested_answers: dict[str, Any] | None = None
    sent_at: str | None = None
    due_date: str | None = None
    completed_at: str | None = None
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    responses: dict[str, Any] | None = None
    created_at: str
    updated_at: str | None = None
    created_by: str | None = None

    model_config = {"from_attributes": True}


class QuestionnaireSubmitRequest(BaseModel):
    responses: dict[str, Any]


class QuestionnaireTransitionRequest(BaseModel):
    status: str


class QuestionnaireSummaryResponse(BaseModel):
    total: int
    by_status: dict[str, int]
    overdue: int
    templates: int
    avg_risk_score: float | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _template_to_response(t: QuestionnaireTemplate) -> TemplateResponse:
    return TemplateResponse(
        id=t.id,
        name=t.name,
        template_type=t.template_type,
        version=t.version,
        description=t.description,
        total_questions=t.total_questions or 0,
        is_active=t.is_active or True,
        created_at=_dt_str(t.created_at) or "",
    )


def _questionnaire_to_response(q: Questionnaire) -> QuestionnaireResponseModel:
    return QuestionnaireResponseModel(
        id=q.id,
        template_id=q.template_id,
        vendor_name=q.vendor_name,
        vendor_contact_email=q.vendor_contact_email,
        status=q.status,
        completion_pct=q.completion_pct or 0.0,
        risk_score=q.risk_score,
        risk_findings=q.risk_findings,
        ai_suggested_answers=q.ai_suggested_answers,
        sent_at=_dt_str(q.sent_at),
        due_date=_dt_str(q.due_date),
        completed_at=_dt_str(q.completed_at),
        reviewed_by=q.reviewed_by,
        reviewed_at=_dt_str(q.reviewed_at),
        responses=q.responses,
        created_at=_dt_str(q.created_at) or "",
        updated_at=_dt_str(q.updated_at),
        created_by=q.created_by,
    )


# ---------------------------------------------------------------------------
# Routes — OSCAL Export
# ---------------------------------------------------------------------------


@router.post("/export/oscal")
def export_oscal(
    body: OSCALExportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("export")),
):
    from warlock.export.oscal import OscalExporter

    exporter = OscalExporter()

    if body.export_type == "ar":
        return exporter.export_assessment_results(db, body.framework, body.system_name)
    elif body.export_type == "ssp":
        if not body.framework:
            raise HTTPException(status_code=400, detail="framework is required for SSP export")
        return exporter.export_ssp(db, body.framework, body.system_name, body.description)
    elif body.export_type == "poam":
        return exporter.export_poam(db, body.framework, body.system_name)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown export_type: {body.export_type}. Use ar, ssp, or poam.",
        )


# ---------------------------------------------------------------------------
# Routes — Questionnaires
# ---------------------------------------------------------------------------


@router.get("/questionnaires/templates", response_model=list[TemplateResponse])
def list_questionnaire_templates(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    rows = repos.questionnaire_templates.active_templates()
    return [_template_to_response(t) for t in rows]


@router.post("/questionnaires/templates", response_model=TemplateResponse, status_code=201)
def create_questionnaire_template(
    body: TemplateCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager

    mgr = QuestionnaireManager()
    t = mgr.create_template(
        db,
        name=body.name,
        template_type=body.template_type,
        questions=body.questions,
        description=body.description,
        version=body.version,
    )
    return _template_to_response(t)


@router.post("/questionnaires/templates/seed", response_model=list[TemplateResponse])
def seed_questionnaire_templates(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager

    mgr = QuestionnaireManager()
    templates = mgr.seed_default_templates(db)
    return [_template_to_response(t) for t in templates]


@router.get("/questionnaires/overdue", response_model=list[QuestionnaireResponseModel])
def overdue_questionnaires(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager

    mgr = QuestionnaireManager()
    rows = mgr.overdue(db)
    return [_questionnaire_to_response(q) for q in rows]


@router.get("/questionnaires", response_model=PaginatedResponse)
def list_questionnaires(
    vendor_name: str | None = Query(None),
    q_status: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    rows, total = repos.questionnaires.list_filtered(
        vendor_name=vendor_name,
        status=q_status,
        limit=limit,
        offset=offset,
    )
    items = [_questionnaire_to_response(q) for q in rows]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.post("/questionnaires", response_model=QuestionnaireResponseModel, status_code=201)
def create_questionnaire_endpoint(
    body: QuestionnaireCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager

    mgr = QuestionnaireManager()
    try:
        q = mgr.create_questionnaire(
            db,
            template_id=body.template_id,
            vendor_name=body.vendor_name,
            vendor_email=body.vendor_email,
            due_days=body.due_days,
            created_by=current_user.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _questionnaire_to_response(q)


@router.get("/questionnaires/{questionnaire_id}", response_model=QuestionnaireResponseModel)
def get_questionnaire(
    questionnaire_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    q = repos.questionnaires.get(questionnaire_id)
    if not q:
        raise HTTPException(status_code=404, detail="Questionnaire not found")
    return _questionnaire_to_response(q)


@router.post(
    "/questionnaires/{questionnaire_id}/responses",
    response_model=QuestionnaireResponseModel,
)
def submit_questionnaire_responses(
    questionnaire_id: str,
    body: QuestionnaireSubmitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager

    mgr = QuestionnaireManager()
    try:
        q = mgr.submit_bulk_responses(db, questionnaire_id, body.responses)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _questionnaire_to_response(q)


@router.post("/questionnaires/{questionnaire_id}/score", response_model=QuestionnaireResponseModel)
def score_questionnaire(
    questionnaire_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager

    mgr = QuestionnaireManager()
    try:
        q = mgr.score_responses(db, questionnaire_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _questionnaire_to_response(q)


@router.post(
    "/questionnaires/{questionnaire_id}/ai-suggest",
    response_model=QuestionnaireResponseModel,
)
def ai_suggest_questionnaire(
    questionnaire_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager

    mgr = QuestionnaireManager()
    try:
        q = mgr.ai_suggest_answers(db, questionnaire_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _questionnaire_to_response(q)


@router.post(
    "/questionnaires/{questionnaire_id}/transition",
    response_model=QuestionnaireResponseModel,
)
def transition_questionnaire(
    questionnaire_id: str,
    body: QuestionnaireTransitionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager

    mgr = QuestionnaireManager()
    try:
        q = mgr.transition(db, questionnaire_id, body.status, actor=current_user.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _questionnaire_to_response(q)
