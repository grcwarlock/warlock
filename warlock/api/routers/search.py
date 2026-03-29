"""Search routes: unified full-text and faceted search across GRC entities."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import (
    get_db,
    get_pagination,
    require_permission,
    apply_framework_scope,
)
from warlock.api.routers.schemas import PaginatedResponse, _escape_like
from warlock.db.models import (
    ControlResult,
    Finding,
    Issue,
    POAM,
    User,
    Vendor,
)

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class SearchResultItem(BaseModel):
    entity_type: str
    id: str
    title: str
    detail: str | None = None
    score: float = 0.0


class FacetBucket(BaseModel):
    value: str
    count: int


class FacetedSearchResponse(BaseModel):
    total: int
    items: list[SearchResultItem]
    facets: dict[str, list[FacetBucket]]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/search", response_model=PaginatedResponse)
def unified_search(
    q: str = Query(..., min_length=1, max_length=500),
    entity_type: str | None = Query(
        None,
        description="Filter: findings, controls, issues, poams, vendors",
    ),
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Unified full-text search across findings, controls, issues, POAMs, vendors."""
    limit, offset = pagination
    pattern = f"%{_escape_like(q)}%"
    results: list[SearchResultItem] = []

    types = [entity_type] if entity_type else ["findings", "controls", "issues", "poams", "vendors"]

    if "findings" in types:
        fq = db.query(Finding).filter(Finding.title.ilike(pattern))
        fq = apply_framework_scope(fq, Finding, current_user)
        for f in fq.limit(limit).all():
            results.append(
                SearchResultItem(
                    entity_type="finding",
                    id=f.id,
                    title=f.title or "",
                    detail=f.source,
                )
            )

    if "controls" in types:
        cq = db.query(ControlResult).filter(ControlResult.control_id.ilike(pattern))
        cq = apply_framework_scope(cq, ControlResult, current_user)
        for c in cq.limit(limit).all():
            results.append(
                SearchResultItem(
                    entity_type="control_result",
                    id=c.id,
                    title=f"{c.framework}/{c.control_id}",
                    detail=c.status,
                )
            )

    if "issues" in types:
        iq = db.query(Issue).filter(Issue.title.ilike(pattern))
        for i in iq.limit(limit).all():
            results.append(
                SearchResultItem(
                    entity_type="issue",
                    id=i.id,
                    title=i.title or "",
                    detail=i.status,
                )
            )

    if "poams" in types:
        pq = db.query(POAM).filter(POAM.weakness_description.ilike(pattern))
        for p in pq.limit(limit).all():
            results.append(
                SearchResultItem(
                    entity_type="poam",
                    id=p.id,
                    title=(p.weakness_description or "")[:120],
                    detail=p.status,
                )
            )

    if "vendors" in types:
        vq = db.query(Vendor).filter(Vendor.name.ilike(pattern))
        for v in vq.limit(limit).all():
            results.append(
                SearchResultItem(
                    entity_type="vendor",
                    id=v.id,
                    title=v.name,
                    detail=v.risk_tier,
                )
            )

    total = len(results)
    paged = results[offset : offset + limit]

    return PaginatedResponse(
        items=[r.model_dump() for r in paged],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/search/faceted", response_model=FacetedSearchResponse)
def faceted_search(
    q: str = Query(..., min_length=1, max_length=500),
    framework: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Faceted search with framework/severity/status filters."""
    limit, offset = pagination
    pattern = f"%{_escape_like(q)}%"

    fq = db.query(Finding).filter(Finding.title.ilike(pattern))
    fq = apply_framework_scope(fq, Finding, current_user)
    if severity:
        fq = fq.filter(Finding.severity == severity)

    findings = fq.limit(5000).all()

    # Build facets
    severity_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    for f in findings:
        sev = (f.severity or "unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        src = f.source or "unknown"
        source_counts[src] = source_counts.get(src, 0) + 1

    items = [
        SearchResultItem(
            entity_type="finding",
            id=f.id,
            title=f.title or "",
            detail=f.source,
        )
        for f in findings
    ]

    total = len(items)
    paged = items[offset : offset + limit]

    return FacetedSearchResponse(
        total=total,
        items=paged,
        facets={
            "severity": [
                FacetBucket(value=k, count=v)
                for k, v in sorted(
                    severity_counts.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )
            ],
            "source": [
                FacetBucket(value=k, count=v)
                for k, v in sorted(
                    source_counts.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )
            ],
        },
    )
