"""Direct SQLAlchemy read queries for the TUI.

All reads go through get_read_session(). No API calls here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import case, func

from warlock.db.engine import get_read_session, init_db
from warlock.db.models import (
    ControlResult,
    Finding,
    PipelineRun,
    POAM,
    Remediation,
    SystemProfile,
    Vendor,
)
from warlock.utils import ensure_aware


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _is_overdue(due_date: datetime | None) -> bool:
    if due_date is None:
        return False
    return ensure_aware(due_date) < _utcnow()


def _days_until(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    delta = ensure_aware(dt) - _utcnow()
    return delta.days


# ------------------------------------------------------------------ #
# Remediations                                                         #
# ------------------------------------------------------------------ #


def get_remediations(
    status: str | None = None,
    severity: str | None = None,
    assignee: str | None = None,
    framework: str | None = None,
    overdue_only: bool = False,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Fetch remediations with computed fields."""
    init_db()
    with get_read_session() as session:
        q = session.query(Remediation)
        if status:
            q = q.filter(Remediation.status == status)
        if severity:
            # Severity is stored in remediation_steps or derived from finding
            pass  # filtered in post-processing
        if assignee:
            q = q.filter(Remediation.assigned_to == assignee)
        if framework:
            q = q.filter(Remediation.framework == framework)
        q = q.order_by(Remediation.due_date.asc().nullslast(), Remediation.created_at.desc())
        rows = q.limit(limit).all()

        results = []
        for r in rows:
            due = ensure_aware(r.due_date) if r.due_date else None
            overdue = _is_overdue(r.due_date)
            if overdue_only and not overdue:
                continue
            # Derive severity from linked finding if not on remediation directly
            sev = _get_remediation_severity(session, r)
            if severity and sev != severity:
                continue
            results.append(
                {
                    "id": r.id,
                    "title": r.title or "(untitled)",
                    "description": r.description or "",
                    "status": r.status or "open",
                    "severity": sev,
                    "assigned_to": r.assigned_to or "",
                    "due_date": due,
                    "days_until_due": _days_until(r.due_date),
                    "overdue": overdue,
                    "framework": r.framework or "",
                    "control_id": r.control_id or "",
                    "finding_id": r.finding_id or "",
                    "remediation_plan": r.remediation_plan or "",
                    "steps": r.remediation_steps or [],
                    "evidence": r.evidence or [],
                    "created_at": ensure_aware(r.created_at) if r.created_at else None,
                    "updated_at": ensure_aware(r.updated_at) if r.updated_at else None,
                    "created_by": r.created_by or "",
                    "verified_by": r.verified_by or "",
                    "verification_notes": r.verification_notes or "",
                }
            )
    # Sort: overdue first, then by severity rank, then due date
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(
        key=lambda r: (
            not r["overdue"],
            sev_rank.get(r["severity"], 4),
            r["due_date"] or datetime(2099, 1, 1, tzinfo=timezone.utc),
        )
    )
    return results


def _get_remediation_severity(session, rem: Remediation) -> str:
    """Derive severity from linked finding or default to medium."""
    if rem.finding_id:
        finding = session.query(Finding).filter(Finding.id == rem.finding_id).first()
        if finding and finding.severity:
            return finding.severity.lower()
    return "medium"


def get_remediation_detail(rem_id: str) -> dict[str, Any] | None:
    """Full detail for a single remediation including linked entities."""
    init_db()
    with get_read_session() as session:
        r = session.query(Remediation).filter(Remediation.id == rem_id).first()
        if not r:
            return None

        detail: dict[str, Any] = {
            "id": r.id,
            "title": r.title or "(untitled)",
            "description": r.description or "",
            "status": r.status or "open",
            "severity": _get_remediation_severity(session, r),
            "assigned_to": r.assigned_to or "",
            "assigned_by": r.assigned_by or "",
            "due_date": ensure_aware(r.due_date) if r.due_date else None,
            "days_until_due": _days_until(r.due_date),
            "overdue": _is_overdue(r.due_date),
            "framework": r.framework or "",
            "control_id": r.control_id or "",
            "finding_id": r.finding_id or "",
            "remediation_plan": r.remediation_plan or "",
            "steps": r.remediation_steps or [],
            "evidence": r.evidence or [],
            "created_at": ensure_aware(r.created_at) if r.created_at else None,
            "created_by": r.created_by or "",
            "verified_by": r.verified_by or "",
            "verification_notes": r.verification_notes or "",
            "impacted_systems": [],
            "control_impact": [],
            "activity": [],
        }

        # Impacted systems — via finding → system mapping
        if r.finding_id:
            finding = session.query(Finding).filter(Finding.id == r.finding_id).first()
            if finding:
                detail["finding_title"] = finding.title or ""
                detail["finding_source"] = finding.source or ""
                # Get systems from finding metadata
                # Look up system profiles
                systems = session.query(SystemProfile).all()
                for sp in systems:
                    # Match by environment/resource references
                    detail["impacted_systems"].append(
                        {
                            "id": sp.id,
                            "name": sp.name or sp.acronym or sp.id[:8],
                            "acronym": sp.acronym or "",
                            "environment": (sp.metadata_ or {}).get("environment", "production")
                            if hasattr(sp, "metadata_")
                            else "production",
                            "ato_status": sp.ato_status or "Active",
                        }
                    )
                if not detail["impacted_systems"] and systems:
                    # Fallback: show first system
                    sp = systems[0]
                    detail["impacted_systems"].append(
                        {
                            "id": sp.id,
                            "name": sp.name or sp.acronym or sp.id[:8],
                            "acronym": sp.acronym or "",
                            "environment": "production",
                            "ato_status": sp.ato_status or "Active",
                        }
                    )

        # Control impact — find control results for this control across frameworks
        if r.control_id:
            crs = (
                session.query(ControlResult)
                .filter(ControlResult.control_id == r.control_id)
                .limit(20)
                .all()
            )
            for cr in crs:
                detail["control_impact"].append(
                    {
                        "framework": cr.framework or "",
                        "control_id": cr.control_id or "",
                        "control_title": cr.control_title or "",
                        "status": cr.status or "not_assessed",
                    }
                )
        elif r.framework and r.finding_id:
            # Try broader search by framework
            crs = (
                session.query(ControlResult)
                .filter(ControlResult.framework == r.framework)
                .filter(ControlResult.status == "non_compliant")
                .limit(10)
                .all()
            )
            for cr in crs:
                detail["control_impact"].append(
                    {
                        "framework": cr.framework or "",
                        "control_id": cr.control_id or "",
                        "control_title": cr.control_title or "",
                        "status": cr.status or "not_assessed",
                    }
                )

        return detail


def get_remediation_counts() -> dict[str, int]:
    """Summary counts for header badges."""
    init_db()
    with get_read_session() as session:
        all_rem = session.query(Remediation).all()
        counts = {"total": 0, "critical": 0, "overdue": 0, "open": 0, "closed": 0}
        for r in all_rem:
            counts["total"] += 1
            if r.status == "closed":
                counts["closed"] += 1
            else:
                counts["open"] += 1
                if _is_overdue(r.due_date):
                    counts["overdue"] += 1
                sev = _get_remediation_severity(session, r)
                if sev == "critical":
                    counts["critical"] += 1
        return counts


# ------------------------------------------------------------------ #
# Findings                                                             #
# ------------------------------------------------------------------ #


def get_findings(
    severity: str | None = None,
    source: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    init_db()
    with get_read_session() as session:
        q = session.query(Finding)
        if severity:
            q = q.filter(Finding.severity == severity)
        if source:
            q = q.filter(Finding.source == source)
        q = q.order_by(Finding.ingested_at.desc())
        rows = q.limit(limit).all()
        return [
            {
                "id": f.id,
                "title": f.title or "(untitled)",
                "severity": (f.severity or "medium").lower(),
                "source": f.source or "",
                "observation_type": f.observation_type or "",
                "resource_type": f.resource_type or "",
                "provider": f.provider or "",
                "ingested_at": ensure_aware(f.ingested_at) if f.ingested_at else None,
            }
            for f in rows
        ]


def get_finding_counts() -> dict[str, int]:
    init_db()
    with get_read_session() as session:
        total = session.query(func.count(Finding.id)).scalar() or 0
        critical = (
            session.query(func.count(Finding.id)).filter(Finding.severity == "critical").scalar()
            or 0
        )
        high = (
            session.query(func.count(Finding.id)).filter(Finding.severity == "high").scalar() or 0
        )
        return {"total": total, "critical": critical, "high": high}


# ------------------------------------------------------------------ #
# Controls                                                             #
# ------------------------------------------------------------------ #


def get_control_results(
    framework: str | None = None,
    status: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    init_db()
    with get_read_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        if status:
            q = q.filter(ControlResult.status == status)
        q = q.order_by(ControlResult.framework, ControlResult.control_id)
        rows = q.limit(limit).all()
        return [
            {
                "id": cr.id,
                "framework": cr.framework or "",
                "control_id": cr.control_id or "",
                "control_title": cr.control_title or "",
                "status": cr.status or "not_assessed",
            }
            for cr in rows
        ]


def get_control_counts() -> dict[str, int]:
    init_db()
    with get_read_session() as session:
        total = session.query(func.count(ControlResult.id)).scalar() or 0
        nc = (
            session.query(func.count(ControlResult.id))
            .filter(ControlResult.status == "non_compliant")
            .scalar()
            or 0
        )
        return {"total": total, "non_compliant": nc}


# ------------------------------------------------------------------ #
# POA&Ms                                                               #
# ------------------------------------------------------------------ #


def get_poams(limit: int = 500) -> list[dict[str, Any]]:
    init_db()
    with get_read_session() as session:
        rows = session.query(POAM).order_by(POAM.due_date.asc().nullslast()).limit(limit).all()
        return [
            {
                "id": p.id,
                "control_id": p.control_id or "",
                "framework": p.framework or "",
                "weakness": p.weakness or "",
                "status": p.status or "draft",
                "due_date": ensure_aware(p.due_date) if p.due_date else None,
                "overdue": _is_overdue(p.due_date),
                "assigned_to": p.assigned_to or "",
                "severity": (p.severity or "moderate").lower(),
                "cost_estimate": p.cost_estimate,
            }
            for p in rows
        ]


def get_poam_counts() -> dict[str, int]:
    init_db()
    with get_read_session() as session:
        total = session.query(func.count(POAM.id)).scalar() or 0
        open_count = (
            session.query(func.count(POAM.id))
            .filter(POAM.status.in_(["draft", "open", "in_progress"]))
            .scalar()
            or 0
        )
        return {"total": total, "open": open_count}


# ------------------------------------------------------------------ #
# Pipeline                                                             #
# ------------------------------------------------------------------ #


def get_pipeline_runs(limit: int = 50) -> list[dict[str, Any]]:
    init_db()
    with get_read_session() as session:
        rows = session.query(PipelineRun).order_by(PipelineRun.started_at.desc()).limit(limit).all()
        return [
            {
                "id": pr.id,
                "status": pr.status or "unknown",
                "started_at": ensure_aware(pr.started_at) if pr.started_at else None,
                "completed_at": ensure_aware(pr.completed_at) if pr.completed_at else None,
                "duration_seconds": pr.duration_seconds,
                "raw_events": pr.raw_events_collected or 0,
                "findings": pr.findings_normalized or 0,
                "controls_mapped": pr.controls_mapped or 0,
                "connectors_ok": pr.connectors_succeeded or 0,
                "connectors_failed": pr.connectors_failed or 0,
                "errors": pr.errors or [],
            }
            for pr in rows
        ]


# ------------------------------------------------------------------ #
# Frameworks                                                           #
# ------------------------------------------------------------------ #


def get_frameworks_summary() -> list[dict[str, Any]]:
    """Per-framework posture summary."""
    init_db()
    with get_read_session() as session:
        frameworks = (
            session.query(
                ControlResult.framework,
                func.count(ControlResult.id).label("total"),
                func.sum(case((ControlResult.status == "compliant", 1), else_=0)).label(
                    "compliant"
                ),
                func.sum(case((ControlResult.status == "non_compliant", 1), else_=0)).label(
                    "non_compliant"
                ),
            )
            .group_by(ControlResult.framework)
            .all()
        )
        results = []
        for fw_name, total, compliant, non_compliant in frameworks:
            if not fw_name:
                continue
            pct = round(100 * (compliant or 0) / total, 1) if total else 0.0
            results.append(
                {
                    "framework": fw_name,
                    "total": total or 0,
                    "compliant": compliant or 0,
                    "non_compliant": non_compliant or 0,
                    "posture_pct": pct,
                }
            )
        results.sort(key=lambda x: x["posture_pct"])
        return results


# ------------------------------------------------------------------ #
# Vendors                                                              #
# ------------------------------------------------------------------ #


def get_vendors(limit: int = 200) -> list[dict[str, Any]]:
    init_db()
    with get_read_session() as session:
        rows = session.query(Vendor).order_by(Vendor.name).limit(limit).all()
        return [
            {
                "id": v.id,
                "name": v.name or "(unnamed)",
                "tier": v.tier or "",
                "risk_score": v.risk_score,
                "contract_expires": ensure_aware(v.contract_expires)
                if v.contract_expires
                else None,
                "last_assessment": ensure_aware(v.last_assessment) if v.last_assessment else None,
            }
            for v in rows
        ]


# ------------------------------------------------------------------ #
# Systems                                                              #
# ------------------------------------------------------------------ #


def get_systems() -> list[dict[str, Any]]:
    init_db()
    with get_read_session() as session:
        rows = session.query(SystemProfile).all()
        return [
            {
                "id": sp.id,
                "name": sp.name or sp.acronym or sp.id[:8],
                "acronym": sp.acronym or "",
                "ato_status": sp.ato_status or "Active",
            }
            for sp in rows
        ]


# ------------------------------------------------------------------ #
# Search (for command palette)                                         #
# ------------------------------------------------------------------ #


def search_entities(query: str, limit: int = 20) -> list[dict[str, Any]]:
    """Fuzzy search across remediations, findings, controls."""
    if not query or len(query) < 2:
        return []

    init_db()
    results: list[dict[str, Any]] = []
    q_lower = query.lower()

    with get_read_session() as session:
        # Remediations
        rems = session.query(Remediation).limit(200).all()
        for r in rems:
            title = (r.title or "").lower()
            if q_lower in title or q_lower in (r.assigned_to or "").lower():
                results.append(
                    {
                        "type": "remediation",
                        "id": r.id,
                        "label": r.title or r.id[:8],
                        "detail": f"{r.status} · {r.assigned_to or 'unassigned'}",
                    }
                )

        # Findings
        findings = session.query(Finding).limit(200).all()
        for f in findings:
            title = (f.title or "").lower()
            if q_lower in title or q_lower in (f.source or "").lower():
                results.append(
                    {
                        "type": "finding",
                        "id": f.id,
                        "label": f.title or f.id[:8],
                        "detail": f"{f.severity} · {f.source}",
                    }
                )

        # Controls
        crs = session.query(ControlResult).limit(200).all()
        for cr in crs:
            cid = (cr.control_id or "").lower()
            title = (cr.control_title or "").lower()
            if q_lower in cid or q_lower in title or q_lower in (cr.framework or "").lower():
                results.append(
                    {
                        "type": "control",
                        "id": cr.id,
                        "label": f"{cr.framework} {cr.control_id}",
                        "detail": f"{cr.control_title} · {cr.status}",
                    }
                )

    return results[:limit]
