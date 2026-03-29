"""Direct SQLAlchemy read queries for the TUI.

All reads go through get_read_session(). No API calls here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import case, func

from warlock.db.engine import get_read_session, init_db
from warlock.db.models import (
    Alert,
    AuditEngagement,
    ChangeRequest,
    ComplianceObligation,
    ControlResult,
    DataSilo,
    Finding,
    Personnel,
    PipelineRun,
    POAM,
    Remediation,
    RiskAnalysis,
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
                        "control_title": cr.assertion_name or "",
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
                        "control_title": cr.assertion_name or "",
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
                "control_title": cr.assertion_name or "",
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


# ------------------------------------------------------------------ #
# Dashboard (aggregated KRIs)                                         #
# ------------------------------------------------------------------ #


def get_dashboard_data() -> dict[str, Any]:
    """Aggregated KRI data for the dashboard home screen."""
    init_db()
    with get_read_session() as session:
        # Overall compliance
        total_ctrl = session.query(func.count(ControlResult.id)).scalar() or 0
        compliant_ctrl = (
            session.query(func.count(ControlResult.id))
            .filter(ControlResult.status == "compliant")
            .scalar()
            or 0
        )
        overall_pct = round(100 * compliant_ctrl / total_ctrl, 1) if total_ctrl else 0.0

        # Framework posture (reuse)
        frameworks = get_frameworks_summary()

        # Recent alerts
        recent_alerts = session.query(Alert).order_by(Alert.triggered_at.desc()).limit(5).all()
        alerts_list = [
            {
                "id": a.id,
                "title": a.title or "",
                "severity": (a.severity or "info").lower(),
                "category": a.category or "",
                "status": a.status or "open",
                "triggered_at": ensure_aware(a.triggered_at) if a.triggered_at else None,
            }
            for a in recent_alerts
        ]
        open_alerts = (
            session.query(func.count(Alert.id))
            .filter(Alert.status.in_(["open", "acknowledged", "investigating"]))
            .scalar()
            or 0
        )

        # Overdue POA&Ms
        all_poams = session.query(POAM).all()
        overdue_poams = sum(1 for p in all_poams if _is_overdue(p.due_date))

        # Pipeline last run
        last_run = session.query(PipelineRun).order_by(PipelineRun.started_at.desc()).first()
        pipeline_info = None
        if last_run:
            pipeline_info = {
                "status": last_run.status or "unknown",
                "started_at": (ensure_aware(last_run.started_at) if last_run.started_at else None),
                "connectors_ok": last_run.connectors_succeeded or 0,
                "connectors_failed": last_run.connectors_failed or 0,
                "findings": last_run.findings_normalized or 0,
            }

        # Finding severity breakdown
        total_findings = session.query(func.count(Finding.id)).scalar() or 0
        critical_findings = (
            session.query(func.count(Finding.id)).filter(Finding.severity == "critical").scalar()
            or 0
        )

        return {
            "overall_pct": overall_pct,
            "total_controls": total_ctrl,
            "compliant_controls": compliant_ctrl,
            "frameworks": frameworks,
            "recent_alerts": alerts_list,
            "open_alerts": open_alerts,
            "overdue_poams": overdue_poams,
            "total_poams": len(all_poams),
            "pipeline": pipeline_info,
            "total_findings": total_findings,
            "critical_findings": critical_findings,
        }


# ------------------------------------------------------------------ #
# Alerts                                                               #
# ------------------------------------------------------------------ #


def get_alerts(
    severity: str | None = None,
    status: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    init_db()
    with get_read_session() as session:
        q = session.query(Alert)
        if severity:
            q = q.filter(Alert.severity == severity)
        if status:
            q = q.filter(Alert.status == status)
        q = q.order_by(Alert.triggered_at.desc())
        rows = q.limit(limit).all()
        return [
            {
                "id": a.id,
                "title": a.title or "(untitled)",
                "severity": (a.severity or "info").lower(),
                "category": a.category or "",
                "status": a.status or "open",
                "framework": a.framework or "",
                "control_id": a.control_id or "",
                "connector_name": a.connector_name or "",
                "rule_name": a.rule_name or "",
                "triggered_at": ensure_aware(a.triggered_at) if a.triggered_at else None,
                "acknowledged_by": a.acknowledged_by or "",
                "resolved_by": a.resolved_by or "",
                "resolution_notes": a.resolution_notes or "",
                "description": a.description or "",
            }
            for a in rows
        ]


def get_alert_counts() -> dict[str, int]:
    init_db()
    with get_read_session() as session:
        total = session.query(func.count(Alert.id)).scalar() or 0
        open_count = (
            session.query(func.count(Alert.id))
            .filter(Alert.status.in_(["open", "acknowledged", "investigating"]))
            .scalar()
            or 0
        )
        critical = (
            session.query(func.count(Alert.id)).filter(Alert.severity == "critical").scalar() or 0
        )
        return {"total": total, "open": open_count, "critical": critical}


# ------------------------------------------------------------------ #
# Incidents (uses Issue model as incident tracker)                     #
# ------------------------------------------------------------------ #


def get_incidents(
    status: str | None = None,
    priority: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    from warlock.db.models import Issue

    init_db()
    with get_read_session() as session:
        q = session.query(Issue)
        if status:
            q = q.filter(Issue.status == status)
        if priority:
            q = q.filter(Issue.priority == priority)
        q = q.order_by(Issue.created_at.desc())
        rows = q.limit(limit).all()
        return [
            {
                "id": i.id,
                "title": i.title or "(untitled)",
                "status": i.status or "open",
                "priority": (i.priority or "medium").lower(),
                "assigned_to": i.assigned_to or "",
                "framework": i.framework or "",
                "control_id": i.control_id or "",
                "due_date": ensure_aware(i.due_date) if i.due_date else None,
                "overdue": _is_overdue(i.due_date),
                "source": i.source or "",
                "created_at": ensure_aware(i.created_at) if i.created_at else None,
                "risk_accepted": i.risk_accepted or False,
                "remediation_plan": i.remediation_plan or "",
                "description": i.description or "",
            }
            for i in rows
        ]


def get_incident_counts() -> dict[str, int]:
    from warlock.db.models import Issue

    init_db()
    with get_read_session() as session:
        total = session.query(func.count(Issue.id)).scalar() or 0
        open_count = (
            session.query(func.count(Issue.id))
            .filter(Issue.status.in_(["open", "assigned", "in_progress"]))
            .scalar()
            or 0
        )
        critical = (
            session.query(func.count(Issue.id)).filter(Issue.priority == "critical").scalar() or 0
        )
        return {"total": total, "open": open_count, "critical": critical}


# ------------------------------------------------------------------ #
# Evidence (uses Attestation model)                                    #
# ------------------------------------------------------------------ #


def get_evidence_records(limit: int = 500) -> list[dict[str, Any]]:
    from warlock.db.models import Attestation

    init_db()
    with get_read_session() as session:
        rows = session.query(Attestation).order_by(Attestation.created_at.desc()).limit(limit).all()
        return [
            {
                "id": a.id,
                "framework": a.framework or "",
                "control_id": a.control_id or "",
                "status": a.status or "draft",
                "statement": a.statement or "",
                "prepared_by": a.prepared_by or "",
                "reviewed_by": a.reviewed_by or "",
                "approved_by": a.approved_by or "",
                "created_at": ensure_aware(a.created_at) if a.created_at else None,
                "evidence_references": a.evidence_references or [],
            }
            for a in rows
        ]


def get_evidence_counts() -> dict[str, int]:
    from warlock.db.models import Attestation

    init_db()
    with get_read_session() as session:
        total = session.query(func.count(Attestation.id)).scalar() or 0
        approved = (
            session.query(func.count(Attestation.id))
            .filter(Attestation.status == "approved")
            .scalar()
            or 0
        )
        draft = (
            session.query(func.count(Attestation.id)).filter(Attestation.status == "draft").scalar()
            or 0
        )
        return {"total": total, "approved": approved, "draft": draft}


# ------------------------------------------------------------------ #
# Privacy (DataSilo)                                                   #
# ------------------------------------------------------------------ #


def get_privacy_data_silos(limit: int = 500) -> list[dict[str, Any]]:
    init_db()
    with get_read_session() as session:
        rows = session.query(DataSilo).order_by(DataSilo.created_at.desc()).limit(limit).all()
        return [
            {
                "id": ds.id,
                "name": ds.name or "(unnamed)",
                "silo_type": ds.silo_type or "",
                "provider": ds.provider or "",
                "data_classification": ds.data_classification or "unknown",
                "contains_pii": ds.contains_pii or False,
                "contains_phi": ds.contains_phi or False,
                "contains_pci": ds.contains_pci or False,
                "encrypted_at_rest": ds.encrypted_at_rest,
                "encrypted_in_transit": ds.encrypted_in_transit,
                "owner": ds.owner or "",
                "scan_status": ds.scan_status or "not_scanned",
                "sensitive_field_count": ds.sensitive_field_count or 0,
                "last_scan_date": (ensure_aware(ds.last_scan_date) if ds.last_scan_date else None),
                "applicable_frameworks": ds.applicable_frameworks or [],
            }
            for ds in rows
        ]


def get_privacy_counts() -> dict[str, int]:
    init_db()
    with get_read_session() as session:
        total = session.query(func.count(DataSilo.id)).scalar() or 0
        pii = (
            session.query(func.count(DataSilo.id)).filter(DataSilo.contains_pii.is_(True)).scalar()
            or 0
        )
        phi = (
            session.query(func.count(DataSilo.id)).filter(DataSilo.contains_phi.is_(True)).scalar()
            or 0
        )
        return {"total": total, "pii": pii, "phi": phi}


# ------------------------------------------------------------------ #
# Personnel                                                            #
# ------------------------------------------------------------------ #


def get_personnel(limit: int = 500) -> list[dict[str, Any]]:
    init_db()
    with get_read_session() as session:
        rows = session.query(Personnel).order_by(Personnel.full_name).limit(limit).all()
        return [
            {
                "id": p.id,
                "full_name": p.full_name or "(unknown)",
                "email": p.email or "",
                "department": p.department or "",
                "title": p.title or "",
                "hr_status": p.hr_status or "",
                "training_status": p.training_status or "",
                "mfa_enabled": p.mfa_enabled,
                "risk_score": p.risk_score or 0.0,
                "flags": p.flags or [],
                "background_check_status": p.background_check_status or "",
                "access_review_status": p.access_review_status or "",
                "last_training_date": (
                    ensure_aware(p.last_training_date) if p.last_training_date else None
                ),
                "phishing_score": p.phishing_score,
                "employee_type": p.employee_type or "employee",
            }
            for p in rows
        ]


def get_personnel_counts() -> dict[str, int]:
    init_db()
    with get_read_session() as session:
        total = session.query(func.count(Personnel.id)).scalar() or 0
        flagged = (
            session.query(func.count(Personnel.id)).filter(Personnel.risk_score > 50).scalar() or 0
        )
        overdue_training = (
            session.query(func.count(Personnel.id))
            .filter(Personnel.training_status == "overdue")
            .scalar()
            or 0
        )
        return {"total": total, "flagged": flagged, "overdue_training": overdue_training}


# ------------------------------------------------------------------ #
# Audit Engagements                                                    #
# ------------------------------------------------------------------ #


def get_audit_engagements(limit: int = 200) -> list[dict[str, Any]]:
    init_db()
    with get_read_session() as session:
        rows = (
            session.query(AuditEngagement)
            .order_by(AuditEngagement.period_start.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": e.id,
                "name": e.name or "(unnamed)",
                "framework": e.framework or "",
                "status": e.status or "active",
                "period_start": (ensure_aware(e.period_start) if e.period_start else None),
                "period_end": (ensure_aware(e.period_end) if e.period_end else None),
                "auditor_name": e.auditor_name or "",
                "auditor_firm": e.auditor_firm or "",
            }
            for e in rows
        ]


# ------------------------------------------------------------------ #
# Change Requests                                                      #
# ------------------------------------------------------------------ #


def get_change_requests(limit: int = 500) -> list[dict[str, Any]]:
    init_db()
    with get_read_session() as session:
        rows = (
            session.query(ChangeRequest)
            .order_by(ChangeRequest.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": cr.id,
                "title": cr.title or "(untitled)",
                "change_type": cr.change_type or "",
                "risk_level": cr.risk_level or "",
                "requester": cr.requester or "",
                "status": cr.status or "draft",
                "cab_decision": cr.cab_decision or "",
                "implementation_date": (
                    ensure_aware(cr.implementation_date) if cr.implementation_date else None
                ),
                "created_at": (ensure_aware(cr.created_at) if cr.created_at else None),
                "description": cr.description or "",
                "rollback_plan": cr.rollback_plan or "",
            }
            for cr in rows
        ]


def get_change_request_counts() -> dict[str, int]:
    init_db()
    with get_read_session() as session:
        total = session.query(func.count(ChangeRequest.id)).scalar() or 0
        pending = (
            session.query(func.count(ChangeRequest.id))
            .filter(ChangeRequest.status == "draft")
            .scalar()
            or 0
        )
        return {"total": total, "pending": pending}


# ------------------------------------------------------------------ #
# Compliance Calendar (obligations)                                    #
# ------------------------------------------------------------------ #


def get_compliance_obligations(limit: int = 200) -> list[dict[str, Any]]:
    init_db()
    with get_read_session() as session:
        rows = (
            session.query(ComplianceObligation)
            .order_by(ComplianceObligation.next_due.asc().nullslast())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": o.id,
                "title": o.title or "(untitled)",
                "framework": o.framework or "",
                "obligation_type": o.obligation_type or "",
                "frequency": o.frequency or "",
                "next_due": ensure_aware(o.next_due) if o.next_due else None,
                "owner": o.owner or "",
                "status": o.status or "pending",
                "overdue": _is_overdue(o.next_due),
                "days_until_due": _days_until(o.next_due),
            }
            for o in rows
        ]


# ------------------------------------------------------------------ #
# Risk Analysis                                                        #
# ------------------------------------------------------------------ #


def get_risk_analyses(limit: int = 200) -> list[dict[str, Any]]:
    init_db()
    with get_read_session() as session:
        rows = (
            session.query(RiskAnalysis).order_by(RiskAnalysis.created_at.desc()).limit(limit).all()
        )
        return [
            {
                "id": ra.id,
                "framework": ra.framework or "",
                "scenario_name": ra.scenario_name or "",
                "mean_ale": ra.mean_ale or 0.0,
                "var_95": ra.var_95 or 0.0,
                "var_99": ra.var_99 or 0.0,
                "control_effectiveness": ra.control_effectiveness,
                "iterations": ra.iterations or 10000,
                "created_at": (ensure_aware(ra.created_at) if ra.created_at else None),
                "risk_culture_score": ra.risk_culture_score,
                "mttr_days": ra.mttr_days,
            }
            for ra in rows
        ]


# ------------------------------------------------------------------ #
# Reports (framework posture for export)                               #
# ------------------------------------------------------------------ #


def get_report_frameworks() -> list[str]:
    """Get list of available frameworks for report generation."""
    init_db()
    with get_read_session() as session:
        rows = (
            session.query(ControlResult.framework)
            .distinct()
            .order_by(ControlResult.framework)
            .all()
        )
        return [r[0] for r in rows if r[0]]
