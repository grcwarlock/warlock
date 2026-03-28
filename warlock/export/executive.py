"""Executive summary generation for GRC posture reporting.

Produces structured data and formatted markdown summaries suitable for
C-suite and board-level communication of compliance posture.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.models import (
    Alert,
    ConnectorRun,
    ControlResult,
    Issue,
    PostureSnapshot,
    Remediation,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity ordering for risk ranking
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _severity_sort_key(result: ControlResult) -> tuple[int, str]:
    """Sort key: severity rank first, then control_id for stable ordering."""
    return (_SEVERITY_ORDER.get(result.severity, 99), result.control_id)


# ---------------------------------------------------------------------------
# Core data generation
# ---------------------------------------------------------------------------


def generate_executive_summary(
    session: Session,
    framework: str | None = None,
) -> dict[str, Any]:
    """Generate a structured executive summary of compliance posture.

    Queries across ControlResult, PostureSnapshot, Issue, Remediation,
    Alert, and ConnectorRun to build a comprehensive posture picture.

    Args:
        session: SQLAlchemy session.
        framework: Optional framework filter. When None, summarises all.

    Returns:
        Dict with keys: generated_at, overall_posture_score, framework_scores,
        top_risks, trend, open_issues_count, open_remediations_count,
        active_alerts_count, connector_health.
    """
    now = datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Control results (per-framework rollup)
    # ------------------------------------------------------------------
    cr_query = session.query(ControlResult)
    if framework:
        cr_query = cr_query.filter(ControlResult.framework == framework)
    all_results = cr_query.all()

    # Group by framework
    by_fw: dict[str, list[ControlResult]] = {}
    for r in all_results:
        by_fw.setdefault(r.framework, []).append(r)

    framework_scores: list[dict[str, Any]] = []
    total_compliant = 0
    total_controls = 0

    for fw in sorted(by_fw.keys()):
        results = by_fw[fw]
        compliant = sum(1 for r in results if r.status == "compliant")
        non_compliant = sum(1 for r in results if r.status == "non_compliant")
        count = len(results)
        score = (compliant / count * 100) if count else 0.0

        framework_scores.append(
            {
                "framework": fw,
                "score": round(score, 1),
                "compliant": compliant,
                "non_compliant": non_compliant,
                "total": count,
            }
        )
        total_compliant += compliant
        total_controls += count

    overall_score = (total_compliant / total_controls * 100) if total_controls else 0.0

    # ------------------------------------------------------------------
    # Top risks: non-compliant controls sorted by severity
    # ------------------------------------------------------------------
    non_compliant_results = [r for r in all_results if r.status == "non_compliant"]
    non_compliant_results.sort(key=_severity_sort_key)

    # Deduplicate by control_id (keep worst severity per control)
    seen_controls: set[str] = set()
    top_risks: list[dict[str, Any]] = []
    for r in non_compliant_results:
        key = f"{r.framework}:{r.control_id}"
        if key in seen_controls:
            continue
        seen_controls.add(key)
        top_risks.append(
            {
                "framework": r.framework,
                "control_id": r.control_id,
                "severity": r.severity,
                "finding_id": r.finding_id,
            }
        )
        if len(top_risks) >= 5:
            break

    # ------------------------------------------------------------------
    # Trend from PostureSnapshot
    # ------------------------------------------------------------------
    snap_query = session.query(PostureSnapshot)
    if framework:
        snap_query = snap_query.filter(PostureSnapshot.framework == framework)
    snap_query = snap_query.order_by(PostureSnapshot.snapshot_date.desc()).limit(200)
    snapshots = snap_query.all()

    trend = _compute_trend(snapshots)

    # ------------------------------------------------------------------
    # Open issues
    # ------------------------------------------------------------------
    issue_query = session.query(Issue).filter(Issue.status.notin_(["closed", "verified"]))
    if framework:
        issue_query = issue_query.filter(Issue.framework == framework)
    open_issues_count = issue_query.count()

    # ------------------------------------------------------------------
    # Open remediations
    # ------------------------------------------------------------------
    rem_query = session.query(Remediation).filter(Remediation.status.notin_(["closed"]))
    if framework:
        rem_query = rem_query.filter(Remediation.framework == framework)
    open_remediations_count = rem_query.count()

    # ------------------------------------------------------------------
    # Active alerts
    # ------------------------------------------------------------------
    alert_query = session.query(Alert).filter(Alert.status == "open")
    if framework:
        alert_query = alert_query.filter(Alert.framework == framework)
    active_alerts_count = alert_query.count()

    # ------------------------------------------------------------------
    # Connector health
    # ------------------------------------------------------------------
    connector_health = _compute_connector_health(session)

    return {
        "generated_at": now.isoformat(),
        "overall_posture_score": round(overall_score, 1),
        "framework_scores": framework_scores,
        "top_risks": top_risks,
        "trend": trend,
        "open_issues_count": open_issues_count,
        "open_remediations_count": open_remediations_count,
        "active_alerts_count": active_alerts_count,
        "connector_health": connector_health,
    }


# ---------------------------------------------------------------------------
# Trend computation
# ---------------------------------------------------------------------------


def _compute_trend(snapshots: list[PostureSnapshot]) -> str:
    """Determine posture direction from recent snapshots.

    Compares the average score of the most recent half of snapshots
    against the older half. Returns 'improving', 'declining', or 'stable'.

    Args:
        snapshots: PostureSnapshot records ordered by date descending.

    Returns:
        One of 'improving', 'declining', or 'stable'.
    """
    if len(snapshots) < 2:
        return "stable"

    mid = len(snapshots) // 2
    recent = snapshots[:mid]
    older = snapshots[mid:]

    recent_avg = sum(s.posture_score for s in recent) / len(recent)
    older_avg = sum(s.posture_score for s in older) / len(older)

    delta = recent_avg - older_avg
    if delta > 2.0:
        return "improving"
    elif delta < -2.0:
        return "declining"
    return "stable"


# ---------------------------------------------------------------------------
# Connector health
# ---------------------------------------------------------------------------


def _compute_connector_health(session: Session) -> dict[str, int]:
    """Compute connector health from the most recent run per connector.

    Args:
        session: SQLAlchemy session.

    Returns:
        Dict with total, healthy, unhealthy counts.
    """
    from sqlalchemy import func

    # Get latest run per connector
    subq = (
        session.query(
            ConnectorRun.connector_name,
            func.max(ConnectorRun.started_at).label("latest"),
        )
        .group_by(ConnectorRun.connector_name)
        .subquery()
    )

    latest_runs = (
        session.query(ConnectorRun)
        .join(
            subq,
            (ConnectorRun.connector_name == subq.c.connector_name)
            & (ConnectorRun.started_at == subq.c.latest),
        )
        .all()
    )

    total = len(latest_runs)
    healthy = sum(1 for r in latest_runs if r.status in ("success", "partial"))
    unhealthy = total - healthy

    return {"total": total, "healthy": healthy, "unhealthy": unhealthy}


# ---------------------------------------------------------------------------
# Markdown formatting
# ---------------------------------------------------------------------------


def format_executive_text(data: dict[str, Any]) -> str:
    """Render executive summary data as a one-page markdown summary.

    Designed for quick consumption by executives who need a posture
    snapshot without diving into per-control details.

    Args:
        data: Dict returned by generate_executive_summary().

    Returns:
        Markdown string.
    """
    lines: list[str] = []

    lines.append("# Executive Compliance Summary")
    lines.append("")
    lines.append(f"**Generated:** {data['generated_at']}")
    lines.append("")

    # Overall posture
    score = data["overall_posture_score"]
    posture_label = "Strong" if score >= 80 else ("Moderate" if score >= 60 else "Needs Attention")
    lines.append("## Overall Posture")
    lines.append("")
    lines.append(f"- **Score:** {score}% ({posture_label})")
    lines.append(f"- **Trend:** {data['trend'].capitalize()}")
    lines.append(f"- **Open Issues:** {data['open_issues_count']}")
    lines.append(f"- **Open Remediations:** {data['open_remediations_count']}")
    lines.append(f"- **Active Alerts:** {data['active_alerts_count']}")
    lines.append("")

    # Framework scores
    fw_scores = data.get("framework_scores", [])
    if fw_scores:
        lines.append("## Framework Scores")
        lines.append("")
        lines.append("| Framework | Score | Compliant | Non-Compliant | Total |")
        lines.append("|-----------|-------|-----------|---------------|-------|")
        for fw in fw_scores:
            lines.append(
                f"| {fw['framework']} | {fw['score']}% "
                f"| {fw['compliant']} | {fw['non_compliant']} | {fw['total']} |"
            )
        lines.append("")

    # Top risks
    top_risks = data.get("top_risks", [])
    if top_risks:
        lines.append("## Top Risks")
        lines.append("")
        for idx, risk in enumerate(top_risks, 1):
            lines.append(
                f"{idx}. **[{risk['severity'].upper()}]** "
                f"{risk['framework']} / {risk['control_id']}"
            )
        lines.append("")

    # Connector health
    ch = data.get("connector_health", {})
    if ch.get("total", 0) > 0:
        lines.append("## Connector Health")
        lines.append("")
        lines.append(f"- **Total:** {ch['total']}")
        lines.append(f"- **Healthy:** {ch['healthy']}")
        lines.append(f"- **Unhealthy:** {ch['unhealthy']}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by Warlock GRC Platform*")

    return "\n".join(lines)
