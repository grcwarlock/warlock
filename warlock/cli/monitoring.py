"""Monitoring commands: cadence, posture-history, sufficiency, drift,
effectiveness, simulate-audit."""

from __future__ import annotations

import click
from rich.table import Table

from warlock.cli import cli, console, _check_ai_available


@cli.command("cadence")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--stale-only", is_flag=True, help="Show only stale controls")
def cadence_check(framework: str | None, stale_only: bool) -> None:
    """Check monitoring cadence -- are controls being assessed on schedule?"""
    from warlock.db.engine import get_session, init_db
    from warlock.assessors.cadence import CadenceChecker

    init_db()
    checker = CadenceChecker()

    with get_session() as session:
        if stale_only:
            cadences = checker.get_stale_controls(session, framework=framework)
        elif framework:
            cadences = checker.check_framework(session, framework)
        else:
            all_c = checker.check_all(session)
            cadences = [c for clist in all_c.values() for c in clist]

    if not cadences:
        if stale_only:
            console.print("[green]All controls within monitoring frequency.[/green]")
        else:
            console.print("[dim]No control results found.[/dim]")
        return

    table = Table(title="Monitoring Cadence")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Frequency")
    table.add_column("Last Evidence")
    table.add_column("Hours Since", justify="right")
    table.add_column("Status")

    for c in cadences:
        if c.last_evidence_at:
            last_str = c.last_evidence_at.strftime("%Y-%m-%d %H:%M")
            hours_str = f"{c.hours_since:.0f}"
        else:
            last_str = "never"
            hours_str = "\u2014"

        if c.staleness_ratio > 2.0:
            status = "[red bold]CRITICAL[/red bold]"
        elif c.is_stale:
            status = "[yellow]STALE[/yellow]"
        else:
            status = "[green]OK[/green]"

        table.add_row(c.framework, c.control_id, c.required_frequency, last_str, hours_str, status)

    console.print(table)

    stale_count = sum(1 for c in cadences if c.is_stale)
    if stale_count:
        console.print(f"\n[yellow]{stale_count} stale control(s)[/yellow]")


@cli.command("posture-history")
@click.option("--framework", "-f", required=True, help="Framework to query")
@click.option("--control", "-c", default=None, help="Specific control ID")
@click.option("--days", "-d", default=90, help="Lookback window in days")
def posture_history(framework: str, control: str | None, days: int) -> None:
    """Show posture trends over time per control."""
    from warlock.db.engine import get_session, init_db
    from warlock.assessors.posture import PostureTimeSeriesQuery

    init_db()
    tsq = PostureTimeSeriesQuery()

    with get_session() as session:
        if control:
            series_list = [tsq.query_control(session, framework, control, days)]
        else:
            series_list = tsq.query_framework(session, framework, days)

    if not series_list:
        console.print("[dim]No posture snapshots found. Run 'warlock collect' first.[/dim]")
        return

    table = Table(title=f"Posture Trends ({days}d)")
    table.add_column("Control")
    table.add_column("Trend")
    table.add_column("Slope", justify="right")
    table.add_column("Points", justify="right")
    table.add_column("Latest Score", justify="right")
    table.add_column("Latest Status")

    for ts in series_list:
        if ts.trend == "improving":
            trend_str = "[green]\u2191 improving[/green]"
        elif ts.trend == "degrading":
            trend_str = "[red]\u2193 degrading[/red]"
        else:
            trend_str = "[dim]\u2192 stable[/dim]"

        if ts.points:
            latest = ts.points[-1]
            score_str = f"{latest.posture_score:.1f}"
            status_str = latest.status
        else:
            score_str = "\u2014"
            status_str = "no data"

        table.add_row(
            ts.control_id,
            trend_str,
            f"{ts.trend_slope:+.3f}/d",
            str(len(ts.points)),
            score_str,
            status_str,
        )

    console.print(table)


@cli.command("sufficiency")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--below", type=float, default=None, help="Show only controls below this score")
def sufficiency_check(framework: str | None, below: float | None) -> None:
    """Show evidence sufficiency scores per control."""
    from warlock.db.engine import get_session, init_db
    from warlock.assessors.posture import EvidenceSufficiencyScorer

    init_db()
    scorer = EvidenceSufficiencyScorer()

    with get_session() as session:
        if framework:
            fw_result = scorer.score_framework(session, framework)
            scores = fw_result.control_scores
        else:
            from sqlalchemy import distinct
            from warlock.db.models import ControlResult

            fw_rows = session.query(distinct(ControlResult.framework)).all()
            scores = []
            for (fw,) in fw_rows:
                fw_result = scorer.score_framework(session, fw)
                scores.extend(fw_result.control_scores)

    if below is not None:
        scores = [s for s in scores if s.score < below]

    scores.sort(key=lambda s: s.score)

    if not scores:
        console.print("[green]All controls have sufficient evidence.[/green]")
        return

    table = Table(title="Evidence Sufficiency")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Score", justify="right")
    table.add_column("Volume", justify="right")
    table.add_column("Freshness", justify="right")
    table.add_column("Diversity", justify="right")
    table.add_column("Assertion", justify="right")
    table.add_column("Gaps")

    for s in scores:
        score_style = "red" if s.score < 40 else ("yellow" if s.score < 60 else "green")
        gaps_str = "; ".join(s.gaps[:2]) if s.gaps else "\u2014"
        if len(s.gaps) > 2:
            gaps_str += f" (+{len(s.gaps) - 2})"

        table.add_row(
            s.framework,
            s.control_id,
            f"[{score_style}]{s.score:.0f}[/{score_style}]",
            f"{s.evidence_volume:.0f}",
            f"{s.evidence_freshness:.0f}",
            f"{s.evidence_diversity:.0f}",
            f"{s.assertion_coverage:.0f}",
            gaps_str,
        )

    console.print(table)


@cli.command("drift")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--days", "-d", default=30, help="Lookback window in days")
@click.option("--direction", default=None, help="Filter: improved or degraded")
def drift_list(framework: str | None, days: int, direction: str | None) -> None:
    """Show compliance drift events with correlated changes."""
    from warlock.db.engine import get_session, init_db
    from warlock.assessors.drift import DriftDetector

    init_db()
    detector = DriftDetector()

    with get_session() as session:
        drifts = detector.get_drifts(session, framework=framework, days=days, direction=direction)

    if not drifts:
        console.print("[green]No compliance drift detected.[/green]")
        return

    table = Table(title=f"Compliance Drift ({days}d)")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Direction")
    table.add_column("From")
    table.add_column("To")
    table.add_column("Correlated Changes", justify="right")
    table.add_column("Detected")

    for d in drifts:
        dir_style = "red" if d.drift_direction == "degraded" else "green"
        changes = len(d.correlated_change_event_ids or [])
        table.add_row(
            d.framework,
            d.control_id,
            f"[{dir_style}]{d.drift_direction}[/{dir_style}]",
            d.previous_status,
            d.new_status,
            str(changes),
            d.detected_at.strftime("%Y-%m-%d %H:%M") if d.detected_at else "\u2014",
        )

    console.print(table)


@cli.command("effectiveness")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--days", "-d", default=365, help="Trailing window in days")
def effectiveness_report(framework: str | None, days: int) -> None:
    """Show control effectiveness scores over time."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import PostureSnapshot

    init_db()

    with get_session() as session:
        from datetime import timedelta
        from datetime import datetime, timezone

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        q = session.query(PostureSnapshot).filter(
            PostureSnapshot.snapshot_date >= cutoff,
            PostureSnapshot.uptime_pct.isnot(None),
        )
        if framework:
            q = q.filter(PostureSnapshot.framework == framework)

        # Get latest snapshot per control
        latest = q.order_by(PostureSnapshot.snapshot_date.desc()).all()
        seen = set()
        rows = []
        for s in latest:
            key = (s.framework, s.control_id)
            if key not in seen:
                seen.add(key)
                rows.append(s)

    if not rows:
        console.print("[dim]No effectiveness data. Run posture snapshots first.[/dim]")
        return

    rows.sort(key=lambda s: s.uptime_pct or 0)

    table = Table(title=f"Control Effectiveness ({days}d)")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Uptime %", justify="right")
    table.add_column("MTTR (hrs)", justify="right")
    table.add_column("Drift Count", justify="right")

    for s in rows:
        uptime = f"{s.uptime_pct:.1f}" if s.uptime_pct is not None else "\u2014"
        mttr = f"{s.mttr_hours:.1f}" if s.mttr_hours is not None else "\u2014"
        drift = str(s.drift_count) if s.drift_count is not None else "\u2014"
        style = (
            "red"
            if (s.uptime_pct or 0) < 80
            else ("yellow" if (s.uptime_pct or 0) < 95 else "green")
        )
        table.add_row(s.framework, s.control_id, f"[{style}]{uptime}[/{style}]", mttr, drift)

    console.print(table)


@cli.command("simulate-audit")
@click.option("--framework", "-f", required=True, help="Framework to simulate")
@click.option("--date", default=None, help="Target audit date (YYYY-MM-DD, default: +90 days)")
@click.option("--system", default=None, help="System profile ID")
@click.option(
    "--ai/--no-ai", "use_ai", default=None, help="Override AI toggle for auditor simulation"
)
def simulate_audit(framework: str, date: str, system: str | None, use_ai: bool | None) -> None:
    """Simulate what an auditor would see at a future date."""
    from datetime import datetime as dt, timedelta
    from warlock.db.engine import get_session, init_db
    from warlock.assessors.simulation import AuditSimulator

    if date is None:
        date = (dt.now().date() + timedelta(days=90)).isoformat()
        console.print(f"[dim]No --date specified, using +90 days: {date}[/dim]")

    init_db()
    try:
        target = dt.fromisoformat(date).replace(tzinfo=__import__("datetime").timezone.utc)
    except ValueError:
        raise click.BadParameter("Invalid date format. Use YYYY-MM-DD.")
    sim = AuditSimulator()

    with get_session() as session:
        result = sim.simulate(session, framework, target, system_id=system)

    console.print(f"\n[bold]Audit Simulation: {framework} @ {date}[/bold]")
    console.print(
        f"  Projected coverage: [{'green' if result.projected_coverage >= 80 else 'red'}]{result.projected_coverage:.1f}%[/]"
    )
    console.print(f"  Total controls:     {result.total_controls}")
    console.print(f"  Stale by date:      [yellow]{len(result.stale_controls)}[/yellow]")
    console.print(f"  Overdue POA&Ms:     [yellow]{len(result.overdue_poams)}[/yellow]")
    console.print(f"  Expiring acceptances: [yellow]{len(result.expiring_acceptances)}[/yellow]")
    console.print(f"  At-risk controls:   [red]{len(result.at_risk_controls)}[/red]")

    # AI auditor readiness assessment
    if _check_ai_available(use_ai):
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import AITask

        svc = get_ai_service()
        if svc.is_task_enabled(AITask.AUDIT_READINESS):
            ai_context = {
                "framework": framework,
                "target_date": date,
                "projected_coverage": result.projected_coverage,
                "total_controls": result.total_controls,
                "stale_controls_count": len(result.stale_controls),
                "overdue_poams_count": len(result.overdue_poams),
                "expiring_acceptances_count": len(result.expiring_acceptances),
                "at_risk_controls_count": len(result.at_risk_controls),
            }
            try:
                ai_result = svc.reason(AITask.AUDIT_READINESS, context=ai_context)
                if ai_result.ai_used:
                    console.print("\n[bold]AI Audit Readiness Assessment:[/bold]")
                    value = ai_result.value
                    if isinstance(value, dict):
                        assessment = value.get("assessment") or value.get("narrative") or ""
                        readiness_score = value.get("readiness_score")
                        actions = value.get("actions", [])
                        if readiness_score is not None:
                            score_style = (
                                "green"
                                if readiness_score >= 0.8
                                else "yellow"
                                if readiness_score >= 0.5
                                else "red"
                            )
                            console.print(
                                f"  Readiness score: [{score_style}]{readiness_score:.0%}[/]"
                            )
                        if assessment:
                            console.print(f"\n{assessment}")
                        if actions:
                            console.print("\n[bold]Recommended actions:[/bold]")
                            for action in actions:
                                console.print(f"  [dim]\u2022 {action}[/dim]")
                    else:
                        console.print(str(value) if value else "")
            except Exception as exc:
                console.print(f"\n[dim]AI assessment unavailable: {exc.__class__.__name__}[/dim]")
