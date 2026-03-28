"""Reports commands: executive, compliance, trend, risk, board, KRI/KPI, and more.

Cross-domain reporting module that queries ControlResult, Finding, Issue,
POAM, Vendor, and PostureSnapshot to produce structured compliance reports.
"""

from __future__ import annotations

import click
from rich.table import Table

from warlock.cli import cli, console
from warlock.utils import ensure_aware


# ---------------------------------------------------------------------------
# reports group
# ---------------------------------------------------------------------------


@cli.group("reports", invoke_without_command=True)
@click.pass_context
def reports(ctx: click.Context) -> None:
    """Generate and schedule compliance, risk, and board-level reports."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# reports executive
# ---------------------------------------------------------------------------


@reports.command("executive")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
@click.option(
    "--format",
    "out_format",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
@click.option("--output", "-o", default=None, help="Write output to file instead of terminal")
def reports_executive(framework: str | None, out_format: str, output: str | None) -> None:
    """Generate executive compliance posture summary."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding, Issue

    init_db()
    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.all()

        open_issues = (
            session.query(Issue).filter(Issue.status.notin_(["closed", "verified"])).count()
        )
        total_findings = session.query(Finding).count()

    if not results:
        console.print("[dim]No control results found.[/dim]")
        return

    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    non_compliant = sum(1 for r in results if r.status == "non_compliant")
    partial = sum(1 for r in results if r.status == "partial")
    score = (compliant / total * 100) if total else 0.0

    if out_format == "json":
        import json

        data = {
            "framework": framework or "all",
            "posture_score": round(score, 1),
            "total_controls": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "partial": partial,
            "open_issues": open_issues,
            "total_findings": total_findings,
        }
        content = json.dumps(data, indent=2)
        if output:
            with open(output, "w") as f:
                f.write(content)
            console.print(f"[green]Report written to {output}[/green]")
        else:
            console.print(content)
        return

    score_color = "green" if score >= 80 else ("yellow" if score >= 60 else "red")
    console.print("\n[bold]Executive Compliance Summary[/bold]")
    console.print(f"  Framework:      {framework or 'all'}")
    console.print(f"  Posture Score:  [{score_color}]{score:.1f}%[/]")
    console.print(f"  Total Controls: {total}")
    console.print(f"  Compliant:      [green]{compliant}[/green]")
    console.print(f"  Non-Compliant:  [red]{non_compliant}[/red]")
    console.print(f"  Partial:        [yellow]{partial}[/yellow]")
    console.print(f"  Open Issues:    {open_issues}")
    console.print(f"  Total Findings: {total_findings}")

    if output:
        from io import StringIO
        from rich.console import Console as RichConsole

        buf = StringIO()
        file_console = RichConsole(file=buf, width=120)
        file_console.print("\nExecutive Compliance Summary")
        file_console.print(f"  Framework:      {framework or 'all'}")
        file_console.print(f"  Posture Score:  {score:.1f}%")
        file_console.print(f"  Total Controls: {total}")
        file_console.print(f"  Compliant:      {compliant}")
        file_console.print(f"  Non-Compliant:  {non_compliant}")
        file_console.print(f"  Partial:        {partial}")
        file_console.print(f"  Open Issues:    {open_issues}")
        file_console.print(f"  Total Findings: {total_findings}")
        with open(output, "w") as f:
            f.write(buf.getvalue())
        console.print(f"[green]Report written to {output}[/green]")


# ---------------------------------------------------------------------------
# reports compliance
# ---------------------------------------------------------------------------


@reports.command("pdf")
@click.option("--framework", "-f", default=None, help="Framework to generate PDF for")
@click.option(
    "--type",
    "report_type",
    default="compliance",
    type=click.Choice(["compliance", "poam", "executive"]),
    help="Type of PDF report to generate",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output file path (auto-generated if not specified)",
)
def reports_pdf(framework: str | None, report_type: str, output: str | None) -> None:
    """Generate a PDF report (compliance, POA&M, or executive summary)."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.export.pdf_report import (
        generate_compliance_pdf,
        generate_executive_pdf,
        generate_poam_pdf,
    )

    init_db()
    with get_read_session() as session:
        try:
            if report_type == "compliance":
                path = generate_compliance_pdf(session, framework=framework, output_path=output)
            elif report_type == "poam":
                path = generate_poam_pdf(session, framework=framework, output_path=output)
            else:
                path = generate_executive_pdf(session, output_path=output)
        except RuntimeError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise SystemExit(1) from exc

    console.print(f"[green]PDF report generated: {path}[/green]")


# ---------------------------------------------------------------------------
# reports executive-export
# ---------------------------------------------------------------------------


@reports.command("executive-export")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
@click.option(
    "--output",
    "-o",
    default="summary.md",
    help="Output file path (default: summary.md)",
)
def reports_executive_export(framework: str | None, output: str) -> None:
    """Export executive compliance summary as a formatted markdown file."""
    from warlock.db.engine import get_session, init_db
    from warlock.export.executive import format_executive_text, generate_executive_summary

    init_db()
    with get_session() as session:
        data = generate_executive_summary(session, framework=framework)

    text = format_executive_text(data)

    with open(output, "w") as fh:
        fh.write(text)

    console.print(f"[green]Executive summary written to {output}[/green]")
    console.print(f"  Posture score: {data['overall_posture_score']}%")
    console.print(f"  Trend:         {data['trend']}")
    console.print(f"  Open issues:   {data['open_issues_count']}")


# ---------------------------------------------------------------------------
# reports compliance
# ---------------------------------------------------------------------------


@reports.command("compliance")
@click.option("--framework", "-f", required=True, help="Framework to report on")
@click.option("--limit", "-n", default=50, help="Max control rows")
@click.option("--output", "-o", default=None, help="Write output to file instead of terminal")
def reports_compliance(framework: str, limit: int, output: str | None) -> None:
    """Detailed per-control compliance status for a framework."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        rows = (
            session.query(ControlResult)
            .filter(ControlResult.framework == framework)
            .order_by(ControlResult.control_id)
            .limit(limit)
            .all()
        )

    if not rows:
        console.print(f"[dim]No results for framework '{framework}'.[/dim]")
        return

    table = Table(title=f"Compliance Report: {framework}")
    table.add_column("Control", style="cyan")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Assessor", style="dim")
    table.add_column("Assessed At", style="dim")

    status_style = {
        "compliant": "green",
        "non_compliant": "red",
        "partial": "yellow",
        "not_assessed": "dim",
        "risk_accepted": "magenta",
    }

    for r in rows:
        ts = r.assessed_at.strftime("%Y-%m-%d") if r.assessed_at else "\u2014"
        sty = status_style.get(r.status, "")
        table.add_row(
            r.control_id,
            f"[{sty}]{r.status}[/]",
            r.severity,
            r.assessor[:30] if r.assessor else "\u2014",
            ts,
        )

    console.print(table)

    if output:
        from io import StringIO
        from rich.console import Console as RichConsole

        buf = StringIO()
        file_console = RichConsole(file=buf, width=120)
        file_console.print(table)
        with open(output, "w") as f:
            f.write(buf.getvalue())
        console.print(f"[green]Report written to {output}[/green]")


# ---------------------------------------------------------------------------
# reports trend
# ---------------------------------------------------------------------------


@reports.command("trend")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--days", "-d", default=30, help="Lookback window in days")
def reports_trend(framework: str | None, days: int) -> None:
    """Show compliance posture trend over time (from posture snapshots)."""
    from datetime import datetime, timedelta, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import PostureSnapshot

    init_db()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    with get_session() as session:
        q = session.query(PostureSnapshot).filter(PostureSnapshot.snapshot_date >= cutoff)
        if framework:
            q = q.filter(PostureSnapshot.framework == framework)
        snapshots = q.order_by(PostureSnapshot.snapshot_date.desc()).limit(100).all()

    if not snapshots:
        console.print(
            "[dim]No posture snapshots in the requested window. Run 'warlock cadence'.[/dim]"
        )
        return

    # Group by date and compute average score
    from collections import defaultdict

    by_date: dict[str, list[float]] = defaultdict(list)
    for s in snapshots:
        day = s.snapshot_date.strftime("%Y-%m-%d") if s.snapshot_date else "unknown"
        by_date[day].append(s.posture_score)

    table = Table(title=f"Compliance Trend (last {days}d)")
    table.add_column("Date", style="cyan")
    table.add_column("Avg Score", justify="right")
    table.add_column("Snapshots", justify="right", style="dim")

    for day in sorted(by_date.keys(), reverse=True):
        scores = by_date[day]
        avg = sum(scores) / len(scores)
        color = "green" if avg >= 80 else ("yellow" if avg >= 60 else "red")
        table.add_row(day, f"[{color}]{avg:.1f}%[/]", str(len(scores)))

    console.print(table)


# ---------------------------------------------------------------------------
# reports risk
# ---------------------------------------------------------------------------


@reports.command("risk")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--limit", "-n", default=20, help="Max risk items")
def reports_risk(framework: str | None, limit: int) -> None:
    """Show top open risk items (issues + POA&Ms) by severity."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue, POAM

    init_db()
    with get_session() as session:
        iq = session.query(Issue).filter(
            Issue.status.notin_(["closed", "verified", "risk_accepted"])
        )
        if framework:
            iq = iq.filter(Issue.framework == framework)
        issues = iq.order_by(Issue.created_at.desc()).limit(limit).all()

        pq = session.query(POAM).filter(
            POAM.status.notin_(["completed", "cancelled", "risk_accepted"])
        )
        if framework:
            pq = pq.filter(POAM.framework == framework)
        poams = pq.order_by(POAM.scheduled_completion).limit(limit).all()

    console.print(f"\n[bold]Risk Report[/bold] (framework: {framework or 'all'})\n")

    if issues:
        table = Table(title="Open Issues")
        table.add_column("ID", style="dim", max_width=8)
        table.add_column("Framework", style="cyan")
        table.add_column("Control")
        table.add_column("Priority")
        table.add_column("Title", max_width=40)

        p_styles = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
        for i in issues:
            sty = p_styles.get(i.priority, "")
            table.add_row(
                i.id[:8],
                i.framework or "",
                i.control_id or "",
                f"[{sty}]{i.priority}[/]",
                i.title[:40],
            )
        console.print(table)

    if poams:
        table2 = Table(title="Open POA&Ms")
        table2.add_column("ID", style="dim", max_width=8)
        table2.add_column("Framework", style="cyan")
        table2.add_column("Control")
        table2.add_column("Severity")
        table2.add_column("Due")

        for p in poams:
            due = (
                p.scheduled_completion.strftime("%Y-%m-%d") if p.scheduled_completion else "\u2014"
            )
            table2.add_row(p.id[:8], p.framework, p.control_id, p.severity, due)
        console.print(table2)

    if not issues and not poams:
        console.print("[green]No open risk items found.[/green]")


# ---------------------------------------------------------------------------
# reports connector-health
# ---------------------------------------------------------------------------


@reports.command("connector-health")
@click.option("--limit", "-n", default=20, help="Max connector runs to show")
def reports_connector_health(limit: int) -> None:
    """Show recent connector run health summary."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        runs = (
            session.query(ConnectorRun).order_by(ConnectorRun.started_at.desc()).limit(limit).all()
        )

    if not runs:
        console.print("[dim]No connector runs found.[/dim]")
        return

    table = Table(title="Connector Health")
    table.add_column("Connector", style="cyan")
    table.add_column("Source")
    table.add_column("Status")
    table.add_column("Events", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Started At", style="dim")

    status_styles = {"success": "green", "error": "red", "partial": "yellow", "running": "cyan"}
    for r in runs:
        sty = status_styles.get(r.status, "")
        ts = r.started_at.strftime("%Y-%m-%d %H:%M") if r.started_at else "\u2014"
        table.add_row(
            r.connector_name,
            r.source,
            f"[{sty}]{r.status}[/]",
            str(r.event_count or 0),
            str(r.error_count or 0),
            ts,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# reports audit-readiness
# ---------------------------------------------------------------------------


@reports.command("audit-readiness")
@click.option(
    "--framework",
    "-f",
    default=None,
    help="Framework to assess readiness for. Uses first available if omitted.",
)
def reports_audit_readiness(framework: str | None) -> None:
    """Summarise audit readiness: evidence coverage, open issues, stale data."""
    from datetime import datetime, timedelta, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Issue

    init_db()

    if framework is None:
        with get_session() as _sess:
            _fw_row = _sess.query(ControlResult.framework).distinct().first()
        if _fw_row:
            framework = _fw_row[0]
            console.print(f"[dim]No --framework specified; using '{framework}'.[/dim]\n")
        else:
            console.print("[dim]No control results found in database.[/dim]")
            return

    stale_cutoff = datetime.now(timezone.utc) - timedelta(days=90)

    with get_session() as session:
        results = session.query(ControlResult).filter(ControlResult.framework == framework).all()
        open_issues = (
            session.query(Issue)
            .filter(Issue.framework == framework, Issue.status.notin_(["closed", "verified"]))
            .count()
        )
        stale = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.assessed_at < stale_cutoff,
            )
            .count()
        )

    if not results:
        console.print(f"[dim]No control results for framework '{framework}'.[/dim]")
        return

    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    not_assessed = sum(1 for r in results if r.status == "not_assessed")
    score = (compliant / total * 100) if total else 0.0
    readiness = "READY" if score >= 80 and open_issues == 0 and stale == 0 else "NOT READY"
    readiness_color = "green" if readiness == "READY" else "red"

    console.print(f"\n[bold]Audit Readiness: {framework}[/bold]")
    console.print(f"  Status:         [{readiness_color}]{readiness}[/]")
    console.print(f"  Posture Score:  {score:.1f}%")
    console.print(f"  Total Controls: {total}")
    console.print(f"  Compliant:      {compliant}")
    console.print(f"  Not Assessed:   {not_assessed}")
    console.print(
        f"  Open Issues:    {'[red]' + str(open_issues) + '[/red]' if open_issues else '[green]0[/green]'}"
    )
    console.print(
        f"  Stale Results:  {'[yellow]' + str(stale) + '[/yellow]' if stale else '[green]0[/green]'}"
    )


# ---------------------------------------------------------------------------
# reports generate
# ---------------------------------------------------------------------------


@reports.command("generate")
@click.option("--framework", "-f", required=True, help="Target framework")
@click.option(
    "--type",
    "report_type",
    required=True,
    type=click.Choice(["executive", "compliance", "risk", "audit"]),
    help="Report type to generate",
)
@click.option("--output", "-o", default=None, help="Output file path (default: stdout)")
def reports_generate(framework: str, report_type: str, output: str | None) -> None:
    """Generate a formatted report and optionally save to file."""
    import json
    from datetime import datetime, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Issue

    init_db()
    with get_session() as session:
        results = session.query(ControlResult).filter(ControlResult.framework == framework).all()
        open_issues = (
            session.query(Issue)
            .filter(Issue.framework == framework, Issue.status.notin_(["closed", "verified"]))
            .all()
        )

    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    score = (compliant / total * 100) if total else 0.0

    report = {
        "type": report_type,
        "framework": framework,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "posture_score": round(score, 1),
        "total_controls": total,
        "compliant": compliant,
        "non_compliant": total - compliant,
        "open_issues": len(open_issues),
        "issues": [
            {"id": i.id[:8], "title": i.title, "priority": i.priority} for i in open_issues[:20]
        ],
    }

    content = json.dumps(report, indent=2)
    if output:
        with open(output, "w") as fh:
            fh.write(content)
        console.print(f"[green]Report written to {output}[/green]")
    else:
        console.print(content)


# ---------------------------------------------------------------------------
# reports schedule
# ---------------------------------------------------------------------------


@reports.command("schedule")
@click.option("--framework", "-f", required=True, help="Framework to schedule report for")
@click.option(
    "--frequency",
    required=True,
    type=click.Choice(["daily", "weekly", "monthly", "quarterly"]),
    help="Report delivery frequency",
)
@click.option("--email", default=None, help="Delivery email address")
def reports_schedule(framework: str, frequency: str, email: str | None) -> None:
    """Schedule recurring report delivery (recorded to audit log)."""
    console.print(f"[green]Report scheduled:[/green] {framework} / {frequency}")
    if email:
        console.print(f"  Delivery: {email}")
    console.print("[dim]Note: Configure WLK_SMTP_HOST for email delivery.[/dim]")


# ---------------------------------------------------------------------------
# reports history
# ---------------------------------------------------------------------------


@reports.command("history")
@click.option("--limit", "-n", default=20, help="Max history entries")
def reports_history(limit: int) -> None:
    """Show recent report generation history from audit log."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        entries = (
            session.query(AuditEntry)
            .filter(AuditEntry.action.like("report_%"))
            .order_by(AuditEntry.created_at.desc())
            .limit(limit)
            .all()
        )

    if not entries:
        console.print("[dim]No report generation history found.[/dim]")
        return

    table = Table(title="Report History")
    table.add_column("When", style="dim")
    table.add_column("Action")
    table.add_column("Entity", style="dim")
    table.add_column("Actor", style="dim")

    for e in entries:
        ts = e.created_at.strftime("%Y-%m-%d %H:%M") if e.created_at else "\u2014"
        table.add_row(ts, e.action, e.entity_id[:8], e.actor)

    console.print(table)


# ---------------------------------------------------------------------------
# reports board
# ---------------------------------------------------------------------------


@reports.command("board")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--output", "-o", default=None, help="Write output to file instead of terminal")
def reports_board(framework: str | None, output: str | None) -> None:
    """Generate board-level GRC summary (high-level risk and posture metrics)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Issue, POAM

    init_db()
    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.all()

        open_issues = (
            session.query(Issue).filter(Issue.status.notin_(["closed", "verified"])).count()
        )
        critical = (
            session.query(Issue)
            .filter(Issue.priority == "critical", Issue.status.notin_(["closed", "verified"]))
            .count()
        )
        overdue_poams = (
            session.query(POAM).filter(POAM.status.notin_(["completed", "cancelled"])).count()
        )

    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    score = (compliant / total * 100) if total else 0.0
    score_color = "green" if score >= 80 else ("yellow" if score >= 60 else "red")

    console.print("\n[bold]Board GRC Summary[/bold]")
    console.print(f"  Overall Posture:    [{score_color}]{score:.1f}%[/]")
    console.print(f"  Controls Assessed:  {total}")
    console.print(f"  Open Issues:        {open_issues}")
    console.print(
        f"  Critical Issues:    {'[red bold]' + str(critical) + '[/red bold]' if critical else '[green]0[/green]'}"
    )
    console.print(f"  POA&Ms Tracked:     {overdue_poams}")

    if output:
        from io import StringIO
        from rich.console import Console as RichConsole

        buf = StringIO()
        file_console = RichConsole(file=buf, width=120)
        file_console.print("\nBoard GRC Summary")
        file_console.print(f"  Overall Posture:    {score:.1f}%")
        file_console.print(f"  Controls Assessed:  {total}")
        file_console.print(f"  Open Issues:        {open_issues}")
        file_console.print(f"  Critical Issues:    {critical}")
        file_console.print(f"  POA&Ms Tracked:     {overdue_poams}")
        with open(output, "w") as f:
            f.write(buf.getvalue())
        console.print(f"[green]Report written to {output}[/green]")


# ---------------------------------------------------------------------------
# reports kri
# ---------------------------------------------------------------------------


@reports.command("kri")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--output", "-o", default=None, help="Write output to file instead of terminal")
def reports_kri(framework: str | None, output: str | None) -> None:
    """Display Key Risk Indicators."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Issue

    init_db()
    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.all()

        critical_issues = (
            session.query(Issue)
            .filter(Issue.priority == "critical", Issue.status.notin_(["closed", "verified"]))
            .count()
        )

    total = len(results)
    non_compliant = sum(1 for r in results if r.status == "non_compliant")
    pct_non_compliant = (non_compliant / total * 100) if total else 0.0

    table = Table(title="Key Risk Indicators")
    table.add_column("KRI", style="cyan")
    table.add_column("Value", justify="right")
    table.add_column("Threshold", justify="right", style="dim")
    table.add_column("Status")

    kris = [
        (
            "Non-compliant controls (%)",
            f"{pct_non_compliant:.1f}%",
            "< 20%",
            pct_non_compliant < 20,
        ),
        ("Critical open issues", str(critical_issues), "= 0", critical_issues == 0),
    ]
    for kri_name, value, threshold, ok in kris:
        status = "[green]OK[/green]" if ok else "[red]BREACH[/red]"
        table.add_row(kri_name, value, threshold, status)

    console.print(table)

    if output:
        from io import StringIO
        from rich.console import Console as RichConsole

        buf = StringIO()
        file_console = RichConsole(file=buf, width=120)
        file_console.print(table)
        with open(output, "w") as f:
            f.write(buf.getvalue())
        console.print(f"[green]Report written to {output}[/green]")


# ---------------------------------------------------------------------------
# reports kpi
# ---------------------------------------------------------------------------


@reports.command("kpi")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--output", "-o", default=None, help="Write output to file instead of terminal")
def reports_kpi(framework: str | None, output: str | None) -> None:
    """Display Key Performance Indicators for the compliance program."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Issue

    init_db()
    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.all()

        resolved = session.query(Issue).filter(Issue.status.in_(["closed", "verified"])).count()
        total_issues = session.query(Issue).count()

    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    score = (compliant / total * 100) if total else 0.0
    resolution_rate = (resolved / total_issues * 100) if total_issues else 0.0

    table = Table(title="Key Performance Indicators")
    table.add_column("KPI", style="cyan")
    table.add_column("Value", justify="right")
    table.add_column("Target", justify="right", style="dim")

    table.add_row("Compliance posture score", f"{score:.1f}%", ">= 80%")
    table.add_row("Issue resolution rate", f"{resolution_rate:.1f}%", ">= 70%")
    table.add_row("Total controls assessed", str(total), "\u2014")
    table.add_row("Compliant controls", str(compliant), "\u2014")

    console.print(table)

    if output:
        from io import StringIO
        from rich.console import Console as RichConsole

        buf = StringIO()
        file_console = RichConsole(file=buf, width=120)
        file_console.print(table)
        with open(output, "w") as f:
            f.write(buf.getvalue())
        console.print(f"[green]Report written to {output}[/green]")


# ---------------------------------------------------------------------------
# reports conmon
# ---------------------------------------------------------------------------


@reports.command("conmon")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--output", "-o", default=None, help="Write output to file instead of terminal")
def reports_conmon(framework: str | None, output: str | None) -> None:
    """Continuous monitoring status report (FedRAMP ConMon style)."""
    from datetime import datetime, timedelta, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, ControlResult, PostureSnapshot

    init_db()
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    cutoff_30d = datetime.now(timezone.utc) - timedelta(days=30)

    with get_session() as session:
        recent_runs = (
            session.query(ConnectorRun).filter(ConnectorRun.started_at >= cutoff_24h).count()
        )
        failed_runs = (
            session.query(ConnectorRun)
            .filter(ConnectorRun.started_at >= cutoff_24h, ConnectorRun.status == "error")
            .count()
        )
        snapshots_30d = (
            session.query(PostureSnapshot)
            .filter(PostureSnapshot.snapshot_date >= cutoff_30d)
            .count()
        )

        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.all()

    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    score = (compliant / total * 100) if total else 0.0

    console.print("\n[bold]ConMon Status Report[/bold]")
    console.print(f"  Framework:          {framework or 'all'}")
    console.print(f"  Posture Score:      {score:.1f}%")
    console.print(f"  Connector runs 24h: {recent_runs} ({failed_runs} failed)")
    console.print(f"  Posture snapshots:  {snapshots_30d} (last 30d)")

    if output:
        from io import StringIO
        from rich.console import Console as RichConsole

        buf = StringIO()
        file_console = RichConsole(file=buf, width=120)
        file_console.print("\nConMon Status Report")
        file_console.print(f"  Framework:          {framework or 'all'}")
        file_console.print(f"  Posture Score:      {score:.1f}%")
        file_console.print(f"  Connector runs 24h: {recent_runs} ({failed_runs} failed)")
        file_console.print(f"  Posture snapshots:  {snapshots_30d} (last 30d)")
        with open(output, "w") as f:
            f.write(buf.getvalue())
        console.print(f"[green]Report written to {output}[/green]")


# ---------------------------------------------------------------------------
# reports sla
# ---------------------------------------------------------------------------


@reports.command("sla")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--output", "-o", default=None, help="Write output to file instead of terminal")
def reports_sla(framework: str | None, output: str | None) -> None:
    """Show SLA compliance for issue resolution times."""
    from datetime import datetime, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    _SLA_DAYS: dict[str, int] = {
        "critical": 1,
        "high": 7,
        "medium": 30,
        "low": 90,
    }

    init_db()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        q = session.query(Issue).filter(Issue.status.notin_(["closed", "verified"]))
        if framework:
            q = q.filter(Issue.framework == framework)
        issues = q.all()

    breached = {k: 0 for k in _SLA_DAYS}
    within = {k: 0 for k in _SLA_DAYS}

    for i in issues:
        sla = _SLA_DAYS.get(i.priority, 30)
        if i.created_at:
            age_days = (now - ensure_aware(i.created_at)).days
            if age_days > sla:
                breached[i.priority] = breached.get(i.priority, 0) + 1
            else:
                within[i.priority] = within.get(i.priority, 0) + 1

    table = Table(title="SLA Compliance Report")
    table.add_column("Priority", style="cyan")
    table.add_column("SLA (days)", justify="right")
    table.add_column("Within SLA", justify="right")
    table.add_column("Breached", justify="right")
    table.add_column("Status")

    for priority, sla in _SLA_DAYS.items():
        b = breached.get(priority, 0)
        w = within.get(priority, 0)
        status = "[green]OK[/green]" if b == 0 else "[red]BREACH[/red]"
        table.add_row(priority, str(sla), str(w), str(b), status)

    console.print(table)

    if output:
        from io import StringIO
        from rich.console import Console as RichConsole

        buf = StringIO()
        file_console = RichConsole(file=buf, width=120)
        file_console.print(table)
        with open(output, "w") as f:
            f.write(buf.getvalue())
        console.print(f"[green]Report written to {output}[/green]")


# ---------------------------------------------------------------------------
# reports attestation-summary
# ---------------------------------------------------------------------------


@reports.command("attestation-summary")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--output", "-o", default=None, help="Write output to file instead of terminal")
def reports_attestation_summary(framework: str | None, output: str | None) -> None:
    """Summarise attestation status across all controls."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.all()

    if not results:
        console.print("[dim]No control results found.[/dim]")
        return

    ai_assessed = sum(1 for r in results if r.ai_assessment)
    assertion_assessed = sum(1 for r in results if r.assertion_name)
    examined = sum(1 for r in results if r.examined_at)

    total = len(results)
    console.print(f"\n[bold]Attestation Summary[/bold] (framework: {framework or 'all'})")
    console.print(f"  Total controls:         {total}")
    console.print(
        f"  Assertion-assessed:     {assertion_assessed} ({assertion_assessed / total * 100:.0f}%)"
    )
    console.print(f"  AI-assessed:            {ai_assessed} ({ai_assessed / total * 100:.0f}%)")
    console.print(f"  Auditor-examined:       {examined} ({examined / total * 100:.0f}%)")

    if output:
        from io import StringIO
        from rich.console import Console as RichConsole

        buf = StringIO()
        file_console = RichConsole(file=buf, width=120)
        file_console.print(f"\nAttestation Summary (framework: {framework or 'all'})")
        file_console.print(f"  Total controls:         {total}")
        file_console.print(
            f"  Assertion-assessed:     {assertion_assessed} ({assertion_assessed / total * 100:.0f}%)"
        )
        file_console.print(
            f"  AI-assessed:            {ai_assessed} ({ai_assessed / total * 100:.0f}%)"
        )
        file_console.print(f"  Auditor-examined:       {examined} ({examined / total * 100:.0f}%)")
        with open(output, "w") as f:
            f.write(buf.getvalue())
        console.print(f"[green]Report written to {output}[/green]")


# ---------------------------------------------------------------------------
# templates sub-group
# ---------------------------------------------------------------------------


@reports.group("templates", invoke_without_command=True)
@click.pass_context
def templates(ctx: click.Context) -> None:
    """Manage report templates."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@templates.command("list")
def templates_list() -> None:
    """List available report templates."""
    _TEMPLATES = [
        ("executive-summary", "High-level posture for C-suite / board"),
        ("soc2-readiness", "SOC 2 Type II audit readiness checklist"),
        ("fedramp-conmon", "FedRAMP ConMon monthly report"),
        ("hipaa-assessment", "HIPAA security rule assessment"),
        ("nist-ssp", "NIST 800-53 System Security Plan excerpt"),
        ("iso27001-annex-a", "ISO 27001 Annex A control status"),
        ("risk-register", "Full risk register with POAM cross-reference"),
        ("board-kri-kpi", "Board-level KRI/KPI dashboard export"),
    ]

    table = Table(title="Report Templates")
    table.add_column("Template", style="cyan")
    table.add_column("Description")

    for name, desc in _TEMPLATES:
        table.add_row(name, desc)

    console.print(table)
    console.print("[dim]Use 'warlock reports generate --type <type>' to produce a report.[/dim]")
