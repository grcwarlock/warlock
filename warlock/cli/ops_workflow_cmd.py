"""Daily operations workflow commands (top-level).

Top-level commands (not inside a group):
  warlock morning         -- Morning operations review
  warlock weekly          -- Weekly operations summary
  warlock monthly-review  -- Monthly GRC review
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import click
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from warlock.cli import _get_actor, cli, console
from warlock.utils import ensure_aware

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _severity_color(sev: str) -> str:
    return {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }.get(sev, "white")


def _rag_label(value: float, warn: float = 70.0, good: float = 85.0) -> str:
    """Return RAG Rich markup for a percentage value."""
    if value >= good:
        return f"[green]{value:.1f}%[/green]"
    if value >= warn:
        return f"[yellow]{value:.1f}%[/yellow]"
    return f"[red]{value:.1f}%[/red]"


# ---------------------------------------------------------------------------
# warlock morning
# ---------------------------------------------------------------------------


@cli.command("morning")
@click.option("--framework", "-f", default=None, help="Filter to a specific framework")
@click.option("--no-prompt", is_flag=True, help="Print summary only, do not prompt for focus area")
def morning(framework: str | None, no_prompt: bool) -> None:
    """Morning operations review: overnight summary and attention items.

    Shows new critical/high findings, failed connectors, active incidents,
    SLA breaches, overdue POA&Ms, and expiring exceptions, then routes
    to the relevant workflow.

    \b
    Examples:
        warlock morning
        warlock morning --framework soc2
        warlock morning --no-prompt
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        POAM,
        ConnectorRun,
        Finding,
        Issue,
        RiskAcceptance,
    )

    init_db()

    actor = _get_actor()
    now = _utcnow()
    overnight_cutoff = now - timedelta(hours=24)
    sla_warning_days = 7

    # Greeting
    hour = now.hour
    greeting = "Good morning" if hour < 12 else ("Good afternoon" if hour < 17 else "Good evening")
    console.print(
        Panel(
            f"[bold]{greeting}, {actor}[/bold]\n"
            f"Today is {now.strftime('%A, %Y-%m-%d')}  |  "
            f"UTC {now.strftime('%H:%M')}",
            style="cyan",
            subtitle="Warlock GRC — Daily Operations",
        )
    )

    with get_session() as session:
        # ---------------------------------------------------------------
        # Overnight summary
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]Overnight Summary (last 24h)[/bold cyan]")

        # New critical/high findings
        fq = session.query(Finding).filter(Finding.ingested_at >= overnight_cutoff)
        if framework:
            pass  # findings don't carry framework directly
        new_findings = fq.all()
        crit_high = [f for f in new_findings if f.severity in ("critical", "high")]
        sources: dict[str, int] = {}
        for f in crit_high:
            sources[f.source] = sources.get(f.source, 0) + 1

        f_color = "red bold" if len(crit_high) > 0 else "green"
        console.print(
            f"  New critical/high findings: [{f_color}]{len(crit_high)}[/{f_color}]"
            + (
                "  (" + ", ".join(f"{s}:{n}" for s, n in sorted(sources.items())) + ")"
                if sources
                else ""
            )
        )

        # Failed connector runs
        failed_connectors = (
            session.query(ConnectorRun)
            .filter(
                ConnectorRun.started_at >= overnight_cutoff,
                ConnectorRun.status.in_(["error", "partial"]),
            )
            .all()
        )
        c_color = "red" if failed_connectors else "green"
        console.print(
            f"  Failed connector runs: [{c_color}]{len(failed_connectors)}[/{c_color}]"
            + (
                "  (" + ", ".join(r.connector_name for r in failed_connectors[:5]) + ")"
                if failed_connectors
                else ""
            )
        )

        # Active incidents (open critical/high issues)
        incident_q = session.query(Issue).filter(
            Issue.status.notin_(["closed", "verified"]),
            Issue.priority.in_(["critical", "high"]),
        )
        if framework:
            incident_q = incident_q.filter(Issue.framework == framework)
        active_incidents = incident_q.count()
        i_color = "red" if active_incidents > 0 else "green"
        console.print(
            f"  Active critical/high incidents: [{i_color}]{active_incidents}[/{i_color}]"
        )

        # Items due today
        eod = now.replace(hour=23, minute=59, second=59)
        due_poams = (
            session.query(POAM)
            .filter(
                POAM.scheduled_completion <= eod,
                POAM.scheduled_completion >= now.replace(hour=0, minute=0, second=0),
                POAM.status.notin_(["completed", "verified", "closed", "cancelled"]),
            )
            .count()
        )
        if framework:
            due_poams = (
                session.query(POAM)
                .filter(
                    POAM.framework == framework,
                    POAM.scheduled_completion <= eod,
                    POAM.scheduled_completion >= now.replace(hour=0, minute=0, second=0),
                    POAM.status.notin_(["completed", "verified", "closed", "cancelled"]),
                )
                .count()
            )

        console.print(
            f"  POA&Ms due today: [{'yellow' if due_poams > 0 else 'green'}]{due_poams}[/]"
        )

        # ---------------------------------------------------------------
        # Attention needed
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]Attention Needed[/bold cyan]")

        attention_items: list[tuple[str, str, str]] = []  # (label, count_str, hint_cmd)

        # SLA breaches: issues past due_date
        sla_q = session.query(Issue).filter(
            Issue.due_date < now,
            Issue.due_date.isnot(None),
            Issue.status.notin_(["closed", "verified"]),
        )
        if framework:
            sla_q = sla_q.filter(Issue.framework == framework)
        sla_breaches = sla_q.count()
        if sla_breaches > 0:
            attention_items.append(
                (
                    "SLA breaches (findings past remediation SLA)",
                    str(sla_breaches),
                    "warlock issues --status open",
                )
            )

        # Overdue POA&Ms
        overdue_poam_q = session.query(POAM).filter(
            POAM.scheduled_completion < now,
            POAM.status.notin_(["completed", "verified", "closed", "cancelled"]),
        )
        if framework:
            overdue_poam_q = overdue_poam_q.filter(POAM.framework == framework)
        overdue_poam_count = overdue_poam_q.count()
        if overdue_poam_count > 0:
            attention_items.append(
                ("Overdue POA&Ms", str(overdue_poam_count), "warlock poams --overdue")
            )

        # Expiring risk acceptances (next 7 days)
        expiry_cutoff = now + timedelta(days=sla_warning_days)
        expiring_ra_q = session.query(RiskAcceptance).filter(
            RiskAcceptance.expiry_date <= expiry_cutoff,
            RiskAcceptance.expiry_date > now,
            RiskAcceptance.status.in_(["approved", "active"]),
        )
        if framework:
            expiring_ra_q = expiring_ra_q.filter(RiskAcceptance.framework == framework)
        expiring_ra = expiring_ra_q.count()
        if expiring_ra > 0:
            attention_items.append(
                (
                    f"Risk acceptances expiring in next {sla_warning_days} days",
                    str(expiring_ra),
                    "warlock risk-acceptances --expiring-soon 7",
                )
            )

        # Stale evidence (control results not assessed in 30+ days)
        stale_cutoff = now - timedelta(days=30)
        try:
            from warlock.db.models import ControlResult

            stale_q = session.query(ControlResult).filter(ControlResult.assessed_at < stale_cutoff)
            if framework:
                stale_q = stale_q.filter(ControlResult.framework == framework)
            stale_evidence = stale_q.count()
        except Exception:
            stale_evidence = 0
        if stale_evidence > 0:
            attention_items.append(
                (
                    "Stale evidence (>30d since last assessment)",
                    str(stale_evidence),
                    "warlock collect",
                )
            )

        if attention_items:
            attn_table = Table(show_header=False, box=None, pad_edge=False)
            attn_table.add_column("Item")
            attn_table.add_column("Count", justify="right")
            attn_table.add_column("Command", style="dim")
            for label, count, cmd in attention_items:
                attn_table.add_row(
                    f"[yellow]{label}[/yellow]",
                    f"[bold]{count}[/bold]",
                    cmd,
                )
            console.print(attn_table)
        else:
            console.print("  [green]Nothing urgent. All clear.[/green]")

        # ---------------------------------------------------------------
        # Focus prompt
        # ---------------------------------------------------------------
        if no_prompt or not attention_items:
            if not attention_items:
                console.print(
                    "\n  [dim]Tip: run 'warlock briefing' for a full cross-domain priority view.[/dim]"
                )
            return

        console.print("")
        try:
            focus = Prompt.ask(
                "Focus on",
                choices=["f", "i", "o", "c", "q"],
                default="q",
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Have a good day.[/dim]")
            return

        focus_map = {
            "f": (
                "Findings",
                "warlock findings --severity high --status open",
                "Run: warlock issues --priority high",
            ),
            "i": (
                "Incidents",
                "warlock issues --priority critical",
                "Run: warlock issues --priority critical --status open",
            ),
            "o": (
                "Overdue items",
                "warlock poams --overdue",
                "Run: warlock poams --overdue",
            ),
            "c": (
                "Connectors",
                "warlock connectors status",
                "Run: warlock connectors list --status error",
            ),
            "q": ("Quit", "", ""),
        }

        label, _, hint = focus_map.get(focus, ("Quit", "", ""))
        if focus != "q":
            console.print(f"\n  [bold]{label}[/bold]")
            if hint:
                console.print(f"  [dim]{hint}[/dim]")
        else:
            console.print("\n[dim]Have a good day.[/dim]")


# ---------------------------------------------------------------------------
# warlock weekly
# ---------------------------------------------------------------------------


@cli.command("weekly")
@click.option("--framework", "-f", default=None, help="Filter to a specific framework")
@click.option("--output", "-o", default=None, help="Save weekly report to file")
def weekly(framework: str | None, output: str | None) -> None:
    """Weekly operations summary: week-over-week metrics, connector health, deadlines.

    \b
    Examples:
        warlock weekly
        warlock weekly --framework soc2 --output weekly.md
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        POAM,
        ConnectorRun,
        ControlResult,
        Finding,
        Issue,
    )

    init_db()

    actor = _get_actor()
    now = _utcnow()
    this_week_start = now - timedelta(days=7)
    last_week_start = now - timedelta(days=14)
    two_weeks_out = now + timedelta(days=14)

    console.print(
        Panel(
            "[bold]Weekly Operations Summary[/bold]\n"
            f"Week ending: {now.strftime('%Y-%m-%d')}   "
            f"Framework: {framework or 'all'}",
            style="cyan",
        )
    )

    with get_session() as session:
        # ---------------------------------------------------------------
        # Findings: new vs closed
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]Findings (this week vs last week)[/bold cyan]")

        new_this = session.query(Finding).filter(Finding.ingested_at >= this_week_start).count()
        new_last = (
            session.query(Finding)
            .filter(
                Finding.ingested_at >= last_week_start,
                Finding.ingested_at < this_week_start,
            )
            .count()
        )

        delta_f = new_this - new_last
        delta_f_str = (
            f"[green]-{abs(delta_f)}[/green]"
            if delta_f < 0
            else (f"[red]+{delta_f}[/red]" if delta_f > 0 else "[dim]0[/dim]")
        )

        crit_this = (
            session.query(Finding)
            .filter(
                Finding.ingested_at >= this_week_start,
                Finding.severity.in_(["critical", "high"]),
            )
            .count()
        )

        console.print(
            f"  New this week: [bold]{new_this}[/bold]   "
            f"Last week: {new_last}   "
            f"Change: {delta_f_str}   "
            f"Critical/high this week: [{'red' if crit_this > 0 else 'green'}]{crit_this}[/]"
        )

        # ---------------------------------------------------------------
        # Controls: compliant % change
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]Controls Compliance[/bold cyan]")

        ctrl_q = session.query(ControlResult)
        if framework:
            ctrl_q = ctrl_q.filter(ControlResult.framework == framework)
        all_results = ctrl_q.all()

        if all_results:
            total = len(all_results)
            compliant = sum(
                1 for r in all_results if r.status in ("compliant", "inherited_compliant")
            )
            compliant_pct = compliant / total * 100
            console.print(
                f"  Compliant: {_rag_label(compliant_pct)}  "
                f"({compliant}/{total} controls)"
                + (f"  Framework: {framework}" if framework else "")
            )
        else:
            console.print("  [dim]No control results found.[/dim]")

        # ---------------------------------------------------------------
        # Issues: opened vs resolved
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]Issues (this week)[/bold cyan]")

        iq = session.query(Issue)
        if framework:
            iq = iq.filter(Issue.framework == framework)

        opened_this = iq.filter(Issue.created_at >= this_week_start).count()
        resolved_this = (
            session.query(Issue)
            .filter(
                Issue.status.in_(["closed", "verified"]),
                Issue.updated_at >= this_week_start,
            )
            .count()
        )
        open_total = (
            session.query(Issue).filter(Issue.status.notin_(["closed", "verified"])).count()
        )

        i_color = "red" if opened_this > resolved_this else "green"
        console.print(
            f"  Opened: [{i_color}]{opened_this}[/{i_color}]   "
            f"Resolved: [green]{resolved_this}[/green]   "
            f"Total open: [bold]{open_total}[/bold]"
        )

        # ---------------------------------------------------------------
        # POA&Ms: on-track vs delayed
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]POA&Ms[/bold cyan]")

        poam_q = session.query(POAM).filter(
            POAM.status.notin_(["completed", "verified", "closed", "cancelled"])
        )
        if framework:
            poam_q = poam_q.filter(POAM.framework == framework)
        open_poams = poam_q.all()

        overdue_count = sum(
            1
            for p in open_poams
            if p.scheduled_completion and ensure_aware(p.scheduled_completion) < now
        )
        on_track_count = len(open_poams) - overdue_count
        p_color = "red" if overdue_count > 0 else "green"

        console.print(
            f"  Open: [bold]{len(open_poams)}[/bold]   "
            f"On-track: [green]{on_track_count}[/green]   "
            f"Delayed/overdue: [{p_color}]{overdue_count}[/{p_color}]"
        )

        # ---------------------------------------------------------------
        # Connector health
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]Connector Health (last 7 days)[/bold cyan]")

        all_runs = (
            session.query(ConnectorRun).filter(ConnectorRun.started_at >= this_week_start).all()
        )
        total_runs = len(all_runs)
        error_runs = [r for r in all_runs if r.status in ("error", "partial")]
        success_rate = ((total_runs - len(error_runs)) / total_runs * 100) if total_runs else 0.0
        c_color = "green" if success_rate >= 95 else ("yellow" if success_rate >= 80 else "red")

        console.print(
            f"  Total runs: {total_runs}   "
            f"Errors: [{'red' if error_runs else 'green'}]{len(error_runs)}[/]   "
            f"Success rate: [{c_color}]{success_rate:.1f}%[/{c_color}]"
        )
        if error_runs:
            for run in error_runs[:5]:
                console.print(
                    f"    [red]{run.connector_name}[/red]  "
                    f"status={run.status}  "
                    f"errors={run.error_count}"
                )

        # ---------------------------------------------------------------
        # Upcoming deadlines (next 2 weeks)
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]Upcoming Deadlines (next 14 days)[/bold cyan]")

        deadline_q = session.query(POAM).filter(
            POAM.scheduled_completion >= now,
            POAM.scheduled_completion <= two_weeks_out,
            POAM.status.notin_(["completed", "verified", "closed", "cancelled"]),
        )
        if framework:
            deadline_q = deadline_q.filter(POAM.framework == framework)
        upcoming_deadlines = deadline_q.order_by(POAM.scheduled_completion.asc()).limit(10).all()

        if upcoming_deadlines:
            dl_table = Table(show_lines=False)
            dl_table.add_column("Control")
            dl_table.add_column("Framework")
            dl_table.add_column("Due Date")
            dl_table.add_column("Status")
            for p in upcoming_deadlines:
                days_left = (ensure_aware(p.scheduled_completion) - now).days
                color = "red" if days_left <= 3 else ("yellow" if days_left <= 7 else "white")
                dl_table.add_row(
                    p.control_id,
                    p.framework,
                    f"[{color}]{p.scheduled_completion.strftime('%Y-%m-%d')} "
                    f"({days_left}d)[/{color}]",
                    p.status,
                )
            console.print(dl_table)
        else:
            console.print("  [green]No POA&M deadlines in the next 14 days.[/green]")

        # ---------------------------------------------------------------
        # Build weekly report
        # ---------------------------------------------------------------
        report_lines = [
            f"# Weekly Operations Summary — {now.strftime('%Y-%m-%d')}",
            "",
            f"**Prepared by:** {actor}  ",
            f"**Framework:** {framework or 'All Frameworks'}  ",
            "",
            "## Metrics",
            "",
            "| Metric | This Week | Last Week | Change |",
            "|--------|-----------|-----------|--------|",
            f"| New findings | {new_this} | {new_last} | {'+' if delta_f >= 0 else ''}{delta_f} |",
            f"| Issues opened | {opened_this} | — | — |",
            f"| Issues resolved | {resolved_this} | — | — |",
            f"| Open POA&Ms | {len(open_poams)} | — | — |",
            f"| Overdue POA&Ms | {overdue_count} | — | — |",
            f"| Connector success rate | {success_rate:.1f}% | — | — |",
            "",
        ]

        if all_results:
            report_lines += [
                "## Compliance Posture",
                "",
                f"- {framework or 'All'}: **{compliant_pct:.1f}%** compliant ({compliant}/{total})",
                "",
            ]

        report_lines += [
            "---",
            f"*Generated by Warlock GRC Platform on {now.strftime('%Y-%m-%d %H:%M')} UTC*",
        ]
        report_text = "\n".join(report_lines)

        if output:
            try:
                with open(output, "w") as f:
                    f.write(report_text)
                console.print(f"\n  [green]Weekly report saved to {output}[/green]")
            except OSError as exc:
                console.print(f"\n  [red]Failed to write report: {exc}[/red]")
        else:
            console.print(Panel(report_text, title="Weekly Report", style="dim"))


# ---------------------------------------------------------------------------
# warlock monthly-review
# ---------------------------------------------------------------------------


@cli.command("monthly-review")
@click.option("--framework", "-f", default=None, help="Filter to a specific framework")
@click.option("--output", "-o", default=None, help="Save monthly report to file")
def monthly_review(framework: str | None, output: str | None) -> None:
    """Monthly GRC review: KRI evaluation, ConMon, vendors, training, attestations.

    \b
    Examples:
        warlock monthly-review
        warlock monthly-review --framework nist_800_53 --output monthly.md
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        POAM,
        Attestation,
        ConnectorRun,
        ControlResult,
        Finding,
        Issue,
        Personnel,
        Vendor,
    )

    init_db()

    actor = _get_actor()
    now = _utcnow()
    this_month_start = now - timedelta(days=30)
    last_month_start = now - timedelta(days=60)
    vendor_reassess_cutoff = now - timedelta(days=180)  # 6-month reassessment cycle
    attestation_expiry_cutoff = now + timedelta(days=30)

    console.print(
        Panel(
            "[bold]Monthly GRC Review[/bold]\n"
            f"Period: {this_month_start.strftime('%Y-%m-%d')} — {now.strftime('%Y-%m-%d')}\n"
            f"Framework: {framework or 'all'}",
            style="cyan",
        )
    )

    with get_session() as session:
        # ---------------------------------------------------------------
        # 1. Month-over-month trends
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]1. Month-Over-Month Trends[/bold cyan]")

        fq = session.query(Finding)
        new_this = fq.filter(Finding.ingested_at >= this_month_start).count()
        new_last = fq.filter(
            Finding.ingested_at >= last_month_start,
            Finding.ingested_at < this_month_start,
        ).count()

        iq = session.query(Issue)
        if framework:
            iq = iq.filter(Issue.framework == framework)
        open_issues = iq.filter(Issue.status.notin_(["closed", "verified"])).count()
        closed_this = iq.filter(
            Issue.status.in_(["closed", "verified"]),
            Issue.updated_at >= this_month_start,
        ).count()

        trend_table = Table(title="Trends", show_lines=False)
        trend_table.add_column("Metric")
        trend_table.add_column("This Month", justify="right")
        trend_table.add_column("Last Month", justify="right")
        trend_table.add_column("Trend")
        for label, this, last in [
            ("New findings", new_this, new_last),
        ]:
            delta = this - last
            trend_str = (
                "[green]improved[/green]"
                if delta < 0
                else ("[red]degraded[/red]" if delta > 0 else "[dim]stable[/dim]")
            )
            trend_table.add_row(label, str(this), str(last), trend_str)
        trend_table.add_row(
            "Issues resolved",
            str(closed_this),
            "—",
            "[dim]—[/dim]",
        )
        trend_table.add_row("Open issues", str(open_issues), "—", "[dim]—[/dim]")
        console.print(trend_table)

        # ---------------------------------------------------------------
        # 2. KRI evaluation (red/amber/green)
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]2. Key Risk Indicators (KRI)[/bold cyan]")

        ctrl_q = session.query(ControlResult)
        if framework:
            ctrl_q = ctrl_q.filter(ControlResult.framework == framework)
        all_results = ctrl_q.all()

        kri_table = Table(title="KRI Dashboard", show_lines=False)
        kri_table.add_column("KRI")
        kri_table.add_column("Value", justify="right")
        kri_table.add_column("Threshold")
        kri_table.add_column("Status")

        if all_results:
            total = len(all_results)
            compliant = sum(
                1 for r in all_results if r.status in ("compliant", "inherited_compliant")
            )
            non_compliant = sum(1 for r in all_results if r.status == "non_compliant")
            compliant_pct = compliant / total * 100

            kri_table.add_row(
                "Compliance rate",
                f"{compliant_pct:.1f}%",
                ">= 85%",
                "[green]OK[/green]"
                if compliant_pct >= 85
                else ("[yellow]WARN[/yellow]" if compliant_pct >= 70 else "[red]ALERT[/red]"),
            )
            kri_table.add_row(
                "Non-compliant controls",
                str(non_compliant),
                "< 50",
                "[green]OK[/green]"
                if non_compliant < 50
                else ("[yellow]WARN[/yellow]" if non_compliant < 100 else "[red]ALERT[/red]"),
            )
        else:
            kri_table.add_row("Compliance rate", "N/A", ">= 85%", "[dim]N/A[/dim]")

        crit_findings_month = (
            session.query(Finding)
            .filter(
                Finding.ingested_at >= this_month_start,
                Finding.severity == "critical",
            )
            .count()
        )
        kri_table.add_row(
            "Critical findings (30d)",
            str(crit_findings_month),
            "< 5",
            "[green]OK[/green]"
            if crit_findings_month < 5
            else ("[yellow]WARN[/yellow]" if crit_findings_month < 10 else "[red]ALERT[/red]"),
        )

        overdue_poams = (
            session.query(POAM)
            .filter(
                POAM.scheduled_completion < now,
                POAM.status.notin_(["completed", "verified", "closed", "cancelled"]),
            )
            .count()
        )
        kri_table.add_row(
            "Overdue POA&Ms",
            str(overdue_poams),
            "0",
            "[green]OK[/green]"
            if overdue_poams == 0
            else ("[yellow]WARN[/yellow]" if overdue_poams <= 5 else "[red]ALERT[/red]"),
        )

        # -- Open issues count
        open_issues_kri = (
            session.query(Issue)
            .filter(Issue.status.notin_(["closed", "resolved", "cancelled"]))
            .count()
        )
        kri_table.add_row(
            "Open issues",
            str(open_issues_kri),
            "< 25",
            "[green]OK[/green]"
            if open_issues_kri < 25
            else ("[yellow]WARN[/yellow]" if open_issues_kri < 50 else "[red]ALERT[/red]"),
        )

        # -- Training compliance %
        total_personnel = (
            session.query(Personnel)
            .filter(Personnel.is_active == True)  # noqa: E712
            .count()
        )
        trained_personnel = (
            session.query(Personnel)
            .filter(
                Personnel.is_active == True,  # noqa: E712
                Personnel.training_status == "current",
            )
            .count()
        )
        training_pct = trained_personnel / total_personnel * 100 if total_personnel else 0.0
        kri_table.add_row(
            "Training compliance",
            f"{training_pct:.1f}%",
            ">= 90%",
            "[green]OK[/green]"
            if training_pct >= 90
            else ("[yellow]WARN[/yellow]" if training_pct >= 75 else "[red]ALERT[/red]"),
        )

        # -- High-risk vendors count (risk_score >= 70)
        high_risk_vendors = session.query(Vendor).filter(Vendor.risk_score >= 70).count()
        kri_table.add_row(
            "High-risk vendors",
            str(high_risk_vendors),
            "< 3",
            "[green]OK[/green]"
            if high_risk_vendors < 3
            else ("[yellow]WARN[/yellow]" if high_risk_vendors < 5 else "[red]ALERT[/red]"),
        )

        # -- Failed connectors in last 30 days
        failed_connectors_30d = (
            session.query(ConnectorRun)
            .filter(
                ConnectorRun.started_at >= this_month_start,
                ConnectorRun.status == "error",
            )
            .count()
        )
        kri_table.add_row(
            "Failed connectors (30d)",
            str(failed_connectors_30d),
            "0",
            "[green]OK[/green]"
            if failed_connectors_30d == 0
            else ("[yellow]WARN[/yellow]" if failed_connectors_30d <= 3 else "[red]ALERT[/red]"),
        )

        console.print(kri_table)

        # ---------------------------------------------------------------
        # 3. ConMon checklist status
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]3. Continuous Monitoring (ConMon) Checklist[/bold cyan]")

        recent_runs = (
            session.query(ConnectorRun).filter(ConnectorRun.started_at >= this_month_start).all()
        )
        successful_runs = [r for r in recent_runs if r.status == "success"]
        error_runs = [r for r in recent_runs if r.status in ("error", "partial")]

        conmon_checks = [
            (
                "Connectors ran this month",
                len(recent_runs) > 0,
                f"{len(recent_runs)} runs ({len(successful_runs)} success, {len(error_runs)} errors)",
            ),
            (
                "Critical findings reviewed",
                crit_findings_month < 5,
                f"{crit_findings_month} critical finding(s)",
            ),
            (
                "POA&Ms on track",
                overdue_poams == 0,
                f"{overdue_poams} overdue",
            ),
            (
                "Control results current",
                bool(all_results),
                f"{len(all_results)} control results" if all_results else "No results found",
            ),
        ]

        for check, passed, detail in conmon_checks:
            icon = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
            console.print(f"  {icon}  {check}  [dim]({detail})[/dim]")

        # ---------------------------------------------------------------
        # 4. Vendor reassessments due
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]4. Vendor Reassessments Due[/bold cyan]")

        overdue_vendors = []
        try:
            vendors = session.query(Vendor).all()
            overdue_vendors = [
                v
                for v in vendors
                if v.last_assessment is None or v.last_assessment < vendor_reassess_cutoff
            ]

            if overdue_vendors:
                v_table = Table(show_lines=False)
                v_table.add_column("Vendor")
                v_table.add_column("Tier")
                v_table.add_column("Last Assessment")
                v_table.add_column("Risk Score")
                for v in overdue_vendors[:10]:
                    last_a = (
                        v.last_assessment.strftime("%Y-%m-%d") if v.last_assessment else "never"
                    )
                    risk_color = (
                        "red"
                        if (v.risk_score or 0) >= 70
                        else ("yellow" if (v.risk_score or 0) >= 40 else "green")
                    )
                    v_table.add_row(
                        v.name,
                        v.tier or "—",
                        f"[{'red' if v.last_assessment is None else 'yellow'}]{last_a}[/]",
                        f"[{risk_color}]{v.risk_score or '—'}[/{risk_color}]",
                    )
                console.print(v_table)
                console.print(
                    f"  [yellow]{len(overdue_vendors)}[/yellow] vendor(s) need reassessment. "
                    "Run: warlock vendors list"
                )
            else:
                console.print("  [green]All vendors assessed within the last 180 days.[/green]")
        except Exception:
            console.print("  [dim]Vendor data unavailable.[/dim]")

        # ---------------------------------------------------------------
        # 5. Training compliance status
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]5. Training Compliance[/bold cyan]")
        console.print(
            "  [dim]Run 'warlock training status' for full training compliance report.[/dim]"
        )

        # ---------------------------------------------------------------
        # 6. Attestations expiring
        # ---------------------------------------------------------------
        console.print("\n[bold cyan]6. Attestations Expiring (next 30 days)[/bold cyan]")

        attest_q = session.query(Attestation).filter(
            Attestation.status == "approved",
        )
        if framework:
            attest_q = attest_q.filter(Attestation.framework == framework)
        approved_attestations = attest_q.all()

        # We don't have an explicit expiry on Attestation — use approved_at + 12 months as proxy
        expiring_attests = [
            a
            for a in approved_attestations
            if a.approved_at
            and (ensure_aware(a.approved_at) + timedelta(days=365)) <= attestation_expiry_cutoff
        ]

        if expiring_attests:
            a_table = Table(show_lines=False)
            a_table.add_column("ID", max_width=8)
            a_table.add_column("Framework")
            a_table.add_column("Control")
            a_table.add_column("Approved At")
            a_table.add_column("Approx Expiry")
            for a in expiring_attests[:10]:
                approx_expiry = (ensure_aware(a.approved_at) + timedelta(days=365)).strftime(
                    "%Y-%m-%d"
                )
                a_table.add_row(
                    a.id[:8],
                    a.framework,
                    a.control_id or "—",
                    a.approved_at.strftime("%Y-%m-%d"),
                    f"[yellow]{approx_expiry}[/yellow]",
                )
            console.print(a_table)
            console.print(
                f"  [yellow]{len(expiring_attests)}[/yellow] attestation(s) may need renewal."
            )
        else:
            console.print("  [green]No attestations expiring in the next 30 days.[/green]")

        # ---------------------------------------------------------------
        # Monthly report
        # ---------------------------------------------------------------
        report_lines: list[str] = [
            f"# Monthly GRC Review — {now.strftime('%Y-%m')}",
            "",
            f"**Prepared by:** {actor}  ",
            f"**Framework:** {framework or 'All Frameworks'}  ",
            f"**Period:** {this_month_start.strftime('%Y-%m-%d')} — {now.strftime('%Y-%m-%d')}  ",
            "",
            "## Key Metrics",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| New findings | {new_this} |",
            f"| Critical findings | {crit_findings_month} |",
            f"| Open issues | {open_issues} |",
            f"| Issues resolved this month | {closed_this} |",
            f"| Overdue POA&Ms | {overdue_poams} |",
        ]

        if all_results:
            report_lines.append(f"| Compliance rate | {compliant_pct:.1f}% |")

        report_lines += [
            "",
            "## KRI Status",
            "",
            "| KRI | Value | Status |",
            "|-----|-------|--------|",
            f"| Critical findings (30d) | {crit_findings_month} | {'OK' if crit_findings_month < 5 else 'ALERT'} |",
            f"| Overdue POA&Ms | {overdue_poams} | {'OK' if overdue_poams == 0 else 'ALERT'} |",
            f"| Open issues | {open_issues_kri} | {'OK' if open_issues_kri < 25 else 'ALERT'} |",
            f"| Training compliance | {training_pct:.1f}% | {'OK' if training_pct >= 90 else 'ALERT'} |",
            f"| High-risk vendors | {high_risk_vendors} | {'OK' if high_risk_vendors < 3 else 'ALERT'} |",
            f"| Failed connectors (30d) | {failed_connectors_30d} | {'OK' if failed_connectors_30d == 0 else 'ALERT'} |",
        ]
        if all_results:
            report_lines.append(
                f"| Compliance rate | {compliant_pct:.1f}% | {'OK' if compliant_pct >= 85 else 'ALERT'} |"
            )

        report_lines += [
            "",
            "## ConMon Summary",
            "",
            f"- Connector runs this month: {len(recent_runs)} ({len(error_runs)} errors)",
        ]

        if overdue_vendors:
            report_lines += [
                "",
                "## Vendor Reassessments Due",
                "",
            ]
            for v in overdue_vendors[:5]:
                last_a = v.last_assessment.strftime("%Y-%m-%d") if v.last_assessment else "never"
                report_lines.append(f"- {v.name} (last assessed: {last_a})")

        if expiring_attests:
            report_lines += [
                "",
                "## Attestations Expiring",
                "",
            ]
            for a in expiring_attests[:5]:
                approx_expiry = (ensure_aware(a.approved_at) + timedelta(days=365)).strftime(
                    "%Y-%m-%d"
                )
                report_lines.append(
                    f"- {a.framework}/{a.control_id or 'framework'} — expires ~{approx_expiry}"
                )

        report_lines += [
            "",
            "---",
            f"*Generated by Warlock GRC Platform on {now.strftime('%Y-%m-%d %H:%M')} UTC*",
        ]
        report_text = "\n".join(report_lines)

        if output:
            try:
                with open(output, "w") as f:
                    f.write(report_text)
                console.print(f"\n  [green]Monthly report saved to {output}[/green]")
            except OSError as exc:
                console.print(f"\n  [red]Failed to write report: {exc}[/red]")
        else:
            console.print(
                Panel(
                    report_text[:2500] + ("…" if len(report_text) > 2500 else ""),
                    title="Monthly GRC Report",
                    style="dim",
                )
            )

        console.print(
            Panel(
                "[bold]Monthly Review Complete[/bold]\n\n"
                "Next steps:\n"
                "  warlock risk-review quarterly — review risk ratings\n"
                "  warlock risk-review board-report — prepare board summary\n"
                "  warlock vendors list — schedule vendor reassessments",
                style="green",
            )
        )
