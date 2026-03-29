"""Readiness-to-audit CLI commands.

Unified view: readiness score, timeline projection, and prioritized gaps.
"""

from __future__ import annotations

import click
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from warlock.cli import cli, console


@cli.group("readiness", invoke_without_command=True)
@click.pass_context
def readiness(ctx: click.Context) -> None:
    """Audit readiness assessment (score, timeline, gaps)."""
    if ctx.invoked_subcommand is not None:
        return

    console.print(
        "[dim]Usage: warlock readiness <command>\n"
        "  score     -- Readiness score for a framework\n"
        "  timeline  -- Projected date to reach target score\n"
        "  gaps      -- Prioritized gap list with effort estimates[/dim]"
    )


# ---------------------------------------------------------------------------
# score
# ---------------------------------------------------------------------------


@readiness.command("score")
@click.option("--framework", "-f", required=True, help="Framework (e.g. soc2, nist_800_53)")
@click.option("--system", "-s", default=None, help="System profile ID or acronym")
def readiness_score(framework: str, system: str | None) -> None:
    """Show readiness score with breakdown."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.workflows.readiness import ReadinessAssessor

    init_db()
    system_id = None
    if system:
        from warlock.cli import _resolve_system_id
        from warlock.db.engine import get_read_session as _grs

        with _grs() as sess:
            system_id = _resolve_system_id(sess, system)

    with get_read_session() as session:
        assessor = ReadinessAssessor()
        result = assessor.score(session, framework, system_id=system_id)

    if result["total"] == 0:
        console.print(f"[yellow]No control results found for framework '{framework}'.[/yellow]")
        return

    score = result["score"]
    if score >= 85:
        score_style = "green bold"
    elif score >= 60:
        score_style = "yellow bold"
    else:
        score_style = "red bold"

    panel_text = (
        f"[{score_style}]{score:.1f}%[/{score_style}] readiness\n\n"
        f"Total controls: {result['total']}\n"
        f"[green]Compliant:[/green] {result['compliant']}\n"
        f"[red]Non-compliant:[/red] {result['non_compliant']}\n"
        f"[yellow]Partial:[/yellow] {result['partial']}\n"
        f"[dim]Not assessed:[/dim] {result['not_assessed']}\n"
        f"[dim]Not applicable:[/dim] {result['not_applicable']}"
    )

    console.print(Panel(panel_text, title=f"Readiness: {escape(framework)}", border_style="cyan"))


# ---------------------------------------------------------------------------
# timeline
# ---------------------------------------------------------------------------


@readiness.command("timeline")
@click.option("--framework", "-f", required=True, help="Framework (e.g. soc2, nist_800_53)")
@click.option("--target", "-t", default=85.0, type=float, help="Target score (default: 85)")
@click.option("--system", "-s", default=None, help="System profile ID or acronym")
def readiness_timeline(framework: str, target: float, system: str | None) -> None:
    """Project timeline to reach target readiness score."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.workflows.readiness import ReadinessAssessor

    init_db()
    system_id = None
    if system:
        from warlock.cli import _resolve_system_id
        from warlock.db.engine import get_read_session as _grs

        with _grs() as sess:
            system_id = _resolve_system_id(sess, system)

    with get_read_session() as session:
        assessor = ReadinessAssessor()
        result = assessor.timeline(session, framework, target_score=target, system_id=system_id)

    status = result["status"]

    if status == "target_met":
        console.print(
            f"[green bold]Target already met![/green bold] "
            f"Current score: {result['current_score']:.1f}% "
            f"(target: {target:.1f}%)"
        )
        return

    if status == "no_data":
        console.print(f"[yellow]No control results found for framework '{framework}'.[/yellow]")
        return

    if status == "no_velocity":
        console.print(
            f"[yellow]Cannot project timeline:[/yellow] "
            f"No remediation activity detected in the last 30 days.\n"
            f"Current score: {result['current_score']:.1f}% "
            f"(target: {target:.1f}%)\n"
            f"Gap: {result['gap_controls']} controls need remediation."
        )
        return

    # Normal projection
    projected_date = result["projected_date"][:10] if result["projected_date"] else "N/A"

    panel_text = (
        f"Current score: [yellow]{result['current_score']:.1f}%[/yellow]\n"
        f"Target score:  [green]{target:.1f}%[/green]\n"
        f"Gap controls:  {result['gap_controls']}\n"
        f"Velocity:      {result['velocity_per_week']:.1f} controls/week\n"
        f"Projected:     [cyan bold]{result['projected_days']} days[/cyan bold] "
        f"({projected_date})"
    )

    console.print(Panel(panel_text, title=f"Timeline: {escape(framework)}", border_style="cyan"))


# ---------------------------------------------------------------------------
# gaps
# ---------------------------------------------------------------------------


@readiness.command("gaps")
@click.option("--framework", "-f", required=True, help="Framework (e.g. soc2, nist_800_53)")
@click.option("--system", "-s", default=None, help="System profile ID or acronym")
@click.option("--limit", "-n", default=25, help="Max results (default: 25)")
def readiness_gaps(framework: str, system: str | None, limit: int) -> None:
    """Show prioritized gap list with effort estimates."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.workflows.readiness import ReadinessAssessor

    init_db()
    system_id = None
    if system:
        from warlock.cli import _resolve_system_id
        from warlock.db.engine import get_read_session as _grs

        with _grs() as sess:
            system_id = _resolve_system_id(sess, system)

    with get_read_session() as session:
        assessor = ReadinessAssessor()
        gaps = assessor.gaps(session, framework, system_id=system_id, limit=limit)

    if not gaps:
        console.print(f"[green]No gaps found for framework '{escape(framework)}'.[/green]")
        return

    table = Table(title=f"Prioritized Gaps: {escape(framework)} ({len(gaps)})")
    table.add_column("Priority", justify="right", style="cyan")
    table.add_column("Control", max_width=15)
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Effort")
    table.add_column("Impact", justify="right")
    table.add_column("Score", justify="right", style="cyan bold")
    table.add_column("Remediation", max_width=35)

    severity_styles = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }

    status_styles = {
        "non_compliant": "red",
        "partial": "yellow",
        "not_assessed": "dim",
    }

    for i, gap in enumerate(gaps, 1):
        sev_style = severity_styles.get(gap["severity"], "")
        st_style = status_styles.get(gap["status"], "")
        table.add_row(
            str(i),
            escape(gap["control_id"]),
            f"[{st_style}]{gap['status']}[/]",
            f"[{sev_style}]{gap['severity']}[/]",
            gap["effort"],
            str(gap["impact"]),
            str(gap["priority_score"]),
            escape((gap["remediation_summary"] or "\u2014")[:35]),
        )

    console.print(table)
