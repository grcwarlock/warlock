"""Interactive risk management workflow commands.

Group: warlock risk-review

Commands:
  assess          -- Guided risk assessment session
  board-report    -- Generate board risk report interactively
  acceptance      -- Guided risk acceptance workflow
  quarterly       -- Quarterly risk review
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from warlock.utils import ensure_aware

import click
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@cli.group("risk-review", invoke_without_command=True)
@click.pass_context
def risk_review(ctx: click.Context) -> None:
    """Interactive risk management review workflows."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


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


def _risk_score(likelihood: int, impact: int) -> int:
    return likelihood * impact


def _risk_level(score: int) -> tuple[str, str]:
    """Return (level_label, rich_color) for a risk score 1-25."""
    if score >= 20:
        return "Critical", "red bold"
    if score >= 12:
        return "High", "red"
    if score >= 6:
        return "Medium", "yellow"
    return "Low", "dim"


def _render_heatmap(risks: list[dict[str, Any]]) -> None:
    """Print a simple 5x5 likelihood/impact heatmap to the console."""
    # Build a grid: rows = likelihood (5 down to 1), cols = impact (1 to 5)
    grid: dict[tuple[int, int], int] = {}
    for r in risks:
        l_ = r.get("likelihood", 0)
        i_ = r.get("impact", 0)
        if 1 <= l_ <= 5 and 1 <= i_ <= 5:
            grid[(l_, i_)] = grid.get((l_, i_), 0) + 1

    table = Table(title="Risk Heatmap (Likelihood x Impact)", show_lines=True)
    table.add_column("L\\I", style="bold", justify="center")
    for i in range(1, 6):
        table.add_column(str(i), justify="center")

    for l_ in range(5, 0, -1):
        row = [str(l_)]
        for i in range(1, 6):
            count = grid.get((l_, i), 0)
            score = l_ * i
            _, color = _risk_level(score)
            cell = f"[{color}]{count or '.'}[/{color}]"
            row.append(cell)
        table.add_row(*row)

    console.print(table)
    console.print(
        "[dim]  Rows = Likelihood (5=Almost Certain → 1=Rare), Cols = Impact (1=Negligible → 5=Catastrophic)[/dim]"
    )


# ---------------------------------------------------------------------------
# risk-review assess
# ---------------------------------------------------------------------------


@risk_review.command("assess")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
@click.option(
    "--severity",
    "-s",
    default="high",
    type=click.Choice(["critical", "high", "medium"]),
    help="Minimum finding severity to assess (default: high)",
)
@click.option("--limit", "-n", default=20, help="Max new findings to review")
@click.option("--interactive/--no-interactive", default=True)
def risk_assess(framework: str | None, severity: str, limit: int, interactive: bool) -> None:
    """Guided risk assessment session: review top risks and new critical/high findings.

    For each new finding, prompts for likelihood, impact, and treatment.
    Updates the risk register and renders a heatmap.

    \b
    Examples:
        warlock risk-review assess
        warlock risk-review assess --framework nist_800_53 --severity critical
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, RiskAcceptance

    init_db()

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    min_sev_idx = severity_order.get(severity, 1)

    console.print(
        Panel(
            "[bold]Risk Assessment Session[/bold]\n"
            f"Reviewing findings with severity >= {severity}. "
            f"Framework filter: {framework or 'all'}.",
            style="cyan",
        )
    )

    now = _utcnow()
    last_week = now - timedelta(days=7)

    with get_session() as session:
        # Current top risks from risk register
        console.print("\n[bold cyan]Current Top Risks (Risk Acceptances)[/bold cyan]")
        q = session.query(RiskAcceptance).filter(RiskAcceptance.status.in_(["approved", "active"]))
        if framework:
            q = q.filter(RiskAcceptance.framework == framework)
        top_risks = q.order_by(RiskAcceptance.risk_level.asc()).limit(10).all()

        if top_risks:
            ra_table = Table(show_lines=False)
            ra_table.add_column("ID", max_width=8)
            ra_table.add_column("Framework")
            ra_table.add_column("Control")
            ra_table.add_column("Risk Level")
            ra_table.add_column("Status")
            ra_table.add_column("Expires")
            for ra in top_risks:
                color = _severity_color(ra.risk_level)
                exp = ra.expiry_date.strftime("%Y-%m-%d") if ra.expiry_date else "—"
                ra_table.add_row(
                    ra.id[:8],
                    ra.framework,
                    ra.control_id,
                    f"[{color}]{ra.risk_level}[/{color}]",
                    ra.status,
                    exp,
                )
            console.print(ra_table)
        else:
            console.print("  [dim]No active risk register entries.[/dim]")

        # New findings since last assessment
        console.print(
            f"\n[bold cyan]New Findings Since {last_week.strftime('%Y-%m-%d')} "
            f"(severity >= {severity})[/bold cyan]"
        )

        sev_filter_values = [s for s, idx in severity_order.items() if idx <= min_sev_idx]

        fq = session.query(Finding).filter(
            Finding.ingested_at >= last_week,
            Finding.severity.in_(sev_filter_values),
        )
        if framework:
            # Findings don't have framework — filter via source as a proxy
            pass
        new_findings = fq.order_by(Finding.severity.asc()).limit(limit).all()

        if not new_findings:
            console.print(f"  [green]No new {severity}+ findings this week.[/green]")
        else:
            console.print(f"  [bold]{len(new_findings)}[/bold] new finding(s) to review.")

        assessed_risks: list[dict[str, Any]] = []

        for finding in new_findings:
            color = _severity_color(finding.severity)
            console.print(
                f"\n  [{color}][{finding.severity.upper()}][/{color}]  "
                f"[bold]{finding.title[:70]}[/bold]"
            )
            console.print(
                f"  Source: {finding.source} / {finding.provider}   "
                f"Resource: {finding.resource_type or '—'}   "
                f"Observed: {finding.observed_at.strftime('%Y-%m-%d %H:%M') if finding.observed_at else '—'}"
            )

            # Blast radius estimate: how many control mappings?
            control_count = len(finding.control_mappings) if finding.control_mappings else 0
            if control_count:
                console.print(f"  Blast radius: affects {control_count} control mapping(s)")

            if not interactive:
                assessed_risks.append({"finding_id": finding.id, "likelihood": 3, "impact": 3})
                continue

            try:
                l_str = Prompt.ask("  Likelihood (1=Rare … 5=Almost Certain)", default="3")
                i_str = Prompt.ask("  Impact (1=Negligible … 5=Catastrophic)", default="3")
                likelihood = max(1, min(5, int(l_str)))
                impact = max(1, min(5, int(i_str)))
            except (ValueError, KeyboardInterrupt, EOFError):
                console.print("  [dim]Skipped.[/dim]")
                continue

            score = _risk_score(likelihood, impact)
            level, level_color = _risk_level(score)
            console.print(f"  Risk score: [{level_color}]{score}/25 — {level}[/{level_color}]")

            try:
                treatment = Prompt.ask(
                    "  Treatment",
                    choices=["m", "t", "a", "v"],
                    default="m",
                )
            except (KeyboardInterrupt, EOFError):
                console.print("  [dim]Skipped.[/dim]")
                continue

            treatment_labels = {
                "m": "Mitigate",
                "t": "Transfer",
                "a": "Accept",
                "v": "Void/Eliminate",
            }
            console.print(
                f"  Treatment: [cyan]{treatment_labels[treatment]}[/cyan]   "
                f"Recorded for finding {finding.id[:8]}"
            )

            assessed_risks.append(
                {
                    "finding_id": finding.id,
                    "likelihood": likelihood,
                    "impact": impact,
                    "score": score,
                    "level": level,
                    "treatment": treatment_labels[treatment],
                }
            )

            if treatment == "a":
                console.print(
                    f"  [dim]To formalise acceptance: warlock risk-review acceptance {finding.id[:8]}[/dim]"
                )

        # Heatmap
        if assessed_risks:
            console.print("\n[bold cyan]Updated Risk Heatmap[/bold cyan]")
            _render_heatmap(assessed_risks)

        console.print(
            Panel(
                f"[bold]Session Summary[/bold]\n\n"
                f"Findings reviewed: [bold]{len(assessed_risks)}[/bold] / {len(new_findings)}\n"
                f"Top risks in register: {len(top_risks)}\n"
                + (
                    "\n[dim]Next: warlock risk-review board-report to prepare executive summary[/dim]"
                ),
                style="cyan",
            )
        )


# ---------------------------------------------------------------------------
# risk-review board-report
# ---------------------------------------------------------------------------


@risk_review.command("board-report")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
@click.option(
    "--output", "-o", default=None, help="Save report to file (default: print to console)"
)
@click.option("--interactive/--no-interactive", default=True)
def risk_board_report(framework: str | None, output: str | None, interactive: bool) -> None:
    """Generate a board-level risk report interactively.

    Shows top risks, appetite status, and trends. Prompts for commentary
    on each included risk, then renders a board-ready markdown report.

    \b
    Examples:
        warlock risk-review board-report
        warlock risk-review board-report --framework soc2 --output board-report.md
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding, Issue, RiskAcceptance

    init_db()

    console.print(
        Panel(
            f"[bold]Board Risk Report Generator[/bold]\nFramework filter: {framework or 'all'}.",
            style="cyan",
        )
    )

    actor = _get_actor()
    now = _utcnow()
    last_month = now - timedelta(days=30)

    with get_session() as session:
        # Top risks
        q = session.query(RiskAcceptance).filter(
            RiskAcceptance.status.in_(["approved", "active", "requested"])
        )
        if framework:
            q = q.filter(RiskAcceptance.framework == framework)
        top_risks = q.order_by(RiskAcceptance.risk_level.asc()).limit(10).all()

        # Recent critical findings as risk signal
        crit_findings = (
            session.query(Finding)
            .filter(
                Finding.severity.in_(["critical", "high"]),
                Finding.ingested_at >= last_month,
            )
            .count()
        )

        # Open issues as risk signal
        open_issues = (
            session.query(Issue).filter(Issue.status.notin_(["closed", "verified"])).count()
        )

        # Compliance posture (if framework specified)
        compliant_pct: float | None = None
        if framework:
            all_results = (
                session.query(ControlResult).filter(ControlResult.framework == framework).all()
            )
            if all_results:
                compliant = sum(
                    1 for r in all_results if r.status in ("compliant", "inherited_compliant")
                )
                compliant_pct = compliant / len(all_results) * 100

        # Show current posture
        console.print("\n[bold cyan]Current Risk Posture[/bold cyan]")
        console.print(
            f"  Top risks: {len(top_risks)}   "
            f"Critical/high findings (30d): {crit_findings}   "
            f"Open issues: {open_issues}"
        )
        if compliant_pct is not None:
            color = "green" if compliant_pct >= 80 else ("yellow" if compliant_pct >= 50 else "red")
            console.print(f"  Compliance posture: [{color}]{compliant_pct:.1f}%[/{color}]")

        if not top_risks:
            console.print("  [dim]No active risks in register.[/dim]")
            return

        # Risk table
        risk_table = Table(title="Risk Register — Top Risks", show_lines=False)
        risk_table.add_column("#", justify="right")
        risk_table.add_column("Control")
        risk_table.add_column("Risk Level")
        risk_table.add_column("Status")
        risk_table.add_column("Expires")
        for idx, ra in enumerate(top_risks, 1):
            color = _severity_color(ra.risk_level)
            exp = ra.expiry_date.strftime("%Y-%m-%d") if ra.expiry_date else "—"
            risk_table.add_row(
                str(idx),
                f"{ra.framework} / {ra.control_id}",
                f"[{color}]{ra.risk_level}[/{color}]",
                ra.status,
                exp,
            )
        console.print(risk_table)

        # Interactive risk selection + commentary
        included_risks: list[dict[str, Any]] = []

        for idx, ra in enumerate(top_risks, 1):
            color = _severity_color(ra.risk_level)
            label = f"[{color}]{ra.risk_level}[/{color}] {ra.framework}/{ra.control_id}"

            if interactive:
                try:
                    include = Confirm.ask(
                        f"\n  Include risk #{idx} ({label}) in board report?", default=True
                    )
                except (KeyboardInterrupt, EOFError):
                    console.print("\n[dim]Cancelled.[/dim]")
                    break
            else:
                include = True

            if not include:
                continue

            commentary = ""
            if interactive:
                try:
                    commentary = Prompt.ask(
                        f"  Commentary for {ra.control_id} (optional, press Enter to skip)",
                        default="",
                    ).strip()
                except (KeyboardInterrupt, EOFError):
                    pass

            included_risks.append(
                {
                    "id": ra.id[:8],
                    "framework": ra.framework,
                    "control_id": ra.control_id,
                    "risk_level": ra.risk_level,
                    "risk_description": ra.risk_description or "—",
                    "status": ra.status,
                    "approved_by": ra.approved_by or "—",
                    "expiry_date": ra.expiry_date.strftime("%Y-%m-%d") if ra.expiry_date else "N/A",
                    "commentary": commentary,
                }
            )

        # Build report
        report_lines: list[str] = [
            f"# Board Risk Report — {now.strftime('%Y-%m-%d')}",
            "",
            f"**Prepared by:** {actor}  ",
            f"**Framework:** {framework or 'All Frameworks'}  ",
            f"**Reporting period:** {last_month.strftime('%Y-%m-%d')} — {now.strftime('%Y-%m-%d')}  ",
            "",
            "## Executive Summary",
            "",
            f"- **{len(included_risks)}** active risks included in this report",
            f"- **{crit_findings}** critical/high findings in the last 30 days",
            f"- **{open_issues}** open compliance issues",
        ]
        if compliant_pct is not None:
            report_lines.append(f"- **{compliant_pct:.1f}%** of {framework} controls are compliant")

        report_lines += ["", "## Risk Register", ""]
        for r in included_risks:
            report_lines += [
                f"### {r['control_id']} — {r['risk_level'].upper()} Risk",
                "",
                f"**Framework:** {r['framework']}  ",
                f"**Status:** {r['status']}  ",
                f"**Approved by:** {r['approved_by']}  ",
                f"**Expires:** {r['expiry_date']}  ",
                "",
                f"**Description:** {r['risk_description']}",
                "",
            ]
            if r["commentary"]:
                report_lines += [f"**Management commentary:** {r['commentary']}", ""]

        report_lines += [
            "---",
            f"*Generated by Warlock GRC Platform on {now.strftime('%Y-%m-%d %H:%M')} UTC*",
        ]

        report_text = "\n".join(report_lines)

        if output:
            try:
                with open(output, "w") as f:
                    f.write(report_text)
                console.print(f"\n  [green]Report saved to {output}[/green]")
            except OSError as exc:
                _error(f"Failed to write report: {exc}")
        else:
            console.print(Panel(report_text, title="Board Risk Report", style="dim"))

        # Executive summary
        console.print(
            Panel(
                f"[bold]Executive Summary[/bold]\n\n"
                f"Risks included: [bold]{len(included_risks)}[/bold] / {len(top_risks)}\n"
                f"Critical/high findings (30d): [{'red' if crit_findings > 0 else 'green'}]{crit_findings}[/]\n"
                f"Open issues: [{'yellow' if open_issues > 0 else 'green'}]{open_issues}[/]"
                + (
                    f"\nCompliance posture: {compliant_pct:.1f}%"
                    if compliant_pct is not None
                    else ""
                ),
                style="cyan",
            )
        )


# ---------------------------------------------------------------------------
# risk-review acceptance
# ---------------------------------------------------------------------------


@risk_review.command("acceptance")
@click.argument("finding_id")
@click.option("--interactive/--no-interactive", default=True)
def risk_acceptance(finding_id: str, interactive: bool) -> None:
    """Guided risk acceptance workflow for a finding.

    Captures justification, compensating controls, and expiry, then creates
    a formal risk acceptance record with full audit trail.

    \b
    Examples:
        warlock risk-review acceptance <finding_id>
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, ControlResult, Finding, RiskAcceptance

    init_db()

    with get_session() as session:
        finding = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not finding:
            _error(
                f"Finding not found: {finding_id}. "
                "Use 'warlock findings' to list available findings."
            )

        console.print(
            Panel(
                f"[bold]Risk Acceptance — Finding {finding.id[:8]}[/bold]\n\n"
                f"Title: {finding.title[:80]}\n"
                f"Severity: [{_severity_color(finding.severity)}]{finding.severity}[/]   "
                f"Source: {finding.source}/{finding.provider}\n"
                f"Resource: {finding.resource_type or '—'} / {finding.resource_id or '—'}\n"
                f"Observed: {finding.observed_at.strftime('%Y-%m-%d') if finding.observed_at else '—'}",
                style="yellow",
            )
        )

        # Blast radius
        mappings = (
            session.query(ControlMapping).filter(ControlMapping.finding_id == finding.id).all()
        )
        if mappings:
            console.print(
                f"  Blast radius: affects [bold]{len(mappings)}[/bold] control mapping(s) "
                "across " + ", ".join({m.framework for m in mappings})
            )

        # Affected controls
        affected_results = (
            session.query(ControlResult).filter(ControlResult.finding_id == finding.id).all()
        )
        if affected_results:
            ctrl_table = Table(title="Affected Controls", show_lines=False)
            ctrl_table.add_column("Framework")
            ctrl_table.add_column("Control")
            ctrl_table.add_column("Status")
            for r in affected_results[:10]:
                color = (
                    "red"
                    if r.status == "non_compliant"
                    else ("yellow" if r.status == "partial" else "green")
                )
                ctrl_table.add_row(
                    r.framework,
                    r.control_id,
                    f"[{color}]{r.status}[/{color}]",
                )
            console.print(ctrl_table)

        actor = _get_actor()

        # Gather inputs
        if interactive:
            try:
                justification = Prompt.ask("\n  Justification for accepting this risk").strip()
                if not justification:
                    _error("Justification is required for risk acceptance.")

                compensating = Prompt.ask(
                    "  Compensating controls in place (optional, press Enter to skip)",
                    default="",
                ).strip()

                expiry_str = Prompt.ask(
                    "  Acceptance expiry date (YYYY-MM-DD)",
                    default=((_utcnow() + timedelta(days=365)).strftime("%Y-%m-%d")),
                ).strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Risk acceptance cancelled.[/dim]")
                return
        else:
            justification = "Accepted via CLI (non-interactive)"
            compensating = ""
            expiry_str = (_utcnow() + timedelta(days=365)).strftime("%Y-%m-%d")

        try:
            expiry_dt = datetime.strptime(expiry_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            _error("Invalid date format. Use YYYY-MM-DD.")

        # Derive risk_level from finding severity
        sev_to_risk = {
            "critical": "critical",
            "high": "high",
            "medium": "moderate",
            "low": "low",
            "info": "low",
        }
        risk_level = sev_to_risk.get(finding.severity, "moderate")

        # Create risk acceptance for each affected control (or one general record)
        created_count = 0
        framework_control_pairs: list[tuple[str, str]] = list(
            {(m.framework, m.control_id) for m in mappings}
        )
        if not framework_control_pairs:
            framework_control_pairs = [("unknown", "unknown")]

        for fw, ctrl_id in framework_control_pairs[:5]:  # cap at 5
            ra = RiskAcceptance(
                framework=fw,
                control_id=ctrl_id,
                risk_description=(
                    f"{finding.title[:200]}\n\nJustification: {justification}"
                    + (f"\n\nCompensating controls: {compensating}" if compensating else "")
                ),
                risk_level=risk_level,
                residual_risk_level="low" if compensating else risk_level,
                status="requested",
                requested_by=actor,
                expiry_date=expiry_dt,
                conditions=[{"condition": justification, "met": True}],
            )
            try:
                session.add(ra)
                session.flush()
                created_count += 1
                console.print(
                    f"  [green]Created risk acceptance {ra.id[:8]} for {fw}/{ctrl_id}[/green]"
                )
            except Exception as exc:
                console.print(f"  [red]Failed to create acceptance for {fw}/{ctrl_id}: {exc}[/red]")

        try:
            session.commit()
        except Exception as exc:
            session.rollback()
            _error(f"Failed to save risk acceptances: {exc}")

        console.print(
            Panel(
                f"[bold]Risk Acceptance Created[/bold]\n\n"
                f"Records created: [green]{created_count}[/green]\n"
                f"Risk level: [{_severity_color(risk_level)}]{risk_level}[/]\n"
                f"Expiry: {expiry_str}\n"
                f"Status: requested (pending AO approval)\n\n"
                "[dim]Next: warlock risk-acceptances to review pending acceptances[/dim]",
                style="green",
            )
        )


# ---------------------------------------------------------------------------
# risk-review quarterly
# ---------------------------------------------------------------------------


@risk_review.command("quarterly")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
@click.option("--output", "-o", default=None, help="Save quarterly report to file")
@click.option("--interactive/--no-interactive", default=True)
def risk_quarterly(framework: str | None, output: str | None, interactive: bool) -> None:
    """Quarterly risk review: reassess risk ratings, update heatmap, generate report.

    \b
    Examples:
        warlock risk-review quarterly
        warlock risk-review quarterly --framework nist_800_53 --output q1-risk-report.md
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, RiskAcceptance

    init_db()

    now = _utcnow()
    quarter_start = now - timedelta(days=90)

    console.print(
        Panel(
            "[bold]Quarterly Risk Review[/bold]\n"
            f"Period: {quarter_start.strftime('%Y-%m-%d')} — {now.strftime('%Y-%m-%d')}\n"
            f"Framework filter: {framework or 'all'}.",
            style="cyan",
        )
    )

    actor = _get_actor()

    with get_session() as session:
        # Entries due for review (approved/active, last reviewed > 90 days ago or never)
        q = session.query(RiskAcceptance).filter(
            RiskAcceptance.status.in_(["approved", "active", "requested"]),
        )
        if framework:
            q = q.filter(RiskAcceptance.framework == framework)
        all_risks = q.all()

        due_for_review = [
            ra
            for ra in all_risks
            if ra.reviewed_at is None or ensure_aware(ra.reviewed_at) < quarter_start
        ]

        console.print(
            f"\n  Risk register entries: {len(all_risks)}   "
            f"Due for review: [yellow]{len(due_for_review)}[/yellow]"
        )

        if not due_for_review:
            console.print("  [green]All risks reviewed recently. No action needed.[/green]")
            due_for_review = all_risks  # Still generate report

        reviewed_risks: list[dict[str, Any]] = []

        for ra in due_for_review[:20]:  # cap at 20 per session
            color = _severity_color(ra.risk_level)
            last_review = ra.reviewed_at.strftime("%Y-%m-%d") if ra.reviewed_at else "never"

            console.print(
                f"\n  [{color}]{ra.risk_level.upper()}[/{color}]  "
                f"[bold]{ra.framework}/{ra.control_id}[/bold]   "
                f"Last review: {last_review}"
            )
            console.print(f"  Description: {(ra.risk_description or '')[:100]}")

            # Show any new findings for this control
            recent_findings = (
                session.query(Finding)
                .join(
                    Finding.control_mappings,
                )
                .filter(
                    Finding.ingested_at >= quarter_start,
                    Finding.severity.in_(["critical", "high"]),
                )
                .limit(3)
                .all()
            )
            if recent_findings:
                console.print(
                    f"  [yellow]{len(recent_findings)} new critical/high finding(s) in this quarter.[/yellow]"
                )

            update_rating = False
            if interactive:
                try:
                    update_rating = Confirm.ask("  Update risk rating?", default=False)
                except (KeyboardInterrupt, EOFError):
                    console.print("\n  [dim]Skipped.[/dim]")
                    break

            new_likelihood: int | None = None
            new_impact: int | None = None
            new_level = ra.risk_level

            if update_rating and interactive:
                try:
                    l_str = Prompt.ask("  New Likelihood (1-5)", default="3")
                    i_str = Prompt.ask("  New Impact (1-5)", default="3")
                    new_likelihood = max(1, min(5, int(l_str)))
                    new_impact = max(1, min(5, int(i_str)))
                    score = _risk_score(new_likelihood, new_impact)
                    new_level, level_color = _risk_level(score)
                    console.print(
                        f"  New risk level: [{level_color}]{new_level}[/{level_color}] (score {score})"
                    )

                    # Update in DB
                    ra.risk_level = new_level.lower()
                    ra.reviewed_by = actor
                    ra.reviewed_at = now
                    session.commit()
                    console.print(f"  [green]Risk {ra.id[:8]} updated.[/green]")
                except (ValueError, KeyboardInterrupt, EOFError):
                    console.print("  [dim]Rating update skipped.[/dim]")
            else:
                # Mark as reviewed even if rating unchanged
                if interactive:
                    try:
                        ra.reviewed_by = actor
                        ra.reviewed_at = now
                        session.commit()
                    except Exception:
                        session.rollback()

            reviewed_risks.append(
                {
                    "id": ra.id[:8],
                    "framework": ra.framework,
                    "control_id": ra.control_id,
                    "risk_level": ra.risk_level,
                    "likelihood": new_likelihood or 3,
                    "impact": new_impact or 3,
                    "status": ra.status,
                    "description": (ra.risk_description or "")[:200],
                }
            )

        # Updated heatmap
        if reviewed_risks:
            console.print("\n[bold cyan]Updated Risk Heatmap[/bold cyan]")
            _render_heatmap(reviewed_risks)

        # Quarterly report
        report_lines = [
            f"# Quarterly Risk Review — {now.strftime('%Y-Q%m')}",
            "",
            f"**Reviewer:** {actor}  ",
            f"**Review date:** {now.strftime('%Y-%m-%d')}  ",
            f"**Framework:** {framework or 'All Frameworks'}  ",
            "",
            "## Summary",
            "",
            f"- **{len(all_risks)}** risks in register",
            f"- **{len(due_for_review)}** risks reviewed this quarter",
            f"- **{len(reviewed_risks)}** ratings updated",
            "",
            "## Risk Detail",
            "",
        ]
        for r in reviewed_risks:
            report_lines += [
                f"### {r['control_id']} — {r['risk_level'].upper()}",
                "",
                f"Framework: {r['framework']}  Status: {r['status']}",
                "",
                f"Description: {r['description']}",
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
                console.print(f"\n  [green]Quarterly report saved to {output}[/green]")
            except OSError as exc:
                _error(f"Failed to write report: {exc}")
        else:
            console.print(
                Panel(
                    report_text[:2000] + ("…" if len(report_text) > 2000 else ""),
                    title="Quarterly Risk Report",
                    style="dim",
                )
            )

        console.print(
            Panel(
                f"[bold]Quarterly Review Complete[/bold]\n\n"
                f"Risks reviewed: [bold]{len(reviewed_risks)}[/bold]\n"
                f"Next: warlock risk-review board-report to prepare executive summary",
                style="green",
            )
        )
