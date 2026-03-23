"""Compliance automation commands: comply group.

Commands cover auto-mapping, gap analysis, audit prep, readiness scoring,
remediation planning, control effectiveness, benchmarking, maturity modeling,
quick wins, regression detection, continuous compliance metrics, debt tracking,
audit scheduling, and executive briefing.

Uses: ControlResult, ControlMapping, Finding, POAM, Attestation, EvidenceRequest,
AuditEntry.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import click
from rich.table import Table

from warlock.cli import cli, console
from warlock.utils import ensure_aware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pct_style(pct: float) -> str:
    if pct >= 80:
        return "green"
    if pct >= 50:
        return "yellow"
    return "red"


def _score_label(score: float) -> str:
    if score >= 80:
        return "[green]Good[/green]"
    if score >= 60:
        return "[yellow]Fair[/yellow]"
    if score >= 40:
        return "[orange3]Poor[/orange3]"
    return "[red bold]Critical[/red bold]"


def _framework_results(session, framework: str | None) -> list:
    """Return ControlResult rows, optionally filtered by framework."""
    from warlock.db.models import ControlResult

    q = session.query(ControlResult)
    if framework:
        q = q.filter(ControlResult.framework == framework)
    return q.all()


def _count_by_status(results: list) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# comply group
# ---------------------------------------------------------------------------


@cli.group("comply", invoke_without_command=True)
@click.pass_context
def comply(ctx: click.Context) -> None:
    """Compliance automation: gap analysis, audit prep, readiness, executive reporting."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# auto-map
# ---------------------------------------------------------------------------


@comply.command("auto-map")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
@click.option("--dry-run", is_flag=True, help="Show what would be mapped without writing")
def auto_map(framework: str | None, dry_run: bool) -> None:
    """Auto-map unmapped findings to controls based on event_type matching.

    Reads Finding.observation_type and checks ControlMapping for existing
    coverage; suggests or creates mappings for gaps.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, Finding

    init_db()
    with get_session() as session:
        # Find findings that have no control mappings
        mapped_ids = {cm.finding_id for cm in session.query(ControlMapping.finding_id).all()}
        q = session.query(Finding)
        findings = q.all()
        unmapped = [f for f in findings if f.id not in mapped_ids]

        if framework:
            # Filter to actionable observation types for framework-scoped auto-mapping
            unmapped = [
                f
                for f in unmapped
                if f.observation_type in ["misconfiguration", "vulnerability", "policy_violation"]
            ]

    if not unmapped:
        console.print("[green]All findings already have control mappings.[/green]")
        return

    table = Table(
        title=f"{'[DRY RUN] ' if dry_run else ''}Auto-Map Candidates ({len(unmapped)} findings)"
    )
    table.add_column("Finding ID", max_width=8, style="dim")
    table.add_column("Observation Type", style="cyan")
    table.add_column("Severity")
    table.add_column("Source")
    table.add_column("Suggested Control")

    # Heuristic: map observation_type to a representative control
    type_to_control: dict[str, tuple[str, str]] = {
        "misconfiguration": ("nist_800_53", "CM-6"),
        "vulnerability": ("nist_800_53", "SI-2"),
        "alert": ("nist_800_53", "IR-6"),
        "policy_violation": ("nist_800_53", "CA-7"),
        "access_anomaly": ("nist_800_53", "AC-2"),
        "inventory": ("nist_800_53", "CM-8"),
    }

    severity_styles: dict[str, str] = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "dim",
    }

    for f in unmapped[:100]:
        fw_ctrl = type_to_control.get(f.observation_type, ("nist_800_53", "CA-7"))
        suggested = f"{fw_ctrl[0]} / {fw_ctrl[1]}"
        sev = f.severity.lower()
        table.add_row(
            f.id[:8],
            f.observation_type,
            f"[{severity_styles.get(sev, '')}]{sev}[/]",
            f.source,
            suggested,
        )

    console.print(table)

    if len(unmapped) > 100:
        console.print(f"[dim]... and {len(unmapped) - 100} more (showing first 100)[/dim]")

    if dry_run:
        console.print(f"\n[dim]DRY RUN: {len(unmapped)} findings would be auto-mapped.[/dim]")
    else:
        console.print(
            "\n[yellow]Note: Run the pipeline ('warlock collect') to create authoritative "
            "control mappings based on event_type rules.[/yellow]"
        )


# ---------------------------------------------------------------------------
# gap-close
# ---------------------------------------------------------------------------


@comply.command("gap-close")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def gap_close(framework: str | None) -> None:
    """Suggest remediation actions for failed controls."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(ControlResult).filter(ControlResult.status == "non_compliant")
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = (
            q.order_by(ControlResult.severity, ControlResult.assessed_at.desc()).limit(200).all()
        )

    if not results:
        console.print("[green]No non-compliant controls found.[/green]")
        return

    # Deduplicate by (framework, control_id) keeping worst severity
    seen: dict[tuple[str, str], ControlResult] = {}
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for r in results:
        key = (r.framework, r.control_id)
        if key not in seen or sev_rank.get(r.severity.lower(), 99) < sev_rank.get(
            seen[key].severity.lower(), 99
        ):
            seen[key] = r

    table = Table(title=f"Gap Close Recommendations ({len(seen)} controls)")
    table.add_column("Framework", style="cyan")
    table.add_column("Control")
    table.add_column("Severity")
    table.add_column("Remediation", max_width=60)

    sev_styles: dict[str, str] = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "green",
    }

    for (fw, ctrl), r in sorted(
        seen.items(), key=lambda x: sev_rank.get(x[1].severity.lower(), 99)
    ):
        sev = r.severity.lower()
        remediation = (
            r.remediation_summary or "Re-run pipeline after applying fix; see warlock remediate."
        )
        table.add_row(
            fw,
            ctrl,
            f"[{sev_styles.get(sev, '')}]{sev}[/]",
            remediation[:60],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# audit-prep
# ---------------------------------------------------------------------------


@comply.command("audit-prep")
@click.argument("framework")
def audit_prep(framework: str) -> None:
    """Pre-flight checklist for an upcoming audit: evidence freshness, coverage, POA&Ms, attestations."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation, ControlResult, POAM

    init_db()
    with get_session() as session:
        results = session.query(ControlResult).filter(ControlResult.framework == framework).all()
        poams = (
            session.query(POAM)
            .filter(
                POAM.framework == framework, POAM.status.notin_(["completed", "verified", "closed"])
            )
            .all()
        )
        attestations = session.query(Attestation).filter(Attestation.framework == framework).all()

    if not results:
        console.print(
            f"[yellow]No control results for framework '{framework}'. Run 'warlock collect' first.[/yellow]"
        )
        return

    total = len(results)
    compliant = sum(1 for r in results if r.status in ("compliant", "inherited_compliant"))
    non_compliant = sum(1 for r in results if r.status == "non_compliant")
    not_assessed = sum(1 for r in results if r.status == "not_assessed")
    coverage_pct = ((total - not_assessed) / total * 100) if total else 0.0

    # Evidence freshness: how many results are older than 30 days
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    stale = sum(1 for r in results if not r.assessed_at or ensure_aware(r.assessed_at) < cutoff)

    approved_attestations = sum(1 for a in attestations if a.status == "approved")

    from rich.panel import Panel

    console.print()
    console.print(
        Panel(
            f"[bold]Framework:[/bold] {framework}\n"
            f"[bold]Total controls assessed:[/bold] {total}\n"
            f"[bold]Compliant:[/bold] [green]{compliant}[/green]  "
            f"[bold]Non-compliant:[/bold] [red]{non_compliant}[/red]  "
            f"[bold]Not assessed:[/bold] [dim]{not_assessed}[/dim]\n"
            f"[bold]Control coverage:[/bold] [{_pct_style(coverage_pct)}]{coverage_pct:.0f}%[/]\n"
            f"[bold]Open POA&Ms:[/bold] {'[red]' + str(len(poams)) + '[/red]' if poams else '[green]0[/green]'}\n"
            f"[bold]Stale evidence (>30 days):[/bold] {'[yellow]' + str(stale) + '[/yellow]' if stale else '[green]0[/green]'}\n"
            f"[bold]Approved attestations:[/bold] {approved_attestations}",
            title=f"[bold]Audit Pre-Flight Checklist \u2014 {framework}[/bold]",
            border_style="cyan",
        )
    )

    # Checklist items
    checks: list[tuple[bool, str]] = [
        (coverage_pct >= 90, f"Control coverage >= 90% (current: {coverage_pct:.0f}%)"),
        (non_compliant == 0, f"No non-compliant controls (current: {non_compliant})"),
        (len(poams) == 0, f"No open POA&Ms (current: {len(poams)})"),
        (stale == 0, f"All evidence fresh (<30 days, stale: {stale})"),
        (
            approved_attestations > 0,
            f"At least one approved attestation (current: {approved_attestations})",
        ),
    ]

    console.print("\n[bold]Checklist:[/bold]")
    for passed, label in checks:
        icon = "[green]\u2713[/green]" if passed else "[red]\u2717[/red]"
        console.print(f"  {icon}  {label}")

    all_passed = all(p for p, _ in checks)
    if all_passed:
        console.print("\n[green bold]READY for audit.[/green bold]")
    else:
        failed_count = sum(1 for p, _ in checks if not p)
        console.print(
            f"\n[yellow]Audit readiness: {len(checks) - failed_count}/{len(checks)} checks passed.[/yellow]"
        )


# ---------------------------------------------------------------------------
# readiness-score
# ---------------------------------------------------------------------------


@comply.command("readiness-score")
@click.argument("framework", required=False, default=None)
@click.option(
    "--framework",
    "-f",
    "framework_opt",
    default=None,
    help="Framework (alternative to positional arg)",
)
def readiness_score(framework: str | None, framework_opt: str | None) -> None:
    """Compute a 0-100 readiness score with breakdown for a framework."""
    framework = framework or framework_opt
    if not framework:
        raise click.UsageError(
            "Missing framework. Usage: readiness-score <framework> or readiness-score -f <framework>"
        )

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation, ControlResult, POAM

    init_db()
    with get_session() as session:
        results = session.query(ControlResult).filter(ControlResult.framework == framework).all()
        open_poams = (
            session.query(POAM)
            .filter(
                POAM.framework == framework, POAM.status.notin_(["completed", "verified", "closed"])
            )
            .count()
        )
        approved_atts = (
            session.query(Attestation)
            .filter(Attestation.framework == framework, Attestation.status == "approved")
            .count()
        )

    if not results:
        console.print(
            f"[yellow]No control results for '{framework}'. Run 'warlock collect' first.[/yellow]"
        )
        return

    total = len(results)
    compliant = sum(1 for r in results if r.status in ("compliant", "inherited_compliant"))
    not_assessed = sum(1 for r in results if r.status == "not_assessed")

    compliance_pct = (compliant / total * 100) if total else 0.0
    coverage_pct = ((total - not_assessed) / total * 100) if total else 0.0

    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    stale = sum(1 for r in results if not r.assessed_at or ensure_aware(r.assessed_at) < cutoff)
    freshness_pct = ((total - stale) / total * 100) if total else 0.0

    poam_penalty = min(open_poams * 5.0, 30.0)  # up to -30 pts
    attestation_bonus = min(approved_atts * 2.0, 10.0)  # up to +10 pts

    score = (
        compliance_pct * 0.5
        + coverage_pct * 0.3
        + freshness_pct * 0.2
        - poam_penalty
        + attestation_bonus
    )
    score = max(0.0, min(100.0, score))

    style = _pct_style(score)
    console.print(f"\n[bold]Readiness Score \u2014 {framework}[/bold]")
    console.print(f"  [{style}][bold]{score:.0f} / 100[/bold][/]  {_score_label(score)}\n")

    table = Table(title="Score Breakdown")
    table.add_column("Component", style="cyan")
    table.add_column("Weight")
    table.add_column("Value", justify="right")
    table.add_column("Contribution", justify="right")

    table.add_row("Compliance rate", "50%", f"{compliance_pct:.0f}%", f"{compliance_pct * 0.5:.1f}")
    table.add_row("Control coverage", "30%", f"{coverage_pct:.0f}%", f"{coverage_pct * 0.3:.1f}")
    table.add_row(
        "Evidence freshness", "20%", f"{freshness_pct:.0f}%", f"{freshness_pct * 0.2:.1f}"
    )
    table.add_row("Open POA&Ms penalty", "\u2014", str(open_poams), f"-{poam_penalty:.1f}")
    table.add_row("Attestation bonus", "\u2014", str(approved_atts), f"+{attestation_bonus:.1f}")

    console.print(table)


# ---------------------------------------------------------------------------
# pre-audit
# ---------------------------------------------------------------------------


@comply.command("pre-audit")
@click.argument("framework")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["md", "json"]),
    default="md",
    show_default=True,
    help="Output format",
)
def pre_audit(framework: str, output_format: str) -> None:
    """Generate a pre-audit report for a framework."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation, ControlResult, POAM

    init_db()
    with get_session() as session:
        results = session.query(ControlResult).filter(ControlResult.framework == framework).all()
        poams = session.query(POAM).filter(POAM.framework == framework).all()
        attestations = session.query(Attestation).filter(Attestation.framework == framework).all()

    total = len(results)
    if not total:
        console.print(f"[yellow]No data for '{framework}'.[/yellow]")
        return

    compliant = sum(1 for r in results if r.status in ("compliant", "inherited_compliant"))
    non_compliant = sum(1 for r in results if r.status == "non_compliant")
    not_assessed = sum(1 for r in results if r.status == "not_assessed")
    open_poams = [p for p in poams if p.status not in ("completed", "verified", "closed")]
    overdue_poams = [
        p
        for p in open_poams
        if p.scheduled_completion and p.scheduled_completion < datetime.now(timezone.utc)
    ]
    approved_atts = sum(1 for a in attestations if a.status == "approved")

    compliance_pct = compliant / total * 100 if total else 0.0
    generated_at = datetime.now(timezone.utc).isoformat()

    if output_format == "json":
        report = {
            "framework": framework,
            "generated_at": generated_at,
            "total_controls": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "not_assessed": not_assessed,
            "compliance_pct": round(compliance_pct, 1),
            "open_poams": len(open_poams),
            "overdue_poams": len(overdue_poams),
            "approved_attestations": approved_atts,
        }
        console.print_json(json.dumps(report, default=str))
        return

    # Markdown output
    lines = [
        f"# Pre-Audit Report: {framework}",
        f"Generated: {generated_at}",
        "",
        "## Executive Summary",
        f"- **Total controls assessed:** {total}",
        f"- **Compliant:** {compliant} ({compliance_pct:.0f}%)",
        f"- **Non-compliant:** {non_compliant}",
        f"- **Not assessed:** {not_assessed}",
        "",
        "## POA&M Status",
        f"- Open POA&Ms: {len(open_poams)}",
        f"- Overdue POA&Ms: {len(overdue_poams)}",
        "",
        "## Attestations",
        f"- Approved attestations: {approved_atts}",
        "",
        "## Recommendation",
    ]

    if non_compliant == 0 and not open_poams:
        lines.append(
            "The system is **ready for audit**. All controls are compliant and no open POA&Ms exist."
        )
    else:
        lines.append(
            f"Address {non_compliant} non-compliant controls and {len(open_poams)} open POA&Ms before audit."
        )

    console.print("\n".join(lines))


# ---------------------------------------------------------------------------
# remediation-plan
# ---------------------------------------------------------------------------


@comply.command("remediation-plan")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high"]),
    default=None,
    help="Filter by severity",
)
def remediation_plan(framework: str | None, severity: str | None) -> None:
    """Generate a prioritized remediation plan for non-compliant controls."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(ControlResult).filter(ControlResult.status == "non_compliant")
        if framework:
            q = q.filter(ControlResult.framework == framework)
        if severity:
            q = q.filter(ControlResult.severity == severity)
        results = q.order_by(ControlResult.severity).limit(300).all()

    if not results:
        console.print("[green]No non-compliant controls found for the given filters.[/green]")
        return

    # Deduplicate by (framework, control_id) keeping earliest result
    seen: dict[tuple[str, str], ControlResult] = {}
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for r in results:
        key = (r.framework, r.control_id)
        if key not in seen or sev_rank.get(r.severity.lower(), 9) < sev_rank.get(
            seen[key].severity.lower(), 9
        ):
            seen[key] = r

    table = Table(title=f"Prioritized Remediation Plan ({len(seen)} controls)")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Framework", style="cyan")
    table.add_column("Control")
    table.add_column("Severity")
    table.add_column("Effort")
    table.add_column("Action", max_width=55)

    sev_styles: dict[str, str] = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "green",
    }
    effort_map: dict[str, str] = {
        "critical": "High",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    sorted_results = sorted(seen.values(), key=lambda r: sev_rank.get(r.severity.lower(), 9))

    for i, r in enumerate(sorted_results, 1):
        sev = r.severity.lower()
        action = (
            r.remediation_summary or "Re-run pipeline after remediation; see 'warlock remediate'."
        )
        table.add_row(
            str(i),
            r.framework,
            r.control_id,
            f"[{sev_styles.get(sev, '')}]{sev}[/]",
            effort_map.get(sev, "Medium"),
            action[:55],
        )

    console.print(table)
    console.print(
        "\n[dim]Tip: Run 'warlock remediate <id>' for step-by-step guidance on each control.[/dim]"
    )


# ---------------------------------------------------------------------------
# control-effectiveness
# ---------------------------------------------------------------------------


@comply.command("control-effectiveness")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def control_effectiveness(framework: str | None) -> None:
    """Analyze control pass/fail rates grouped by framework."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        results = _framework_results(session, framework)

    if not results:
        console.print("[dim]No control results found.[/dim]")
        return

    # Group by framework → control_id
    fw_stats: dict[str, dict] = {}
    for r in results:
        fw = r.framework
        if fw not in fw_stats:
            fw_stats[fw] = {"total": 0, "compliant": 0, "non_compliant": 0, "partial": 0}
        fw_stats[fw]["total"] += 1
        if r.status in ("compliant", "inherited_compliant"):
            fw_stats[fw]["compliant"] += 1
        elif r.status == "non_compliant":
            fw_stats[fw]["non_compliant"] += 1
        elif r.status == "partial":
            fw_stats[fw]["partial"] += 1

    table = Table(title="Control Effectiveness by Framework")
    table.add_column("Framework", style="cyan")
    table.add_column("Total", justify="right")
    table.add_column("Compliant", justify="right")
    table.add_column("Non-Compliant", justify="right")
    table.add_column("Partial", justify="right")
    table.add_column("Pass Rate", justify="right")

    for fw in sorted(fw_stats):
        s = fw_stats[fw]
        pass_rate = s["compliant"] / s["total"] * 100 if s["total"] else 0.0
        style = _pct_style(pass_rate)
        table.add_row(
            fw,
            str(s["total"]),
            f"[green]{s['compliant']}[/green]",
            f"[red]{s['non_compliant']}[/red]",
            str(s["partial"]),
            f"[{style}]{pass_rate:.0f}%[/]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# benchmark
# ---------------------------------------------------------------------------


@comply.command("benchmark")
@click.option("--framework", "-f", default=None, help="Focus on a specific framework")
@click.option("--output", "-o", default=None, help="Write output to file instead of terminal")
def benchmark(framework: str | None, output: str | None) -> None:
    """Compare compliance posture across all active frameworks."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        results = _framework_results(session, framework)

    if not results:
        console.print("[dim]No control results found.[/dim]")
        return

    fw_stats: dict[str, dict] = {}
    for r in results:
        fw = r.framework
        if fw not in fw_stats:
            fw_stats[fw] = {"total": 0, "compliant": 0}
        fw_stats[fw]["total"] += 1
        if r.status in ("compliant", "inherited_compliant"):
            fw_stats[fw]["compliant"] += 1

    table = Table(title="Compliance Benchmark Across Frameworks")
    table.add_column("Framework", style="cyan")
    table.add_column("Controls", justify="right")
    table.add_column("Compliant", justify="right")
    table.add_column("Pass Rate", justify="right")
    table.add_column("Bar")

    for fw in sorted(
        fw_stats,
        key=lambda k: fw_stats[k]["compliant"] / max(fw_stats[k]["total"], 1),
        reverse=True,
    ):
        s = fw_stats[fw]
        rate = s["compliant"] / s["total"] * 100 if s["total"] else 0.0
        bar_len = int(rate / 5)
        style = _pct_style(rate)
        bar = f"[{style}]{'█' * bar_len}{'░' * (20 - bar_len)}[/]"
        table.add_row(fw, str(s["total"]), str(s["compliant"]), f"[{style}]{rate:.0f}%[/]", bar)

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
# maturity-model
# ---------------------------------------------------------------------------


@comply.command("maturity-model")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def maturity_model(framework: str | None) -> None:
    """Assess GRC program maturity on a 1-5 scale."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation, AuditEntry, POAM

    init_db()
    with get_session() as session:
        results = _framework_results(session, framework)
        poam_count = session.query(POAM).count()
        attestation_count = (
            session.query(Attestation).filter(Attestation.status == "approved").count()
        )
        audit_entry_count = session.query(AuditEntry).count()

    total = len(results)
    compliant = sum(1 for r in results if r.status in ("compliant", "inherited_compliant"))
    compliance_pct = compliant / total * 100 if total else 0.0

    # Simplified maturity heuristic
    level_1 = True  # Always: platform exists
    level_2 = total > 0  # Data collected
    level_3 = compliance_pct >= 50 and poam_count > 0
    level_4 = compliance_pct >= 75 and attestation_count > 0
    level_5 = compliance_pct >= 90 and audit_entry_count > 1000

    levels = [level_1, level_2, level_3, level_4, level_5]
    maturity = sum(1 for lvl_passed in levels if lvl_passed)

    labels = {
        1: "Initial — ad-hoc processes, no formal data collection",
        2: "Defined — telemetry collected, controls assessed",
        3: "Managed — POA&Ms tracked, gaps identified",
        4: "Measured — attestations approved, >75% compliant",
        5: "Optimizing — continuous compliance, >90% compliant",
    }
    styles = {1: "red", 2: "orange3", 3: "yellow", 4: "cyan", 5: "green bold"}

    console.print(
        f"\n[bold]GRC Maturity Assessment{f' \u2014 {framework}' if framework else ''}[/bold]"
    )
    console.print(f"  [{styles[maturity]}][bold]Level {maturity}/5[/bold][/]  {labels[maturity]}\n")

    table = Table(title="Maturity Level Breakdown")
    table.add_column("Level", justify="right")
    table.add_column("Description")
    table.add_column("Achieved")

    for lvl in range(1, 6):
        achieved = levels[lvl - 1]
        icon = "[green]\u2713[/green]" if achieved else "[dim]\u25cb[/dim]"
        table.add_row(str(lvl), labels[lvl], icon)

    console.print(table)


# ---------------------------------------------------------------------------
# quick-wins
# ---------------------------------------------------------------------------


@comply.command("quick-wins")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--limit", "-n", default=10, show_default=True, help="Max items to show")
def quick_wins(framework: str | None, limit: int) -> None:
    """Identify lowest-effort, highest-impact compliance improvements."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(ControlResult).filter(ControlResult.status == "non_compliant")
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.all()

    if not results:
        console.print("[green]No non-compliant controls found.[/green]")
        return

    # Quick-win heuristic: low severity non-compliant results that likely
    # have simple remediations (they are "low" or "medium" severity)
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    # High impact = high severity rank (fixing critical is high impact)
    # Low effort proxy: "low" / "medium" severity

    seen: dict[tuple[str, str], ControlResult] = {}
    for r in results:
        key = (r.framework, r.control_id)
        if key not in seen or sev_rank.get(r.severity.lower(), 9) < sev_rank.get(
            seen[key].severity.lower(), 9
        ):
            seen[key] = r

    # Score: medium/low severity with a remediation summary available = quick win
    candidates = []
    for r in seen.values():
        sev = r.severity.lower()
        effort = 1 if sev in ("low", "medium") else 3
        impact = 5 - sev_rank.get(sev, 4)  # critical=5, high=4, medium=3, low=2, info=1
        has_remediation = 1 if r.remediation_summary else 0
        win_score = (impact * 2) - effort + has_remediation
        candidates.append((win_score, r))

    candidates.sort(key=lambda x: x[0], reverse=True)

    table = Table(
        title=f"Quick Wins ({min(limit, len(candidates))} of {len(candidates)} candidates)"
    )
    table.add_column("Score", justify="right", style="bold")
    table.add_column("Framework", style="cyan")
    table.add_column("Control")
    table.add_column("Severity")
    table.add_column("Has Guidance")
    table.add_column("Remediation", max_width=50)

    sev_styles: dict[str, str] = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "green",
    }

    for score, r in candidates[:limit]:
        sev = r.severity.lower()
        guidance = "[green]yes[/green]" if r.remediation_summary else "[dim]no[/dim]"
        table.add_row(
            str(score),
            r.framework,
            r.control_id,
            f"[{sev_styles.get(sev, '')}]{sev}[/]",
            guidance,
            (r.remediation_summary or "")[:50],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# regression-check
# ---------------------------------------------------------------------------


@comply.command("regression-check")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--days", "-d", default=7, show_default=True, help="Lookback window in days")
def regression_check(framework: str | None, days: int) -> None:
    """Identify controls that have regressed (pass -> fail) recently."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    with get_session() as session:
        # Recent non-compliant results
        q_recent = session.query(ControlResult).filter(
            ControlResult.status == "non_compliant", ControlResult.assessed_at >= cutoff
        )
        if framework:
            q_recent = q_recent.filter(ControlResult.framework == framework)
        recent_failures = q_recent.all()

        # Earlier compliant results for the same (framework, control_id)
        regressions = []
        for r in recent_failures:
            earlier = (
                session.query(ControlResult)
                .filter(
                    ControlResult.framework == r.framework,
                    ControlResult.control_id == r.control_id,
                    ControlResult.status.in_(["compliant", "inherited_compliant"]),
                    ControlResult.assessed_at < cutoff,
                )
                .order_by(ControlResult.assessed_at.desc())
                .first()
            )
            if earlier:
                regressions.append((r, earlier))

    if not regressions:
        console.print(f"[green]No regressions detected in the past {days} days.[/green]")
        return

    table = Table(title=f"Control Regressions in Last {days} Days ({len(regressions)} found)")
    table.add_column("Framework", style="cyan")
    table.add_column("Control")
    table.add_column("Severity")
    table.add_column("Last Passed")
    table.add_column("Failed At")

    sev_styles: dict[str, str] = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "green",
    }

    for current, previous in sorted(regressions, key=lambda x: x[0].assessed_at, reverse=True):
        sev = current.severity.lower()
        table.add_row(
            current.framework,
            current.control_id,
            f"[{sev_styles.get(sev, '')}]{sev}[/]",
            previous.assessed_at.strftime("%Y-%m-%d %H:%M"),
            current.assessed_at.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# continuous-compliance
# ---------------------------------------------------------------------------


@comply.command("continuous-compliance")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def continuous_compliance(framework: str | None) -> None:
    """Show current continuous compliance percentage by framework."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        results = _framework_results(session, framework)

    if not results:
        console.print("[dim]No control results found.[/dim]")
        return

    fw_stats: dict[str, dict] = {}
    for r in results:
        fw = r.framework
        if fw not in fw_stats:
            fw_stats[fw] = {"total": 0, "compliant": 0}
        fw_stats[fw]["total"] += 1
        if r.status in ("compliant", "inherited_compliant"):
            fw_stats[fw]["compliant"] += 1

    table = Table(title="Continuous Compliance Status")
    table.add_column("Framework", style="cyan")
    table.add_column("Controls", justify="right")
    table.add_column("Compliant", justify="right")
    table.add_column("Compliance %", justify="right")
    table.add_column("Status")

    for fw in sorted(fw_stats):
        s = fw_stats[fw]
        pct = s["compliant"] / s["total"] * 100 if s["total"] else 0.0
        style = _pct_style(pct)
        status_label = (
            "[green]In Compliance[/green]"
            if pct >= 80
            else "[yellow]Partial[/yellow]"
            if pct >= 50
            else "[red bold]Out of Compliance[/red bold]"
        )
        table.add_row(
            fw,
            str(s["total"]),
            str(s["compliant"]),
            f"[{style}]{pct:.0f}%[/]",
            status_label,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# debt
# ---------------------------------------------------------------------------


@comply.command("debt")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def debt(framework: str | None) -> None:
    """Show compliance debt: overdue POA&Ms, expired attestations, stale evidence."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation, ControlResult, POAM

    init_db()
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=30)

    with get_session() as session:
        poam_q = session.query(POAM).filter(
            POAM.status.notin_(["completed", "verified", "closed"]),
            POAM.scheduled_completion < now,
        )
        if framework:
            poam_q = poam_q.filter(POAM.framework == framework)
        overdue_poams = poam_q.all()

        att_q = session.query(Attestation).filter(Attestation.status.in_(["draft", "submitted"]))
        if framework:
            att_q = att_q.filter(Attestation.framework == framework)
        pending_atts = att_q.all()

        cr_q = session.query(ControlResult).filter(ControlResult.assessed_at < stale_cutoff)
        if framework:
            cr_q = cr_q.filter(ControlResult.framework == framework)
        stale_results = cr_q.count()

    total_debt = len(overdue_poams) + len(pending_atts) + (1 if stale_results > 0 else 0)

    from rich.panel import Panel

    debt_style = "red bold" if total_debt > 10 else "yellow" if total_debt > 0 else "green"
    console.print(
        Panel(
            f"[bold]Compliance Debt{f' \u2014 {framework}' if framework else ''}[/bold]\n\n"
            f"[{debt_style}]Overdue POA&Ms:[/] {len(overdue_poams)}\n"
            f"Pending/draft attestations: {len(pending_atts)}\n"
            f"Stale evidence (>30 days): {stale_results} control results",
            title="[bold red]Compliance Debt[/bold red]",
            border_style="red" if total_debt > 0 else "green",
        )
    )

    if overdue_poams:
        table = Table(title="Overdue POA&Ms")
        table.add_column("ID", max_width=8, style="dim")
        table.add_column("Framework", style="cyan")
        table.add_column("Control")
        table.add_column("Severity")
        table.add_column("Due Date")
        table.add_column("Days Overdue", justify="right")

        for p in sorted(overdue_poams, key=lambda x: x.scheduled_completion or now):
            due = p.scheduled_completion
            overdue_days = (now - due).days if due else 0
            table.add_row(
                p.id[:8],
                p.framework,
                p.control_id,
                p.severity,
                due.strftime("%Y-%m-%d") if due else "\u2014",
                f"[red]{overdue_days}[/red]",
            )
        console.print(table)


# ---------------------------------------------------------------------------
# schedule-audit
# ---------------------------------------------------------------------------


@comply.command("schedule-audit")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def schedule_audit(framework: str | None) -> None:
    """Recommend an audit timeline based on current compliance posture."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM

    init_db()
    with get_session() as session:
        results = _framework_results(session, framework)
        open_poams = session.query(POAM).filter(
            POAM.status.notin_(["completed", "verified", "closed"])
        )
        if framework:
            open_poams = open_poams.filter(POAM.framework == framework)
        poam_count = open_poams.count()

    total = len(results)
    if not total:
        console.print(f"[yellow]No control results for '{framework or 'all frameworks'}'.[/yellow]")
        return

    compliant = sum(1 for r in results if r.status in ("compliant", "inherited_compliant"))
    compliance_pct = compliant / total * 100 if total else 0.0
    now = datetime.now(timezone.utc)

    # Recommend audit readiness date based on current posture
    if compliance_pct >= 90 and poam_count == 0:
        ready_in_days = 14
        recommendation = "Ready for audit within 2 weeks. Schedule now."
        style = "green"
    elif compliance_pct >= 75 and poam_count <= 5:
        ready_in_days = 45
        recommendation = "Address open gaps first. Target audit in ~45 days."
        style = "yellow"
    elif compliance_pct >= 50:
        ready_in_days = 90
        recommendation = "Significant gaps remain. Target audit in ~90 days."
        style = "orange3"
    else:
        ready_in_days = 180
        recommendation = "Major remediation needed. Target audit in ~6 months."
        style = "red"

    target_date = now + timedelta(days=ready_in_days)

    console.print(
        f"\n[bold]Audit Schedule Recommendation{f' \u2014 {framework}' if framework else ''}[/bold]"
    )
    console.print(f"  Current compliance: [{_pct_style(compliance_pct)}]{compliance_pct:.0f}%[/]")
    console.print(f"  Open POA&Ms: {poam_count}")
    console.print(f"  [{style}]{recommendation}[/]")
    console.print(f"  Suggested target date: [bold]{target_date.strftime('%Y-%m-%d')}[/bold]")
    console.print(
        f"\n[dim]Tip: Run 'warlock comply readiness-score {framework or '<framework>'}' for a detailed score.[/dim]"
    )


# ---------------------------------------------------------------------------
# executive-brief
# ---------------------------------------------------------------------------


@comply.command("executive-brief")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["md", "json"]),
    default="md",
    show_default=True,
    help="Output format",
)
@click.option("--output", "-o", default=None, help="Write output to file instead of terminal")
def executive_brief(framework: str | None, output_format: str, output: str | None) -> None:
    """Generate a one-page executive compliance brief."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation, POAM

    init_db()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        results = _framework_results(session, framework)
        poam_q = session.query(POAM).filter(POAM.status.notin_(["completed", "verified", "closed"]))
        if framework:
            poam_q = poam_q.filter(POAM.framework == framework)
        open_poams = poam_q.count()

        att_q = session.query(Attestation).filter(Attestation.status == "approved")
        if framework:
            att_q = att_q.filter(Attestation.framework == framework)
        approved_atts = att_q.count()

    total = len(results)
    compliant = sum(1 for r in results if r.status in ("compliant", "inherited_compliant"))
    non_compliant = sum(1 for r in results if r.status == "non_compliant")
    not_assessed = sum(1 for r in results if r.status == "not_assessed")
    compliance_pct = compliant / total * 100 if total else 0.0

    # Critical/high counts
    critical_nc = sum(
        1 for r in results if r.status == "non_compliant" and r.severity.lower() == "critical"
    )
    high_nc = sum(
        1 for r in results if r.status == "non_compliant" and r.severity.lower() == "high"
    )

    # Overall rating
    if compliance_pct >= 90 and critical_nc == 0:
        rating = "Strong"
    elif compliance_pct >= 75 and critical_nc == 0:
        rating = "Adequate"
    elif compliance_pct >= 50:
        rating = "Needs Improvement"
    else:
        rating = "At Risk"

    generated_at = now.isoformat()

    if output_format == "json":
        brief = {
            "generated_at": generated_at,
            "framework": framework or "all",
            "overall_rating": rating,
            "compliance_pct": round(compliance_pct, 1),
            "total_controls": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "not_assessed": not_assessed,
            "critical_non_compliant": critical_nc,
            "high_non_compliant": high_nc,
            "open_poams": open_poams,
            "approved_attestations": approved_atts,
        }
        content = json.dumps(brief, indent=2, default=str)
        if output:
            with open(output, "w") as f:
                f.write(content)
            console.print(f"[green]Report written to {output}[/green]")
        else:
            console.print_json(json.dumps(brief, default=str))
        return

    # Markdown
    rating_md = {
        "Strong": "**Strong**",
        "Adequate": "**Adequate**",
        "Needs Improvement": "**Needs Improvement**",
        "At Risk": "**:warning: At Risk**",
    }.get(rating, rating)

    lines = [
        f"# Executive Compliance Brief{f': {framework}' if framework else ''}",
        f"*Generated: {generated_at}*",
        "",
        f"## Overall Posture: {rating_md}",
        "",
        "## Key Metrics",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Compliance rate | {compliance_pct:.0f}% |",
        f"| Compliant controls | {compliant} / {total} |",
        f"| Non-compliant (critical) | {critical_nc} |",
        f"| Non-compliant (high) | {high_nc} |",
        f"| Not assessed | {not_assessed} |",
        f"| Open POA&Ms | {open_poams} |",
        f"| Approved attestations | {approved_atts} |",
        "",
        "## Executive Summary",
    ]

    if rating == "Strong":
        lines.append(
            f"The organization maintains a strong compliance posture with {compliance_pct:.0f}% "
            "of controls compliant. No critical findings are outstanding."
        )
    elif rating == "Adequate":
        lines.append(
            f"Compliance posture is adequate at {compliance_pct:.0f}%. "
            f"There are {non_compliant} non-compliant controls requiring attention."
        )
    else:
        lines.append(
            f"Compliance posture requires immediate attention: {compliance_pct:.0f}% compliant, "
            f"{critical_nc} critical and {high_nc} high severity gaps outstanding. "
            f"{open_poams} POA&Ms remain open."
        )

    lines += [
        "",
        "## Recommended Actions",
        f"1. Address {critical_nc} critical non-compliant controls immediately.",
        f"2. Resolve {open_poams} open POA&Ms, prioritizing overdue items.",
        "3. Run `warlock comply remediation-plan` for a prioritized fix list.",
        f"4. Run `warlock comply audit-prep {framework or '<framework>'}` for audit checklist.",
    ]

    content = "\n".join(lines)
    console.print(content)

    if output:
        with open(output, "w") as f:
            f.write(content)
        console.print(f"[green]Report written to {output}[/green]")
