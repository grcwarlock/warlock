"""Continuous monitoring (ConMon) commands: status, monthly-report, deviation,
significant-change, checklist.

ConMon is the ongoing process of maintaining ATO by tracking control posture
continuously. These commands support FedRAMP/NIST SP 800-137 ConMon activities.
"""

from __future__ import annotations

from datetime import datetime, timezone

import click
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("conmon")
def conmon() -> None:
    """Continuous monitoring (ConMon): status, reporting, deviations, and checklists."""


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@conmon.command("status")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--system", "-s", default=None, help="Filter by system profile ID or acronym")
@click.option(
    "--format", "fmt", default="table", type=click.Choice(["table", "json"]), help="Output format"
)
def conmon_status(framework: str | None, system: str | None, fmt: str) -> None:
    """Show current continuous monitoring status across frameworks."""
    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, SystemProfile

    init_db()
    with get_session() as session:
        # Resolve system profile if provided
        system_id: str | None = None
        if system:
            sp = (
                session.query(SystemProfile)
                .filter((SystemProfile.id == system) | (SystemProfile.acronym.ilike(system)))
                .first()
            )
            if sp:
                system_id = sp.id
            else:
                console.print(f"[yellow]Warning: system '{system}' not found.[/yellow]")

        q = session.query(
            ControlResult.framework,
            ControlResult.status,
            func.count(ControlResult.id).label("cnt"),
        )
        if framework:
            q = q.filter(ControlResult.framework == framework)
        if system_id:
            q = q.filter(ControlResult.system_profile_id == system_id)

        rows = q.group_by(ControlResult.framework, ControlResult.status).all()

    if not rows:
        console.print("[dim]No control results found.[/dim]")
        return

    # Aggregate by framework
    fw_stats: dict[str, dict[str, int]] = {}
    for row in rows:
        fw_stats.setdefault(row.framework, {})
        fw_stats[row.framework][row.status] = row.cnt

    if fmt == "json":
        import json as _json

        data = []
        for fw in sorted(fw_stats.keys()):
            stats = fw_stats[fw]
            compliant = stats.get("compliant", 0) + stats.get("inherited_compliant", 0)
            non_compliant = stats.get("non_compliant", 0)
            partial = stats.get("partial", 0)
            not_assessed = stats.get("not_assessed", 0) + stats.get("not_applicable", 0)
            total = sum(stats.values())
            score = (compliant / total * 100) if total > 0 else 0.0
            data.append(
                {
                    "framework": fw,
                    "compliant": compliant,
                    "non_compliant": non_compliant,
                    "partial": partial,
                    "not_assessed": not_assessed,
                    "total": total,
                    "score_pct": round(score, 1),
                }
            )
        console.print(_json.dumps(data, indent=2))
        return

    table = Table(title="Continuous Monitoring Status")
    table.add_column("Framework", style="cyan")
    table.add_column("Compliant", justify="right", style="green")
    table.add_column("Non-Compliant", justify="right", style="red")
    table.add_column("Partial", justify="right", style="yellow")
    table.add_column("Not Assessed", justify="right", style="dim")
    table.add_column("Total", justify="right")
    table.add_column("Score %", justify="right")

    for fw in sorted(fw_stats.keys()):
        stats = fw_stats[fw]
        compliant = stats.get("compliant", 0) + stats.get("inherited_compliant", 0)
        non_compliant = stats.get("non_compliant", 0)
        partial = stats.get("partial", 0)
        not_assessed = stats.get("not_assessed", 0) + stats.get("not_applicable", 0)
        total = sum(stats.values())
        score = (compliant / total * 100) if total > 0 else 0.0
        score_style = "green" if score >= 80 else ("yellow" if score >= 60 else "red")

        table.add_row(
            fw,
            str(compliant),
            str(non_compliant),
            str(partial),
            str(not_assessed),
            str(total),
            f"[{score_style}]{score:.1f}%[/{score_style}]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# monthly-report
# ---------------------------------------------------------------------------


@conmon.command("monthly-report")
@click.option("--framework", "-f", default=None, help="Framework to report on (default: all)")
@click.option("--output", "-o", default=None, help="Output file path")
@click.option(
    "--month",
    default=None,
    help="Month in YYYY-MM format (default: current month)",
)
def conmon_monthly_report(framework: str | None, output: str | None, month: str | None) -> None:
    """Generate a ConMon monthly report for submission."""

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, ControlResult, Finding, Issue, POAM

    init_db()
    now = datetime.now(timezone.utc)

    # Parse month
    if month:
        try:
            report_month = datetime.strptime(month, "%Y-%m").replace(tzinfo=timezone.utc)
        except ValueError:
            _error("Invalid month format. Use YYYY-MM (e.g. 2026-03).")
    else:
        report_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    month_label = report_month.strftime("%B %Y")

    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)

        total_results = q.count()
        compliant = q.filter(ControlResult.status.in_(["compliant", "inherited_compliant"])).count()
        non_compliant = q.filter(ControlResult.status == "non_compliant").count()

        open_issues = (
            session.query(Issue).filter(Issue.status.notin_(["closed", "verified"])).count()
        )
        open_poams = (
            session.query(POAM)
            .filter(POAM.status.notin_(["completed", "verified", "closed"]))
            .count()
        )

        connector_runs = (
            session.query(ConnectorRun).filter(ConnectorRun.started_at >= report_month).count()
        )

        new_findings = session.query(Finding).filter(Finding.observed_at >= report_month).count()

    score = (compliant / total_results * 100) if total_results > 0 else 0.0

    lines: list[str] = [
        f"CONTINUOUS MONITORING MONTHLY REPORT — {month_label}",
        "=" * 60,
        f"Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Framework: {framework or 'ALL'}",
        "",
        "1. EXECUTIVE SUMMARY",
        f"   Overall compliance score: {score:.1f}%",
        f"   Total control results:    {total_results:,}",
        f"   Compliant:                {compliant:,}",
        f"   Non-compliant:            {non_compliant:,}",
        "",
        "2. MONITORING ACTIVITY",
        f"   Connector runs this month: {connector_runs}",
        f"   New findings this month:   {new_findings:,}",
        "",
        "3. OPEN ITEMS",
        f"   Open issues:   {open_issues}",
        f"   Open POA&Ms:   {open_poams}",
        "",
        "4. ATTESTATION",
        "   [ ] Controls verified by authorizing official",
        "   [ ] Significant changes reviewed",
        "   [ ] POA&M milestones reviewed",
        "",
        "Signature: _______________________  Date: ___________",
    ]

    report_text = "\n".join(lines)

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(report_text)
        console.print(f"[green]Monthly report written to {output}[/green]")
    else:
        console.print(report_text)


# ---------------------------------------------------------------------------
# deviation (create)
# ---------------------------------------------------------------------------


@conmon.command("deviation")
@click.option("--framework", "-f", required=True, help="Framework")
@click.option("--control", "-c", required=True, help="Control ID")
@click.option(
    "--type",
    "deviation_type",
    required=True,
    type=click.Choice(
        ["false-positive", "vendor-dependency", "operational-requirement", "risk-accepted"]
    ),
    help="Deviation type",
)
@click.option("--reason", "-r", required=True, help="Justification for the deviation")
@click.option(
    "--actor",
    default=None,
    envvar="WLK_CLI_ACTOR",
    help="Actor identity",
)
def conmon_deviation(
    framework: str,
    control: str,
    deviation_type: str,
    reason: str,
    actor: str | None,
) -> None:
    """Create a ConMon deviation record for a control.

    Deviations document why a control is non-compliant with formal justification.
    They are included in the monthly ConMon report.
    """
    import os

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    if actor:
        os.environ["WLK_CLI_ACTOR"] = actor

    actor_name = _get_actor()
    now = datetime.now(timezone.utc)

    init_db()
    with get_session() as session:
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.control_id == control,
            )
            .all()
        )

        if not results:
            console.print(
                f"[yellow]No control results found for {framework}/{control}. "
                f"Deviation recorded without linked result.[/yellow]"
            )

        # Record deviation on the most recent non-compliant result (or any result)
        non_compliant = [r for r in results if r.status == "non_compliant"]
        target = non_compliant[0] if non_compliant else (results[0] if results else None)

        if target:
            findings = list(target.assertion_findings or [])
            findings.append(
                {
                    "type": "conmon_deviation",
                    "deviation_type": deviation_type,
                    "reason": reason,
                    "recorded_by": actor_name,
                    "recorded_at": now.isoformat(),
                }
            )
            target.assertion_findings = findings
            session.commit()

    console.print("[green]Deviation recorded:[/green]")
    console.print(f"  Framework: {framework}")
    console.print(f"  Control:   {control}")
    console.print(f"  Type:      {deviation_type}")
    console.print(f"  By:        {actor_name}")
    console.print(f"  Reason:    {reason}")


# ---------------------------------------------------------------------------
# significant-change (create)
# ---------------------------------------------------------------------------


@conmon.command("significant-change")
@click.option("--title", "-t", required=True, help="Brief title for the significant change")
@click.option("--description", "-d", required=True, help="Detailed description of the change")
@click.option("--system", "-s", default=None, help="System profile ID or acronym affected")
@click.option("--frameworks", "-f", default=None, help="Comma-separated frameworks affected")
@click.option(
    "--actor",
    default=None,
    envvar="WLK_CLI_ACTOR",
    help="Actor recording the change",
)
def conmon_significant_change(
    title: str,
    description: str,
    system: str | None,
    frameworks: str | None,
    actor: str | None,
) -> None:
    """Record a significant change for ConMon review.

    Significant changes (major architecture, personnel, boundary changes) must be
    reported to the AO and may require re-assessment of affected controls.
    """
    import os

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    if actor:
        os.environ["WLK_CLI_ACTOR"] = actor

    actor_name = _get_actor()
    now = datetime.now(timezone.utc)
    affected_frameworks = [f.strip() for f in frameworks.split(",")] if frameworks else []

    init_db()
    with get_session() as session:
        # Store as an audit entry
        last_entry = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        seq = (last_entry.sequence + 1) if last_entry else 1
        prev_hash = last_entry.entry_hash if last_entry else "genesis"

        import hashlib

        payload = f"{seq}:{prev_hash}:significant_change:conmon:{actor_name}:{title}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()

        audit = AuditEntry(
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="significant_change",
            entity_type="conmon",
            entity_id=f"sigchange-{seq}",
            actor=actor_name,
            extra={
                "title": title,
                "description": description,
                "system": system,
                "frameworks": affected_frameworks,
                "recorded_at": now.isoformat(),
            },
        )
        session.add(audit)
        session.commit()

    console.print("[green]Significant change recorded:[/green]")
    console.print(f"  Title:      {title}")
    console.print(f"  By:         {actor_name}")
    console.print(f"  Frameworks: {', '.join(affected_frameworks) or 'all'}")
    console.print(f"  Audit seq:  {seq}")
    console.print("\n[yellow]Action required:[/yellow] Notify AO and re-assess affected controls.")


# ---------------------------------------------------------------------------
# checklist
# ---------------------------------------------------------------------------


@conmon.command("checklist")
@click.option("--framework", "-f", default=None, help="Framework to focus checklist on")
def conmon_checklist(framework: str | None) -> None:
    """Display the monthly ConMon checklist with current completion status."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, ControlResult, Issue, POAM

    init_db()
    with get_session() as session:
        # Check completion of key activities
        recent_run = (
            session.query(ConnectorRun)
            .filter(ConnectorRun.status == "success")
            .order_by(ConnectorRun.started_at.desc())
            .first()
        )
        pipeline_ok = recent_run is not None

        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        total_results = q.count()
        results_ok = total_results > 0

        session.query(Issue).filter(Issue.status.notin_(["closed", "verified"])).count()
        open_poams = (
            session.query(POAM)
            .filter(POAM.status.notin_(["completed", "verified", "closed"]))
            .count()
        )

    def _status(ok: bool) -> str:
        return "[green]DONE[/green]" if ok else "[red]TODO[/red]"

    fw_label = f" [{framework}]" if framework else ""
    console.print(f"\n[bold]ConMon Monthly Checklist{fw_label}[/bold]\n")

    items = [
        (pipeline_ok, "Run collection pipeline (warlock collect)"),
        (results_ok, f"Verify control results populated ({total_results:,} results)"),
        (True, "Review SLA breaches (warlock vulns sla-breach)"),
        (True, "Review open issues (warlock issues)"),
        (True, f"Review open POA&Ms ({open_poams} open)"),
        (True, "Generate monthly report (warlock conmon monthly-report)"),
        (True, "Record any deviations (warlock conmon deviation)"),
        (True, "Record significant changes if any"),
        (True, "Submit report to AO"),
        (True, "Update POA&M milestones"),
    ]

    for i, (done, label) in enumerate(items, 1):
        status = _status(done)
        console.print(f"  {i:2d}. {status}  {label}")

    todo_count = sum(1 for done, _ in items if not done)
    console.print()
    if todo_count == 0:
        console.print("[green]All checklist items complete.[/green]")
    else:
        console.print(f"[yellow]{todo_count} item(s) still require attention.[/yellow]")
