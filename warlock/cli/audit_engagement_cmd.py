"""CLI commands for audit engagement management.

Groups:
  warlock audit engagement ...   -- create, list, show, status, package
  warlock audit findings-import  -- import findings from CSV
  warlock audit corrective-actions -- track corrective actions
"""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


@cli.group("audit", invoke_without_command=True)
@click.pass_context
def audit_grp(ctx: click.Context) -> None:
    """Manage audit engagements, findings, and corrective actions."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# engagement sub-group
# ---------------------------------------------------------------------------


@audit_grp.group("engagement", invoke_without_command=True)
@click.pass_context
def engagement_grp(ctx: click.Context) -> None:
    """Create and manage audit engagement periods."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@engagement_grp.command("create")
@click.option("--framework", "-f", required=True, help="Framework name (e.g. soc2, nist_800_53)")
@click.option("--name", "-n", required=True, help='Engagement name (e.g. "SOC 2 Type II 2025")')
@click.option(
    "--auditor",
    default=None,
    help="Auditor name (may include firm, e.g. 'Jane Smith, Deloitte')",
)
@click.option("--start-date", required=True, help="Period start date (YYYY-MM-DD)")
@click.option("--end-date", required=True, help="Period end date (YYYY-MM-DD)")
@click.option(
    "--actor",
    default=None,
    envvar="WLK_CLI_ACTOR",
    help="Actor identity for audit trail",
)
def engagement_create(
    framework: str,
    name: str,
    auditor: str | None,
    start_date: str,
    end_date: str,
    actor: str | None,
) -> None:
    """Create a new audit engagement."""
    import os
    from datetime import datetime, timezone
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEngagement

    if actor:
        os.environ["WLK_CLI_ACTOR"] = actor

    try:
        period_start = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        period_end = datetime.strptime(end_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        _error(f"Invalid date format: {exc}. Use YYYY-MM-DD.")

    if period_end <= period_start:
        _error("--end-date must be after --start-date.")

    # Parse optional "Name, Firm" pattern
    auditor_name: str | None = None
    auditor_firm: str | None = None
    if auditor:
        parts = [p.strip() for p in auditor.split(",", 1)]
        auditor_name = parts[0] if parts else None
        auditor_firm = parts[1] if len(parts) > 1 else None

    init_db()
    with get_session() as session:
        eng = AuditEngagement(
            name=name,
            framework=framework,
            period_start=period_start,
            period_end=period_end,
            auditor_name=auditor_name,
            auditor_firm=auditor_firm,
            status="active",
        )
        session.add(eng)
        session.flush()
        eng_id = eng.id

    console.print(f"[green]Engagement created:[/green] {eng_id[:8]}")
    console.print(f"  Name:      {name}")
    console.print(f"  Framework: {framework}")
    console.print(f"  Period:    {start_date} to {end_date}")
    if auditor_name:
        firm_str = f", {auditor_firm}" if auditor_firm else ""
        console.print(f"  Auditor:   {auditor_name}{firm_str}")


@engagement_grp.command("list")
@click.option("--status", "-s", default=None, help="Filter by status (active, completed, archived)")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
def engagement_list(
    status: str | None,
    framework: str | None,
    output_format: str,
) -> None:
    """List audit engagements."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEngagement

    init_db()
    with get_session() as session:
        q = session.query(AuditEngagement)
        if status:
            q = q.filter(AuditEngagement.status == status)
        if framework:
            q = q.filter(AuditEngagement.framework == framework)
        rows = q.order_by(AuditEngagement.created_at.desc()).all()
        data = [
            {
                "id": r.id,
                "name": r.name,
                "framework": r.framework,
                "status": r.status,
                "period_start": str(r.period_start)[:10],
                "period_end": str(r.period_end)[:10],
                "auditor_name": r.auditor_name or "",
                "auditor_firm": r.auditor_firm or "",
            }
            for r in rows
        ]

    if not data:
        console.print("[dim]No engagements found.[/dim]")
        return

    if output_format == "json":
        import json

        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Audit Engagements ({len(data)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", max_width=35)
    table.add_column("Framework", style="cyan")
    table.add_column("Status")
    table.add_column("Period")
    table.add_column("Auditor", max_width=25)

    for r in data:
        status_style = {
            "active": "green",
            "completed": "blue",
            "archived": "dim",
        }.get(r["status"], "")
        auditor_str = r["auditor_name"]
        if r["auditor_firm"]:
            auditor_str += f" ({r['auditor_firm']})"
        table.add_row(
            r["id"][:8],
            r["name"][:35],
            r["framework"],
            f"[{status_style}]{r['status']}[/]",
            f"{r['period_start']} \u2013 {r['period_end']}",
            auditor_str[:25],
        )

    console.print(table)


@engagement_grp.command("show")
@click.argument("engagement_id")
def engagement_show(engagement_id: str) -> None:
    """Show details of an audit engagement."""
    from rich.panel import Panel
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEngagement, AuditComment

    init_db()
    with get_session() as session:
        eng = (
            session.query(AuditEngagement)
            .filter(AuditEngagement.id.startswith(engagement_id))
            .first()
        )
        if not eng:
            _error(f"Engagement not found: {engagement_id}")

        comments = (
            session.query(AuditComment)
            .filter(AuditComment.engagement_id == eng.id)
            .order_by(AuditComment.created_at.desc())
            .limit(10)
            .all()
        )
        comment_rows = [
            {
                "author": c.author,
                "role": c.author_role or "",
                "content": c.content[:80],
                "resolved": c.resolved,
                "created_at": str(c.created_at)[:19],
            }
            for c in comments
        ]
        eng_data = {
            "id": eng.id,
            "name": eng.name,
            "framework": eng.framework,
            "status": eng.status,
            "period_start": str(eng.period_start)[:10],
            "period_end": str(eng.period_end)[:10],
            "auditor_name": eng.auditor_name,
            "auditor_firm": eng.auditor_firm,
            "in_scope_controls": eng.in_scope_controls or [],
            "excluded_controls": eng.excluded_controls or [],
            "created_at": str(eng.created_at)[:19],
            "completed_at": str(eng.completed_at)[:19] if eng.completed_at else None,
        }

    firm_str = f", {eng_data['auditor_firm']}" if eng_data["auditor_firm"] else ""
    auditor_str = f"{eng_data['auditor_name']}{firm_str}" if eng_data["auditor_name"] else "\u2014"
    in_scope = (
        ", ".join(eng_data["in_scope_controls"][:5])
        + (
            f" (+{len(eng_data['in_scope_controls']) - 5} more)"
            if len(eng_data["in_scope_controls"]) > 5
            else ""
        )
        if eng_data["in_scope_controls"]
        else "all controls"
    )

    console.print(
        Panel(
            f"[bold]{eng_data['name']}[/bold]\n\n"
            f"ID: {eng_data['id'][:8]}  |  Framework: {eng_data['framework']}  |  "
            f"Status: {eng_data['status']}\n"
            f"Period: {eng_data['period_start']} to {eng_data['period_end']}\n"
            f"Auditor: {auditor_str}\n"
            f"In-scope controls: {in_scope}\n"
            f"Created: {eng_data['created_at']}"
            + (f"  |  Completed: {eng_data['completed_at']}" if eng_data["completed_at"] else ""),
            title="[bold cyan]Audit Engagement[/bold cyan]",
            border_style="cyan",
        )
    )

    if comment_rows:
        console.print("\n[bold]Recent Comments:[/bold]")
        for c in comment_rows:
            resolved_str = " [dim](resolved)[/dim]" if c["resolved"] else ""
            console.print(
                f"  [{c['created_at']}] [cyan]{c['author']}[/cyan] "
                f"[dim]({c['role']})[/dim]{resolved_str}: {c['content']}"
            )


@engagement_grp.command("status")
@click.argument("engagement_id")
def engagement_status(engagement_id: str) -> None:
    """Show progress summary for an engagement (control coverage, open items)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEngagement, ControlResult, AuditComment

    init_db()
    with get_session() as session:
        eng = (
            session.query(AuditEngagement)
            .filter(AuditEngagement.id.startswith(engagement_id))
            .first()
        )
        if not eng:
            _error(f"Engagement not found: {engagement_id}")

        # Control result counts for framework
        result_counts: dict[str, int] = {}
        results = (
            session.query(ControlResult.status)
            .filter(ControlResult.framework == eng.framework)
            .all()
        )
        for (s,) in results:
            result_counts[s] = result_counts.get(s, 0) + 1

        total_results = sum(result_counts.values())

        # Open comments
        open_comments = (
            session.query(AuditComment)
            .filter(
                AuditComment.engagement_id == eng.id,
                AuditComment.resolved == False,  # noqa: E712
            )
            .count()
        )
        total_comments = (
            session.query(AuditComment).filter(AuditComment.engagement_id == eng.id).count()
        )

    console.print(f"\n[bold cyan]Engagement Status: {escape(eng.name or '')}[/bold cyan]")
    console.print(f"  Framework: {eng.framework}  |  Status: {eng.status}")
    console.print(f"  Period: {str(eng.period_start)[:10]} to {str(eng.period_end)[:10]}")

    if total_results:
        table = Table(title="Control Result Summary")
        table.add_column("Status", style="cyan")
        table.add_column("Count", justify="right")
        table.add_column("Pct", justify="right")
        for s, count in sorted(result_counts.items(), key=lambda x: -x[1]):
            pct = f"{count / total_results * 100:.1f}%"
            table.add_row(s, str(count), pct)
        table.add_row("[bold]Total[/bold]", f"[bold]{total_results}[/bold]", "100%")
        console.print(table)
    else:
        console.print("  [dim]No control results for this framework yet.[/dim]")

    console.print(f"\n  Comments: {total_comments} total, [yellow]{open_comments} open[/yellow]")


@engagement_grp.command("package")
@click.argument("engagement_id")
@click.option(
    "--output",
    "-o",
    default=".",
    help="Output directory for the evidence binder",
    type=click.Path(file_okay=False),
)
def engagement_package(engagement_id: str, output: str) -> None:
    """Generate evidence binder package for an engagement."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEngagement

    init_db()
    with get_session() as session:
        eng = (
            session.query(AuditEngagement)
            .filter(AuditEngagement.id.startswith(engagement_id))
            .first()
        )
        if not eng:
            _error(f"Engagement not found: {engagement_id}")
        eng_name = eng.name
        eng_framework = eng.framework
        eng_id = eng.id

    console.print(f"[cyan]Generating evidence binder for:[/cyan] {eng_name}")
    console.print(f"  Framework: {eng_framework}")
    console.print(f"  Output:    {output}/")

    try:
        from warlock.export.binder import generate_binder

        outfile = generate_binder(eng_id, output_dir=output)
        console.print(f"[green]Binder written:[/green] {outfile}")
    except Exception as exc:
        # Binder generation is best-effort; surface the error without crashing
        console.print(f"[yellow]Binder generation error: {exc.__class__.__name__}: {exc}[/yellow]")
        console.print(
            "[dim]Tip: run 'warlock export binder' for full binder generation options.[/dim]"
        )


# ---------------------------------------------------------------------------
# findings-import command (top-level under audit group)
# ---------------------------------------------------------------------------


@audit_grp.command("findings-import")
@click.argument("engagement_id")
@click.option(
    "--file",
    "-f",
    "import_file",
    required=True,
    help="CSV file of findings to import",
    type=click.Path(exists=True, readable=True),
)
@click.option(
    "--actor",
    default=None,
    envvar="WLK_CLI_ACTOR",
    help="Actor identity for audit trail",
)
def findings_import(engagement_id: str, import_file: str, actor: str | None) -> None:
    """Import findings from a CSV file into an engagement.

    Expected CSV columns: control_id, framework, status, severity, notes
    """
    import csv
    import os
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEngagement, AuditComment

    if actor:
        os.environ["WLK_CLI_ACTOR"] = actor
    actor_id = actor or _get_actor()

    init_db()
    with get_session() as session:
        eng = (
            session.query(AuditEngagement)
            .filter(AuditEngagement.id.startswith(engagement_id))
            .first()
        )
        if not eng:
            _error(f"Engagement not found: {engagement_id}")
        eng_id = eng.id

    imported = 0
    skipped = 0

    with open(import_file, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        rows_to_add: list[dict] = []
        for row in reader:
            control_id = (row.get("control_id") or "").strip()
            if not control_id:
                skipped += 1
                continue
            rows_to_add.append(
                {
                    "control_id": control_id,
                    "framework": (row.get("framework") or "").strip(),
                    "status": (row.get("status") or "").strip(),
                    "severity": (row.get("severity") or "").strip(),
                    "notes": (row.get("notes") or "").strip(),
                }
            )

    with get_session() as session:
        for row in rows_to_add:
            notes = row["notes"] or f"Imported finding: {row['control_id']} [{row['status']}]"
            comment = AuditComment(
                engagement_id=eng_id,
                target_type="control",
                target_id=row["control_id"],
                author=actor_id,
                author_role="practitioner",
                content=notes,
            )
            session.add(comment)
            imported += 1

    console.print(
        f"[green]Imported {imported} finding(s)[/green] "
        f"({'skipped ' + str(skipped) if skipped else 'no skips'}) "
        f"into engagement {engagement_id[:8]}."
    )


# ---------------------------------------------------------------------------
# corrective-actions command (top-level under audit group)
# ---------------------------------------------------------------------------


@audit_grp.command("corrective-actions")
@click.argument("engagement_id")
@click.option("--status", "-s", default=None, help="Filter by status (open, resolved)")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
def corrective_actions(
    engagement_id: str,
    status: str | None,
    output_format: str,
) -> None:
    """List corrective action comments for an engagement.

    Corrective actions are tracked as unresolved audit comments of role 'practitioner'.
    Use 'warlock audit engagement show <id>' to see all comment threads.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEngagement, AuditComment

    init_db()
    with get_session() as session:
        eng = (
            session.query(AuditEngagement)
            .filter(AuditEngagement.id.startswith(engagement_id))
            .first()
        )
        if not eng:
            _error(f"Engagement not found: {engagement_id}")
        eng_id = eng.id

        q = session.query(AuditComment).filter(AuditComment.engagement_id == eng_id)
        if status == "open":
            q = q.filter(AuditComment.resolved == False)  # noqa: E712
        elif status == "resolved":
            q = q.filter(AuditComment.resolved == True)  # noqa: E712
        comments = q.order_by(AuditComment.created_at.desc()).all()

        data = [
            {
                "id": c.id,
                "target_type": c.target_type,
                "target_id": c.target_id,
                "author": c.author,
                "role": c.author_role or "",
                "content": c.content[:100],
                "resolved": c.resolved,
                "created_at": str(c.created_at)[:19],
            }
            for c in comments
        ]

    if not data:
        console.print("[dim]No corrective actions found.[/dim]")
        return

    if output_format == "json":
        import json

        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Corrective Actions — {eng.name} ({len(data)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Target Type")
    table.add_column("Target ID", max_width=15)
    table.add_column("Author", max_width=20)
    table.add_column("Status")
    table.add_column("Content", max_width=50)
    table.add_column("Created")

    for r in data:
        resolved_str = "[dim]resolved[/dim]" if r["resolved"] else "[yellow]open[/yellow]"
        table.add_row(
            r["id"][:8],
            r["target_type"],
            r["target_id"][:15],
            r["author"][:20],
            resolved_str,
            r["content"][:50],
            r["created_at"],
        )

    console.print(table)
