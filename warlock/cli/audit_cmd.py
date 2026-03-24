"""CLI commands for audit management workflows.

Adds commands to the existing audit group (defined in audit_engagement_cmd.py):
  warlock audit sample          -- statistical sampling for an engagement
  warlock audit workpapers      -- list/create workpapers
  warlock audit evidence-check  -- evidence validity check
  warlock audit package         -- assemble certification package summary
"""

from __future__ import annotations

import json

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import console, _error
from warlock.cli.audit_engagement_cmd import audit_grp


# ---------------------------------------------------------------------------
# audit sample
# ---------------------------------------------------------------------------


@audit_grp.command("sample")
@click.argument("engagement_id")
@click.option(
    "--confidence",
    "-c",
    default=0.95,
    type=click.FloatRange(0.80, 0.99),
    help="Confidence level (default 0.95)",
)
@click.option(
    "--margin",
    "-m",
    default=0.05,
    type=click.FloatRange(0.01, 0.20),
    help="Margin of error (default 0.05)",
)
@click.option("--seed", default=42, type=int, help="Random seed for reproducibility")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def audit_sample(
    engagement_id: str,
    confidence: float,
    margin: float,
    seed: int,
    fmt: str,
) -> None:
    """Select a statistically significant sample of controls for testing."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.audit_manager import AuditManager

    init_db()
    mgr = AuditManager()

    with get_session() as session:
        try:
            result = mgr.select_sample(
                session,
                engagement_id,
                confidence_level=confidence,
                margin_error=margin,
                seed=seed,
            )
        except ValueError as exc:
            _error(str(exc))

    if fmt == "json":
        console.print_json(json.dumps(result, indent=2))
        return

    console.print("\n[bold cyan]Sampling Results[/bold cyan]")
    console.print(f"  Engagement:       {result['engagement_id'][:8]}")
    console.print(f"  Population size:  {result['population_size']}")
    console.print(f"  Sample size:      {result['sample_size']}")
    console.print(f"  Confidence level: {result['confidence_level']:.0%}")
    console.print(f"  Margin of error:  {result['margin_error']:.0%}")

    selected = result["selected_control_ids"]
    if not selected:
        console.print("\n[dim]No controls in population to sample.[/dim]")
        return

    table = Table(title=f"Selected Controls ({len(selected)})")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Control ID", style="cyan")

    for i, ctrl_id in enumerate(selected, 1):
        table.add_row(str(i), ctrl_id)

    console.print(table)


# ---------------------------------------------------------------------------
# audit workpapers
# ---------------------------------------------------------------------------


@audit_grp.command("workpapers")
@click.argument("engagement_id")
@click.option(
    "--create",
    "create_mode",
    is_flag=True,
    default=False,
    help="Create a new workpaper interactively",
)
@click.option("--control-id", default=None, help="Control ID for new workpaper")
@click.option(
    "--template",
    type=click.Choice(["test_of_design", "test_of_effectiveness", "walkthrough"]),
    default=None,
    help="Template type for new workpaper",
)
@click.option("--reviewer", default=None, help="Reviewer for new workpaper")
@click.option(
    "--actor",
    default=None,
    envvar="WLK_CLI_ACTOR",
    help="Actor identity for audit trail",
)
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def audit_workpapers(
    engagement_id: str,
    create_mode: bool,
    control_id: str | None,
    template: str | None,
    reviewer: str | None,
    actor: str | None,
    fmt: str,
) -> None:
    """List workpapers for an engagement, or create a new one with --create."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry
    from warlock.cli import _get_actor
    from warlock.workflows.audit_manager import AuditManager

    init_db()
    mgr = AuditManager()
    resolved_actor = actor or _get_actor()

    if create_mode:
        if not control_id:
            _error("--control-id is required when using --create")
        if not template:
            _error("--template is required when using --create")
        if not reviewer:
            _error("--reviewer is required when using --create")

        with get_session() as session:
            try:
                wp = mgr.create_workpaper(
                    session,
                    engagement_id,
                    control_id,
                    template,
                    reviewer,
                    actor=resolved_actor,
                )
            except ValueError as exc:
                _error(str(exc))

        console.print(f"[green]Workpaper created:[/green] {wp['id'][:8]}")
        console.print(f"  Control:  {wp['control_id']}")
        console.print(f"  Template: {wp['template_type']}")
        console.print(f"  Reviewer: {wp['reviewer']}")
        console.print(f"  Status:   {wp['status']}")
        return

    # List mode: show workpapers from audit trail entries
    with get_session() as session:
        entries = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action.in_(
                    ["workpaper_created", "workpaper_reviewed", "workpaper_signed_off"]
                ),
            )
            .order_by(AuditEntry.created_at.desc())
            .limit(200)
            .all()
        )

        # Filter to this engagement
        workpapers: dict[str, dict] = {}
        for e in entries:
            meta = e.extra or {}
            if meta.get("engagement_id", "").startswith(engagement_id):
                wp_id = e.entity_id
                if wp_id not in workpapers:
                    workpapers[wp_id] = {
                        "id": wp_id,
                        "control_id": meta.get("control_id", ""),
                        "template_type": meta.get("template_type", ""),
                        "reviewer": meta.get("reviewer", ""),
                        "status": "draft",
                        "created_at": str(e.created_at)[:19] if e.created_at else "",
                    }
                # Update status from latest action
                if e.action == "workpaper_reviewed":
                    workpapers[wp_id]["status"] = "reviewed"
                elif e.action == "workpaper_signed_off":
                    workpapers[wp_id]["status"] = "signed_off"

    wp_list = list(workpapers.values())

    if fmt == "json":
        console.print_json(json.dumps(wp_list, indent=2))
        return

    if not wp_list:
        console.print("[dim]No workpapers found for this engagement.[/dim]")
        return

    table = Table(title=f"Workpapers ({len(wp_list)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Control", style="cyan")
    table.add_column("Template")
    table.add_column("Reviewer")
    table.add_column("Status")
    table.add_column("Created", style="dim")

    for wp in wp_list:
        status_style = {
            "draft": "yellow",
            "reviewed": "blue",
            "signed_off": "green",
        }.get(wp["status"], "")
        table.add_row(
            wp["id"][:8],
            wp["control_id"],
            wp["template_type"],
            wp["reviewer"],
            f"[{status_style}]{wp['status']}[/{status_style}]" if status_style else wp["status"],
            wp["created_at"],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# audit evidence-check
# ---------------------------------------------------------------------------


@audit_grp.command("evidence-check")
@click.argument("engagement_id")
@click.option("--max-age", default=90, type=int, help="Maximum evidence age in days (default 90)")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def audit_evidence_check(engagement_id: str, max_age: int, fmt: str) -> None:
    """Run evidence validity check: flag stale or missing evidence."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.audit_manager import AuditManager

    init_db()
    mgr = AuditManager()

    with get_session() as session:
        try:
            result = mgr.check_evidence_validity(
                session,
                engagement_id,
                max_age_days=max_age,
            )
        except ValueError as exc:
            _error(str(exc))

    if fmt == "json":
        console.print_json(json.dumps(result, indent=2))
        return

    summary = result["summary"]
    console.print("\n[bold cyan]Evidence Validity Check[/bold cyan]")
    console.print(f"  Framework:       {result['framework']}")
    console.print(f"  Max age:         {result['max_age_days']} days")
    console.print(f"  Total controls:  {summary['total_controls']}")
    console.print(
        f"  Valid:           [green]{summary['valid_count']}[/green]  "
        f"Stale: [yellow]{summary['stale_count']}[/yellow]  "
        f"Missing: [red]{summary['missing_count']}[/red]"
    )

    if result["stale"]:
        table = Table(title=f"Stale Evidence ({len(result['stale'])})")
        table.add_column("Control ID", style="yellow")
        table.add_column("Last Assessed", style="dim")
        table.add_column("Age (days)", justify="right")
        table.add_column("Status")

        for item in result["stale"][:50]:
            table.add_row(
                item["control_id"],
                item["last_assessed"][:10],
                str(item["age_days"]),
                item["status"],
            )
        console.print(table)

    if result["missing"]:
        table = Table(title=f"Missing Evidence ({len(result['missing'])})")
        table.add_column("Control ID", style="red")
        table.add_column("Reason")

        for item in result["missing"][:50]:
            table.add_row(item["control_id"], item["reason"])
        console.print(table)

    if not result["stale"] and not result["missing"]:
        console.print("\n[green]All evidence is valid and current.[/green]")


# ---------------------------------------------------------------------------
# audit package
# ---------------------------------------------------------------------------


@audit_grp.command("package")
@click.argument("engagement_id")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def audit_package(engagement_id: str, fmt: str) -> None:
    """Assemble and display certification package summary."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.audit_manager import AuditManager

    init_db()
    mgr = AuditManager()

    with get_session() as session:
        try:
            pkg = mgr.assemble_package(session, engagement_id)
        except ValueError as exc:
            _error(str(exc))

    if fmt == "json":
        console.print_json(json.dumps(pkg, indent=2))
        return

    eng = pkg["engagement"]
    console.print("\n[bold cyan]Certification Package[/bold cyan]")
    console.print(f"  Package ID:   {pkg['package_id'][:8]}")
    console.print(f"  Assembled:    {pkg['assembled_at'][:19]}")
    console.print(f"  Engagement:   {escape(eng['name'] or '')}")
    console.print(f"  Framework:    {eng['framework']}")
    console.print(
        f"  Period:       {(eng['period_start'] or '')[:10]} to {(eng['period_end'] or '')[:10]}"
    )
    if eng.get("auditor_name"):
        firm = f", {eng['auditor_firm']}" if eng.get("auditor_firm") else ""
        console.print(f"  Auditor:      {eng['auditor_name']}{firm}")

    # Control results summary
    cr = pkg["control_results"]
    console.print(f"\n[bold]Control Results ({cr['total']})[/bold]")
    if cr["by_status"]:
        table = Table()
        table.add_column("Status", style="cyan")
        table.add_column("Count", justify="right")
        for status, count in sorted(cr["by_status"].items(), key=lambda x: -x[1]):
            table.add_row(status, str(count))
        console.print(table)

    # Findings summary
    console.print(f"\n[bold]Findings: {pkg['findings']['total']}[/bold]")

    # Evidence validity
    ev = pkg["evidence_validity"]
    console.print(
        f"\n[bold]Evidence Validity:[/bold] "
        f"[green]{ev['valid_count']} valid[/green], "
        f"[yellow]{ev['stale_count']} stale[/yellow], "
        f"[red]{ev['missing_count']} missing[/red]"
    )

    # Audit trail
    at = pkg["audit_trail"]
    chain_status = "[green]intact[/green]" if at["chain_valid"] else "[red]BROKEN[/red]"
    console.print(f"\n[bold]Audit Trail:[/bold] {at['entries']} entries, chain {chain_status}")
    if at["chain_errors"]:
        for err in at["chain_errors"][:5]:
            console.print(f"  [red]{escape(err)}[/red]")
