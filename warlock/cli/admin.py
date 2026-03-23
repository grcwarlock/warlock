"""Admin commands: systems, systems-create, personnel, personnel-sync,
retention (group with report, purge), data-silos, data-silos-discover,
questionnaires, questionnaires-seed."""

from __future__ import annotations

import click
from rich.table import Table

from warlock.cli import cli, console


@cli.command("systems")
@click.option(
    "--status",
    default=None,
    type=click.Choice(
        ["authorized", "in_process", "not_authorized", "denied", "revoked"],
        case_sensitive=False,
    ),
    help="Filter by authorization status",
)
def systems_list(status: str | None) -> None:
    """List system profiles. Use --status to filter (e.g. --status not_authorized)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SystemProfile
    from warlock.workflows.system_profile import SystemProfileManager

    init_db()
    mgr = SystemProfileManager()

    with get_session() as session:
        if status:
            profiles = (
                session.query(SystemProfile)
                .filter(
                    SystemProfile.is_active == True,  # noqa: E712
                    SystemProfile.authorization_status == status,
                )
                .order_by(SystemProfile.name)
                .all()
            )
        else:
            profiles = mgr.list_active(session)

    if not profiles:
        console.print(
            "[dim]No system profiles found. Create one with 'warlock systems-create'.[/dim]"
        )
        return

    table = Table(title=f"System Profiles ({len(profiles)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", style="cyan")
    table.add_column("Acronym")
    table.add_column("Impact")
    table.add_column("Auth Status")
    table.add_column("Frameworks", style="dim")

    for sp in profiles:
        auth_style = {
            "authorized": "green",
            "in_process": "yellow",
            "not_authorized": "red",
            "denied": "red bold",
            "revoked": "red",
        }.get(sp.authorization_status, "")
        frameworks_str = ", ".join(sp.frameworks or [])
        table.add_row(
            sp.id[:8],
            sp.name,
            sp.acronym or "",
            sp.overall_impact or "moderate",
            f"[{auth_style}]{sp.authorization_status or 'not_authorized'}[/]",
            frameworks_str[:40],
        )

    console.print(table)


@cli.command("systems-create")
@click.option("--name", "-n", required=True, help="System name")
@click.option("--acronym", "-a", default=None, help="System acronym")
@click.option("--description", "-d", default="", help="System description")
@click.option(
    "--impact",
    type=click.Choice(["low", "moderate", "high"]),
    default="moderate",
    help="Overall impact level",
)
@click.option(
    "--framework", "-f", multiple=True, help="Applicable frameworks (can specify multiple)"
)
@click.option("--connector", "-c", multiple=True, help="Connector scope (can specify multiple)")
def systems_create(
    name: str,
    acronym: str | None,
    description: str,
    impact: str,
    framework: tuple,
    connector: tuple,
) -> None:
    """Create a new system profile."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.system_profile import SystemProfileManager

    init_db()
    mgr = SystemProfileManager()

    kwargs = {
        "overall_impact": impact,
        "confidentiality_impact": impact,
        "integrity_impact": impact,
        "availability_impact": impact,
    }
    if acronym:
        kwargs["acronym"] = acronym
    if framework:
        kwargs["frameworks"] = list(framework)
    if connector:
        kwargs["connector_scope"] = list(connector)

    with get_session() as session:
        sp = mgr.create(session, name=name, description=description, **kwargs)

    console.print(f"[green]System profile created: {sp.id}[/green]")
    console.print(f"  Name:   {sp.name}")
    console.print(f"  Impact: {sp.overall_impact}")
    if sp.frameworks:
        console.print(f"  Frameworks: {', '.join(sp.frameworks)}")


@cli.command("personnel")
@click.option("--department", "-d", default=None, help="Filter by department")
@click.option(
    "--status", "-s", default=None, help="Filter by HR status (active, terminated, leave)"
)
@click.option("--flagged", is_flag=True, help="Show only flagged personnel")
@click.option("--limit", "-n", default=50, help="Max results")
def personnel_list(department: str | None, status: str | None, flagged: bool, limit: int) -> None:
    """List personnel records with HR/IdP/training cross-reference."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Personnel

    init_db()

    with get_session() as session:
        q = session.query(Personnel).filter(Personnel.is_active == True)  # noqa: E712
        if department:
            q = q.filter(Personnel.department == department)
        if status:
            q = q.filter(Personnel.hr_status == status)
        if flagged:
            q = q.filter(Personnel.risk_score > 0)
        q = q.order_by(Personnel.risk_score.desc(), Personnel.full_name).limit(limit)
        rows = q.all()

    if not rows:
        console.print("[dim]No personnel records found. Run 'warlock personnel-sync' first.[/dim]")
        return

    table = Table(title=f"Personnel ({len(rows)})")
    table.add_column("Name", style="cyan")
    table.add_column("Email")
    table.add_column("Dept", style="dim")
    table.add_column("HR Status")
    table.add_column("IdP Status")
    table.add_column("MFA")
    table.add_column("Training")
    table.add_column("Risk", justify="right")
    table.add_column("Flags", style="dim")

    for p in rows:
        hr_style = {"active": "green", "terminated": "red", "leave": "yellow"}.get(
            p.hr_status or "", "dim"
        )
        idp_style = {
            "active": "green",
            "ACTIVE": "green",
            "suspended": "yellow",
            "deprovisioned": "red",
        }.get(p.idp_status or "", "dim")
        mfa_str = (
            "[green]Yes[/]"
            if p.mfa_enabled
            else "[red]No[/]"
            if p.mfa_enabled is False
            else "[dim]?[/]"
        )
        training_style = {"current": "green", "overdue": "red", "not_enrolled": "yellow"}.get(
            p.training_status or "", "dim"
        )
        risk_style = (
            "red bold"
            if (p.risk_score or 0) >= 50
            else "yellow"
            if (p.risk_score or 0) > 0
            else "green"
        )
        flags_str = ", ".join(p.flags[:3]) if p.flags else ""

        table.add_row(
            p.full_name,
            p.email,
            p.department or "",
            f"[{hr_style}]{p.hr_status or 'unknown'}[/]",
            f"[{idp_style}]{p.idp_status or 'unknown'}[/]",
            mfa_str,
            f"[{training_style}]{p.training_status or 'unknown'}[/]",
            f"[{risk_style}]{p.risk_score or 0:.0f}[/]",
            flags_str,
        )

    console.print(table)


@cli.command("personnel-sync")
def personnel_sync() -> None:
    """Sync personnel records from HR, IdP, and training findings."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.personnel import PersonnelManager

    init_db()
    mgr = PersonnelManager()

    with get_session() as session:
        result = mgr.sync_all(session)

    console.print("[bold]Personnel Sync Complete[/bold]")

    for source in ("hr", "idp", "training"):
        data = result.get(source, {})
        console.print(
            f"  {source.upper():10s}  created={data.get('created', 0)}  "
            f"updated={data.get('updated', 0)}  flagged={data.get('flagged', 0)}"
        )

    console.print(f"\n  Total personnel: {result.get('total_personnel', 0)}")

    # Show terminated-with-active-access as a critical alert
    with get_session() as session:
        terminated = mgr.terminated_with_active_access(session)

    if terminated:
        console.print(
            f"\n[red bold]CRITICAL: {len(terminated)} terminated employee(s) "
            f"still active in IdP:[/red bold]"
        )
        for p in terminated[:10]:
            console.print(
                f"  [red]\u2022 {p.full_name} ({p.email}) \u2014 HR: {p.hr_status}, IdP: {p.idp_status}[/red]"
            )


@cli.group()
def retention() -> None:
    """Data retention policies and legal holds."""


@retention.command("report")
def retention_report() -> None:
    """Show retention report: record ages, purgeable counts, legal holds."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.retention import RetentionManager, FRAMEWORK_RETENTION

    init_db()
    mgr = RetentionManager()

    with get_session() as session:
        report = mgr.retention_report(session)

    console.print("\n[bold]Retention Report[/bold]")
    console.print(f"  Total raw events: {report['total_raw_events']}")

    # Age buckets
    table = Table(title="Records by Age")
    table.add_column("Bucket", style="cyan")
    table.add_column("Count", justify="right")
    for bucket, count in report["age_buckets"].items():
        table.add_row(bucket, str(count))
    console.print(table)

    # Purgeable
    purgeable = report["purgeable"]
    console.print("\n[bold]Purgeable Records[/bold]")
    console.print(f"  Raw events:      {purgeable['raw_events']}")
    console.print(f"  Findings:        {purgeable['findings']}")
    console.print(f"  Control results: {purgeable['control_results']}")
    console.print(f"  Total:           {purgeable['total']}")

    # Legal holds
    holds = report["active_holds"]
    if holds:
        console.print(f"\n[yellow]Active Legal Holds ({len(holds)}):[/yellow]")
        for h in holds:
            console.print(f"  [dim]\u2022 {h['id'][:8]} \u2014 {h['reason']}[/dim]")
    else:
        console.print("\n[green]No active legal holds.[/green]")

    # Framework retention periods
    console.print("\n[bold]Framework Retention Periods[/bold]")
    for fw, days in sorted(FRAMEWORK_RETENTION.items()):
        years = days / 365
        console.print(f"  {fw:20s} {days:5d} days ({years:.0f} years)")


@retention.command("purge")
@click.option("--dry-run/--execute", default=True, help="Dry run (default) or actually delete")
@click.option(
    "--framework", "-f", default=None, help="Limit to a specific framework's retention period"
)
def retention_purge(dry_run: bool, framework: str | None) -> None:
    """Purge records past their retention period."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.retention import RetentionManager

    init_db()
    mgr = RetentionManager()

    with get_session() as session:
        result = mgr.purge_expired(session, dry_run=dry_run, framework=framework)

    if result.get("reason"):
        console.print(f"[yellow]{result['reason']}[/yellow]")

    mode = "[dim]DRY RUN[/dim]" if dry_run else "[red]EXECUTED[/red]"
    console.print(f"\n[bold]Purge {mode}[/bold]")
    console.print(f"  Raw events:       {result.get('raw_events', 0)}")
    console.print(f"  Findings:         {result.get('findings', 0)}")
    console.print(f"  Control results:  {result.get('control_results', 0)}")
    console.print(f"  Control mappings: {result.get('control_mappings', 0)}")
    console.print(f"  Total:            {result.get('total', 0)}")

    if result.get("cutoff_date"):
        console.print(f"  Cutoff date:      {result['cutoff_date']}")

    if not dry_run and result.get("purged"):
        console.print("\n[green]Records purged successfully.[/green]")


@cli.command("data-silos")
@click.option(
    "--type", "silo_type", default=None, help="Filter by silo type (s3_bucket, rds_database, ...)"
)
@click.option("--classification", "-c", default=None, help="Filter by classification")
@click.option("--provider", "-p", default=None, help="Filter by cloud provider")
@click.option("--limit", "-n", default=50, help="Max results")
def data_silos_list(
    silo_type: str | None, classification: str | None, provider: str | None, limit: int
) -> None:
    """List discovered data silos."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DataSilo

    init_db()

    with get_session() as session:
        q = session.query(DataSilo).filter(DataSilo.is_active == True)  # noqa: E712
        if silo_type:
            q = q.filter(DataSilo.silo_type == silo_type)
        if classification:
            q = q.filter(DataSilo.data_classification == classification)
        if provider:
            q = q.filter(DataSilo.provider == provider)
        q = q.order_by(DataSilo.data_classification.desc(), DataSilo.name).limit(limit)
        rows = q.all()

    if not rows:
        console.print("[dim]No data silos found. Run 'warlock data-silos-discover' first.[/dim]")
        return

    table = Table(title=f"Data Silos ({len(rows)})")
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Provider", style="dim")
    table.add_column("Classification")
    table.add_column("PII")
    table.add_column("PHI")
    table.add_column("PCI")
    table.add_column("Encrypted")
    table.add_column("Logging")

    for s in rows:
        class_style = {
            "restricted": "red bold",
            "confidential": "red",
            "internal": "yellow",
            "public": "green",
            "unknown": "dim",
        }.get(s.data_classification or "unknown", "dim")

        def _bool_str(v):
            if v is True:
                return "[green]Yes[/]"
            elif v is False:
                return "[red]No[/]"
            return "[dim]?[/]"

        table.add_row(
            s.name[:40],
            s.silo_type,
            s.provider or "",
            f"[{class_style}]{s.data_classification or 'unknown'}[/]",
            _bool_str(s.contains_pii),
            _bool_str(s.contains_phi),
            _bool_str(s.contains_pci),
            _bool_str(s.encrypted_at_rest),
            _bool_str(s.access_logging_enabled),
        )

    console.print(table)


@cli.command("data-silos-discover")
def data_silos_discover() -> None:
    """Auto-discover data silos from findings."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.data_silos import DataSiloManager

    init_db()
    mgr = DataSiloManager()

    with get_session() as session:
        result = mgr.discover_from_findings(session)

    console.print("[bold]Data Silo Discovery Complete[/bold]")
    console.print(f"  Created:  {result['created']}")
    console.print(f"  Updated:  {result['updated']}")
    console.print(f"  Total:    {result['total']}")

    # Show unprotected silos as a warning
    with get_session() as session:
        unprotected = mgr.unprotected(session)
        unclassified = mgr.unclassified(session)

    if unprotected:
        console.print(f"\n[yellow]Unprotected silos ({len(unprotected)}):[/yellow]")
        for s in unprotected[:10]:
            issues = []
            if not s.encrypted_at_rest:
                issues.append("no encryption")
            if not s.access_logging_enabled:
                issues.append("no logging")
            console.print(
                f"  [dim]\u2022 {s.name} ({s.silo_type}) \u2014 {', '.join(issues)}[/dim]"
            )

    if unclassified:
        console.print(f"\n[yellow]Unclassified silos ({len(unclassified)}):[/yellow]")
        for s in unclassified[:10]:
            console.print(f"  [dim]\u2022 {s.name} ({s.silo_type})[/dim]")


@cli.command("questionnaires")
@click.option("--status", "-s", default=None, help="Filter by status")
@click.option("--vendor", "-v", default=None, help="Filter by vendor name")
@click.option("--limit", "-n", default=50, help="Max results")
def questionnaires_list(status: str | None, vendor: str | None, limit: int) -> None:
    """List vendor questionnaires."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Questionnaire

    init_db()

    with get_session() as session:
        q = session.query(Questionnaire)
        if status:
            q = q.filter(Questionnaire.status == status)
        if vendor:
            q = q.filter(Questionnaire.vendor_name.ilike(f"%{vendor}%"))
        q = q.order_by(Questionnaire.created_at.desc()).limit(limit)
        rows = q.all()

    if not rows:
        console.print("[dim]No questionnaires found. Create one with the API.[/dim]")
        return

    table = Table(title=f"Questionnaires ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Vendor", style="cyan")
    table.add_column("Status")
    table.add_column("Completion", justify="right")
    table.add_column("Risk Score", justify="right")
    table.add_column("Due Date", style="dim")

    for q_row in rows:
        status_style = {
            "draft": "dim",
            "sent": "blue",
            "in_progress": "cyan",
            "completed": "green",
            "reviewed": "green bold",
            "accepted": "green bold",
            "rejected": "red",
        }.get(q_row.status, "")
        risk_style = ""
        if q_row.risk_score is not None:
            risk_style = (
                "red" if q_row.risk_score > 50 else "yellow" if q_row.risk_score > 25 else "green"
            )

        due_str = ""
        if q_row.due_date:
            due_str = (
                q_row.due_date.strftime("%Y-%m-%d")
                if hasattr(q_row.due_date, "strftime")
                else str(q_row.due_date)[:10]
            )

        table.add_row(
            q_row.id[:8],
            q_row.vendor_name,
            f"[{status_style}]{q_row.status}[/]",
            f"{q_row.completion_pct or 0:.0f}%",
            f"[{risk_style}]{q_row.risk_score:.0f}[/]"
            if q_row.risk_score is not None
            else "[dim]\u2014[/]",
            due_str,
        )

    console.print(table)


@cli.command("questionnaires-seed")
def questionnaires_seed() -> None:
    """Seed default questionnaire templates (SIG Lite, DDQ)."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.questionnaires import QuestionnaireManager

    init_db()
    mgr = QuestionnaireManager()

    with get_session() as session:
        templates = mgr.seed_default_templates(session)

    if not templates:
        console.print("[dim]Default templates already exist.[/dim]")
        return

    console.print(f"[green]Created {len(templates)} template(s):[/green]")
    for t in templates:
        console.print(
            f"  [cyan]{t.id[:8]}[/cyan] {t.name} ({t.template_type}) \u2014 "
            f"{t.total_questions} questions"
        )
