"""Compliance commands: results, coverage, control, findings, connectors, sources."""

from __future__ import annotations

import click
from rich.table import Table

from warlock.cli import _ai_repl, _check_ai_available, _error, _parse_ai_response, cli, console


@cli.command()
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--status",
    default=None,
    type=click.Choice(
        ["compliant", "non_compliant", "not_assessed", "partial"], case_sensitive=False
    ),
    help="Filter by status",
)
@click.option("--system", default=None, help="Filter by system profile name or ID")
@click.option("--limit", "-n", default=50, type=click.IntRange(min=1), help="Max results")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "csv"]), default=None)
@click.option("--export", "export_path", default=None, help="Export to file (json/csv)")
@click.pass_context
def results(
    ctx: click.Context,
    framework: str | None,
    status: str | None,
    system: str | None,
    limit: int,
    fmt: str | None,
    export_path: str | None,
) -> None:
    """Query control results from the last pipeline run."""
    from warlock.cli.output import format_output, get_output_format
    from warlock.config import get_settings

    settings = get_settings()
    effective_fmt = get_output_format(ctx, fmt)

    _COLUMNS = [
        {"key": "framework", "header": "Framework", "style": "cyan"},
        {"key": "control_id", "header": "Control", "style": "cyan"},
        {"key": "status", "header": "Status"},
        {"key": "severity", "header": "Severity"},
        {"key": "assessor", "header": "Assessor", "style": "dim"},
    ]
    _STYLE_MAP = {
        "status": {
            "compliant": "green",
            "non_compliant": "red",
            "partial": "yellow",
            "not_assessed": "dim",
        },
        "severity": {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
            "info": "dim",
        },
    }

    # Lake-first path (no system filter -- lake has no system profile join)
    if not system and settings.lake_reads_enabled("results_list"):
        try:
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            lake_rows = readers.results_list(framework=framework, status=status, limit=limit)
            readers.close()
            if lake_rows:
                format_output(
                    lake_rows,
                    _COLUMNS,
                    fmt=effective_fmt,
                    title=f"Control Results ({len(lake_rows)}) [lake]",
                    style_map=_STYLE_MAP,
                    export_path=export_path,
                )
                return
        except Exception:
            pass  # Fall back to OLTP

    from warlock.db.engine import get_session
    from warlock.db.models import ControlResult, SystemProfile

    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        if status:
            q = q.filter(ControlResult.status == status)
        if system:
            sp = (
                session.query(SystemProfile)
                .filter(
                    (SystemProfile.name.ilike(f"%{system}%"))
                    | (SystemProfile.id.like(f"{system}%"))
                )
                .first()
            )
            if sp and sp.frameworks:
                q = q.filter(ControlResult.framework.in_(sp.frameworks))
            else:
                console.print(f"[red]System '{system}' not found or has no frameworks.[/red]")
                return
        q = q.order_by(ControlResult.assessed_at.desc()).limit(limit)
        rows = q.all()

    if not rows:
        console.print("[dim]No results found.[/dim]")
        return

    data = [
        {
            "framework": r.framework or "",
            "control_id": r.control_id or "",
            "status": r.status or "",
            "severity": r.severity or "",
            "assessor": r.assessor or "",
        }
        for r in rows
    ]

    format_output(
        data,
        _COLUMNS,
        fmt=effective_fmt,
        title=f"Control Results ({len(rows)})",
        style_map=_STYLE_MAP,
        export_path=export_path,
    )


@cli.command()
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--ai/--no-ai", "use_ai", default=None, help="Override AI toggle for executive summary"
)
def coverage(framework: str | None, use_ai: bool | None) -> None:
    """Show compliance coverage summary."""
    from warlock.config import get_settings

    settings = get_settings()
    rows: list[tuple] = []

    # Lake-first path
    if settings.lake_reads_enabled("coverage_by_status"):
        try:
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            rows = readers.coverage_by_status(
                framework=framework,
            )
            readers.close()
        except Exception:
            rows = []  # Fall back to OLTP

    if not rows:
        from sqlalchemy import func

        from warlock.db.engine import get_session
        from warlock.db.models import ControlResult

        with get_session() as session:
            q = session.query(
                ControlResult.framework,
                ControlResult.status,
                func.count(ControlResult.id),
            ).group_by(ControlResult.framework, ControlResult.status)

            if framework:
                q = q.filter(ControlResult.framework == framework)

            rows = q.all()

    if not rows:
        console.print("[dim]No results found. Run 'warlock collect' first.[/dim]")
        return

    # Aggregate by framework
    data: dict[str, dict[str, int]] = {}
    for fw, status, count in rows:
        data.setdefault(fw, {})
        data[fw][status] = count

    table = Table(title="Compliance Coverage")
    table.add_column("Framework", style="cyan")
    table.add_column("Compliant", style="green")
    table.add_column("Non-Compliant", style="red")
    table.add_column("Partial", style="yellow")
    table.add_column("Not Assessed", style="dim")
    table.add_column("Total")
    table.add_column("Rate")

    coverage_context: dict = {}
    for fw, counts in sorted(data.items()):
        total = sum(counts.values())
        compliant = counts.get("compliant", 0)
        assessed = total - counts.get("not_assessed", 0)
        rate = (compliant / assessed * 100) if assessed else 0
        rate_style = "green" if rate >= 80 else "yellow" if rate >= 50 else "red"
        table.add_row(
            fw,
            str(compliant),
            str(counts.get("non_compliant", 0)),
            str(counts.get("partial", 0)),
            str(counts.get("not_assessed", 0)),
            str(total),
            f"[{rate_style}]{rate:.0f}%[/]",
        )
        coverage_context[fw] = {
            "compliant": compliant,
            "non_compliant": counts.get("non_compliant", 0),
            "partial": counts.get("partial", 0),
            "not_assessed": counts.get("not_assessed", 0),
            "total": total,
            "rate": round(rate, 1),
        }

    console.print(table)

    # AI narrative summary
    if _check_ai_available(use_ai):
        try:
            from warlock.ai.service import get_ai_service
            from warlock.ai.types import AITask

            svc = get_ai_service()
            if svc.is_task_enabled(AITask.EXECUTIVE_REPORT):
                result = svc.reason(
                    AITask.EXECUTIVE_REPORT, context={"frameworks": coverage_context}
                )
                if result.ai_used:
                    console.print("\n[bold]AI Analysis:[/bold]")
                    value = result.value
                    if isinstance(value, dict):
                        narrative = value.get("report") or value.get("narrative") or str(value)
                    else:
                        narrative = str(value) if value else ""
                    if narrative:
                        console.print(narrative)
        except Exception as exc:
            console.print(f"\n[dim]AI analysis unavailable: {exc.__class__.__name__}[/dim]")


@cli.command()
@click.argument("control_id")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--remediate/--no-remediate",
    "show_remediation",
    default=True,
    help="Show/hide remediation guidance (default: show)",
)
@click.option(
    "--ai/--no-ai", "use_ai", default=None, help="AI-enhanced per-resource remediation commands"
)
@click.option(
    "--ask", is_flag=True, default=False, help="Interactive AI reasoning about this control"
)
def control(
    control_id: str,
    framework: str | None,
    show_remediation: bool,
    use_ai: bool | None,
    ask: bool,
) -> None:
    """Show control detail: status, resources, and remediation guidance.

    \b
    Examples:
        warlock control SC-28                        # show control across all frameworks
        warlock control AC-2 -f nist_800_53          # filter to NIST 800-53
        warlock control CC6.1 --no-remediate          # hide remediation section
        warlock control SC-28 --ai                   # AI-enhanced per-resource commands
        warlock control AC-2 --ask                   # interactive AI reasoning
    """
    from rich.panel import Panel

    from warlock.assessors.remediation_loader import get_control_detail
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        detail = get_control_detail(session, control_id, framework)

    if not detail:
        _error(f"No results found for control '{control_id}'. Check the ID or specify --framework.")

    # --- Control header ---
    fw_list = ", ".join(detail["frameworks"])
    desc = detail["description"] or "[dim]no description[/dim]"
    console.print()
    console.print(
        Panel(
            f"[bold]{control_id}[/bold]\n\n{desc}\n\nFramework(s): [cyan]{fw_list}[/cyan]",
            title="[bold cyan]Control Detail[/bold cyan]",
            border_style="cyan",
        )
    )

    # --- Status summary ---
    total = detail["total_results"]
    compliant = detail["compliant_count"]
    non_compliant = detail["non_compliant_count"]
    partial = detail["partial_count"]
    not_assessed = detail["not_assessed_count"]
    console.print(
        f"  [green]Compliant: {compliant}[/green]  "
        f"[red]Non-compliant: {non_compliant}[/red]  "
        f"[yellow]Partial: {partial}[/yellow]  "
        f"[dim]Not assessed: {not_assessed}[/dim]  "
        f"Total: {total}\n"
    )

    # --- Passing resources table ---
    if detail["passing_resources"]:
        pass_table = Table(title="Passing Resources", border_style="green")
        pass_table.add_column("Resource ID", style="green")
        pass_table.add_column("Type", style="green")
        pass_table.add_column("Source", style="green")
        for res in detail["passing_resources"]:
            pass_table.add_row(
                res["resource_id"] or "",
                res["resource_type"] or "",
                res["source"] or "",
            )
        console.print(pass_table)
        console.print()

    # --- Failing resources table ---
    if detail["failing_resources"]:
        fail_table = Table(title="Failing Resources", border_style="red")
        fail_table.add_column("Resource ID", style="red")
        fail_table.add_column("Type", style="red")
        fail_table.add_column("Source", style="red")
        fail_table.add_column("Severity", style="red")
        for res in detail["failing_resources"]:
            sev = res["severity"]
            sev_style = (
                "bold red"
                if sev == "critical"
                else "red"
                if sev == "high"
                else "yellow"
                if sev == "medium"
                else "dim"
            )
            fail_table.add_row(
                res["resource_id"] or "",
                res["resource_type"] or "",
                res["source"] or "",
                f"[{sev_style}]{sev}[/]",
            )
        console.print(fail_table)
        console.print()

    # --- KB Remediation section ---
    if show_remediation and detail["remediation"]:
        guidance = detail["remediation"]
        remediation_text = ""
        if guidance.get("summary"):
            remediation_text += f"[bold]Summary:[/bold] {guidance['summary']}\n\n"
        steps = guidance.get("steps") or guidance.get("remediation_steps") or []
        if steps:
            remediation_text += "[bold]Steps:[/bold]\n"
            for i, step in enumerate(steps, 1):
                remediation_text += f"  {i}. {step}\n"
            remediation_text += "\n"
        if guidance.get("console_path"):
            remediation_text += f"[bold]Console path:[/bold] {guidance['console_path']}\n"
        if guidance.get("recommended_reading"):
            remediation_text += "\n[bold]Recommended reading:[/bold]\n"
            for ref in guidance["recommended_reading"]:
                remediation_text += f"  - {ref}\n"

        if remediation_text.strip():
            console.print(
                Panel(
                    remediation_text.rstrip(),
                    title="[bold green]Remediation Guidance[/bold green]",
                    border_style="green",
                )
            )

    # --- AI-enhanced per-resource commands ---
    if _check_ai_available(use_ai) and use_ai is not None and detail["failing_resources"]:
        try:
            from warlock.assessors.remediation_loader import get_ai_control_remediation

            fw = framework or detail["frameworks"][0]
            with get_session() as ai_session:
                ai_result = get_ai_control_remediation(
                    session=ai_session,
                    control_id=control_id,
                    framework=fw,
                    failing_resources=detail["failing_resources"],
                )
            if ai_result:
                console.print("\n[bold]AI Per-Resource Remediation:[/bold]")
                if isinstance(ai_result, dict):
                    for key, val in ai_result.items():
                        console.print(f"  [cyan]{key}:[/cyan] {val}")
                elif isinstance(ai_result, str):
                    console.print(ai_result)
                else:
                    console.print(str(ai_result))
        except Exception as exc:
            console.print(f"\n[dim]AI remediation unavailable: {exc.__class__.__name__}[/dim]")

    # --- Interactive AI reasoning ---
    if ask:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import ConversationContext

        svc = get_ai_service()
        if not svc.is_available():
            console.print(
                "[yellow]AI service not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY.[/yellow]"
            )
            return

        import uuid

        session_id = uuid.uuid4().hex
        entity_data = {
            "control_id": control_id,
            "frameworks": detail["frameworks"],
            "compliant_count": detail["compliant_count"],
            "non_compliant_count": detail["non_compliant_count"],
            "partial_count": detail["partial_count"],
            "not_assessed_count": detail["not_assessed_count"],
            "failing_count": len(detail["failing_resources"]),
            "passing_count": len(detail["passing_resources"]),
            "remediation": detail["remediation"],
        }
        ctx = ConversationContext(
            entity_type="control",
            entity_id=control_id,
            entity_data=entity_data,
            session_id=session_id,
        )
        _ai_repl(svc, session_id, ctx, f"control {control_id}")


@cli.command()
@click.option("--ask", default=None, help="Ask AI a question about the listed findings")
def findings(ask: str | None) -> None:
    """Show recent findings."""
    from warlock.db.engine import get_session
    from warlock.db.models import Finding

    with get_session() as session:
        rows = session.query(Finding).order_by(Finding.ingested_at.desc()).limit(50).all()

    if not rows:
        console.print("[dim]No findings. Run 'warlock collect' first.[/dim]")
        return

    table = Table(title=f"Findings ({len(rows)})")
    table.add_column("Type", style="cyan")
    table.add_column("Title")
    table.add_column("Resource")
    table.add_column("Severity")
    table.add_column("Source", style="dim")

    for f in rows:
        sev_style = {"critical": "red bold", "high": "red", "medium": "yellow"}.get(
            f.severity, "dim"
        )
        table.add_row(
            f.observation_type,
            f.title[:80],
            f.resource_type or "",
            f"[{sev_style}]{f.severity}[/]",
            f.provider,
        )

    console.print(table)

    # --ask: AI question about the listed findings (or REPL if empty)
    if ask is not None:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import ConversationContext

        svc = get_ai_service()
        if not svc.is_available():
            console.print(
                "[yellow]AI service not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY.[/yellow]"
            )
            return

        import uuid

        session_id = uuid.uuid4().hex
        findings_summary = [
            {
                "title": f.title[:80],
                "observation_type": f.observation_type,
                "severity": f.severity,
                "provider": f.provider,
                "resource_type": f.resource_type or "",
            }
            for f in rows
        ]
        ctx = ConversationContext(
            entity_type="findings_list",
            entity_id="batch",
            entity_data={"findings": findings_summary, "count": len(rows)},
            session_id=session_id,
        )
        question = ask.strip() if ask.strip() else None
        if question:
            result = svc.converse(session_id=session_id, message=question, context=ctx)
            if result.ai_used:
                console.print("\n[bold]AI:[/bold]")
                console.print(_parse_ai_response(result.value))
            else:
                console.print(f"[yellow]AI unavailable: {result.fallback_reason}[/yellow]")
        else:
            _ai_repl(svc, session_id, ctx, f"findings ({len(rows)} items)")


@cli.command()
def connectors() -> None:
    """List registered connector types."""
    from warlock.connectors.base import registry as conn_registry
    from warlock.pipeline.loader import load_all_connectors

    load_all_connectors()
    table = Table(title="Registered Connectors")
    table.add_column("Provider")
    table.add_column("Status")
    for provider in conn_registry.list_types():
        table.add_row(provider, "[green]registered[/green]")
    console.print(table)


@cli.command()
def sources() -> None:
    """List all registered connector types and normalizer types."""
    from warlock.connectors.base import registry as conn_registry
    from warlock.normalizers.base import registry as norm_registry
    from warlock.pipeline.loader import load_all_connectors, load_all_normalizers

    load_all_connectors()
    load_all_normalizers()

    table = Table(title="Registered Sources")
    table.add_column("Type", style="cyan")
    table.add_column("Name")
    table.add_column("Status")

    for provider in sorted(conn_registry.list_types()):
        table.add_row("connector", provider, "[green]registered[/green]")
    for normalizer in norm_registry.list_normalizers():
        name = type(normalizer).__name__
        table.add_row("normalizer", name, "[green]registered[/green]")

    console.print(table)
