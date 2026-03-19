"""CLI — the interface to the pipeline."""

from __future__ import annotations

import logging

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def cli(verbose: bool) -> None:
    """Warlock — compliance telemetry pipeline."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )


@cli.command()
def init() -> None:
    """Initialize the database."""
    from warlock.db.engine import init_db
    init_db()
    console.print("[green]Database initialized.[/green]")


@cli.command()
@click.option("--source", "-s", multiple=True, help="Limit to specific sources (e.g., aws)")
def collect(source: tuple[str, ...]) -> None:
    """Run the full pipeline: collect → normalize → map → assess."""
    from warlock.db.engine import get_session, init_db
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline

    # Bootstrap
    init_db()
    bus = EventBus()
    pipeline = build_pipeline(bus, sources=source or None)

    # Wire up a simple event logger
    bus.subscribe_all(lambda e: logging.getLogger("bus").debug(
        "%s → %s", e.event_type, e.payload_id[:8]
    ))

    # Run
    with get_session() as session:
        stats = pipeline.run(session)

    # Report
    _print_stats(stats)


@cli.command()
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--status", default=None, help="Filter by status")
@click.option("--limit", "-n", default=50, help="Max results")
def results(framework: str | None, status: str | None, limit: int) -> None:
    """Query control results from the last pipeline run."""
    from warlock.db.engine import get_session
    from warlock.db.models import ControlResult

    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        if status:
            q = q.filter(ControlResult.status == status)
        q = q.order_by(ControlResult.assessed_at.desc()).limit(limit)
        rows = q.all()

    if not rows:
        console.print("[dim]No results found.[/dim]")
        return

    table = Table(title=f"Control Results ({len(rows)})")
    table.add_column("Framework", style="cyan")
    table.add_column("Control", style="cyan")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Assessor", style="dim")

    for r in rows:
        status_style = {
            "compliant": "green",
            "non_compliant": "red",
            "partial": "yellow",
            "not_assessed": "dim",
        }.get(r.status, "")
        sev_style = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
            "info": "dim",
        }.get(r.severity, "")
        table.add_row(
            r.framework, r.control_id,
            f"[{status_style}]{r.status}[/]",
            f"[{sev_style}]{r.severity}[/]",
            r.assessor,
        )

    console.print(table)


@cli.command()
@click.option("--framework", "-f", default=None, help="Filter by framework")
def coverage(framework: str | None) -> None:
    """Show compliance coverage summary."""
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

    for fw, counts in sorted(data.items()):
        total = sum(counts.values())
        compliant = counts.get("compliant", 0)
        rate = (compliant / total * 100) if total else 0
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

    console.print(table)


@cli.command()
def findings() -> None:
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
        sev_style = {"critical": "red bold", "high": "red", "medium": "yellow"}.get(f.severity, "dim")
        table.add_row(
            f.observation_type,
            f.title[:80],
            f.resource_type or "",
            f"[{sev_style}]{f.severity}[/]",
            f.provider,
        )

    console.print(table)


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
    for normalizer in norm_registry._normalizers:
        name = type(normalizer).__name__
        table.add_row("normalizer", name, "[green]registered[/green]")

    console.print(table)


@cli.command()
@click.option("--source", "-s", required=True, help="Source identifier (e.g., webhook, manual)")
@click.option("--provider", "-p", required=True, help="Provider name (e.g., crowdstrike, okta)")
@click.option("--event-type", "-t", required=True, help="Event type label (e.g., falcon_detections)")
@click.option("--file", "-f", "file_path", required=True, type=click.Path(exists=True), help="Path to JSON file")
def ingest(source: str, provider: str, event_type: str, file_path: str) -> None:
    """Ingest a JSON file through the webhook receiver and pipeline."""
    import json
    from warlock.connectors.webhook import WebhookReceiver
    from warlock.connectors.base import ConnectorResult, SourceType
    from warlock.db.engine import get_session, init_db
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline

    # Read the JSON payload
    with open(file_path) as fh:
        payload = json.load(fh)

    # Wrap in a list if it's a single object
    payloads = payload if isinstance(payload, list) else [payload]

    # Bootstrap
    init_db()
    bus = EventBus()
    pipeline = build_pipeline(bus)

    # Ingest through the webhook receiver
    receiver = WebhookReceiver()
    raw_events = receiver.ingest_batch(
        payloads, source=source, provider=provider, event_type=event_type,
    )

    # Synthesise a ConnectorResult so the pipeline persistence works
    cr = ConnectorResult(
        connector_name=f"ingest:{source}",
        source=source,
        source_type=raw_events[0].source_type if raw_events else SourceType.CUSTOM,
        provider=provider,
        events=raw_events,
    )
    cr.complete()

    # Run through stages 2-4 by feeding the connector result into the pipeline
    from warlock.pipeline.orchestrator import PipelineRunStats
    stats = PipelineRunStats()

    with get_session() as session:
        db_run = pipeline._persist_connector_run(session, cr)
        stats.connectors_succeeded = 1

        for raw_event in cr.events:
            db_raw = pipeline._persist_raw_event(session, raw_event, db_run.id)
            stats.raw_events_collected += 1

            findings = pipeline.normalizers.normalize(raw_event)
            for finding in findings:
                finding.raw_event_id = db_raw.id
                db_finding = pipeline._persist_finding(session, finding)
                stats.findings_normalized += 1

                mapped = pipeline.mapper.map(finding)
                for mapping in mapped.mappings:
                    pipeline._persist_mapping(session, mapping)
                    stats.controls_mapped += 1

                results = pipeline.assessor.assess(mapped, raw_data=raw_event.raw_data)
                for result in results:
                    pipeline._persist_result(session, result)
                    stats.results_assessed += 1

        session.flush()

    from datetime import datetime, timezone
    stats.completed_at = datetime.now(timezone.utc)
    _print_stats(stats)


@cli.command()
@click.option("-f", "--framework", default=None, help="Filter by framework (e.g. nist_800_53, iso_27001)")
@click.option("-s", "--system-name", default="Warlock GRC System", help="System name for OSCAL metadata")
@click.option("-o", "--output", default=None, help="Output file path (default: stdout)")
@click.option("--format", "fmt", type=click.Choice(["ar", "ssp", "poam"]), default="ar", help="OSCAL document type")
@click.option("--description", default="", help="System description (for SSP)")
@click.option("--ai/--no-ai", default=False, help="Use AI to generate framework-aware narratives (SSP/POA&M)")
def oscal(framework, system_name, output, fmt, description, ai):
    """Export assessment data in OSCAL JSON format.

    Use --ai with SSP or POA&M to generate rich, framework-aware narratives.
    The AI adapts its language to match the framework: NIST SSP language,
    ISO SoA language, SOC 2 report language, etc.

    Requires WLK_AI_PROVIDER and WLK_AI_API_KEY to be set.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.export.oscal import OscalExporter

    init_db()
    exporter = OscalExporter()

    # Set up AI narrator if requested
    narrator = None
    if ai and fmt in ("ssp", "poam"):
        from warlock.assessors.ai_narrator import create_narrator
        narrator = create_narrator()
        if narrator is None:
            console.print("[yellow]Warning: --ai requested but WLK_AI_PROVIDER / WLK_AI_API_KEY not configured. Falling back to deterministic output.[/yellow]")
        else:
            console.print(f"[cyan]AI narrator active: {narrator.provider}/{narrator.model}[/cyan]")

    with get_session() as session:
        if fmt == "ar":
            data = exporter.export_assessment_results(session, framework=framework, system_name=system_name)
        elif fmt == "ssp":
            if not framework:
                console.print("[red]SSP export requires --framework[/red]")
                raise SystemExit(1)
            data = exporter.export_ssp(
                session, framework=framework, system_name=system_name,
                description=description or f"{system_name} System Security Plan",
                narrator=narrator,
            )
        elif fmt == "poam":
            data = exporter.export_poam(
                session, framework=framework, system_name=system_name,
                narrator=narrator,
            )

    json_str = exporter.to_json(data)

    if output:
        exporter.to_file(data, output)
        console.print(f"[green]OSCAL {fmt.upper()} written to {output}[/green]")
    else:
        console.print(json_str)


@cli.command()
@click.option("-f", "--framework", required=True, help="Framework to analyze (e.g. nist_800_53)")
@click.option("-n", "--iterations", default=10000, help="Monte Carlo iterations")
def risk(framework: str, iterations: int) -> None:
    """Run FAIR risk quantification for a framework."""
    from warlock.assessors.risk_engine import RiskEngine
    from warlock.db.engine import get_session, init_db

    init_db()
    engine = RiskEngine(default_iterations=iterations)

    with get_session() as session:
        result = engine.analyze_framework_risk(session, framework, iterations=iterations)

    scenarios = result.get("scenarios", [])
    portfolio = result.get("portfolio", {})

    if not scenarios:
        console.print(f"[dim]No risk scenarios for framework '{framework}'.[/dim]")
        return

    table = Table(title=f"FAIR Risk Analysis — {framework}")
    table.add_column("Scenario", style="cyan")
    table.add_column("Mean ALE", justify="right")
    table.add_column("VaR 95", justify="right")
    table.add_column("VaR 99", justify="right")
    table.add_column("Control Eff.", justify="right")

    for s in scenarios:
        table.add_row(
            s["name"],
            f"${s['mean_ale']:,.0f}",
            f"${s['var_95']:,.0f}",
            f"${s['var_99']:,.0f}",
            f"{s['control_effectiveness']:.0%}",
        )

    console.print(table)
    console.print()
    console.print(f"[bold]Portfolio Total Mean ALE:[/bold] ${portfolio['total_mean_ale']:,.0f}")
    console.print(f"[bold]Portfolio Total VaR 95:[/bold]  ${portfolio['total_var_95']:,.0f}")
    console.print(f"[bold]Scenarios:[/bold]               {portfolio['scenario_count']}")
    console.print(f"[bold]Iterations:[/bold]              {portfolio['iterations']:,}")


@cli.command()
@click.option("-p", "--provider", default="securityscorecard", help="Vendor data provider")
@click.option("-t", "--threshold", default=60.0, help="High-risk threshold (0-100)")
def vendors(provider: str, threshold: float) -> None:
    """Score and monitor vendor risk."""
    from warlock.assessors.vendor_risk import VendorRiskEngine
    from warlock.db.engine import get_session, init_db

    init_db()
    engine = VendorRiskEngine()

    with get_session() as session:
        scores = engine.monitor_all(session, provider=provider, high_risk_threshold=threshold)

    if not scores:
        console.print(f"[dim]No vendor data from provider '{provider}'.[/dim]")
        return

    table = Table(title="Vendor Risk Scores")
    table.add_column("Vendor", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Level")
    table.add_column("Issues", justify="right")
    table.add_column("Security", justify="right", style="dim")
    table.add_column("Currency", justify="right", style="dim")

    for s in sorted(scores, key=lambda x: x.overall_score):
        level_style = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "green",
        }.get(s.risk_level, "")
        table.add_row(
            s.vendor_name,
            f"{s.overall_score:.0f}",
            f"[{level_style}]{s.risk_level}[/]",
            str(s.issues_count),
            f"{s.security_posture_score:.0f}/25",
            f"{s.assessment_currency_score:.0f}/20",
        )

    console.print(table)

    high_risk = [s for s in scores if s.overall_score < threshold]
    if high_risk:
        console.print(f"\n[yellow]High-risk vendors ({len(high_risk)}):[/yellow]")
        for s in high_risk:
            for rec in s.recommendations:
                console.print(f"  [dim]• {rec}[/dim]")


@cli.command("policy-coverage")
@click.option("-f", "--framework", required=True, help="Framework to check coverage for")
@click.option("--no-rag", is_flag=True, help="Skip RAG matching, use keyword heuristics only")
def policy_coverage(framework: str, no_rag: bool) -> None:
    """Check policy documentation coverage for a framework."""
    from warlock.assessors.policy_discovery import score_policy_coverage
    from warlock.db.engine import get_session, init_db

    init_db()

    with get_session() as session:
        coverage = score_policy_coverage(session, framework, use_rag=not no_rag)

    if coverage.total_controls == 0:
        console.print(f"[dim]No controls found for framework '{framework}'.[/dim]")
        return

    pct_style = "green" if coverage.coverage_pct >= 80 else "yellow" if coverage.coverage_pct >= 50 else "red"

    console.print(f"\n[bold]Policy Coverage — {framework}[/bold]")
    console.print(f"  Total controls:       {coverage.total_controls}")
    console.print(f"  With policy docs:     {coverage.controls_with_policy}")
    console.print(f"  Coverage:             [{pct_style}]{coverage.coverage_pct:.0f}%[/]")

    if coverage.policy_map:
        table = Table(title="Policy-to-Control Mapping")
        table.add_column("Control", style="cyan")
        table.add_column("Policies")

        for control_id in sorted(coverage.policy_map):
            policies = coverage.policy_map[control_id]
            table.add_row(control_id, ", ".join(policies[:3]))

        console.print(table)

    if coverage.gaps:
        console.print(f"\n[yellow]Policy gaps ({len(coverage.gaps)} controls):[/yellow]")
        for gap in sorted(coverage.gaps)[:20]:
            console.print(f"  [dim]• {gap}[/dim]")
        if len(coverage.gaps) > 20:
            console.print(f"  [dim]... and {len(coverage.gaps) - 20} more[/dim]")


@cli.command("issues")
@click.option("--status", "-s", default=None, help="Filter by status (open, assigned, in_progress, etc.)")
@click.option("--priority", "-p", default=None, help="Filter by priority (critical, high, medium, low)")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--assigned-to", default=None, help="Filter by assignee")
@click.option("--limit", "-n", default=50, help="Max results")
def issues(status: str | None, priority: str | None, framework: str | None, assigned_to: str | None, limit: int) -> None:
    """List and manage compliance issues."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    init_db()

    with get_session() as session:
        q = session.query(Issue)
        if status:
            q = q.filter(Issue.status == status)
        else:
            # Default: show non-closed issues
            q = q.filter(Issue.status.notin_(["closed", "verified"]))
        if priority:
            q = q.filter(Issue.priority == priority)
        if framework:
            q = q.filter(Issue.framework == framework)
        if assigned_to:
            q = q.filter(Issue.assigned_to == assigned_to)
        q = q.order_by(Issue.created_at.desc()).limit(limit)
        rows = q.all()

    if not rows:
        console.print("[dim]No issues found.[/dim]")
        return

    table = Table(title=f"Issues ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Framework", style="cyan")
    table.add_column("Control", style="cyan")
    table.add_column("Title", max_width=50)
    table.add_column("Status")
    table.add_column("Priority")
    table.add_column("Assigned To", style="dim")

    for i in rows:
        status_style = {
            "open": "yellow",
            "assigned": "blue",
            "in_progress": "cyan",
            "remediated": "green",
            "verified": "green bold",
            "closed": "dim",
            "risk_accepted": "magenta",
        }.get(i.status, "")
        priority_style = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
        }.get(i.priority, "")
        table.add_row(
            i.id[:8],
            i.framework or "",
            i.control_id or "",
            i.title[:50],
            f"[{status_style}]{i.status}[/]",
            f"[{priority_style}]{i.priority}[/]",
            i.assigned_to or "",
        )

    console.print(table)


@cli.command("issues-auto-create")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
def issues_auto_create(framework: str | None) -> None:
    """Auto-create issues from non-compliant control results."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.issues import IssueManager

    init_db()
    mgr = IssueManager()

    with get_session() as session:
        created = mgr.auto_create_from_results(session, framework=framework)

    if not created:
        console.print("[dim]No new issues to create. All non-compliant results already have issues.[/dim]")
        return

    console.print(f"[green]Created {len(created)} issue(s):[/green]")
    for issue in created:
        console.print(f"  [cyan]{issue.id[:8]}[/cyan] [{issue.priority}] {issue.title[:70]}")


@cli.command("systems")
def systems_list() -> None:
    """List active system profiles."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.system_profile import SystemProfileManager

    init_db()
    mgr = SystemProfileManager()

    with get_session() as session:
        profiles = mgr.list_active(session)

    if not profiles:
        console.print("[dim]No system profiles found. Create one with 'warlock systems-create'.[/dim]")
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
@click.option("--impact", type=click.Choice(["low", "moderate", "high"]), default="moderate", help="Overall impact level")
@click.option("--framework", "-f", multiple=True, help="Applicable frameworks (can specify multiple)")
@click.option("--connector", "-c", multiple=True, help="Connector scope (can specify multiple)")
def systems_create(name: str, acronym: str | None, description: str, impact: str, framework: tuple, connector: tuple) -> None:
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


def _print_stats(stats) -> None:
    table = Table(title="Pipeline Run")
    table.add_column("Metric", style="cyan")
    table.add_column("Value")
    table.add_row("Raw events collected", str(stats.raw_events_collected))
    table.add_row("Findings normalized", str(stats.findings_normalized))
    table.add_row("Controls mapped", str(stats.controls_mapped))
    table.add_row("Results assessed", str(stats.results_assessed))
    table.add_row("Connectors OK", str(stats.connectors_succeeded))
    table.add_row("Connectors failed", str(stats.connectors_failed))
    table.add_row("Duration", f"{stats.duration_seconds:.1f}s" if stats.duration_seconds else "—")
    if stats.errors:
        table.add_row("Errors", str(len(stats.errors)))
    console.print(table)

    if stats.errors:
        console.print(f"\n[yellow]Errors ({len(stats.errors)}):[/yellow]")
        for err in stats.errors[:10]:
            console.print(f"  [dim]• {err}[/dim]")
        if len(stats.errors) > 10:
            console.print(f"  [dim]... and {len(stats.errors) - 10} more[/dim]")


if __name__ == "__main__":
    cli()
