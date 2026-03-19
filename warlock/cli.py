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
                pipeline._persist_finding(session, finding)
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

    if output:
        exporter.to_file(data, output)
        console.print(f"[green]OSCAL {fmt.upper()} written to {output}[/green]")
    else:
        from warlock.export.paths import export_path

        dest = export_path(fmt, framework=framework)
        exporter.to_file(data, str(dest))
        console.print(f"[green]OSCAL {fmt.upper()} written to {dest}[/green]")


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


# ---------------------------------------------------------------------------
# Retention commands
# ---------------------------------------------------------------------------


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
            console.print(f"  [dim]• {h['id'][:8]} — {h['reason']}[/dim]")
    else:
        console.print("\n[green]No active legal holds.[/green]")

    # Framework retention periods
    console.print("\n[bold]Framework Retention Periods[/bold]")
    for fw, days in sorted(FRAMEWORK_RETENTION.items()):
        years = days / 365
        console.print(f"  {fw:20s} {days:5d} days ({years:.0f} years)")


@retention.command("purge")
@click.option("--dry-run/--execute", default=True, help="Dry run (default) or actually delete")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework's retention period")
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


# ---------------------------------------------------------------------------
# Scheduler commands
# ---------------------------------------------------------------------------


@cli.group()
def scheduler() -> None:
    """Pipeline scheduler for continuous monitoring."""


@scheduler.command("start")
@click.option("--interval", "-i", default=60, help="Interval in minutes between pipeline runs")
def scheduler_start(interval: int) -> None:
    """Start the pipeline scheduler."""
    from warlock.pipeline.scheduler import get_scheduler

    sched = get_scheduler(interval_minutes=interval)
    sched.start()

    console.print(f"[green]Scheduler started (interval={interval}m)[/green]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")

    import signal
    import time

    stop_event = False

    def handle_signal(sig, frame):
        nonlocal stop_event
        stop_event = True
        sched.stop()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        while not stop_event and sched._running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sched.stop()
        console.print("\n[yellow]Scheduler stopped.[/yellow]")


@scheduler.command("status")
def scheduler_status() -> None:
    """Show scheduler status."""
    from warlock.pipeline.scheduler import get_scheduler

    sched = get_scheduler()
    st = sched.status

    console.print("\n[bold]Scheduler Status[/bold]")
    running_style = "green" if st["running"] else "red"
    console.print(f"  Running:    [{running_style}]{st['running']}[/]")
    console.print(f"  Interval:   {st['interval_minutes']}m")
    console.print(f"  Run count:  {st['run_count']}")
    console.print(f"  Last run:   {st['last_run'] or 'never'}")
    console.print(f"  Next run:   {st['next_run'] or 'n/a'}")
    if st["last_error"]:
        console.print(f"  Last error: [red]{st['last_error']}[/red]")


# ---------------------------------------------------------------------------
# Personnel commands
# ---------------------------------------------------------------------------


@cli.command("personnel")
@click.option("--department", "-d", default=None, help="Filter by department")
@click.option("--status", "-s", default=None, help="Filter by HR status (active, terminated, leave)")
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
        idp_style = {"active": "green", "ACTIVE": "green", "suspended": "yellow",
                      "deprovisioned": "red"}.get(p.idp_status or "", "dim")
        mfa_str = "[green]Yes[/]" if p.mfa_enabled else "[red]No[/]" if p.mfa_enabled is False else "[dim]?[/]"
        training_style = {"current": "green", "overdue": "red", "not_enrolled": "yellow"}.get(
            p.training_status or "", "dim"
        )
        risk_style = "red bold" if (p.risk_score or 0) >= 50 else "yellow" if (p.risk_score or 0) > 0 else "green"
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
        console.print(f"  {source.upper():10s}  created={data.get('created', 0)}  "
                      f"updated={data.get('updated', 0)}  flagged={data.get('flagged', 0)}")

    console.print(f"\n  Total personnel: {result.get('total_personnel', 0)}")

    # Show terminated-with-active-access as a critical alert
    with get_session() as session:
        terminated = mgr.terminated_with_active_access(session)

    if terminated:
        console.print(f"\n[red bold]CRITICAL: {len(terminated)} terminated employee(s) "
                      f"still active in IdP:[/red bold]")
        for p in terminated[:10]:
            console.print(f"  [red]• {p.full_name} ({p.email}) — HR: {p.hr_status}, "
                          f"IdP: {p.idp_status}[/red]")


# ---------------------------------------------------------------------------
# Questionnaire commands
# ---------------------------------------------------------------------------


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
            "draft": "dim", "sent": "blue", "in_progress": "cyan",
            "completed": "green", "reviewed": "green bold",
            "accepted": "green bold", "rejected": "red",
        }.get(q_row.status, "")
        risk_style = ""
        if q_row.risk_score is not None:
            risk_style = "red" if q_row.risk_score > 50 else "yellow" if q_row.risk_score > 25 else "green"

        due_str = ""
        if q_row.due_date:
            due_str = q_row.due_date.strftime("%Y-%m-%d") if hasattr(q_row.due_date, "strftime") else str(q_row.due_date)[:10]

        table.add_row(
            q_row.id[:8],
            q_row.vendor_name,
            f"[{status_style}]{q_row.status}[/]",
            f"{q_row.completion_pct or 0:.0f}%",
            f"[{risk_style}]{q_row.risk_score:.0f}[/]" if q_row.risk_score is not None else "[dim]—[/]",
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
        console.print(f"  [cyan]{t.id[:8]}[/cyan] {t.name} ({t.template_type}) — "
                      f"{t.total_questions} questions")


# ---------------------------------------------------------------------------
# Data Silo commands
# ---------------------------------------------------------------------------


@cli.command("data-silos")
@click.option("--type", "silo_type", default=None, help="Filter by silo type (s3_bucket, rds_database, ...)")
@click.option("--classification", "-c", default=None, help="Filter by classification")
@click.option("--provider", "-p", default=None, help="Filter by cloud provider")
@click.option("--limit", "-n", default=50, help="Max results")
def data_silos_list(silo_type: str | None, classification: str | None, provider: str | None, limit: int) -> None:
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
            "restricted": "red bold", "confidential": "red", "internal": "yellow",
            "public": "green", "unknown": "dim",
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
            console.print(f"  [dim]• {s.name} ({s.silo_type}) — {', '.join(issues)}[/dim]")

    if unclassified:
        console.print(f"\n[yellow]Unclassified silos ({len(unclassified)}):[/yellow]")
        for s in unclassified[:10]:
            console.print(f"  [dim]• {s.name} ({s.silo_type})[/dim]")


@cli.command("cadence")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--stale-only", is_flag=True, help="Show only stale controls")
def cadence_check(framework: str | None, stale_only: bool) -> None:
    """Check monitoring cadence — are controls being assessed on schedule?"""
    from warlock.db.engine import get_session, init_db
    from warlock.assessors.cadence import CadenceChecker

    init_db()
    checker = CadenceChecker()

    with get_session() as session:
        if stale_only:
            cadences = checker.get_stale_controls(session, framework=framework)
        elif framework:
            cadences = checker.check_framework(session, framework)
        else:
            all_c = checker.check_all(session)
            cadences = [c for clist in all_c.values() for c in clist]

    if not cadences:
        if stale_only:
            console.print("[green]All controls within monitoring frequency.[/green]")
        else:
            console.print("[dim]No control results found.[/dim]")
        return

    table = Table(title="Monitoring Cadence")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Frequency")
    table.add_column("Last Evidence")
    table.add_column("Hours Since", justify="right")
    table.add_column("Status")

    for c in cadences:
        if c.last_evidence_at:
            last_str = c.last_evidence_at.strftime("%Y-%m-%d %H:%M")
            hours_str = f"{c.hours_since:.0f}"
        else:
            last_str = "never"
            hours_str = "—"

        if c.staleness_ratio > 2.0:
            status = "[red bold]CRITICAL[/red bold]"
        elif c.is_stale:
            status = "[yellow]STALE[/yellow]"
        else:
            status = "[green]OK[/green]"

        table.add_row(c.framework, c.control_id, c.required_frequency, last_str, hours_str, status)

    console.print(table)

    stale_count = sum(1 for c in cadences if c.is_stale)
    if stale_count:
        console.print(f"\n[yellow]{stale_count} stale control(s)[/yellow]")


@cli.command("posture-history")
@click.option("--framework", "-f", required=True, help="Framework to query")
@click.option("--control", "-c", default=None, help="Specific control ID")
@click.option("--days", "-d", default=90, help="Lookback window in days")
def posture_history(framework: str, control: str | None, days: int) -> None:
    """Show posture trends over time per control."""
    from warlock.db.engine import get_session, init_db
    from warlock.assessors.posture import PostureTimeSeriesQuery

    init_db()
    tsq = PostureTimeSeriesQuery()

    with get_session() as session:
        if control:
            series_list = [tsq.query_control(session, framework, control, days)]
        else:
            series_list = tsq.query_framework(session, framework, days)

    if not series_list:
        console.print("[dim]No posture snapshots found. Run 'warlock collect' first.[/dim]")
        return

    table = Table(title=f"Posture Trends ({days}d)")
    table.add_column("Control")
    table.add_column("Trend")
    table.add_column("Slope", justify="right")
    table.add_column("Points", justify="right")
    table.add_column("Latest Score", justify="right")
    table.add_column("Latest Status")

    for ts in series_list:
        if ts.trend == "improving":
            trend_str = "[green]\u2191 improving[/green]"
        elif ts.trend == "degrading":
            trend_str = "[red]\u2193 degrading[/red]"
        else:
            trend_str = "[dim]\u2192 stable[/dim]"

        if ts.points:
            latest = ts.points[-1]
            score_str = f"{latest.posture_score:.1f}"
            status_str = latest.status
        else:
            score_str = "\u2014"
            status_str = "no data"

        table.add_row(
            ts.control_id,
            trend_str,
            f"{ts.trend_slope:+.3f}/d",
            str(len(ts.points)),
            score_str,
            status_str,
        )

    console.print(table)


@cli.command("sufficiency")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--below", type=float, default=None, help="Show only controls below this score")
def sufficiency_check(framework: str | None, below: float | None) -> None:
    """Show evidence sufficiency scores per control."""
    from warlock.db.engine import get_session, init_db
    from warlock.assessors.posture import EvidenceSufficiencyScorer

    init_db()
    scorer = EvidenceSufficiencyScorer()

    with get_session() as session:
        if framework:
            fw_result = scorer.score_framework(session, framework)
            scores = fw_result.control_scores
        else:
            from sqlalchemy import distinct
            from warlock.db.models import ControlResult
            fw_rows = session.query(distinct(ControlResult.framework)).all()
            scores = []
            for (fw,) in fw_rows:
                fw_result = scorer.score_framework(session, fw)
                scores.extend(fw_result.control_scores)

    if below is not None:
        scores = [s for s in scores if s.score < below]

    scores.sort(key=lambda s: s.score)

    if not scores:
        console.print("[green]All controls have sufficient evidence.[/green]")
        return

    table = Table(title="Evidence Sufficiency")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Score", justify="right")
    table.add_column("Volume", justify="right")
    table.add_column("Freshness", justify="right")
    table.add_column("Diversity", justify="right")
    table.add_column("Assertion", justify="right")
    table.add_column("Gaps")

    for s in scores:
        score_style = "red" if s.score < 40 else ("yellow" if s.score < 60 else "green")
        gaps_str = "; ".join(s.gaps[:2]) if s.gaps else "—"
        if len(s.gaps) > 2:
            gaps_str += f" (+{len(s.gaps) - 2})"

        table.add_row(
            s.framework,
            s.control_id,
            f"[{score_style}]{s.score:.0f}[/{score_style}]",
            f"{s.evidence_volume:.0f}",
            f"{s.evidence_freshness:.0f}",
            f"{s.evidence_diversity:.0f}",
            f"{s.assertion_coverage:.0f}",
            gaps_str,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Phase 2: POA&M, Compensating Controls, Risk Acceptance
# ---------------------------------------------------------------------------


@cli.command("poams")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--status", "-s", default=None, help="Filter by status")
@click.option("--overdue", is_flag=True, help="Show only overdue POA&Ms")
@click.option("--limit", "-n", default=50, help="Max results")
def poams_list(framework: str | None, status: str | None, overdue: bool, limit: int) -> None:
    """List Plans of Action & Milestones."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.poam import POAMManager

    init_db()
    mgr = POAMManager()

    with get_session() as session:
        if overdue:
            rows = mgr.get_overdue(session)
        else:
            rows = mgr.list_poams(session, framework=framework, status=status)

    rows = rows[:limit]
    if not rows:
        console.print("[dim]No POA&Ms found.[/dim]")
        return

    table = Table(title="Plans of Action & Milestones")
    table.add_column("ID", max_width=8)
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Due Date")
    table.add_column("Delays", justify="right")
    table.add_column("Weakness", max_width=40)

    for p in rows:
        due = p.scheduled_completion.strftime("%Y-%m-%d") if p.scheduled_completion else "—"
        status_style = "red" if p.status in ("draft", "open") else ("yellow" if p.status == "in_progress" else "green")
        table.add_row(
            p.id[:8], p.framework, p.control_id, p.severity,
            f"[{status_style}]{p.status}[/{status_style}]",
            due, str(p.delay_count or 0),
            (p.weakness_description or "")[:40],
        )

    console.print(table)


@cli.command("compensating-controls")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--status", "-s", default=None, help="Filter by status")
def compensating_list(framework: str | None, status: str | None) -> None:
    """List compensating controls."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.compensating import CompensatingControlManager

    init_db()
    mgr = CompensatingControlManager()

    with get_session() as session:
        rows = mgr.list_controls(session, framework=framework, status=status)

    if not rows:
        console.print("[dim]No compensating controls found.[/dim]")
        return

    table = Table(title="Compensating Controls")
    table.add_column("ID", max_width=8)
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Title", max_width=30)
    table.add_column("Status")
    table.add_column("Effectiveness", justify="right")
    table.add_column("Expiry")

    for c in rows:
        exp = c.expiry_date.strftime("%Y-%m-%d") if c.expiry_date else "—"
        eff = f"{c.effectiveness_score:.0f}" if c.effectiveness_score else "—"
        table.add_row(
            c.id[:8], c.original_framework, c.original_control_id,
            (c.title or "")[:30], c.status, eff, exp,
        )

    console.print(table)


@cli.command("risk-acceptances")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--status", "-s", default=None, help="Filter by status")
@click.option("--expiring-soon", type=int, default=None, help="Show acceptances expiring within N days")
def risk_acceptances_list(framework: str | None, status: str | None, expiring_soon: int | None) -> None:
    """List risk acceptances."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.risk_acceptance import RiskAcceptanceManager

    init_db()
    mgr = RiskAcceptanceManager()

    with get_session() as session:
        rows = mgr.list_acceptances(session, framework=framework, status=status, expiring_days=expiring_soon)

    if not rows:
        console.print("[dim]No risk acceptances found.[/dim]")
        return

    table = Table(title="Risk Acceptances")
    table.add_column("ID", max_width=8)
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Risk Level")
    table.add_column("Status")
    table.add_column("Approved By")
    table.add_column("Expires")

    for r in rows:
        exp = r.expiry_date.strftime("%Y-%m-%d") if r.expiry_date else "—"
        table.add_row(
            r.id[:8], r.framework, r.control_id, r.risk_level,
            r.status, r.approved_by or "—", exp,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Phase 3: Inheritance & Dependencies
# ---------------------------------------------------------------------------


@cli.command("inheritance")
@click.option("--system", required=True, help="System profile ID")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def inheritance_list(system: str, framework: str | None) -> None:
    """Show control inheritance map for a system."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.inheritance import InheritanceManager

    init_db()
    mgr = InheritanceManager()

    with get_session() as session:
        rows = mgr.get_for_system(session, system, framework=framework)

    if not rows:
        console.print("[dim]No inheritance mappings found.[/dim]")
        return

    table = Table(title="Control Inheritance")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Type")
    table.add_column("Provider")
    table.add_column("Evidence Req")
    table.add_column("Status")

    for ci in rows:
        type_style = {"inherited": "cyan", "shared": "yellow", "common": "blue", "system_specific": "white"}.get(ci.inheritance_type, "white")
        table.add_row(
            ci.framework, ci.control_id,
            f"[{type_style}]{ci.inheritance_type}[/{type_style}]",
            ci.provider_system_id[:8] if ci.provider_system_id else "—",
            ci.evidence_requirement, ci.status,
        )

    console.print(table)


@cli.command("dependencies")
@click.option("--system", default=None, help="Filter by system profile ID")
def dependencies_list(system: str | None) -> None:
    """Show cross-system dependency graph."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SystemDependency

    init_db()

    with get_session() as session:
        q = session.query(SystemDependency)
        if system:
            q = q.filter(
                (SystemDependency.consumer_system_id == system) |
                (SystemDependency.provider_system_id == system)
            )
        rows = q.all()

    if not rows:
        console.print("[dim]No system dependencies found.[/dim]")
        return

    table = Table(title="System Dependencies")
    table.add_column("Consumer", max_width=8)
    table.add_column("Provider", max_width=8)
    table.add_column("Type")
    table.add_column("Shared Controls")

    for d in rows:
        ctrls = ", ".join((d.shared_controls or [])[:3])
        if len(d.shared_controls or []) > 3:
            ctrls += f" (+{len(d.shared_controls) - 3})"
        table.add_row(
            d.consumer_system_id[:8], d.provider_system_id[:8],
            d.dependency_type, ctrls,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Phase 4: Drift, Simulation, Effectiveness
# ---------------------------------------------------------------------------


@cli.command("drift")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--days", "-d", default=30, help="Lookback window in days")
@click.option("--direction", default=None, help="Filter: improved or degraded")
def drift_list(framework: str | None, days: int, direction: str | None) -> None:
    """Show compliance drift events with correlated changes."""
    from warlock.db.engine import get_session, init_db
    from warlock.assessors.drift import DriftDetector

    init_db()
    detector = DriftDetector()

    with get_session() as session:
        drifts = detector.get_drifts(session, framework=framework, days=days, direction=direction)

    if not drifts:
        console.print("[green]No compliance drift detected.[/green]")
        return

    table = Table(title=f"Compliance Drift ({days}d)")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Direction")
    table.add_column("From")
    table.add_column("To")
    table.add_column("Correlated Changes", justify="right")
    table.add_column("Detected")

    for d in drifts:
        dir_style = "red" if d.drift_direction == "degraded" else "green"
        changes = len(d.correlated_change_event_ids or [])
        table.add_row(
            d.framework, d.control_id,
            f"[{dir_style}]{d.drift_direction}[/{dir_style}]",
            d.previous_status, d.new_status,
            str(changes),
            d.detected_at.strftime("%Y-%m-%d %H:%M") if d.detected_at else "—",
        )

    console.print(table)


@cli.command("simulate-audit")
@click.option("--framework", "-f", required=True, help="Framework to simulate")
@click.option("--date", required=True, help="Target audit date (YYYY-MM-DD)")
@click.option("--system", default=None, help="System profile ID")
def simulate_audit(framework: str, date: str, system: str | None) -> None:
    """Simulate what an auditor would see at a future date."""
    from datetime import datetime as dt
    from warlock.db.engine import get_session, init_db
    from warlock.assessors.simulation import AuditSimulator

    init_db()
    target = dt.fromisoformat(date).replace(tzinfo=__import__("datetime").timezone.utc)
    sim = AuditSimulator()

    with get_session() as session:
        result = sim.simulate(session, framework, target, system_id=system)

    console.print(f"\n[bold]Audit Simulation: {framework} @ {date}[/bold]")
    console.print(f"  Projected coverage: [{'green' if result.projected_coverage >= 80 else 'red'}]{result.projected_coverage:.1f}%[/]")
    console.print(f"  Total controls:     {result.total_controls}")
    console.print(f"  Stale by date:      [yellow]{len(result.stale_controls)}[/yellow]")
    console.print(f"  Overdue POA&Ms:     [yellow]{len(result.overdue_poams)}[/yellow]")
    console.print(f"  Expiring acceptances: [yellow]{len(result.expiring_acceptances)}[/yellow]")
    console.print(f"  At-risk controls:   [red]{len(result.at_risk_controls)}[/red]")


@cli.command("effectiveness")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--days", "-d", default=365, help="Trailing window in days")
def effectiveness_report(framework: str | None, days: int) -> None:
    """Show control effectiveness scores over time."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import PostureSnapshot

    init_db()

    with get_session() as session:
        from datetime import timedelta
        from datetime import datetime, timezone
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        q = session.query(PostureSnapshot).filter(
            PostureSnapshot.snapshot_date >= cutoff,
            PostureSnapshot.uptime_pct.isnot(None),
        )
        if framework:
            q = q.filter(PostureSnapshot.framework == framework)

        # Get latest snapshot per control
        latest = q.order_by(PostureSnapshot.snapshot_date.desc()).all()
        seen = set()
        rows = []
        for s in latest:
            key = (s.framework, s.control_id)
            if key not in seen:
                seen.add(key)
                rows.append(s)

    if not rows:
        console.print("[dim]No effectiveness data. Run posture snapshots first.[/dim]")
        return

    rows.sort(key=lambda s: s.uptime_pct or 0)

    table = Table(title=f"Control Effectiveness ({days}d)")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Uptime %", justify="right")
    table.add_column("MTTR (hrs)", justify="right")
    table.add_column("Drift Count", justify="right")

    for s in rows:
        uptime = f"{s.uptime_pct:.1f}" if s.uptime_pct is not None else "—"
        mttr = f"{s.mttr_hours:.1f}" if s.mttr_hours is not None else "—"
        drift = str(s.drift_count) if s.drift_count is not None else "—"
        style = "red" if (s.uptime_pct or 0) < 80 else ("yellow" if (s.uptime_pct or 0) < 95 else "green")
        table.add_row(s.framework, s.control_id, f"[{style}]{uptime}[/{style}]", mttr, drift)

    console.print(table)


# ---------------------------------------------------------------------------
# Phase 5: Framework Diff
# ---------------------------------------------------------------------------


@cli.command("framework-diff")
@click.option("--old", "old_path", required=True, help="Path to old framework YAML")
@click.option("--new", "new_path", required=True, help="Path to new framework YAML")
def framework_diff_cmd(old_path: str, new_path: str) -> None:
    """Compare two framework versions and show control changes."""
    from warlock.frameworks.diff import FrameworkDiff

    differ = FrameworkDiff()
    result = differ.diff(old_path, new_path)

    console.print("\n[bold]Framework Diff[/bold]")
    console.print(f"  Added:     [green]{len(result.added_controls)}[/green]")
    console.print(f"  Removed:   [red]{len(result.removed_controls)}[/red]")
    console.print(f"  Modified:  [yellow]{len(result.modified_controls)}[/yellow]")
    console.print(f"  Unchanged: [dim]{len(result.unchanged_controls)}[/dim]")

    if result.added_controls:
        console.print("\n[green]Added:[/green]")
        for c in sorted(result.added_controls)[:20]:
            console.print(f"  + {c}")
    if result.removed_controls:
        console.print("\n[red]Removed:[/red]")
        for c in sorted(result.removed_controls)[:20]:
            console.print(f"  - {c}")
    if result.modified_controls:
        console.print("\n[yellow]Modified:[/yellow]")
        for c in sorted(result.modified_controls)[:20]:
            console.print(f"  ~ {c}")


if __name__ == "__main__":
    cli()
