"""CLI — the interface to the pipeline."""

from __future__ import annotations

import logging
import os

import click
from rich.console import Console
from rich.table import Table

console = Console()


def _error(msg: str) -> None:
    """Print error to stderr and exit with code 1."""
    console.print(f"[red]{msg}[/red]")
    raise SystemExit(1)


def _get_actor() -> str:
    """Return the actor identity from env or default."""
    return os.environ.get("WLK_CLI_ACTOR", "cli@warlock")


def _parse_ai_response(value) -> str:
    """Extract text from an AI response value, handling JSON wrapping."""
    import json as _json
    response_text = value if isinstance(value, str) else str(value)
    try:
        parsed = _json.loads(response_text)
        response_text = parsed.get("response") or str(parsed)
    except (ValueError, KeyError):
        pass
    return response_text


def _ai_repl(svc, session_id: str, ctx, entity_label: str) -> None:
    """Run an interactive AI conversation REPL.

    Parameters
    ----------
    svc: AI service instance
    session_id: conversation session ID
    ctx: ConversationContext for the AI service
    entity_label: human-readable label shown in the REPL prompt
    """
    console.print(f"[cyan]Entering interactive AI session for {entity_label}.[/cyan]")
    console.print("[dim]Type your question and press Enter. Type 'exit' or press Ctrl-C to quit.[/dim]\n")
    while True:
        try:
            user_input = input("You: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Session ended.[/dim]")
            break
        if not user_input or user_input.lower() in ("exit", "quit", "q"):
            console.print("[dim]Session ended.[/dim]")
            break
        result = svc.converse(session_id=session_id, message=user_input, context=ctx)
        if result.ai_used:
            response_text = _parse_ai_response(result.value)
            console.print(f"AI: {response_text}\n")
        else:
            console.print(f"[yellow]AI unavailable: {result.fallback_reason}[/yellow]")
            break


def _resolve_system_id(session, value: str) -> str:
    """Resolve a system profile ID from a UUID, partial UUID, or acronym."""
    from warlock.db.models import SystemProfile

    # C-1: Guard against empty string (startswith("") matches everything)
    if not value or not value.strip():
        return value

    # Try exact UUID match first
    sp = session.query(SystemProfile).filter(SystemProfile.id == value).first()
    if sp:
        return sp.id

    # C-5: Try case-insensitive acronym match, warn on ambiguous
    matches = session.query(SystemProfile).filter(
        SystemProfile.acronym.ilike(value)
    ).all()
    if len(matches) > 1:
        console.print(
            f"[yellow]Warning: ambiguous system match for '{value}'. "
            f"Matches: {', '.join(m.id[:8] + ' (' + (m.name or '') + ')' for m in matches)}. "
            f"Using first match.[/yellow]"
        )
        return matches[0].id
    if matches:
        return matches[0].id

    # C-5: Try partial UUID prefix, warn on ambiguous
    matches = session.query(SystemProfile).filter(
        SystemProfile.id.startswith(value)
    ).all()
    if len(matches) > 1:
        console.print(
            f"[yellow]Warning: ambiguous system match for '{value}'. "
            f"Matches: {', '.join(m.id[:8] + ' (' + (m.name or '') + ')' for m in matches)}. "
            f"Using first match.[/yellow]"
        )
        return matches[0].id
    if matches:
        return matches[0].id

    # Fall through -- return as-is, let the query return empty
    return value


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
    if stats.errors:
        raise SystemExit(1)


@cli.command()
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--status", default=None, type=click.Choice(["compliant", "non_compliant", "not_assessed", "partial"], case_sensitive=False), help="Filter by status")
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
@click.option("--ai/--no-ai", "use_ai", default=None, help="Override AI toggle for executive summary")
def coverage(framework: str | None, use_ai: bool | None) -> None:
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

    coverage_context: dict = {}
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
    if use_ai is not False:
        try:
            from warlock.ai.service import get_ai_service
            from warlock.ai.types import AITask

            svc = get_ai_service()
            if svc.is_task_enabled(AITask.EXECUTIVE_REPORT):
                result = svc.reason(AITask.EXECUTIVE_REPORT, context={"frameworks": coverage_context})
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
        sev_style = {"critical": "red bold", "high": "red", "medium": "yellow"}.get(f.severity, "dim")
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
            console.print("[yellow]AI service not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY.[/yellow]")
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


@cli.command()
@click.option("--source", "-s", required=True, help="Source identifier (e.g., webhook, manual)")
@click.option("--provider", "-p", required=True, help="Provider name (e.g., crowdstrike, okta)")
@click.option("--event-type", "-t", required=True, help="Event type label (e.g., falcon_detections)")
@click.option("--input-file", "file_path", required=True, type=click.Path(exists=True), help="Path to JSON file")
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
@click.option("--ai/--no-ai", "use_ai", default=None, help="Use AI to generate framework-aware narratives (SSP/POA&M)")
def oscal(framework, system_name, output, fmt, description, use_ai):
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
    if use_ai and fmt in ("ssp", "poam"):
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
                raise click.UsageError("SSP export requires --framework (-f)")
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


# NOTE: The `risk` command is now a group defined below (line ~924).
# The original `warlock risk` command is now `warlock risk analyze`.


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
@click.option("--ai/--no-ai", "use_ai", default=None, help="Override AI toggle for governance analysis")
def policy_coverage(framework: str, no_rag: bool, use_ai: bool | None) -> None:
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

    # AI governance analysis
    if use_ai is not False:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import AITask

        svc = get_ai_service()
        if svc.is_task_enabled(AITask.GOVERNANCE_ANALYSIS):
            ai_context = {
                "framework": framework,
                "total_controls": coverage.total_controls,
                "controls_with_policy": coverage.controls_with_policy,
                "coverage_pct": coverage.coverage_pct,
                "gaps": list(coverage.gaps)[:50],
            }
            try:
                result = svc.reason(AITask.GOVERNANCE_ANALYSIS, context=ai_context)
                if result.ai_used:
                    console.print("\n[bold]AI Governance Analysis:[/bold]")
                    value = result.value
                    if isinstance(value, dict):
                        analysis = value.get("analysis") or value.get("narrative") or str(value)
                        recs = value.get("recommendations", [])
                    else:
                        analysis = str(value) if value else ""
                        recs = []
                    if analysis:
                        console.print(analysis)
                    if recs:
                        console.print("\n[bold]Recommendations:[/bold]")
                        for rec in recs:
                            console.print(f"  [dim]• {rec}[/dim]")
            except Exception as exc:
                console.print(f"\n[dim]AI analysis unavailable: {exc.__class__.__name__}[/dim]")


@cli.command("issues")
@click.option("--status", "-s", default=None, help="Filter by status (open, assigned, in_progress, etc.)")
@click.option("--priority", "-p", default=None, help="Filter by priority (critical, high, medium, low)")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--assigned-to", default=None, help="Filter by assignee")
@click.option("--limit", "-n", default=50, help="Max results")
@click.option("--ask", default=None, help="Ask AI a question about the listed issues (e.g. 'What should I fix first?')")
def issues(status: str | None, priority: str | None, framework: str | None, assigned_to: str | None, limit: int, ask: str | None) -> None:
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

    # --ask: AI question about the listed issues (or REPL if empty)
    if ask is not None:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import ConversationContext

        svc = get_ai_service()
        if not svc.is_available():
            console.print("[yellow]AI service not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY.[/yellow]")
            return

        import uuid
        session_id = uuid.uuid4().hex
        issues_summary = [
            {
                "id": i.id[:8],
                "title": i.title,
                "framework": i.framework,
                "control_id": i.control_id,
                "priority": i.priority,
                "status": i.status,
            }
            for i in rows
        ]
        ctx = ConversationContext(
            entity_type="issues_list",
            entity_id="batch",
            entity_data={"issues": issues_summary, "count": len(rows)},
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
            _ai_repl(svc, session_id, ctx, f"issues ({len(rows)} items)")


@cli.command("issues-auto-create")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
@click.option("--actor", default=None, envvar="WLK_CLI_ACTOR", help="Actor identity for audit trail (default: cli@warlock, env: WLK_CLI_ACTOR)")
def issues_auto_create(framework: str | None, actor: str | None) -> None:
    """Auto-create issues from non-compliant control results."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.issues import IssueManager

    if actor:
        os.environ["WLK_CLI_ACTOR"] = actor

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
# Risk commands
# ---------------------------------------------------------------------------


@cli.group(invoke_without_command=True)
@click.pass_context
def risk(ctx: click.Context) -> None:
    """Monte Carlo risk quantification and cache management."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@risk.command("analyze")
@click.option("-f", "--framework", required=True, help="Framework to analyze (e.g. nist_800_53)")
@click.option("-n", "--iterations", default=10000, help="Monte Carlo iterations")
@click.option("--ai/--no-ai", "use_ai", default=None, help="Override AI toggle for risk narrative")
def risk_analyze(framework: str, iterations: int, use_ai: bool | None) -> None:
    """Run FAIR risk quantification for a framework."""
    from warlock.assessors.risk_engine import RiskEngine
    from warlock.db.engine import get_session, init_db

    init_db()
    engine = RiskEngine(default_iterations=iterations)

    console.print("[dim]Running Monte Carlo simulation...[/dim]")

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

    # AI risk narrative
    if use_ai is not False:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import AITask

        svc = get_ai_service()
        if svc.is_task_enabled(AITask.RISK_NARRATIVE):
            ai_context = {
                "framework": framework,
                "scenarios": scenarios,
                "portfolio": portfolio,
            }
            try:
                ai_result = svc.reason(AITask.RISK_NARRATIVE, context=ai_context)
                if ai_result.ai_used:
                    console.print("\n[bold]AI Risk Narrative:[/bold]")
                    value = ai_result.value
                    if isinstance(value, dict):
                        narrative = value.get("narrative") or value.get("analysis") or str(value)
                    else:
                        narrative = str(value) if value else ""
                    if narrative:
                        console.print(narrative)
            except Exception as exc:
                console.print(f"\n[dim]AI narrative unavailable: {exc.__class__.__name__}[/dim]")


@risk.command("precompute")
@click.option(
    "--ttl",
    default=4.0,
    show_default=True,
    help="Cache TTL in hours.  Entries fresher than this are not re-simulated.",
)
def risk_precompute(ttl: float) -> None:
    """Pre-warm the Monte Carlo cache for all active frameworks.

    Discovers active frameworks from ControlResult, then runs
    analyze_framework_risk() for each one.  Frameworks with a valid
    cached entry are skipped (cache hit); stale or missing entries
    trigger a full simulation (cache miss).
    """
    from warlock.assessors.risk_engine import RiskEngine
    from warlock.db.engine import get_session, init_db

    init_db()
    engine = RiskEngine()

    with get_session() as session:
        summary = engine.precompute_all_frameworks(session, cache_ttl_hours=ttl)

    if not summary:
        console.print("[dim]No active frameworks found. Run 'warlock collect' first.[/dim]")
        return

    table = Table(title="Monte Carlo Cache Pre-computation Results")
    table.add_column("Framework", style="cyan")
    table.add_column("Cache Hit", justify="center")
    table.add_column("Duration (ms)", justify="right")
    table.add_column("Notes", style="dim")

    hits = 0
    for framework in sorted(summary):
        entry = summary[framework]
        cached = entry.get("cached", False)
        duration_ms = entry.get("duration_ms", 0)
        error = entry.get("error")

        if cached:
            hits += 1
            hit_display = "[green]yes[/green]"
            notes = "skipped — fresh cache"
        elif error:
            hit_display = "[red]err[/red]"
            notes = error[:60]
        else:
            hit_display = "[yellow]no[/yellow]"
            notes = "simulation ran"

        table.add_row(framework, hit_display, str(duration_ms), notes)

    console.print(table)

    misses = len(summary) - hits
    console.print(
        f"\n[bold]Summary:[/bold] {len(summary)} frameworks — "
        f"[green]{hits} cache hits[/green], "
        f"[yellow]{misses} simulations run[/yellow]"
    )


@risk.command("cache-stats")
def risk_cache_stats() -> None:
    """Show Monte Carlo DB cache statistics."""
    from warlock.assessors.risk_engine import RiskEngine
    from warlock.db.engine import get_session, init_db

    init_db()
    engine = RiskEngine()

    with get_session() as session:
        stats = engine.get_cache_stats(session)

    console.print("\n[bold]Monte Carlo Cache Statistics[/bold]")
    console.print(f"  Total cached entries:   {stats['total_entries']}")
    age = stats["oldest_entry_age_hours"]
    console.print(f"  Oldest entry age:       {f'{age:.1f} hours' if age is not None else 'n/a'}")

    hit_rate = stats["hit_rate"]
    hr_display = f"{hit_rate * 100:.1f}%" if hit_rate is not None else "n/a (no calls recorded)"
    console.print(f"  Cache hits (runtime):   {stats['cache_hits']}")
    console.print(f"  Cache misses (runtime): {stats['cache_misses']}")
    console.print(f"  Hit rate:               {hr_display}")

    if stats["entries_per_framework"]:
        console.print()
        table = Table(title="Entries per Framework")
        table.add_column("Framework", style="cyan")
        table.add_column("Entries", justify="right")
        for fw, count in sorted(stats["entries_per_framework"].items()):
            table.add_row(fw, str(count))
        console.print(table)
    else:
        console.print("\n[dim]No cached entries found.[/dim]")


@risk.command("invalidate")
@click.option("--framework", "-f", default=None, help="Framework to invalidate (omit for all)")
@click.confirmation_option(prompt="This will delete cached risk analyses. Continue?")
def risk_invalidate(framework: str | None) -> None:
    """Delete cached Monte Carlo entries from the database.

    Pass --framework to target a single framework, or omit it to
    clear the entire cache.
    """
    from warlock.assessors.risk_engine import RiskEngine
    from warlock.db.engine import get_session, init_db

    init_db()
    engine = RiskEngine()

    with get_session() as session:
        result = engine.invalidate_cache(session, framework=framework)

    scope = f"framework '{framework}'" if framework else "all frameworks"
    console.print(
        f"[green]Invalidated {result['deleted']} cached entries for {scope}.[/green]"
    )


# ---------------------------------------------------------------------------
# AI commands
# ---------------------------------------------------------------------------


@cli.group(invoke_without_command=True)
@click.pass_context
def ai(ctx: click.Context) -> None:
    """AI reasoning management — status, models, configuration."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@ai.command("status")
def ai_status() -> None:
    """Show AI service status — provider, model, availability."""
    from warlock.ai.service import get_ai_service

    svc = get_ai_service()
    available = svc.is_available()

    if available:
        console.print("[green]AI enabled[/green]")
        console.print(f"  Provider:  {svc._provider_name}")
        console.print(f"  Model:     {svc._model}")
        console.print(f"  Base URL:  {svc._base_url or '(default)'}")
        console.print(f"  Max tokens: {svc._max_tokens}")
    else:
        console.print("[yellow]AI not configured or disabled[/yellow]")
        console.print("  Set WLK_AI_PROVIDER, WLK_AI_API_KEY, and WLK_AI_MODEL to enable.")
        console.print("  Or use: warlock ai configure --provider ollama --model qwen3-coder:30b")


@ai.command("models")
def ai_models() -> None:
    """List available models for the configured provider."""
    from warlock.ai.service import get_ai_service

    svc = get_ai_service()
    if not svc.is_available():
        _error("AI not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY first.")

    console.print(f"[dim]Discovering models for {svc._provider_name}...[/dim]")
    try:
        models = svc.list_models()
    except Exception as exc:
        _error(f"Model discovery failed: {exc}")

    if not models:
        console.print("[yellow]No models found.[/yellow]")
        return

    table = Table(title=f"Available Models ({svc._provider_name})")
    table.add_column("Model ID", style="cyan")
    table.add_column("Display Name")
    table.add_column("Verified", justify="center")

    for m in models:
        verified = "[green]yes[/green]" if m.verified else "[yellow]no[/yellow]"
        table.add_row(m.id, m.display_name, verified)

    console.print(table)
    console.print(f"\n[dim]Current model: {svc._model}[/dim]")


@ai.command("configure")
@click.option("--provider", "-p", required=True, type=click.Choice(["anthropic", "openai", "gemini", "ollama"]), help="AI provider")
@click.option("--api-key", "-k", default=None, help="API key (or set WLK_AI_API_KEY)")
@click.option("--model", "-m", default=None, help="Model to use (omit to see available models)")
@click.option("--base-url", "-u", default="", help="Base URL (for Ollama cloud/local)")
def ai_configure(provider: str, api_key: str | None, model: str | None, base_url: str) -> None:
    """Configure the AI provider — discover models and validate connectivity."""
    from warlock.ai.discovery import ModelDiscovery

    key = api_key or os.environ.get("WLK_AI_API_KEY", "")
    if not key:
        _error("API key required. Pass --api-key or set WLK_AI_API_KEY.")

    console.print(f"[dim]Connecting to {provider}...[/dim]")
    discovery = ModelDiscovery()
    result = discovery.discover(provider, key, base_url)

    if result.connected:
        console.print(f"[green]Connected to {provider}[/green]")
    else:
        console.print(f"[yellow]Could not connect to {provider}: {result.error}[/yellow]")
        if result.models:
            console.print("[dim]Showing fallback model list:[/dim]")

    if result.models:
        table = Table(title="Available Models")
        table.add_column("Model ID", style="cyan")
        table.add_column("Verified", justify="center")
        for m in result.models:
            verified = "[green]yes[/green]" if m.verified else "[dim]fallback[/dim]"
            table.add_row(m.id, verified)
        console.print(table)

    if model:
        console.print(f"\n[dim]Validating model '{model}'...[/dim]")
        valid = discovery.validate_model(provider, key, model, base_url)
        if valid:
            console.print(f"[green]Model '{model}' is accessible.[/green]")
        else:
            console.print(f"[red]Model '{model}' could not be validated.[/red]")

    console.print("\n[bold]To activate, set these environment variables:[/bold]")
    console.print(f"  export WLK_AI_PROVIDER={provider}")
    console.print("  export WLK_AI_API_KEY=<your-key>")
    if model:
        console.print(f"  export WLK_AI_MODEL={model}")
    if base_url:
        console.print(f"  export WLK_AI_BASE_URL={base_url}")


@ai.command("test")
@click.option("--prompt", "-p", default="Respond with OK if you can read this.", help="Test prompt to send")
def ai_test(prompt: str) -> None:
    """Send a test prompt to verify the AI provider is working."""
    from warlock.ai.service import get_ai_service
    from warlock.ai.types import AITask

    svc = get_ai_service()
    if not svc.is_available():
        _error("AI not configured. Run 'warlock ai configure' first.")

    console.print(f"[dim]Sending test prompt to {svc._provider_name}/{svc._model}...[/dim]")
    try:
        result = svc.reason(
            task=AITask.FOLLOW_UP,
            context={"question": prompt, "entity_summary": "Test prompt", "compliance_context": "None"},
        )
        if result.ai_used:
            console.print(f"[green]Response received ({result.latency_ms}ms):[/green]")
            console.print(f"  {result.value}")
            if result.token_usage:
                console.print(f"  [dim]Tokens: {result.token_usage.input_tokens} in / {result.token_usage.output_tokens} out[/dim]")
        else:
            console.print(f"[yellow]AI not used: {result.fallback_reason}[/yellow]")
    except Exception as exc:
        _error(f"AI test failed: {exc}")


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
@click.option("--system", required=True, help="System profile ID or acronym")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def inheritance_list(system: str, framework: str | None) -> None:
    """Show control inheritance map for a system."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.inheritance import InheritanceManager

    init_db()
    mgr = InheritanceManager()

    with get_session() as session:
        system_id = _resolve_system_id(session, system)
        rows = mgr.get_for_system(session, system_id, framework=framework)

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
@click.option("--ai/--no-ai", "use_ai", default=None, help="Override AI toggle for auditor simulation")
def simulate_audit(framework: str, date: str, system: str | None, use_ai: bool | None) -> None:
    """Simulate what an auditor would see at a future date."""
    from datetime import datetime as dt
    from warlock.db.engine import get_session, init_db
    from warlock.assessors.simulation import AuditSimulator

    init_db()
    try:
        target = dt.fromisoformat(date).replace(tzinfo=__import__("datetime").timezone.utc)
    except ValueError:
        raise click.BadParameter("Invalid date format. Use YYYY-MM-DD.")
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

    # AI auditor readiness assessment
    if use_ai is not False:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import AITask

        svc = get_ai_service()
        if svc.is_task_enabled(AITask.AUDIT_READINESS):
            ai_context = {
                "framework": framework,
                "target_date": date,
                "projected_coverage": result.projected_coverage,
                "total_controls": result.total_controls,
                "stale_controls_count": len(result.stale_controls),
                "overdue_poams_count": len(result.overdue_poams),
                "expiring_acceptances_count": len(result.expiring_acceptances),
                "at_risk_controls_count": len(result.at_risk_controls),
            }
            try:
                ai_result = svc.reason(AITask.AUDIT_READINESS, context=ai_context)
                if ai_result.ai_used:
                    console.print("\n[bold]AI Audit Readiness Assessment:[/bold]")
                    value = ai_result.value
                    if isinstance(value, dict):
                        assessment = value.get("assessment") or value.get("narrative") or ""
                        readiness_score = value.get("readiness_score")
                        actions = value.get("actions", [])
                        if readiness_score is not None:
                            score_style = "green" if readiness_score >= 0.8 else "yellow" if readiness_score >= 0.5 else "red"
                            console.print(f"  Readiness score: [{score_style}]{readiness_score:.0%}[/]")
                        if assessment:
                            console.print(f"\n{assessment}")
                        if actions:
                            console.print("\n[bold]Recommended actions:[/bold]")
                            for action in actions:
                                console.print(f"  [dim]• {action}[/dim]")
                    else:
                        console.print(str(value) if value else "")
            except Exception as exc:
                console.print(f"\n[dim]AI assessment unavailable: {exc.__class__.__name__}[/dim]")


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
@click.option("--old", "old_path", required=True, type=click.Path(exists=True), help="Path to old framework YAML")
@click.option("--new", "new_path", required=True, type=click.Path(exists=True), help="Path to new framework YAML")
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


# ---------------------------------------------------------------------------
# Remediation commands
# ---------------------------------------------------------------------------


@cli.command("remediate")
@click.argument("item_id")
@click.option("--action", "-a", type=click.Choice(["show", "assign", "transition", "accept-risk", "extend", "comment"]), default="show", help="Action to take")
@click.option("--to", "to_value", required=False, help="Target value (email for assign, status for transition, days for extend)")
@click.option("--reason", required=False, help="Reason or comment text")
@click.option("--ai/--no-ai", "use_ai", default=None, help="Override AI toggle for remediation guidance")
@click.option("--ask", default=None, help="Ask AI a question about this item (interactive reasoning)")
@click.option("--actor", default=None, envvar="WLK_CLI_ACTOR", help="Actor identity for audit trail (default: cli@warlock, env: WLK_CLI_ACTOR)")
def remediate(item_id: str, action: str, to_value: str | None, reason: str | None, use_ai: bool | None, ask: str | None, actor: str | None) -> None:
    """Show remediation guidance and take action on issues/POA&Ms.

    Default (no --action) shows the full remediation plan: what's wrong,
    how to fix it (CLI + manual steps), what evidence to collect, and
    the current workflow state.

    \b
    Examples:
        warlock remediate <id>                                    # show full remediation plan
        warlock remediate <id> -a assign --to eve@acme.com        # assign to someone
        warlock remediate <id> -a transition --to in_progress     # move to in_progress
        warlock remediate <id> -a accept-risk --reason "Low risk" # accept the risk
        warlock remediate <id> -a extend --to 30 --reason "Delay" # extend deadline by 30 days
        warlock remediate <id> -a comment --reason "Patch staged" # add a comment
        warlock remediate <id> --ask "What is the fastest way to fix this?"
        warlock remediate <id> --ai                              # AI-enhanced remediation plan

    Use 'warlock issues' or 'warlock poams' to find IDs.
    """

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        Issue,
        POAM,
    )

    # If --actor was passed, override the env-based default
    if actor:
        os.environ["WLK_CLI_ACTOR"] = actor

    init_db()
    with get_session() as session:
        # Try to find as issue first, then POA&M
        issue = session.query(Issue).filter(Issue.id.startswith(item_id)).first()
        poam = session.query(POAM).filter(POAM.id.startswith(item_id)).first()

        if not issue and not poam:
            _error(f"Not found: {item_id}. Use 'warlock issues' or 'warlock poams' to find IDs.")

        # --- SHOW MODE: full remediation plan ---
        if action == "show":
            if issue:
                _show_remediation_for_issue(session, issue)
            else:
                _show_remediation_for_poam(session, poam)
            return

        # --- ACTION MODE ---
        if issue:
            from warlock.workflows.issues import IssueManager
            mgr = IssueManager()

            actor = _get_actor()
            if action == "assign":
                if not to_value:
                    _error("--to <email> required")
                mgr.assign(session, issue.id, to_value, assigned_by=actor)
                console.print(f"[green]Issue {issue.id[:8]} assigned to {to_value}[/green]")
            elif action == "transition":
                if not to_value:
                    _error("--to <status> required. Valid: open, assigned, in_progress, resolved, closed, verified, risk_accepted")
                try:
                    mgr.transition(session, issue.id, to_value, actor=actor)
                    console.print(f"[green]Issue {issue.id[:8]} → {to_value}[/green]")
                except ValueError as e:
                    _error(str(e))
            elif action == "accept-risk":
                mgr.accept_risk(session, issue.id, reason=reason or "Accepted via CLI", accepted_by=actor)
                console.print(f"[green]Issue {issue.id[:8]} risk accepted[/green]")
            elif action == "comment":
                if not reason:
                    _error("--reason <text> required")
                mgr.add_comment(session, issue.id, author=actor, content=reason)
                console.print(f"[green]Comment added to issue {issue.id[:8]}[/green]")
            elif action == "extend":
                _error("--action extend is not supported for issues. Use --action transition to change issue state.")

        elif poam:
            from warlock.workflows.poam import POAMManager
            mgr = POAMManager()
            actor = _get_actor()

            if action == "transition":
                if not to_value:
                    _error("--to <status> required. Valid: open, in_progress, remediated, verified, completed, risk_accepted, cancelled")
                try:
                    mgr.transition(session, poam.id, to_value, actor=actor)
                    console.print(f"[green]POA&M {poam.id[:8]} → {to_value}[/green]")
                except ValueError as e:
                    _error(str(e))
            elif action == "extend":
                if not to_value:
                    _error("--to <days> required")
                try:
                    days = int(to_value)
                except ValueError:
                    _error("--to must be number of days")
                from datetime import datetime, timedelta, timezone
                new_date = datetime.now(timezone.utc) + timedelta(days=days)
                mgr.extend(session, poam.id, justification=reason or "Extended via CLI", new_date=new_date, approved_by=actor)
                console.print(f"[green]POA&M {poam.id[:8]} extended by {days} days (new deadline: {new_date.date()})[/green]")
            elif action == "assign":
                _error("POA&Ms cannot be assigned directly. Assign the linked issue instead.")
            elif action == "accept-risk":
                try:
                    mgr.transition(session, poam.id, "risk_accepted", transitioned_by=actor)
                    console.print(f"[green]POA&M {poam.id[:8]} → risk_accepted[/green]")
                except ValueError as e:
                    _error(str(e))
            elif action == "comment":
                if not reason:
                    _error("--reason <text> required")
                # Add comment on linked issue if one exists, otherwise record as audit note
                from warlock.db.models import Issue
                linked_issue = session.query(Issue).filter(Issue.poam_id == poam.id).first()
                if linked_issue:
                    from warlock.workflows.issues import IssueManager
                    issue_mgr = IssueManager()
                    issue_mgr.add_comment(session, linked_issue.id, author=actor, content=reason)
                    console.print(f"[green]Comment added to linked issue {linked_issue.id[:8]} for POA&M {poam.id[:8]}[/green]")
                else:
                    # Store as audit note in delay_justifications (the only list field available)
                    from datetime import datetime, timezone
                    notes = list(poam.delay_justifications or [])
                    notes.append({
                        "date": datetime.now(timezone.utc).isoformat(),
                        "justification": reason,
                        "approved_by": actor,
                        "type": "comment",
                    })
                    poam.delay_justifications = notes
                    session.commit()
                    console.print(f"[green]Audit note added to POA&M {poam.id[:8]}[/green]")

        # --ask: interactive AI reasoning about this item
        if ask is not None:
            from warlock.ai.service import get_ai_service
            from warlock.ai.types import AITask, ConversationContext

            svc = get_ai_service()
            if not svc.is_available():
                console.print("[yellow]AI service not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY.[/yellow]")
                return

            entity_type = "issue" if issue else "poam"
            entity_id = issue.id if issue else poam.id
            entity_data: dict = {}
            if issue:
                entity_data = {
                    "title": issue.title,
                    "status": issue.status,
                    "priority": issue.priority,
                    "framework": issue.framework,
                    "control_id": issue.control_id,
                    "description": issue.description,
                }
            elif poam:
                entity_data = {
                    "weakness": poam.weakness_description,
                    "status": poam.status,
                    "severity": poam.severity,
                    "framework": poam.framework,
                    "control_id": poam.control_id,
                }

            import uuid
            session_id = uuid.uuid4().hex

            ctx = ConversationContext(
                entity_type=entity_type,
                entity_id=entity_id,
                entity_data=entity_data,
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
                _ai_repl(svc, session_id, ctx, f"{entity_type} {entity_id[:8]}")
            return

        # --ai: AI-enhanced remediation guidance appended to show mode
        if action == "show" and use_ai is not False:
            from warlock.ai.service import get_ai_service
            from warlock.ai.types import AITask

            svc = get_ai_service()
            if svc.is_task_enabled(AITask.REMEDIATION_GUIDANCE):
                ai_context: dict = {}
                if issue:
                    ai_context = {
                        "title": issue.title,
                        "framework": issue.framework,
                        "control_id": issue.control_id,
                        "priority": issue.priority,
                        "description": issue.description,
                    }
                elif poam:
                    ai_context = {
                        "weakness": poam.weakness_description,
                        "framework": poam.framework,
                        "control_id": poam.control_id,
                        "severity": poam.severity,
                    }
                try:
                    ai_result = svc.reason(AITask.REMEDIATION_GUIDANCE, context=ai_context)
                    if ai_result.ai_used:
                        console.print("\n[bold]AI Remediation Guidance:[/bold]")
                        value = ai_result.value
                        if isinstance(value, dict):
                            guidance_text = value.get("guidance") or value.get("narrative") or ""
                            steps = value.get("steps", [])
                            if guidance_text:
                                console.print(guidance_text)
                            if steps:
                                console.print("\n[bold]AI-suggested steps:[/bold]")
                                for i, step in enumerate(steps, 1):
                                    console.print(f"  {i}. {step}")
                        else:
                            console.print(str(value) if value else "")
                except Exception as exc:
                    console.print(f"\n[dim]AI guidance unavailable: {exc.__class__.__name__}[/dim]")


def _show_remediation_for_issue(session, issue) -> None:
    """Show full remediation guidance for an issue."""
    from rich.panel import Panel

    from warlock.db.models import CompensatingControl, ControlResult, POAM, RiskAcceptance

    # Header
    console.print()
    console.print(Panel(
        f"[bold]{issue.title}[/bold]\n\n"
        f"ID: {issue.id[:8]}  |  Framework: {issue.framework}  |  Control: {issue.control_id}\n"
        f"Status: [yellow]{issue.status}[/yellow]  |  Priority: {issue.priority}  |  "
        f"Assigned: {issue.assigned_to or '[dim]unassigned[/dim]'}",
        title="[bold red]Issue[/bold red]",
        border_style="red",
    ))

    # Description
    if issue.description:
        console.print(f"\n[bold]What's wrong:[/bold]\n{issue.description}")

    # Get the control result for remediation data
    result = None
    if issue.control_result_id:
        result = session.query(ControlResult).filter(ControlResult.id == issue.control_result_id).first()

    # Remediation steps from assertion engine
    if result and result.remediation_summary:
        console.print("\n[bold green]How to fix:[/bold green]")
        console.print(f"  {result.remediation_summary}")
        if result.remediation_steps:
            console.print("\n[bold]Manual steps:[/bold]")
            for i, step in enumerate(result.remediation_steps, 1):
                console.print(f"  {i}. {step}")
        if result.console_path:
            console.print(f"\n[bold]Console path:[/bold] {result.console_path}")

    if not (result and result.remediation_summary):
        from warlock.assessors.remediation_loader import get_remediation
        guidance = get_remediation(issue.framework, issue.control_id)
        if guidance:
            # Display from KB instead
            console.print("\n[bold green]How to fix:[/bold green]")
            console.print(f"  {guidance.get('summary', '')}")
            if guidance.get("remediation_steps"):
                console.print("\n[bold]Manual steps:[/bold]")
                for i, step in enumerate(guidance["remediation_steps"], 1):
                    console.print(f"  {i}. {step}")
            if guidance.get("console_path"):
                console.print(f"\n[bold]Console path:[/bold] {guidance['console_path']}")
            if guidance.get("recommended_reading"):
                console.print("\n[bold]Recommended reading:[/bold]")
                for ref in guidance["recommended_reading"]:
                    console.print(f"  - {ref}")

    # CLI remediation actions
    console.print("\n[bold cyan]CLI actions:[/bold cyan]")
    console.print(f"  warlock remediate {issue.id[:8]} -a assign --to <email>")
    console.print(f"  warlock remediate {issue.id[:8]} -a transition --to in_progress")
    console.print(f"  warlock remediate {issue.id[:8]} -a comment --reason \"<update>\"")
    console.print(f"  warlock remediate {issue.id[:8]} -a accept-risk --reason \"<justification>\"")

    # Evidence needed
    console.print("\n[bold]Evidence to collect:[/bold]")
    if result and result.assessor and result.assessor.startswith("assertion:"):
        assertion_name = result.assessor.split(":", 1)[1]
        console.print("  Re-run pipeline after fix: warlock collect")
        console.print(f"  Assertion '{assertion_name}' must pass on next assessment")
    else:
        console.print("  Re-run pipeline after fix: warlock collect")
        console.print(f"  Control {issue.control_id} must show as compliant")

    # Related items
    related_poam = session.query(POAM).filter(POAM.control_id == issue.control_id, POAM.framework == issue.framework).first()
    related_cc = session.query(CompensatingControl).filter(CompensatingControl.original_control_id == issue.control_id).first()
    related_ra = session.query(RiskAcceptance).filter(RiskAcceptance.control_id == issue.control_id).first()

    if related_poam or related_cc or related_ra:
        console.print("\n[bold]Related items:[/bold]")
        if related_poam:
            console.print(f"  POA&M: {related_poam.id[:8]} ({related_poam.status})")
        if related_cc:
            console.print(f"  Compensating control: {related_cc.title} ({related_cc.status})")
        if related_ra:
            console.print(f"  Risk acceptance: {related_ra.id[:8]} ({related_ra.status}, expires {related_ra.expiry_date})")

    console.print()


def _show_remediation_for_poam(session, poam) -> None:
    """Show full remediation guidance for a POA&M."""
    from rich.panel import Panel

    from warlock.db.models import CompensatingControl, ControlResult, RiskAcceptance

    console.print()
    console.print(Panel(
        f"[bold]{poam.weakness_description}[/bold]\n\n"
        f"ID: {poam.id[:8]}  |  Framework: {poam.framework}  |  Control: {poam.control_id}\n"
        f"Status: [yellow]{poam.status}[/yellow]  |  Severity: {poam.severity}  |  "
        f"Due: {poam.scheduled_completion or '[dim]no deadline[/dim]'}  |  Delays: {poam.delay_count}",
        title="[bold red]POA&M[/bold red]",
        border_style="red",
    ))

    # Get remediation from linked control result
    result = None
    if poam.control_result_id:
        result = session.query(ControlResult).filter(ControlResult.id == poam.control_result_id).first()
        if result and result.remediation_summary:
            console.print("\n[bold green]How to fix:[/bold green]")
            console.print(f"  {result.remediation_summary}")
            if result.remediation_steps:
                console.print("\n[bold]Manual steps:[/bold]")
                for i, step in enumerate(result.remediation_steps, 1):
                    console.print(f"  {i}. {step}")
            if result.console_path:
                console.print(f"\n[bold]Console path:[/bold] {result.console_path}")

    if not (result and result.remediation_summary):
        from warlock.assessors.remediation_loader import get_remediation
        guidance = get_remediation(poam.framework, poam.control_id)
        if guidance:
            # Display from KB instead
            console.print("\n[bold green]How to fix:[/bold green]")
            console.print(f"  {guidance.get('summary', '')}")
            if guidance.get("remediation_steps"):
                console.print("\n[bold]Manual steps:[/bold]")
                for i, step in enumerate(guidance["remediation_steps"], 1):
                    console.print(f"  {i}. {step}")
            if guidance.get("console_path"):
                console.print(f"\n[bold]Console path:[/bold] {guidance['console_path']}")
            if guidance.get("recommended_reading"):
                console.print("\n[bold]Recommended reading:[/bold]")
                for ref in guidance["recommended_reading"]:
                    console.print(f"  - {ref}")

    # Milestones
    if poam.milestones:
        console.print("\n[bold]Milestones:[/bold]")
        for m in poam.milestones:
            status = m.get("status", "pending")
            icon = "[green]done[/green]" if status == "completed" else "[yellow]pending[/yellow]"
            console.print(f"  {icon}  {m.get('description', '?')}")

    # CLI actions
    console.print("\n[bold cyan]CLI actions:[/bold cyan]")
    console.print(f"  warlock remediate {poam.id[:8]} -a transition --to open")
    console.print(f"  warlock remediate {poam.id[:8]} -a transition --to in_progress")
    console.print(f"  warlock remediate {poam.id[:8]} -a transition --to remediated")
    console.print(f"  warlock remediate {poam.id[:8]} -a extend --to 30 --reason \"<justification>\"")
    console.print(f"  warlock remediate {poam.id[:8]} -a transition --to risk_accepted")

    # Compensating controls
    cc = session.query(CompensatingControl).filter(CompensatingControl.poam_id == poam.id).first()
    if cc:
        console.print("\n[bold]Compensating control:[/bold]")
        console.print(f"  {cc.title} ({cc.status}, effectiveness: {cc.effectiveness_score}%)")

    # Risk acceptance
    ra = session.query(RiskAcceptance).filter(RiskAcceptance.poam_id == poam.id).first()
    if ra:
        console.print("\n[bold]Risk acceptance:[/bold]")
        console.print(f"  {ra.status} — expires {ra.expiry_date} — approved by {ra.approved_by or 'pending'}")

    console.print()


@cli.command("architecture")
@click.option("--format", "fmt", type=click.Choice(["terminal", "svg", "png"]), default="terminal", help="Output format")
@click.option("--output", "-o", default=None, help="Output file path (for svg/png)")
def architecture_diagram(fmt: str, output: str | None) -> None:
    """Render a live architecture diagram from the seeded database."""
    import os
    import shutil
    import subprocess
    import tempfile

    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        AuditEngagement,
        CompensatingControl,
        ComplianceDrift,
        ConnectorRun,
        ControlInheritance,
        ControlResult,
        DataSilo,
        Finding,
        Issue,
        LegalHold,
        Personnel,
        POAM,
        PostureSnapshot,
        RawEvent,
        RiskAcceptance,
        SystemDependency,
        SystemProfile,
    )

    init_db()
    with get_session() as s:
        systems = s.query(SystemProfile).all()
        connector_count = s.query(ConnectorRun).count()
        raw_count = s.query(RawEvent).count()
        finding_count = s.query(Finding).count()
        result_count = s.query(ControlResult).count()
        personnel_count = s.query(Personnel).count()
        issue_count = s.query(Issue).count()
        poam_count = s.query(POAM).count()
        cc_count = s.query(CompensatingControl).count()
        ra_count = s.query(RiskAcceptance).count()
        drift_count = s.query(ComplianceDrift).count()
        snapshot_count = s.query(PostureSnapshot).count()
        silo_count = s.query(DataSilo).count()
        hold_count = s.query(LegalHold).count()
        engagement_count = s.query(AuditEngagement).count()
        dep_count = s.query(SystemDependency).count()
        inheritance_count = s.query(ControlInheritance).count()

        fw_counts = dict(
            s.query(ControlResult.framework, func.count(ControlResult.id))
            .group_by(ControlResult.framework).all()
        )
        source_counts = dict(
            s.query(Finding.source, func.count(Finding.id))
            .group_by(Finding.source).all()
        )
        status_counts = dict(
            s.query(ControlResult.status, func.count(ControlResult.id))
            .group_by(ControlResult.status).all()
        )

        # System dependencies for the diagram
        deps = s.query(SystemDependency).all()

    # --- Terminal mode: Rich tree ---
    if fmt == "terminal":
        from rich.panel import Panel
        from rich.tree import Tree

        tree = Tree("[bold cyan]Warlock GRC Platform[/bold cyan]")

        pipeline = tree.add("[bold green]Pipeline[/bold green]")
        stage1 = pipeline.add(f"[yellow]Stage 1:[/yellow] Connectors — {connector_count} runs → {raw_count} raw events")
        for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1])[:10]:
            stage1.add(f"{src}: {cnt} findings")
        if len(source_counts) > 10:
            stage1.add(f"[dim]... and {len(source_counts) - 10} more sources[/dim]")
        pipeline.add(f"[yellow]Stage 2:[/yellow] Normalizers — {finding_count} findings")
        pipeline.add(f"[yellow]Stage 3:[/yellow] Control Mapper — {result_count:,} control results")
        stage4 = pipeline.add(f"[yellow]Stage 4:[/yellow] Assessor — {status_counts.get('compliant', 0):,} compliant, {status_counts.get('non_compliant', 0):,} non-compliant, {status_counts.get('not_assessed', 0):,} not assessed")
        stage4.add("Tier 1: 25 deterministic assertions")
        stage4.add("Tier 2: AI reasoning (optional)")
        stage4.add("Tier 3: OPA policy evaluation (616 policies)")

        frameworks_node = tree.add(f"[bold green]Frameworks[/bold green] ({len(fw_counts)} active)")
        for fw, cnt in sorted(fw_counts.items(), key=lambda x: -x[1]):
            bar = "█" * min(cnt * 40 // max(fw_counts.values()), 40)
            frameworks_node.add(f"{fw:15s} {cnt:>6,} results  [green]{bar}[/green]")

        sys_tree = tree.add(f"[bold green]Systems[/bold green] ({len(systems)} profiles)")
        for sp in systems:
            style = {"authorized": "green", "in_process": "yellow", "not_authorized": "red"}.get(sp.authorization_status or "", "white")
            node = sys_tree.add(f"[bold]{sp.acronym}[/bold] — {sp.name} ([{style}]{sp.authorization_status}[/{style}], {sp.overall_impact} impact)")
            if sp.frameworks:
                node.add(f"Frameworks: {', '.join(sp.frameworks)}")
            if sp.connector_scope:
                node.add(f"Connectors: {', '.join(sp.connector_scope)}")

        gov = tree.add("[bold green]Governance[/bold green]")
        gov.add(f"Issues: {issue_count}  |  POA&Ms: {poam_count}  |  Compensating: {cc_count}  |  Risk Acceptances: {ra_count}")
        gov.add(f"Inheritances: {inheritance_count}  |  Dependencies: {dep_count}")

        intel = tree.add("[bold green]Intelligence[/bold green]")
        intel.add(f"Drifts: {drift_count}  |  Snapshots: {snapshot_count}")

        assets = tree.add("[bold green]Assets & People[/bold green]")
        assets.add(f"Personnel: {personnel_count}  |  Data Silos: {silo_count}  |  Engagements: {engagement_count}  |  Legal Holds: {hold_count}")

        console.print()
        console.print(Panel(tree, title="[bold]Live Architecture[/bold]", border_style="cyan", expand=False))
        console.print()
        return

    # --- SVG/PNG mode: d2 diagram ---
    if not shutil.which("d2"):
        _error("d2 not installed. Install with: brew install d2")

    # Build d2 source from live data
    sorted(source_counts.items(), key=lambda x: -x[1])[:15]
    source_groups = {
        "Cloud": ["aws", "azure", "gcp", "oci", "ibm_cloud", "alibaba", "digitalocean", "huawei", "ovh", "cloudflare"],
        "Identity": ["okta", "entra_id", "cyberark", "sailpoint", "vault"],
        "Endpoint": ["crowdstrike", "defender", "sentinelone", "intune"],
        "SIEM": ["sentinel", "splunk", "elastic"],
        "Scanners": ["tenable", "qualys", "wiz", "prisma"],
        "Other": ["servicenow", "workday", "knowbe4", "confluence", "onetrust", "snyk", "github", "proofpoint", "purview", "veeam", "verkada", "mlflow", "securityscorecard", "kubernetes"],
    }

    d2 = []
    d2.append("direction: right")
    d2.append("")

    # Connectors container
    d2.append("connectors: Connectors (40 sources) {")
    d2.append("  style.fill: \"#1a1a2e\"")
    d2.append("  style.font-color: \"#e0e0e0\"")
    for group_name, members in source_groups.items():
        active = [m for m in members if m in source_counts]
        if active:
            d2.append(f"  {group_name.lower()}: {group_name} ({len(active)}) {{")
            d2.append("    style.fill: \"#16213e\"")
            for src in active:
                cnt = source_counts[src]
                d2.append(f"    {src}: {src} ({cnt})")
            d2.append("  }")
    d2.append("}")
    d2.append("")

    # Pipeline
    d2.append("pipeline: Pipeline {")
    d2.append("  style.fill: \"#0f3460\"")
    d2.append("  style.font-color: \"#e0e0e0\"")
    d2.append(f"  normalize: Normalize\\n{finding_count} findings")
    d2.append(f"  map: Map Controls\\n{result_count:,} results")
    d2.append("  assess: Assess {")
    d2.append("    tier1: Tier 1 Assertions (25)")
    d2.append("    tier2: Tier 2 AI Reasoning")
    d2.append("    tier3: Tier 3 OPA (616 policies)")
    d2.append("    tier1 -> tier2: fallback")
    d2.append("    tier2 -> tier3: fallback")
    d2.append("  }")
    d2.append("  normalize -> map -> assess")
    d2.append("}")
    d2.append("")

    # Frameworks
    d2.append("frameworks: Frameworks (10) {")
    d2.append("  style.fill: \"#533483\"")
    d2.append("  style.font-color: \"#e0e0e0\"")
    for fw, cnt in sorted(fw_counts.items(), key=lambda x: -x[1]):
        d2.append(f"  {fw}: {fw.upper().replace('_', ' ')}\\n{cnt:,} results")
    d2.append("}")
    d2.append("")

    # Systems
    d2.append("systems: Authorization Boundaries {")
    d2.append("  style.fill: \"#1a1a2e\"")
    d2.append("  style.font-color: \"#e0e0e0\"")
    for sp in systems:
        fws = ", ".join(sp.frameworks or [])
        conns = ", ".join(sp.connector_scope or [])
        d2.append(f"  {sp.acronym}: {sp.acronym} — {sp.name}\\n{sp.authorization_status} | {sp.overall_impact} impact\\nFrameworks: {fws}\\nConnectors: {conns}")
    d2.append("}")
    d2.append("")

    # Governance
    d2.append("governance: Governance {")
    d2.append("  style.fill: \"#e94560\"")
    d2.append("  style.font-color: \"#ffffff\"")
    d2.append(f"  issues: Issues ({issue_count})")
    d2.append(f"  poams: POA&Ms ({poam_count})")
    d2.append(f"  compensating: Compensating ({cc_count})")
    d2.append(f"  risk_accept: Risk Accepted ({ra_count})")
    d2.append("}")
    d2.append("")

    # Intelligence
    d2.append("intelligence: Intelligence {")
    d2.append("  style.fill: \"#0f3460\"")
    d2.append("  style.font-color: \"#e0e0e0\"")
    d2.append(f"  drift: Compliance Drift ({drift_count})")
    d2.append(f"  posture: Posture Trends ({snapshot_count} snapshots)")
    d2.append("}")
    d2.append("")

    # Assets
    d2.append("assets: Assets & People {")
    d2.append("  style.fill: \"#16213e\"")
    d2.append("  style.font-color: \"#e0e0e0\"")
    d2.append(f"  personnel: Personnel ({personnel_count})")
    d2.append(f"  silos: Data Silos ({silo_count})")
    d2.append(f"  engagements: Audit Engagements ({engagement_count})")
    d2.append(f"  holds: Legal Holds ({hold_count})")
    d2.append("}")
    d2.append("")

    # Connections
    d2.append("# Data flow")
    d2.append("connectors -> pipeline.normalize: raw events")
    d2.append("pipeline.assess -> frameworks: map to controls")
    d2.append("pipeline.assess -> systems: scope by boundary")
    d2.append("pipeline.assess -> governance: non-compliant → issues")
    d2.append("pipeline.assess -> intelligence: track over time")
    d2.append("systems -> assets: personnel & data")
    d2.append("")

    # System dependencies
    for dep in deps:
        consumer = next((sp.acronym for sp in systems if sp.id == dep.consumer_system_id), None)
        provider = next((sp.acronym for sp in systems if sp.id == dep.provider_system_id), None)
        if consumer and provider:
            d2.append(f"systems.{consumer} -> systems.{provider}: {dep.dependency_type}")

    d2_source = "\n".join(d2)

    # Write and render
    out_path = output or f"exports/architecture.{fmt}"
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".d2", delete=False) as f:
        f.write(d2_source)
        d2_file = f.name

    try:
        cmd = ["d2", "--theme", "200", d2_file, out_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            console.print(f"[green]Architecture diagram written to {out_path}[/green]")
            # Try to open it
            if fmt == "svg":
                subprocess.run(["open", out_path], capture_output=True)
            elif fmt == "png":
                subprocess.run(["open", out_path], capture_output=True)
        else:
            console.print(f"[red]d2 error: {result.stderr}[/red]")
            # Fall back to writing the d2 source
            d2_out = out_path.rsplit(".", 1)[0] + ".d2"
            with open(d2_out, "w") as f:
                f.write(d2_source)
            console.print(f"[yellow]d2 source written to {d2_out} — render manually with: d2 {d2_out} output.svg[/yellow]")
    finally:
        os.unlink(d2_file)


if __name__ == "__main__":
    cli()
