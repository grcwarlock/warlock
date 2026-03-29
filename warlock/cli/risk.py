"""Risk commands: risk (group with analyze, precompute, cache-stats, invalidate),
vendors, policy-coverage."""

from __future__ import annotations

import click
from rich.table import Table

from warlock.cli import cli, console, _check_ai_available


@cli.group(invoke_without_command=True)
@click.pass_context
def risk(ctx: click.Context) -> None:
    """Monte Carlo risk quantification and cache management."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        console.print("\n[dim]Quick start: warlock risk analyze -f <framework>[/dim]")


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

    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Monte Carlo ({iterations:,} iterations)", total=4)

        progress.update(task, advance=1, description="Loading posture data...")

        with get_session() as session:
            progress.update(task, advance=1, description="Running Monte Carlo simulation...")
            result = engine.analyze_framework_risk(
                session,
                framework,
                iterations=iterations,
            )
            progress.update(task, advance=1, description="Aggregating risk scenarios...")

        progress.update(task, advance=1, description="Risk analysis complete")

    scenarios = result.get("scenarios", [])
    portfolio = result.get("portfolio", {})

    if not scenarios:
        console.print(f"[dim]No risk scenarios for framework '{framework}'.[/dim]")
        return

    table = Table(title=f"FAIR Risk Analysis \u2014 {framework}")
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
    if _check_ai_available(use_ai):
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
            notes = "skipped \u2014 fresh cache"
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
        f"\n[bold]Summary:[/bold] {len(summary)} frameworks \u2014 "
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
    console.print(f"[green]Invalidated {result['deleted']} cached entries for {scope}.[/green]")


@cli.group("vendors", invoke_without_command=True)
@click.option("-p", "--provider", default="securityscorecard", help="Vendor data provider")
@click.option("-t", "--threshold", default=60.0, help="High-risk threshold (0-100)")
@click.pass_context
def vendors(ctx: click.Context, provider: str, threshold: float) -> None:
    """Score and monitor vendor risk."""
    if ctx.invoked_subcommand is not None:
        return
    from warlock.assessors.vendor_risk import VendorRiskEngine
    from warlock.db.engine import get_read_session, init_db

    init_db()
    engine = VendorRiskEngine()

    # Read-only: score vendors without creating findings (no DB writes)
    with get_read_session() as session:
        vendor_list = engine.from_findings(session, provider=provider)
        scores = [engine.score_vendor(v) for v in vendor_list]

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
        level_text = (
            f"[{level_style}]{s.risk_level}[/{level_style}]" if level_style else s.risk_level
        )
        table.add_row(
            s.vendor_name,
            f"{s.overall_score:.0f}",
            level_text,
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
                console.print(f"  [dim]\u2022 {rec}[/dim]")


@vendors.command("list")
@click.option("-p", "--provider", default="securityscorecard", help="Vendor data provider")
@click.option("-t", "--threshold", default=60.0, help="High-risk threshold (0-100)")
@click.pass_context
def vendors_list(ctx: click.Context, provider: str, threshold: float) -> None:
    """List and score all vendors (alias for 'warlock vendors')."""
    ctx.invoke(vendors, provider=provider, threshold=threshold)


@cli.command("policy-coverage")
@click.option("-f", "--framework", required=True, help="Framework to check coverage for")
@click.option("--no-rag", is_flag=True, help="Skip RAG matching, use keyword heuristics only")
@click.option(
    "--ai/--no-ai", "use_ai", default=None, help="Override AI toggle for governance analysis"
)
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

    pct_style = (
        "green"
        if coverage.coverage_pct >= 80
        else "yellow"
        if coverage.coverage_pct >= 50
        else "red"
    )

    console.print(f"\n[bold]Policy Coverage \u2014 {framework}[/bold]")
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
            console.print(f"  [dim]\u2022 {gap}[/dim]")
        if len(coverage.gaps) > 20:
            console.print(f"  [dim]... and {len(coverage.gaps) - 20} more[/dim]")

    # AI governance analysis
    if _check_ai_available(use_ai):
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
                            console.print(f"  [dim]\u2022 {rec}[/dim]")
            except Exception as exc:
                console.print(f"\n[dim]AI analysis unavailable: {exc.__class__.__name__}[/dim]")
