"""CLI commands for AI governance -- model inventory and EU AI Act classification.

Provides:

    warlock ai-governance inventory       -- list registered AI/ML models
    warlock ai-governance risk-classify   -- classify model risk under EU AI Act
    warlock ai-governance register        -- register a new AI model
"""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import _get_actor, cli, console

# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("ai-governance", invoke_without_command=True)
@click.pass_context
def ai_governance(ctx: click.Context) -> None:
    """AI governance -- model inventory and EU AI Act risk classification."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        console.print("\n[dim]Quick start: warlock ai-governance inventory[/dim]")


# ---------------------------------------------------------------------------
# inventory -- list models
# ---------------------------------------------------------------------------


@ai_governance.command("inventory")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def ai_gov_inventory(output_format: str) -> None:
    """List all registered AI/ML models in the inventory."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.workflows.ai_governance import AIModelInventory

    init_db()
    inventory = AIModelInventory()

    with get_read_session() as session:
        models = inventory.list_models(session)

    if not models:
        console.print("[dim]No AI models registered. Use 'warlock ai-governance register'.[/dim]")
        return

    if output_format == "json":
        import dataclasses
        import json

        data = [dataclasses.asdict(m) for m in models]
        console.print(json.dumps(data, indent=2, default=str))
        return

    table = Table(title=f"AI Model Inventory ({len(models)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", style="cyan")
    table.add_column("Provider")
    table.add_column("Type")
    table.add_column("Domain")
    table.add_column("Risk Tier")
    table.add_column("Deployed", justify="center")

    _TIER_STYLES = {
        "unacceptable": "red bold",
        "high": "red",
        "limited": "yellow",
        "minimal": "green",
    }

    for m in models:
        tier_style = _TIER_STYLES.get(m.risk_tier, "")
        tier_display = f"[{tier_style}]{m.risk_tier}[/{tier_style}]" if tier_style else m.risk_tier
        deployed_icon = "[green]yes[/green]" if m.deployed else "[dim]no[/dim]"
        table.add_row(
            m.id[:8],
            escape(m.name),
            escape(m.provider),
            escape(m.model_type),
            escape(m.domain),
            tier_display,
            deployed_icon,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# risk-classify -- EU AI Act risk classification
# ---------------------------------------------------------------------------


@ai_governance.command("risk-classify")
@click.option("--name", "-n", required=True, help="Model name")
@click.option("--domain", "-d", required=True, help="Domain (e.g. healthcare, finance, hr)")
@click.option("--purpose", "-p", required=True, help="Model purpose / use case description")
@click.option("--model-type", "-t", default="classification", help="Model type")
def ai_gov_risk_classify(name: str, domain: str, purpose: str, model_type: str) -> None:
    """Classify an AI model's risk tier under the EU AI Act.

    Uses keyword heuristics to determine the risk tier (unacceptable,
    high, limited, minimal) and lists applicable obligations.
    """
    from warlock.workflows.ai_governance import AIModelRecord, AIRiskClassifier

    model = AIModelRecord(
        name=name,
        domain=domain,
        purpose=purpose,
        model_type=model_type,
    )

    classifier = AIRiskClassifier()
    result = classifier.classify(model)

    _TIER_STYLES = {
        "unacceptable": "red bold",
        "high": "red",
        "limited": "yellow",
        "minimal": "green",
    }

    tier_style = _TIER_STYLES.get(result.risk_tier, "")
    tier_label = (
        f"[{tier_style}]{result.risk_tier.upper()}[/{tier_style}]"
        if tier_style
        else result.risk_tier.upper()
    )

    console.print("\n[bold]EU AI Act Risk Classification[/bold]")
    console.print(f"  Model:       {escape(name)}")
    console.print(f"  Domain:      {escape(domain)}")
    console.print(f"  Purpose:     {escape(purpose)}")
    console.print(f"  Risk Tier:   {tier_label}")
    console.print(f"  Confidence:  {result.confidence:.0%}")
    console.print(f"  Rationale:   {escape(result.rationale)}")

    if result.matched_patterns:
        console.print(f"  Matched:     {', '.join(escape(p) for p in result.matched_patterns)}")

    if result.obligations:
        console.print(f"\n[bold]Obligations ({len(result.obligations)}):[/bold]")
        for ob in result.obligations:
            console.print(f"  [dim]\u2022 {escape(ob)}[/dim]")


# ---------------------------------------------------------------------------
# register -- add a model to the inventory
# ---------------------------------------------------------------------------


@ai_governance.command("register")
@click.option("--name", "-n", required=True, help="Model name")
@click.option("--provider", default="", help="Provider (e.g. OpenAI, internal)")
@click.option("--model-type", "-t", default="classification", help="Model type")
@click.option("--domain", "-d", default="", help="Domain (e.g. healthcare, finance)")
@click.option("--purpose", "-p", default="", help="Purpose description")
@click.option("--deployed/--not-deployed", default=False, help="Deployment status")
@click.option("--region", default="", help="Deployment region")
def ai_gov_register(
    name: str,
    provider: str,
    model_type: str,
    domain: str,
    purpose: str,
    deployed: bool,
    region: str,
) -> None:
    """Register a new AI model in the governance inventory."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.ai_governance import (
        AIModelInventory,
        AIModelRecord,
        AIRiskClassifier,
    )

    init_db()
    actor = _get_actor()

    # Auto-classify risk
    model = AIModelRecord(
        name=name,
        provider=provider,
        model_type=model_type,
        domain=domain,
        purpose=purpose,
        deployed=deployed,
        deployment_region=region,
        owner=actor,
    )

    classifier = AIRiskClassifier()
    classification = classifier.classify(model)
    model.risk_tier = classification.risk_tier

    inventory = AIModelInventory()
    with get_session() as session:
        inventory.register_model(session, model, actor=actor)

    console.print(
        f"[green]AI model registered:[/green] [cyan]{model.id[:8]}[/cyan]"
        f" \u2014 {escape(name)} (risk: {model.risk_tier})"
    )
