"""Risk dependency CLI commands."""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console


@cli.group("risk-dependencies", invoke_without_command=True)
@click.pass_context
def risk_dependencies(ctx: click.Context) -> None:
    """View risk dependency and cascade mappings."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@risk_dependencies.command("list")
@click.option("--risk-id", default=None, help="Filter by source risk ID (prefix)")
@click.option("--type", "rel_type", default=None, help="Filter by relationship type")
@click.option("--limit", "-n", default=50, help="Max results")
def risk_dep_list(risk_id: str | None, rel_type: str | None, limit: int) -> None:
    """List risk dependencies."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import RiskDependency

    init_db()
    with get_read_session() as session:
        q = session.query(RiskDependency)
        if risk_id:
            q = q.filter(RiskDependency.risk_id.startswith(risk_id))
        if rel_type:
            q = q.filter(RiskDependency.relationship_type == rel_type)
        rows = q.order_by(RiskDependency.created_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No risk dependencies found.[/dim]")
        return

    table = Table(title=f"Risk Dependencies ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Risk", style="cyan", max_width=8)
    table.add_column("Depends On", style="cyan", max_width=8)
    table.add_column("Type")
    table.add_column("Weight", justify="right")
    table.add_column("Description", max_width=40)

    for r in rows:
        table.add_row(
            r.id[:8],
            r.risk_id[:8] if r.risk_id else "\u2014",
            r.depends_on_risk_id[:8] if r.depends_on_risk_id else "\u2014",
            escape(r.relationship_type or ""),
            f"{r.weight:.2f}" if r.weight is not None else "\u2014",
            escape((r.description or "")[:40]),
        )

    console.print(table)
