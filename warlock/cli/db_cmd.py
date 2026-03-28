"""CLI commands for database management (ARCH-008)."""

from __future__ import annotations

import click
from rich.markup import escape

from warlock.cli import cli, console


@cli.group("db", invoke_without_command=True)
@click.pass_context
def db_group(ctx: click.Context) -> None:
    """Database management commands."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@db_group.command("partition")
@click.option(
    "--table",
    required=True,
    type=click.Choice(["findings", "control_results", "audit_entries"]),
    help="Table to partition",
)
@click.option(
    "--interval",
    default="monthly",
    type=click.Choice(["monthly", "quarterly"]),
    help="Partition interval (default: monthly)",
)
@click.option("--periods", default=6, type=int, help="Number of partitions to create ahead")
@click.option("--dry-run", is_flag=True, help="Print DDL without executing")
def partition_cmd(table: str, interval: str, periods: int, dry_run: bool) -> None:
    """Create range partitions for high-volume tables (PostgreSQL only).

    Generates PARTITION BY RANGE sub-tables for the specified table.
    This is a no-op on SQLite.
    """
    from warlock.db.engine import get_engine
    from warlock.db.partitioning import setup_partitioning

    engine = get_engine()

    if str(engine.url).startswith("sqlite"):
        console.print(
            "[yellow]Partitioning is a PostgreSQL-only feature — skipped for SQLite.[/yellow]"
        )
        return

    stmts = setup_partitioning(
        engine,
        table_name=table,
        interval=interval,
        periods=periods,
        dry_run=dry_run,
    )

    if dry_run:
        console.print(f"[bold]Dry run — {len(stmts)} partition statements:[/bold]")
        for s in stmts:
            console.print(f"  [dim]{escape(s)}[/dim]")
    else:
        console.print(
            f"[green]Created {len(stmts)} partitions for "
            f"{escape(table)} ({escape(interval)})[/green]"
        )
