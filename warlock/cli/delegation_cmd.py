"""Delegation grant CLI commands."""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console


@cli.group("delegation", invoke_without_command=True)
@click.pass_context
def delegation(ctx: click.Context) -> None:
    """Manage delegated admin authority between users."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@delegation.command("list")
@click.option("--active/--all", default=True, help="Show only active grants (default: active)")
@click.option("--limit", "-n", default=50, help="Max results")
def delegation_list(active: bool, limit: int) -> None:
    """List delegation grants."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import DelegationGrant

    init_db()
    with get_read_session() as session:
        q = session.query(DelegationGrant)
        if active:
            q = q.filter(DelegationGrant.is_active.is_(True))
        rows = q.order_by(DelegationGrant.created_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No delegation grants found.[/dim]")
        return

    table = Table(title=f"Delegation Grants ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Delegator", style="cyan")
    table.add_column("Delegate", style="cyan")
    table.add_column("Permissions", max_width=30)
    table.add_column("Active")
    table.add_column("Expires", style="dim")

    from warlock.utils import ensure_aware

    for g in rows:
        perms = ", ".join(g.permissions or []) if g.permissions else "\u2014"
        expires = (
            ensure_aware(g.expires_at).strftime("%Y-%m-%d %H:%M") if g.expires_at else "\u2014"
        )
        table.add_row(
            g.id[:8],
            g.delegator_id[:8],
            g.delegate_id[:8],
            escape(perms[:30]),
            "[green]Yes[/green]" if g.is_active else "[dim]No[/dim]",
            expires,
        )

    console.print(table)


@delegation.command("grant")
@click.option("--delegator", required=True, help="Delegator user ID (or prefix)")
@click.option("--delegate", required=True, help="Delegate user ID (or prefix)")
@click.option(
    "--permissions",
    "-p",
    required=True,
    help="Comma-separated permissions to delegate",
)
@click.option("--expires-days", default=None, type=int, help="Grant expiry in days")
def delegation_grant(
    delegator: str,
    delegate: str,
    permissions: str,
    expires_days: int | None,
) -> None:
    """Create a new delegation grant."""
    from datetime import datetime, timedelta, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DelegationGrant, User, _uuid

    init_db()
    with get_session() as session:
        d1 = session.query(User).filter(User.id.startswith(delegator)).first()
        d2 = session.query(User).filter(User.id.startswith(delegate)).first()
        if not d1:
            console.print(f"[red]Delegator not found: {escape(delegator)}[/red]")
            return
        if not d2:
            console.print(f"[red]Delegate not found: {escape(delegate)}[/red]")
            return

        expires_at = None
        if expires_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

        grant = DelegationGrant(
            id=_uuid(),
            delegator_id=d1.id,
            delegate_id=d2.id,
            permissions=[p.strip() for p in permissions.split(",")],
            expires_at=expires_at,
            is_active=True,
        )
        session.add(grant)

    console.print(f"[green]Delegation grant created: {grant.id[:8]}[/green]")


@delegation.command("revoke")
@click.argument("grant_id")
def delegation_revoke(grant_id: str) -> None:
    """Revoke a delegation grant."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DelegationGrant

    init_db()
    with get_session() as session:
        grant = (
            session.query(DelegationGrant).filter(DelegationGrant.id.startswith(grant_id)).first()
        )
        if not grant:
            console.print(f"[red]Grant not found: {escape(grant_id)}[/red]")
            return
        grant.is_active = False

    console.print(f"[green]Delegation grant {grant_id[:8]} revoked.[/green]")
