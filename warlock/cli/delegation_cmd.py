"""Delegation grant CLI commands."""

from __future__ import annotations

import os

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console


def _resolve_actor(actor: str | None) -> str:
    """SEC-C9: require an authenticated principal for delegation actions.

    The previous CLI grant path inserted ``DelegationGrant`` rows directly
    with no actor binding, no privilege check, and no audit. Now an actor
    is required via ``--actor`` or ``WLK_CLI_ACTOR`` so the manager-level
    gates (role + subset checks) and the hash-chained trail have something
    to attribute the action to.
    """
    if actor:
        return actor
    env_actor = os.environ.get("WLK_CLI_ACTOR", "").strip()
    if env_actor:
        return env_actor
    raise click.UsageError(
        "Delegation actions require an authenticated principal. "
        "Pass --actor <user-id-or-email> or set WLK_CLI_ACTOR in the environment."
    )


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
@click.option(
    "--actor",
    default=None,
    help="Authenticated principal performing the grant (or WLK_CLI_ACTOR env)",
)
def delegation_grant(
    delegator: str,
    delegate: str,
    permissions: str,
    expires_days: int | None,
    actor: str | None,
) -> None:
    """Create a new delegation grant.

    SEC-C9: routes through :class:`DelegationManager.delegate_admin` so the
    role + subset + self-delegation checks fire. The CLI previously inserted
    a ``DelegationGrant`` row directly with no privilege check, letting any
    caller with DB access escalate themselves to admin. The DB row is now
    written only after the manager-level gates accept the request.
    """
    from datetime import datetime, timedelta, timezone

    from warlock.db.audit import AuditTrail
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DelegationGrant, User, _uuid
    from warlock.platform.delegation import DelegationManager

    actor_id = _resolve_actor(actor)
    perm_list = [p.strip() for p in permissions.split(",") if p.strip()]

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

        # SEC-C9: run the privilege checks (role, subset of granting perms,
        # self-delegation) BEFORE persisting anything. ``delegate_admin``
        # raises PermissionError / ValueError on failure.
        manager = DelegationManager()
        try:
            manager.delegate_admin(
                session,
                from_user_id=d1.id,
                to_user_id=d2.id,
                scope={"actions": perm_list},
                actor=actor_id,
            )
        except (PermissionError, ValueError) as exc:
            console.print(f"[red]Delegation rejected: {escape(str(exc))}[/red]")
            raise SystemExit(1) from exc

        expires_at = None
        if expires_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

        grant = DelegationGrant(
            id=_uuid(),
            delegator_id=d1.id,
            delegate_id=d2.id,
            permissions=perm_list,
            expires_at=expires_at,
            is_active=True,
        )
        session.add(grant)
        session.flush()

        AuditTrail(session).record(
            action="delegation_grant",
            entity_type="delegation",
            entity_id=grant.id,
            actor=actor_id,
            metadata={
                "delegator_id": d1.id,
                "delegate_id": d2.id,
                "permissions": perm_list,
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        )

    console.print(f"[green]Delegation grant created: {grant.id[:8]}[/green]")


@delegation.command("revoke")
@click.argument("grant_id")
@click.option(
    "--actor",
    default=None,
    help="Authenticated principal performing the revoke (or WLK_CLI_ACTOR env)",
)
def delegation_revoke(grant_id: str, actor: str | None) -> None:
    """Revoke a delegation grant."""
    from warlock.db.audit import AuditTrail
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DelegationGrant

    actor_id = _resolve_actor(actor)

    init_db()
    with get_session() as session:
        grant = (
            session.query(DelegationGrant).filter(DelegationGrant.id.startswith(grant_id)).first()
        )
        if not grant:
            console.print(f"[red]Grant not found: {escape(grant_id)}[/red]")
            return
        grant.is_active = False
        session.flush()

        AuditTrail(session).record(
            action="delegation_revoke",
            entity_type="delegation",
            entity_id=grant.id,
            actor=actor_id,
            metadata={"delegator_id": grant.delegator_id, "delegate_id": grant.delegate_id},
        )

    console.print(f"[green]Delegation grant {grant_id[:8]} revoked.[/green]")
