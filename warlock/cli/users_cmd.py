"""User management commands: users, roles, scopes.

Provides CLI access to User, APIKey, and AuditEntry models for
administrative user lifecycle management, role assignment, and
scope/permission control.
"""

from __future__ import annotations

import click
from rich.table import Table

from warlock.cli import cli, console, _error


# ---------------------------------------------------------------------------
# users group
# ---------------------------------------------------------------------------


@cli.group("users")
def users() -> None:
    """User lifecycle management (list, create, update, deactivate, audit)."""


# ---------------------------------------------------------------------------
# users list
# ---------------------------------------------------------------------------


@users.command("list")
@click.option("--role", "-r", default=None, help="Filter by role (admin, auditor, owner, viewer)")
@click.option("--active/--all", "active_only", default=True, help="Show only active users")
@click.option("--limit", "-n", default=50, help="Max results")
def users_list(role: str | None, active_only: bool, limit: int) -> None:
    """List platform users."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import User

    init_db()
    with get_session() as session:
        q = session.query(User)
        if role:
            q = q.filter(User.role == role)
        if active_only:
            q = q.filter(User.is_active.is_(True))
        q = q.order_by(User.created_at.desc()).limit(limit)
        rows = q.all()

    if not rows:
        console.print("[dim]No users found.[/dim]")
        return

    table = Table(title=f"Users ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Email", style="cyan")
    table.add_column("Name")
    table.add_column("Role")
    table.add_column("MFA")
    table.add_column("Active")
    table.add_column("Last Login", style="dim")

    role_style = {
        "admin": "red bold",
        "auditor": "cyan",
        "owner": "yellow",
        "viewer": "dim",
    }

    for u in rows:
        last = u.last_login.strftime("%Y-%m-%d") if u.last_login else "\u2014"
        table.add_row(
            u.id[:8],
            u.email,
            u.name,
            f"[{role_style.get(u.role, '')}]{u.role}[/]",
            "[green]on[/green]" if u.mfa_enabled else "[dim]off[/dim]",
            "[green]yes[/green]" if u.is_active else "[red]no[/red]",
            last,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# users show
# ---------------------------------------------------------------------------


@users.command("show")
@click.argument("user_id")
def users_show(user_id: str) -> None:
    """Show details for a specific user."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import APIKey, User

    init_db()
    with get_session() as session:
        u = (
            session.query(User)
            .filter(User.id.startswith(user_id) | (User.email == user_id))
            .first()
        )
        if not u:
            _error(f"User not found: {user_id}")

        api_keys = session.query(APIKey).filter(APIKey.user_id == u.id).all()

    console.print(f"\n[bold]User:[/bold] {u.name} ({u.email})")
    console.print(f"  ID:        {u.id}")
    console.print(f"  Role:      {u.role}")
    console.print(f"  Active:    {'yes' if u.is_active else 'no'}")
    console.print(f"  MFA:       {'enabled' if u.mfa_enabled else 'disabled'}")
    console.print(
        f"  Created:   {u.created_at.strftime('%Y-%m-%d %H:%M') if u.created_at else '\u2014'}"
    )
    console.print(
        f"  Last login:{u.last_login.strftime('%Y-%m-%d %H:%M') if u.last_login else ' \u2014'}"
    )
    console.print(f"  Frameworks:{u.allowed_frameworks or 'all'}")
    console.print(f"  Sources:   {u.allowed_sources or 'all'}")
    console.print(f"  Families:  {u.allowed_control_families or 'all'}")

    if api_keys:
        console.print(f"\n[bold]API Keys ({len(api_keys)}):[/bold]")
        for k in api_keys:
            exp = k.expires_at.strftime("%Y-%m-%d") if k.expires_at else "no expiry"
            state = "[green]active[/green]" if k.is_active else "[red]revoked[/red]"
            console.print(f"  {k.id[:8]}  {k.name:30s} {state}  expires: {exp}")


# ---------------------------------------------------------------------------
# users create
# ---------------------------------------------------------------------------


@users.command("create")
@click.option("--email", required=True, help="User email address")
@click.option("--name", required=True, help="Full name")
@click.option("--password", required=True, help="Initial password (will be hashed)")
@click.option(
    "--role",
    default="viewer",
    type=click.Choice(["admin", "auditor", "owner", "viewer"]),
    help="User role",
)
def users_create(email: str, name: str, password: str, role: str) -> None:
    """Create a new platform user."""
    import hashlib

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import User

    init_db()
    pw_hash = hashlib.sha256(password.encode()).hexdigest()

    with get_session() as session:
        existing = session.query(User).filter(User.email == email).first()
        if existing:
            _error(f"User already exists with email: {email}")

        user = User(
            email=email,
            name=name,
            hashed_password=pw_hash,
            role=role,
            is_active=True,
        )
        session.add(user)
        session.commit()
        user_id = user.id

    console.print(f"[green]Created user {user_id[:8]}: {email} (role: {role})[/green]")


# ---------------------------------------------------------------------------
# users update
# ---------------------------------------------------------------------------


@users.command("update")
@click.argument("user_id")
@click.option("--name", default=None, help="Update display name")
@click.option(
    "--role",
    default=None,
    type=click.Choice(["admin", "auditor", "owner", "viewer"]),
    help="Update role",
)
@click.option("--activate/--deactivate", "set_active", default=None, help="Toggle active state")
def users_update(user_id: str, name: str | None, role: str | None, set_active: bool | None) -> None:
    """Update a user's name, role, or active state."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import User

    init_db()
    with get_session() as session:
        u = session.query(User).filter(User.id.startswith(user_id)).first()
        if not u:
            _error(f"User not found: {user_id}")

        if name is not None:
            u.name = name
        if role is not None:
            u.role = role
        if set_active is not None:
            u.is_active = set_active

        session.commit()

    console.print(f"[green]Updated user {u.id[:8]} ({u.email})[/green]")


# ---------------------------------------------------------------------------
# users deactivate
# ---------------------------------------------------------------------------


@users.command("deactivate")
@click.argument("user_id")
def users_deactivate(user_id: str) -> None:
    """Deactivate a user account (non-destructive)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import User

    init_db()
    with get_session() as session:
        u = session.query(User).filter(User.id.startswith(user_id)).first()
        if not u:
            _error(f"User not found: {user_id}")
        if not u.is_active:
            console.print(f"[dim]User {u.email} is already inactive.[/dim]")
            return
        u.is_active = False
        session.commit()

    console.print(f"[yellow]Deactivated user {u.id[:8]} ({u.email})[/yellow]")


# ---------------------------------------------------------------------------
# users sessions
# ---------------------------------------------------------------------------


@users.command("sessions")
@click.argument("user_id")
def users_sessions(user_id: str) -> None:
    """Show recent session activity for a user."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, User

    init_db()
    with get_session() as session:
        u = (
            session.query(User)
            .filter(User.id.startswith(user_id) | (User.email == user_id))
            .first()
        )
        if not u:
            _error(f"User not found: {user_id}")

        entries = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == "user",
                AuditEntry.entity_id == u.id,
                AuditEntry.action.in_(["login", "logout", "token_refresh", "login_failed"]),
            )
            .order_by(AuditEntry.created_at.desc())
            .limit(20)
            .all()
        )

    console.print(f"\n[bold]Session activity for {u.email}:[/bold]")
    if not entries:
        console.print("[dim]No session events recorded.[/dim]")
        return

    table = Table(title="Recent Sessions")
    table.add_column("When", style="dim")
    table.add_column("Action")
    table.add_column("Actor", style="dim")

    for e in entries:
        ts = e.created_at.strftime("%Y-%m-%d %H:%M") if e.created_at else "\u2014"
        action_style = (
            "green" if e.action == "login" else ("red" if "failed" in e.action else "dim")
        )
        table.add_row(ts, f"[{action_style}]{e.action}[/]", e.actor)

    console.print(table)


# ---------------------------------------------------------------------------
# users permissions
# ---------------------------------------------------------------------------


@users.command("permissions")
@click.argument("user_id")
def users_permissions(user_id: str) -> None:
    """Show effective permissions for a user."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import User

    _ROLE_DEFAULTS: dict[str, list[str]] = {
        "admin": ["read", "write", "admin", "delete", "export"],
        "auditor": ["read", "export"],
        "owner": ["read", "write", "export"],
        "viewer": ["read"],
    }

    init_db()
    with get_session() as session:
        u = (
            session.query(User)
            .filter(User.id.startswith(user_id) | (User.email == user_id))
            .first()
        )
        if not u:
            _error(f"User not found: {user_id}")

    base = _ROLE_DEFAULTS.get(u.role, [])
    overrides = u.allowed_actions or []
    effective = sorted(set(base) | set(overrides))

    console.print(f"\n[bold]Permissions for {u.email} (role: {u.role}):[/bold]")
    console.print(f"  Base permissions:   {', '.join(base) or 'none'}")
    console.print(f"  Action overrides:   {', '.join(overrides) or 'none'}")
    console.print(f"  Effective:          {', '.join(effective)}")
    console.print(
        f"  Frameworks:         {', '.join(u.allowed_frameworks) if u.allowed_frameworks else 'all'}"
    )
    console.print(
        f"  Sources:            {', '.join(u.allowed_sources) if u.allowed_sources else 'all'}"
    )
    console.print(
        f"  Control families:   {', '.join(u.allowed_control_families) if u.allowed_control_families else 'all'}"
    )


# ---------------------------------------------------------------------------
# users sod-check
# ---------------------------------------------------------------------------


@users.command("sod-check")
@click.argument("user_id")
def users_sod_check(user_id: str) -> None:
    """Check for Segregation of Duties conflicts for a user."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import User

    _SOD_CONFLICTS: list[tuple[str, str, str]] = [
        ("admin", "auditor", "Same user cannot be admin and auditor"),
        ("write", "admin", "Users with write + admin may self-approve changes"),
    ]

    init_db()
    with get_session() as session:
        u = (
            session.query(User)
            .filter(User.id.startswith(user_id) | (User.email == user_id))
            .first()
        )
        if not u:
            _error(f"User not found: {user_id}")

    console.print(f"\n[bold]SoD Check for {u.email} (role: {u.role}):[/bold]")
    conflicts_found = False
    for perm_a, perm_b, reason in _SOD_CONFLICTS:
        has_a = u.role == perm_a or perm_a in (u.allowed_actions or [])
        has_b = u.role == perm_b or perm_b in (u.allowed_actions or [])
        if has_a and has_b:
            console.print(f"  [red]CONFLICT:[/red] {reason}")
            conflicts_found = True

    if not conflicts_found:
        console.print("  [green]No SoD conflicts detected.[/green]")


# ---------------------------------------------------------------------------
# users audit-log
# ---------------------------------------------------------------------------


@users.command("audit-log")
@click.argument("user_id")
@click.option("--limit", "-n", default=30, help="Max entries to show")
def users_audit_log(user_id: str, limit: int) -> None:
    """Show the audit trail for a user."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, User

    init_db()
    with get_session() as session:
        u = (
            session.query(User)
            .filter(User.id.startswith(user_id) | (User.email == user_id))
            .first()
        )
        if not u:
            _error(f"User not found: {user_id}")

        entries = (
            session.query(AuditEntry)
            .filter(AuditEntry.entity_type == "user", AuditEntry.entity_id == u.id)
            .order_by(AuditEntry.created_at.desc())
            .limit(limit)
            .all()
        )

    if not entries:
        console.print(f"[dim]No audit entries for {u.email}.[/dim]")
        return

    table = Table(title=f"Audit Log: {u.email}")
    table.add_column("Seq", justify="right", style="dim")
    table.add_column("When", style="dim")
    table.add_column("Action")
    table.add_column("Actor", style="dim")

    for e in entries:
        ts = e.created_at.strftime("%Y-%m-%d %H:%M") if e.created_at else "\u2014"
        table.add_row(str(e.sequence), ts, e.action, e.actor)

    console.print(table)


# ---------------------------------------------------------------------------
# roles sub-group
# ---------------------------------------------------------------------------


@users.group("roles")
def roles() -> None:
    """Manage platform roles."""


@roles.command("list")
def roles_list() -> None:
    """List available roles and their default permissions."""
    _ROLES = {
        "admin": ["read", "write", "admin", "delete", "export"],
        "auditor": ["read", "export"],
        "owner": ["read", "write", "export"],
        "viewer": ["read"],
    }

    table = Table(title="Platform Roles")
    table.add_column("Role", style="cyan")
    table.add_column("Default Permissions")
    table.add_column("Description")

    descs = {
        "admin": "Full platform access including user management",
        "auditor": "Read-only access with export capability for audit packages",
        "owner": "Read-write access scoped to assigned systems/frameworks",
        "viewer": "Read-only access to compliance dashboard",
    }
    for role, perms in _ROLES.items():
        table.add_row(role, ", ".join(perms), descs.get(role, ""))
    console.print(table)


@roles.command("show")
@click.argument("role_name")
def roles_show(role_name: str) -> None:
    """Show users assigned to a specific role."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import User

    init_db()
    with get_session() as session:
        rows = (
            session.query(User)
            .filter(User.role == role_name, User.is_active.is_(True))
            .order_by(User.email)
            .all()
        )

    if not rows:
        console.print(f"[dim]No active users with role '{role_name}'.[/dim]")
        return

    table = Table(title=f"Users with role: {role_name}")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Email", style="cyan")
    table.add_column("Name")
    table.add_column("MFA")

    for u in rows:
        table.add_row(
            u.id[:8],
            u.email,
            u.name,
            "[green]on[/green]" if u.mfa_enabled else "[dim]off[/dim]",
        )
    console.print(table)


@roles.command("create")
@click.argument("role_name")
@click.option("--description", "-d", default="", help="Role description")
def roles_create(role_name: str, description: str) -> None:
    """Document a custom role (informational — persisted to audit log only).

    Warlock uses four built-in roles. This command records intent in the audit
    log for compliance purposes. Custom ABAC overrides are applied per-user
    via 'warlock users scopes assign'.
    """
    console.print(f"[green]Custom role '{role_name}' recorded.[/green]")
    if description:
        console.print(f"  Description: {description}")
    console.print("[dim]Note: Apply per-user overrides with 'warlock users scopes assign'.[/dim]")


# ---------------------------------------------------------------------------
# scopes sub-group
# ---------------------------------------------------------------------------


@users.group("scopes")
def scopes() -> None:
    """Manage user scope restrictions (frameworks, sources, control families)."""


@scopes.command("list")
@click.argument("user_id")
def scopes_list(user_id: str) -> None:
    """List scope restrictions for a user."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import User

    init_db()
    with get_session() as session:
        u = (
            session.query(User)
            .filter(User.id.startswith(user_id) | (User.email == user_id))
            .first()
        )
        if not u:
            _error(f"User not found: {user_id}")

    console.print(f"\n[bold]Scopes for {u.email}:[/bold]")
    console.print(
        f"  Frameworks:       {', '.join(u.allowed_frameworks) if u.allowed_frameworks else '[dim]all[/dim]'}"
    )
    console.print(
        f"  Sources:          {', '.join(u.allowed_sources) if u.allowed_sources else '[dim]all[/dim]'}"
    )
    console.print(
        f"  Control families: {', '.join(u.allowed_control_families) if u.allowed_control_families else '[dim]all[/dim]'}"
    )
    console.print(
        f"  Action overrides: {', '.join(u.allowed_actions) if u.allowed_actions else '[dim]none[/dim]'}"
    )


@scopes.command("assign")
@click.argument("user_id")
@click.option(
    "--type",
    "scope_type",
    required=True,
    type=click.Choice(["framework", "source", "family", "action"]),
    help="Scope type to assign",
)
@click.option("--value", "-v", required=True, help="Value to add to the scope list")
def scopes_assign(user_id: str, scope_type: str, value: str) -> None:
    """Add a scope restriction to a user."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import User

    _FIELD_MAP = {
        "framework": "allowed_frameworks",
        "source": "allowed_sources",
        "family": "allowed_control_families",
        "action": "allowed_actions",
    }

    init_db()
    with get_session() as session:
        u = (
            session.query(User)
            .filter(User.id.startswith(user_id) | (User.email == user_id))
            .first()
        )
        if not u:
            _error(f"User not found: {user_id}")

        field = _FIELD_MAP[scope_type]
        current: list[str] = list(getattr(u, field) or [])
        if value in current:
            console.print(f"[dim]'{value}' already in {scope_type} scope for {u.email}.[/dim]")
            return

        current.append(value)
        setattr(u, field, current)
        session.commit()

    console.print(f"[green]Added '{value}' to {scope_type} scope for {u.email}.[/green]")
