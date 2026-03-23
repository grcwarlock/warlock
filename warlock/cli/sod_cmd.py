"""Segregation of Duties (SoD) commands: analyze, conflicts, matrix.

SoD analysis detects role conflicts where a single user holds incompatible
permissions that could enable fraud or error without detection. This is a
key requirement for SOX, PCI DSS (Req 7), ISO 27001, and SOC 2 (CC6.3).
"""

from __future__ import annotations

from collections import defaultdict

import click
from rich.table import Table

from warlock.cli import cli, console, _error


# ---------------------------------------------------------------------------
# SoD conflict rule definitions
# ---------------------------------------------------------------------------

# Each rule: (role_a, role_b, description)
# A user holding BOTH roles violates this rule.
_SOD_RULES: list[tuple[str, str, str]] = [
    ("admin", "auditor", "Admins should not perform self-audits"),
    ("admin", "owner", "Admin and system owner create unilateral control"),
    ("owner", "auditor", "System owners auditing their own systems lack independence"),
    ("admin", "viewer", "Admin-viewer duality is low risk but non-standard"),
]

# Role-level permissions (for matrix display)
_ROLE_PERMISSIONS: dict[str, list[str]] = {
    "admin": ["manage_users", "configure_systems", "delete_data", "approve_changes"],
    "auditor": ["read_all", "export_results", "create_findings", "sign_reports"],
    "owner": ["update_controls", "accept_risks", "manage_poams", "approve_exceptions"],
    "viewer": ["read_results", "read_findings"],
}


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("sod")
def sod() -> None:
    """Segregation of Duties (SoD): role conflict analysis and matrix."""


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


@sod.command("analyze")
@click.option("--email", default=None, help="Analyze a specific user by email")
def sod_analyze(email: str | None) -> None:
    """Analyze user roles for Segregation of Duties conflicts."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import User

    init_db()
    with get_session() as session:
        q = session.query(User).filter(User.is_active.is_(True))
        if email:
            q = q.filter(User.email.ilike(f"%{email}%"))
        users = q.all()

    if not users:
        console.print("[dim]No active users found.[/dim]")
        return

    # Detect conflicts — here we look for users whose allowed_actions
    # or role grant access to incompatible permission sets.
    conflicts: list[dict] = []

    for user in users:
        user_roles: list[str] = [user.role]
        # Include any additional roles implied by allowed_actions
        perms = set(user.allowed_actions or [])
        for role, role_perms in _ROLE_PERMISSIONS.items():
            if role != user.role and perms.issuperset(role_perms):
                user_roles.append(f"{role}(via allowed_actions)")

        for rule_a, rule_b, desc in _SOD_RULES:
            roles_normalized = [r.split("(")[0] for r in user_roles]
            if rule_a in roles_normalized and rule_b in roles_normalized:
                conflicts.append({
                    "email": user.email,
                    "name": user.name,
                    "role": user.role,
                    "conflict": f"{rule_a} + {rule_b}",
                    "description": desc,
                })

    if not conflicts:
        console.print(f"[green]No SoD conflicts detected across {len(users)} user(s).[/green]")
        return

    table = Table(title=f"SoD Conflicts ({len(conflicts)} found)")
    table.add_column("Email", style="cyan", max_width=30)
    table.add_column("Name", max_width=20)
    table.add_column("Role")
    table.add_column("Conflict")
    table.add_column("Rule Description", max_width=45)

    for c in conflicts:
        table.add_row(
            c["email"][:30],
            c["name"][:20],
            c["role"],
            f"[red]{c['conflict']}[/red]",
            c["description"],
        )

    console.print(table)
    console.print(
        f"\n[yellow]Action required:[/yellow] Review {len(conflicts)} conflict(s) and "
        "adjust role assignments to restore proper SoD."
    )


# ---------------------------------------------------------------------------
# conflicts
# ---------------------------------------------------------------------------


@sod.command("conflicts")
@click.option("--role", "-r", default=None, help="Show conflicts for a specific role")
def sod_conflicts(role: str | None) -> None:
    """Show known SoD conflict rules and any current violations."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import User

    init_db()

    # Show the rule catalog
    rules_table = Table(title="SoD Rule Catalog")
    rules_table.add_column("Role A", style="cyan")
    rules_table.add_column("Role B", style="cyan")
    rules_table.add_column("Description")
    rules_table.add_column("Violations", justify="right")

    with get_session() as session:
        users = session.query(User).filter(User.is_active.is_(True)).all()

    violation_map: dict[tuple[str, str], int] = defaultdict(int)
    for user in users:
        for rule_a, rule_b, _ in _SOD_RULES:
            if user.role in (rule_a, rule_b):
                other = rule_b if user.role == rule_a else rule_a
                # Check if this user also has the other role via actions
                perms = set(user.allowed_actions or [])
                if other in _ROLE_PERMISSIONS and perms.issuperset(_ROLE_PERMISSIONS[other]):
                    violation_map[(rule_a, rule_b)] += 1

    for rule_a, rule_b, desc in _SOD_RULES:
        if role and role not in (rule_a, rule_b):
            continue
        violations = violation_map.get((rule_a, rule_b), 0)
        viol_str = f"[red]{violations}[/red]" if violations > 0 else "[green]0[/green]"
        rules_table.add_row(rule_a, rule_b, desc, viol_str)

    console.print(rules_table)


# ---------------------------------------------------------------------------
# matrix
# ---------------------------------------------------------------------------


@sod.command("matrix")
def sod_matrix() -> None:
    """Display the role-permission matrix showing access rights per role."""
    # Collect all unique permissions
    all_perms: list[str] = []
    seen: set[str] = set()
    for perms in _ROLE_PERMISSIONS.values():
        for p in perms:
            if p not in seen:
                all_perms.append(p)
                seen.add(p)

    roles = list(_ROLE_PERMISSIONS.keys())

    table = Table(title="Role-Permission Matrix (SoD)")
    table.add_column("Permission", style="cyan")
    for role in roles:
        table.add_column(role.capitalize(), justify="center")

    for perm in all_perms:
        row_cells: list[str] = [perm]
        for role in roles:
            has_perm = perm in _ROLE_PERMISSIONS.get(role, [])
            row_cells.append("[green]Y[/green]" if has_perm else "[dim].[/dim]")
        table.add_row(*row_cells)

    console.print(table)
    console.print(
        "\n[dim]Cells marked Y indicate the role has this permission. "
        "SoD conflicts arise when a single user holds roles with overlapping "
        "or mutually exclusive permissions.[/dim]"
    )

    # Show incompatible role pairs
    console.print("\n[bold]Incompatible Role Pairs:[/bold]")
    for rule_a, rule_b, desc in _SOD_RULES:
        console.print(f"  [red]{rule_a}[/red] + [red]{rule_b}[/red] — {desc}")
