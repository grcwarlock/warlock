"""CLI commands for the unified policy engine."""

from __future__ import annotations

import click
from rich.table import Table

from rich.markup import escape

from warlock.cli import cli, console


@cli.group(invoke_without_command=True)
@click.pass_context
def policy(ctx: click.Context):
    """Push and manage operational policies."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@policy.command("set")
@click.argument(
    "policy_type",
    type=click.Choice(
        [
            "sla",
            "retention",
            "classification",
            "risk-appetite",
            "escalation",
            "auto-assign",
            "auto-create",
            "cadence",
            "confidence",
            "evidence-requirement",
            "pii",
        ]
    ),
)
@click.option("--framework", "-f", default=None, help="Scope to framework")
@click.option("--severity", default=None, help="Scope to severity level")
@click.option("--remediation-days", type=int, default=None, help="SLA: days to remediate")
@click.option("--escalate-after", type=int, default=None, help="SLA: escalate after N days")
@click.option("--days", type=int, default=None, help="Retention: days to keep data")
@click.option("--owner", default=None, help="Auto-assign: owner email")
@click.option("--frequency", default=None, help="Cadence: monitoring frequency")
@click.option("--floor", type=float, default=None, help="Confidence: minimum AI confidence")
@click.option("--max-ale", type=int, default=None, help="Risk appetite: max ALE in dollars")
@click.option("--max-var95", type=int, default=None, help="Risk appetite: max VaR95 in dollars")
@click.option("--priority", type=int, default=0, help="Policy priority (higher wins)")
@click.option("--reason", default="", help="Description / reason for this policy")
@click.option("--actor", default=None, help="Actor identity (default: cli@warlock)")
@click.option("--dry-run", is_flag=True, help="Show what would change without executing")
def policy_set(
    policy_type,
    framework,
    severity,
    remediation_days,
    escalate_after,
    days,
    owner,
    frequency,
    floor,
    max_ale,
    max_var95,
    priority,
    reason,
    actor,
    dry_run,
):
    """Push a policy to the system."""
    import os
    from warlock.db.engine import get_session
    from warlock.domains.policy_engine import PolicyEngine

    actor = actor or os.environ.get("WLK_CLI_ACTOR", "cli@warlock")
    scope = {}
    if framework:
        scope["frameworks"] = [framework]
    if severity:
        scope["severity"] = [severity]

    rules = {}
    if policy_type == "sla":
        if remediation_days is not None:
            rules["remediation_days"] = remediation_days
        if escalate_after is not None:
            rules["escalate_after"] = escalate_after
    elif policy_type == "retention":
        if days is not None:
            rules["days"] = days
    elif policy_type == "auto-assign":
        if owner:
            rules["owner"] = owner
    elif policy_type == "cadence":
        if frequency:
            rules["frequency"] = frequency
    elif policy_type == "confidence":
        if floor is not None:
            rules["floor"] = floor
    elif policy_type == "risk-appetite":
        if max_ale is not None:
            rules["max_ale"] = max_ale
        if max_var95 is not None:
            rules["max_var95"] = max_var95

    if not rules:
        console.print(
            "[red]No rules specified. Use --help to see options for this policy type.[/red]"
        )
        raise SystemExit(1)

    if dry_run:
        console.print(f"[dim]DRY RUN: Would create {policy_type} policy[/dim]")
        console.print(f"  Scope: {scope or 'global'}")
        console.print(f"  Rules: {rules}")
        return

    with get_session() as session:
        engine = PolicyEngine(session)
        p = engine.set_policy(
            policy_type=policy_type.replace("-", "_"),
            scope=scope,
            rules=rules,
            actor=actor,
            priority=priority,
            description=reason,
        )
        console.print(f"[green]Policy created:[/green] {policy_type} (id: {p.id[:8]})")
        console.print(f"  Scope: {scope or 'global'}")
        console.print(f"  Rules: {rules}")


@policy.command("list")
@click.option("--type", "policy_type", default=None, help="Filter by policy type")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def policy_list(policy_type, framework):
    """List active policies."""
    from warlock.db.engine import get_session
    from warlock.domains.policy_engine import PolicyEngine

    with get_session() as session:
        engine = PolicyEngine(session)
        policies = engine.list_policies(
            policy_type=policy_type.replace("-", "_") if policy_type else None,
            framework=framework,
        )
    if not policies:
        console.print("[dim]No policies found.[/dim]")
        return

    table = Table(title=f"Policies ({len(policies)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Type")
    table.add_column("Scope")
    table.add_column("Rules")
    table.add_column("Priority", justify="right")
    table.add_column("Created By")

    for p in policies:
        scope_str = str(p.scope) if p.scope else "global"
        if len(scope_str) > 40:
            scope_str = scope_str[:37] + "..."
        rules_str = str(p.rules)
        if len(rules_str) > 40:
            rules_str = rules_str[:37] + "..."
        table.add_row(p.id[:8], p.policy_type, scope_str, rules_str, str(p.priority), p.created_by)
    console.print(table)


@policy.command("show")
@click.option("--control", default=None, help="Show policies affecting a control")
@click.option("--framework", "-f", default=None, help="Show policies for a framework")
def policy_show(control, framework):
    """Show policies affecting a specific entity."""
    from warlock.db.engine import get_session
    from warlock.domains.policy_engine import PolicyEngine

    with get_session() as session:
        engine = PolicyEngine(session)
        policies = engine.list_policies(framework=framework)
    if not policies:
        console.print("[dim]No matching policies.[/dim]")
        return
    for p in policies:
        console.print(f"[bold]{p.policy_type}[/bold] (priority: {p.priority})")
        console.print(f"  Scope: {p.scope or 'global'}")
        console.print(f"  Rules: {p.rules}")
        console.print(f"  By: {p.created_by}  |  {escape(p.description or '')}")
        console.print()


@policy.command("history")
@click.option("--type", "policy_type", default=None, help="Filter by type")
@click.option("--limit", "-n", default=20, help="Max entries")
def policy_history(policy_type, limit):
    """Show policy change history."""
    from warlock.db.engine import get_session
    from warlock.db.models import PolicyHistory, Policy

    from sqlalchemy.orm import joinedload

    rows_data = []
    with get_session() as session:
        q = session.query(PolicyHistory).join(Policy).options(joinedload(PolicyHistory.policy))
        if policy_type:
            q = q.filter(Policy.policy_type == policy_type.replace("-", "_"))
        db_rows = q.order_by(PolicyHistory.timestamp.desc()).limit(limit).all()
        for h in db_rows:
            rows_data.append(
                {
                    "timestamp": str(h.timestamp)[:19] if h.timestamp else "",
                    "action": h.action,
                    "policy_type": h.policy.policy_type if h.policy else "",
                    "actor": h.actor,
                    "new_rules": str(h.new_rules)[:50],
                }
            )

    if not rows_data:
        console.print("[dim]No policy history.[/dim]")
        return

    table = Table(title="Policy History")
    table.add_column("Timestamp")
    table.add_column("Action")
    table.add_column("Type")
    table.add_column("Actor")
    table.add_column("Rules")

    for row in rows_data:
        table.add_row(
            row["timestamp"], row["action"], row["policy_type"], row["actor"], row["new_rules"]
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Policy Templates (P1 Item 43)
# ---------------------------------------------------------------------------


@policy.group("templates", invoke_without_command=True)
@click.pass_context
def templates(ctx: click.Context) -> None:
    """Built-in policy template library."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@templates.command("list")
@click.option("--category", "-c", default=None, help="Filter by category")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def templates_list(category: str | None, framework: str | None) -> None:
    """List available policy templates."""
    from warlock.workflows.policy_templates import PolicyTemplateLibrary

    lib = PolicyTemplateLibrary()
    results = lib.list_templates(category=category, framework=framework)

    if not results:
        console.print("[dim]No templates matching filters.[/dim]")
        return

    table = Table(title="Policy Templates")
    table.add_column("Slug", style="cyan")
    table.add_column("Title")
    table.add_column("Category")
    table.add_column("Frameworks")

    for t in results:
        table.add_row(
            t.slug,
            escape(t.title),
            escape(t.category),
            ", ".join(t.frameworks[:4]) + ("..." if len(t.frameworks) > 4 else ""),
        )
    console.print(table)
    console.print(
        f"\n[dim]{len(results)} template(s). Use 'policy templates show <slug>' for details.[/dim]"
    )


@templates.command("show")
@click.argument("slug")
def templates_show(slug: str) -> None:
    """Show a policy template with content outline."""
    from rich.panel import Panel

    from warlock.workflows.policy_templates import PolicyTemplateLibrary

    lib = PolicyTemplateLibrary()
    t = lib.get_template(slug)

    if not t:
        from warlock.cli import _error

        _error(f"Template '{slug}' not found. Use 'policy templates list' to see available.")

    content_lines = [
        f"[bold]{t.title}[/bold]",
        f"Category: {t.category}",
        f"Frameworks: {', '.join(t.frameworks)}",
        "",
        f"[dim]{t.description}[/dim]",
        "",
        "[bold]Content Outline:[/bold]",
    ]
    for item in t.outline:
        content_lines.append(f"  {item}")

    console.print(Panel("\n".join(content_lines), title=escape(t.title), border_style="cyan"))


@policy.command("acknowledge")
@click.argument("policy_name")
@click.option("--user", "-u", required=True, help="User email acknowledging the policy")
@click.option("--notes", "-n", default="", help="Acknowledgment notes")
def policy_acknowledge(policy_name: str, user: str, notes: str) -> None:
    """Record a user's acknowledgment of a policy."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.policy_templates import PolicyTemplateLibrary

    init_db()
    with get_session() as session:
        lib = PolicyTemplateLibrary(session)
        ack = lib.acknowledge(policy_name=policy_name, user_email=user, notes=notes)

    console.print("[green]Acknowledgment recorded:[/green]")
    console.print(f"  Policy: {escape(ack.policy_name)}")
    console.print(f"  User:   {escape(ack.user_email)}")
    console.print(f"  At:     {ack.acknowledged_at.strftime('%Y-%m-%d %H:%M:%S')}")


@policy.command("acknowledgments")
@click.option("--policy-name", "-p", default=None, help="Filter by policy name")
@click.option("--user", "-u", default=None, help="Filter by user email")
def policy_acknowledgments(policy_name: str | None, user: str | None) -> None:
    """List policy acknowledgments."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.workflows.policy_templates import PolicyTemplateLibrary

    init_db()
    with get_read_session() as session:
        lib = PolicyTemplateLibrary(session)
        acks = lib.list_acknowledgments(policy_name=policy_name, user_email=user)

    if not acks:
        console.print("[dim]No acknowledgments found.[/dim]")
        return

    table = Table(title="Policy Acknowledgments")
    table.add_column("Policy", style="cyan")
    table.add_column("User")
    table.add_column("Acknowledged At")
    table.add_column("Notes")

    for a in acks:
        table.add_row(
            escape(a.policy_name),
            escape(a.user_email),
            a.acknowledged_at.strftime("%Y-%m-%d %H:%M"),
            escape(a.notes[:40] if a.notes else ""),
        )
    console.print(table)
