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
