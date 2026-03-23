"""Alert management commands.

Provides CLI access to the alert lifecycle: list, acknowledge, resolve,
dismiss, and evaluate rules. Follows the same patterns as incidents_cmd.py.
"""

from __future__ import annotations

from datetime import datetime, timezone

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


# ---------------------------------------------------------------------------
# Severity / status helpers
# ---------------------------------------------------------------------------

_SEVERITY_STYLES: dict[str, str] = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
    "info": "dim",
}

_STATUS_STYLES: dict[str, str] = {
    "open": "yellow",
    "acknowledged": "cyan",
    "investigating": "blue",
    "resolved": "green",
    "dismissed": "dim",
}

_VALID_STATUSES = ["open", "acknowledged", "investigating", "resolved", "dismissed"]
_VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"]
_VALID_CATEGORIES = [
    "control_drift",
    "new_finding",
    "connector_failure",
    "threshold_breach",
    "policy_violation",
]


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("alerts", invoke_without_command=True)
@click.pass_context
def alerts(ctx: click.Context) -> None:
    """Alert lifecycle management (list, ack, resolve, evaluate)."""
    if ctx.invoked_subcommand is not None:
        return

    # Default: show summary of open alerts by severity
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Alert

    init_db()
    with get_session() as session:
        open_alerts = session.query(Alert).filter(Alert.status == "open").all()

    if not open_alerts:
        console.print("[green]No open alerts.[/green]")
        return

    counts: dict[str, int] = {}
    for a in open_alerts:
        counts[a.severity] = counts.get(a.severity, 0) + 1

    table = Table(title=f"Open Alerts ({len(open_alerts)})")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in _VALID_SEVERITIES:
        count = counts.get(sev, 0)
        if count > 0:
            style = _SEVERITY_STYLES.get(sev, "")
            table.add_row(f"[{style}]{sev}[/]", str(count))
    console.print(table)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@alerts.command("list")
@click.option(
    "--status",
    default=None,
    type=click.Choice(_VALID_STATUSES + [""]),
    help="Filter by status",
)
@click.option(
    "--severity",
    default=None,
    type=click.Choice(_VALID_SEVERITIES + [""]),
    help="Filter by severity",
)
@click.option("--limit", "-n", default=50, help="Max results")
def alerts_list(status: str | None, severity: str | None, limit: int) -> None:
    """List alerts with optional filters."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Alert

    init_db()
    with get_session() as session:
        q = session.query(Alert)
        if status:
            q = q.filter(Alert.status == status)
        if severity:
            q = q.filter(Alert.severity == severity)
        rows = q.order_by(Alert.triggered_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No alerts found.[/dim]")
        return

    table = Table(title=f"Alerts ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Title", max_width=50)
    table.add_column("Severity")
    table.add_column("Category", style="dim")
    table.add_column("Status")
    table.add_column("Rule", style="dim")
    table.add_column("Triggered", style="dim")

    for a in rows:
        sev_style = _SEVERITY_STYLES.get(a.severity, "")
        st_style = _STATUS_STYLES.get(a.status, "")
        triggered = a.triggered_at.strftime("%Y-%m-%d %H:%M") if a.triggered_at else "\u2014"
        table.add_row(
            a.id[:8],
            escape(a.title[:50] if a.title else "\u2014"),
            f"[{sev_style}]{a.severity}[/]",
            escape(a.category or "\u2014"),
            f"[{st_style}]{a.status}[/]",
            escape(a.rule_name or "\u2014"),
            triggered,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# ack
# ---------------------------------------------------------------------------


@alerts.command("ack")
@click.argument("alert_id")
def alerts_ack(alert_id: str) -> None:
    """Acknowledge an alert."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Alert

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        alert = session.query(Alert).filter(Alert.id.startswith(alert_id)).first()
        if not alert:
            _error(f"Alert not found: {alert_id}")

        if alert.status not in ("open",):
            _error(f"Cannot acknowledge alert in status '{alert.status}' (must be open)")

        alert.status = "acknowledged"
        alert.acknowledged_by = actor
        alert.acknowledged_at = now
        alert.updated_at = now
        session.commit()

    console.print(f"[green]Alert {alert_id[:8]} acknowledged[/green] by {escape(actor)}")


# ---------------------------------------------------------------------------
# resolve
# ---------------------------------------------------------------------------


@alerts.command("resolve")
@click.argument("alert_id")
@click.option("--notes", default=None, help="Resolution notes")
def alerts_resolve(alert_id: str, notes: str | None) -> None:
    """Resolve an alert."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Alert

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        alert = session.query(Alert).filter(Alert.id.startswith(alert_id)).first()
        if not alert:
            _error(f"Alert not found: {alert_id}")

        if alert.status in ("resolved", "dismissed"):
            _error(f"Alert already in terminal status '{alert.status}'")

        alert.status = "resolved"
        alert.resolved_by = actor
        alert.resolved_at = now
        alert.updated_at = now
        if notes:
            alert.resolution_notes = notes
        session.commit()

    console.print(f"[green]Alert {alert_id[:8]} resolved[/green] by {escape(actor)}")
    if notes:
        console.print(f"  Notes: {escape(notes)}")


# ---------------------------------------------------------------------------
# dismiss
# ---------------------------------------------------------------------------


@alerts.command("dismiss")
@click.argument("alert_id")
def alerts_dismiss(alert_id: str) -> None:
    """Dismiss an alert (false positive or not actionable)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Alert

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        alert = session.query(Alert).filter(Alert.id.startswith(alert_id)).first()
        if not alert:
            _error(f"Alert not found: {alert_id}")

        if alert.status in ("resolved", "dismissed"):
            _error(f"Alert already in terminal status '{alert.status}'")

        alert.status = "dismissed"
        alert.resolved_by = actor
        alert.resolved_at = now
        alert.resolution_notes = "Dismissed"
        alert.updated_at = now
        session.commit()

    console.print(f"[yellow]Alert {alert_id[:8]} dismissed[/yellow] by {escape(actor)}")


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------


@alerts.command("evaluate")
def alerts_evaluate() -> None:
    """Run the alert rules engine and create alerts for any matches."""
    from warlock.db.engine import get_session, init_db
    from warlock.pipeline.alert_rules import AlertRulesEngine

    init_db()
    engine = AlertRulesEngine()

    with get_session() as session:
        new_alerts = engine.evaluate(session)

    if not new_alerts:
        console.print("[green]No new alerts generated.[/green]")
        return

    console.print(f"[bold]{len(new_alerts)} new alert(s) created:[/bold]")
    for a in new_alerts:
        sev_style = _SEVERITY_STYLES.get(a.severity, "")
        console.print(f"  [{sev_style}]{a.severity}[/] {escape(a.title[:80] if a.title else '')}")
