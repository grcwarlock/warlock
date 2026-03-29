"""Notification preferences CLI commands.

Manage per-user notification preferences: channels, events, frequencies.
"""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


@cli.group("notifications", invoke_without_command=True)
@click.pass_context
def notifications(ctx: click.Context) -> None:
    """Notification preferences and testing."""
    if ctx.invoked_subcommand is not None:
        return

    console.print(
        "[dim]Usage: warlock notifications <command>\n"
        "  preferences  -- Manage notification preferences\n"
        "  test         -- Send a test notification[/dim]"
    )


# ---------------------------------------------------------------------------
# preferences group
# ---------------------------------------------------------------------------


@notifications.group("preferences", invoke_without_command=True)
@click.pass_context
def preferences(ctx: click.Context) -> None:
    """Manage notification preferences."""
    if ctx.invoked_subcommand is not None:
        return
    # Default: show current user's preferences
    ctx.invoke(list_preferences)


# ---------------------------------------------------------------------------
# preferences list
# ---------------------------------------------------------------------------


@preferences.command("list")
def list_preferences() -> None:
    """Show current user's notification preferences."""
    from warlock.db.engine import init_db
    from warlock.workflows.notification_engine import (
        NotificationEngine,
    )

    init_db()
    actor = _get_actor()
    engine = NotificationEngine()
    prefs = engine.get_preferences(actor)

    if not prefs:
        console.print(
            f"[dim]No notification preferences set for {escape(actor)}.[/dim]\n"
            f"[dim]Use 'warlock notifications preferences set' to configure, "
            f"or preferences will use role defaults.[/dim]"
        )
        return

    table = Table(title=f"Notification Preferences: {escape(actor)}")
    table.add_column("Event Type")
    table.add_column("Channel")
    table.add_column("Frequency")

    channel_styles = {
        "email": "cyan",
        "slack": "green",
        "teams": "blue",
        "pagerduty": "red",
    }

    for p in sorted(prefs, key=lambda x: (x["event"], x["channel"])):
        ch_style = channel_styles.get(p["channel"], "")
        table.add_row(
            escape(p["event"]),
            f"[{ch_style}]{p['channel']}[/]",
            p["frequency"],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# preferences set
# ---------------------------------------------------------------------------


@preferences.command("set")
@click.option("--event", "-e", required=True, help="Event type (e.g. compliance_drift)")
@click.option(
    "--channel",
    "-c",
    required=True,
    type=click.Choice(["email", "slack", "teams", "pagerduty"]),
    help="Notification channel",
)
@click.option(
    "--frequency",
    "-f",
    required=True,
    type=click.Choice(["realtime", "hourly", "daily", "weekly"]),
    help="Delivery frequency",
)
def set_preference(event: str, channel: str, frequency: str) -> None:
    """Set a notification preference."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.notification_engine import NotificationEngine

    init_db()
    actor = _get_actor()
    engine = NotificationEngine()

    try:
        with get_session() as session:
            pref = engine.set_preference(
                session=session,
                user_email=actor,
                event=event,
                channel=channel,
                frequency=frequency,
                actor=actor,
            )
            console.print(
                f"[green]Preference set:[/green] "
                f"{escape(pref['event'])} -> {escape(pref['channel'])} ({pref['frequency']})"
            )
    except ValueError as e:
        _error(str(e))


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------


@notifications.command("test")
@click.option(
    "--channel",
    "-c",
    required=True,
    type=click.Choice(["email", "slack", "teams", "pagerduty"]),
    help="Channel to test",
)
def test_notification(channel: str) -> None:
    """Send a test notification to verify channel connectivity."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.notification_engine import NotificationEngine

    init_db()
    actor = _get_actor()
    engine = NotificationEngine()

    try:
        with get_session() as session:
            result = engine.send_test(
                session=session,
                user_email=actor,
                channel=channel,
                actor=actor,
            )
            console.print(
                f"[green]Test notification sent[/green] via "
                f"[cyan]{escape(channel)}[/cyan] to {escape(actor)}\n"
                f"[dim]Message: {escape(result['message'])}[/dim]"
            )
    except ValueError as e:
        _error(str(e))


# ---------------------------------------------------------------------------
# route sub-group (Item 72)
# ---------------------------------------------------------------------------


@notifications.group("route", invoke_without_command=True)
@click.pass_context
def route(ctx: click.Context) -> None:
    """Manage notification routing rules."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(route_list)


@route.command("list")
def route_list() -> None:
    """List all notification routing rules."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_read_session() as session:
        entries = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "notification_route_created",
                AuditEntry.entity_type == "notification_route",
            )
            .order_by(AuditEntry.created_at.desc())
            .all()
        )

        # Filter out deleted routes
        deleted_ids: set[str] = set()
        del_entries = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "notification_route_deleted",
                AuditEntry.entity_type == "notification_route",
            )
            .all()
        )
        for d in del_entries:
            deleted_ids.add(d.entity_id)

        routes = []
        for e in entries:
            if e.entity_id in deleted_ids:
                continue
            meta = e.extra or {}
            routes.append(
                {
                    "id": e.entity_id,
                    "event": meta.get("event", ""),
                    "severity": meta.get("severity", ""),
                    "channel": meta.get("channel", ""),
                    "created_by": e.actor or "",
                }
            )

    if not routes:
        console.print("[dim]No notification routes configured.[/dim]")
        console.print("[dim]Use 'warlock notifications route create' to add one.[/dim]")
        return

    table = Table(title=f"Notification Routes ({len(routes)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Event")
    table.add_column("Severity")
    table.add_column("Channel")
    table.add_column("Created By", style="dim")

    channel_styles = {
        "email": "cyan",
        "slack": "green",
        "teams": "blue",
        "pagerduty": "red",
    }

    for r in routes:
        ch_style = channel_styles.get(r["channel"], "")
        table.add_row(
            r["id"][:8],
            escape(r["event"]),
            escape(r["severity"]),
            f"[{ch_style}]{r['channel']}[/]" if ch_style else escape(r["channel"]),
            escape(r["created_by"]),
        )

    console.print(table)


@route.command("create")
@click.option("--event", "-e", required=True, help="Event type (e.g. compliance_drift)")
@click.option(
    "--severity",
    "-s",
    required=True,
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Minimum severity",
)
@click.option(
    "--channel",
    "-c",
    required=True,
    type=click.Choice(["email", "slack", "teams", "pagerduty"]),
    help="Notification channel",
)
def route_create(event: str, severity: str, channel: str) -> None:
    """Create a notification routing rule."""
    from uuid import uuid4

    from warlock.db.engine import get_session, init_db
    from warlock.db.audit import AuditTrail

    init_db()
    actor = _get_actor()
    route_id = str(uuid4())

    with get_session() as session:
        audit = AuditTrail(session)
        audit.record(
            action="notification_route_created",
            entity_type="notification_route",
            entity_id=route_id,
            actor=actor,
            metadata={
                "event": event,
                "severity": severity,
                "channel": channel,
            },
        )

    console.print(
        f"[green]Route created:[/green] {route_id[:8]} "
        f"({escape(event)} >= {escape(severity)} -> {escape(channel)})"
    )


@route.command("delete")
@click.argument("route_id")
def route_delete(route_id: str) -> None:
    """Delete a notification routing rule."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.audit import AuditTrail

    init_db()
    actor = _get_actor()

    with get_session() as session:
        audit = AuditTrail(session)
        audit.record(
            action="notification_route_deleted",
            entity_type="notification_route",
            entity_id=route_id,
            actor=actor,
            metadata={"deleted": True},
        )

    console.print(f"[green]Route deleted:[/green] {escape(route_id[:8])}")
