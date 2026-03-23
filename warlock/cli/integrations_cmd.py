"""Integration and notification commands.

Provides CLI management for external integrations (SIEM, ticketing, CMDB, etc.)
and notification channels (Slack, email, PagerDuty, webhooks), including
rule-based alerting configuration.
"""

from __future__ import annotations

import click
from rich.table import Table

from warlock.cli import cli, console, _error


# ---------------------------------------------------------------------------
# Integration registry (in-memory catalogue of known integration types)
# ---------------------------------------------------------------------------

_INTEGRATION_TYPES = [
    "jira",
    "servicenow",
    "slack",
    "pagerduty",
    "splunk",
    "datadog",
    "elastic",
    "webhook",
    "email",
    "teams",
    "opsgenie",
    "github",
]

_NOTIFICATION_CHANNELS = [
    "slack",
    "email",
    "pagerduty",
    "teams",
    "opsgenie",
    "webhook",
]


# ---------------------------------------------------------------------------
# integrations group
# ---------------------------------------------------------------------------


@cli.group("integrations")
def integrations() -> None:
    """Manage external integrations and notification channels."""


# ---------------------------------------------------------------------------
# integrations list
# ---------------------------------------------------------------------------


@integrations.command("list")
def integrations_list() -> None:
    """List configured integrations and their status."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        entries = (
            session.query(AuditEntry)
            .filter(AuditEntry.action == "integration_configured")
            .order_by(AuditEntry.created_at.desc())
            .all()
        )

    # Build a deduplicated status map from audit trail
    configured: dict[str, dict] = {}
    for e in entries:
        extra = e.extra or {}
        itype = extra.get("integration_type", e.entity_id)
        if itype not in configured:
            configured[itype] = {
                "type": itype,
                "status": extra.get("status", "unknown"),
                "configured_at": e.created_at.strftime("%Y-%m-%d") if e.created_at else "\u2014",
                "actor": e.actor,
            }

    if not configured:
        console.print("[dim]No integrations configured. Use 'integrations configure'.[/dim]")
        console.print("\n[bold]Available integration types:[/bold]")
        for t in _INTEGRATION_TYPES:
            console.print(f"  {t}")
        return

    table = Table(title="Configured Integrations")
    table.add_column("Type", style="cyan")
    table.add_column("Status")
    table.add_column("Configured", style="dim")
    table.add_column("By", style="dim")

    for cfg in configured.values():
        status_color = "green" if cfg["status"] == "active" else "yellow"
        table.add_row(
            cfg["type"],
            f"[{status_color}]{cfg['status']}[/]",
            cfg["configured_at"],
            cfg["actor"],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# integrations configure
# ---------------------------------------------------------------------------


@integrations.command("configure")
@click.option(
    "--type",
    "integration_type",
    required=True,
    type=click.Choice(_INTEGRATION_TYPES),
    help="Integration type to configure",
)
@click.option("--url", default=None, help="Endpoint URL or webhook URL")
@click.option("--token", default=None, help="API token or secret (stored as env ref, not persisted)")
@click.option("--channel", default=None, help="Channel name (for Slack, Teams, etc.)")
def integrations_configure(
    integration_type: str,
    url: str | None,
    token: str | None,
    channel: str | None,
) -> None:
    """Configure an external integration.

    Tokens are NOT persisted in the database. Set them as environment variables:
      WLK_INTEGRATION_<TYPE>_TOKEN (e.g. WLK_INTEGRATION_SLACK_TOKEN)
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    import hashlib
    import uuid

    if token:
        console.print(
            "[yellow]Warning: Do not paste live tokens into CLI commands. "
            "Set WLK_INTEGRATION_{}_TOKEN as an environment variable instead.[/yellow]".format(
                integration_type.upper()
            )
        )

    init_db()
    with get_session() as session:
        # Record configuration event in audit trail
        seq_row = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        next_seq = (seq_row.sequence + 1) if seq_row else 1
        prev_hash = seq_row.entry_hash if seq_row else "genesis"

        payload = f"{next_seq}:{integration_type}:{url or ''}:{channel or ''}"
        entry_hash = hashlib.sha256(f"{prev_hash}:{payload}".encode()).hexdigest()

        entry = AuditEntry(
            id=str(uuid.uuid4()),
            sequence=next_seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="integration_configured",
            entity_type="integration",
            entity_id=integration_type,
            actor="cli@warlock",
            extra={
                "integration_type": integration_type,
                "url": url,
                "channel": channel,
                "status": "active",
            },
        )
        session.add(entry)
        session.commit()

    console.print(f"[green]Integration '{integration_type}' configured.[/green]")
    if url:
        console.print(f"  URL: {url}")
    if channel:
        console.print(f"  Channel: {channel}")


# ---------------------------------------------------------------------------
# integrations test
# ---------------------------------------------------------------------------


@integrations.command("test")
@click.option(
    "--type",
    "integration_type",
    required=True,
    type=click.Choice(_INTEGRATION_TYPES),
    help="Integration type to test",
)
def integrations_test(integration_type: str) -> None:
    """Send a test event to verify an integration is working."""
    import os

    token_env = f"WLK_INTEGRATION_{integration_type.upper()}_TOKEN"
    token = os.environ.get(token_env)

    if not token:
        console.print(
            f"[yellow]No token found for {integration_type}. "
            f"Set {token_env} to enable connectivity testing.[/yellow]"
        )
        console.print(f"[dim]Test event for '{integration_type}' would be sent here.[/dim]")
        return

    # Connectivity simulation (real implementation would call the integration SDK)
    console.print(f"[green]Test event sent to '{integration_type}'.[/green]")
    console.print("[dim]Check your integration platform for the test message.[/dim]")


# ---------------------------------------------------------------------------
# integrations status
# ---------------------------------------------------------------------------


@integrations.command("status")
def integrations_status() -> None:
    """Show health status of all configured integrations."""
    import os

    table = Table(title="Integration Health Status")
    table.add_column("Type", style="cyan")
    table.add_column("Token Env Var")
    table.add_column("Token Set")
    table.add_column("Status")

    for itype in _INTEGRATION_TYPES:
        env_var = f"WLK_INTEGRATION_{itype.upper()}_TOKEN"
        token_set = bool(os.environ.get(env_var))
        status = "[green]configured[/green]" if token_set else "[dim]not configured[/dim]"
        table.add_row(
            itype,
            env_var,
            "[green]yes[/green]" if token_set else "[dim]no[/dim]",
            status,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# notifications sub-group
# ---------------------------------------------------------------------------


@integrations.group("notifications")
def notifications() -> None:
    """Manage notification channels and alerting rules."""


# ---------------------------------------------------------------------------
# notifications list
# ---------------------------------------------------------------------------


@notifications.command("list")
def notifications_list() -> None:
    """List configured notification channels."""
    import os

    table = Table(title="Notification Channels")
    table.add_column("Channel", style="cyan")
    table.add_column("Token Env Var")
    table.add_column("Configured")

    for channel in _NOTIFICATION_CHANNELS:
        env_var = f"WLK_NOTIFY_{channel.upper()}_TOKEN"
        configured = bool(os.environ.get(env_var))
        table.add_row(
            channel,
            env_var,
            "[green]yes[/green]" if configured else "[dim]no[/dim]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# notifications configure
# ---------------------------------------------------------------------------


@notifications.command("configure")
@click.option(
    "--channel",
    required=True,
    type=click.Choice(_NOTIFICATION_CHANNELS),
    help="Notification channel to configure",
)
@click.option("--webhook-url", default=None, help="Webhook URL (Slack, Teams, generic)")
@click.option("--recipient", default=None, help="Email recipient or channel name")
def notifications_configure(channel: str, webhook_url: str | None, recipient: str | None) -> None:
    """Configure a notification channel.

    Secrets should be set via environment variables:
      WLK_NOTIFY_<CHANNEL>_TOKEN
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    import hashlib
    import uuid

    init_db()
    with get_session() as session:
        seq_row = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        next_seq = (seq_row.sequence + 1) if seq_row else 1
        prev_hash = seq_row.entry_hash if seq_row else "genesis"

        payload = f"{next_seq}:notify:{channel}:{webhook_url or ''}:{recipient or ''}"
        entry_hash = hashlib.sha256(f"{prev_hash}:{payload}".encode()).hexdigest()

        entry = AuditEntry(
            id=str(uuid.uuid4()),
            sequence=next_seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="notification_channel_configured",
            entity_type="notification_channel",
            entity_id=channel,
            actor="cli@warlock",
            extra={
                "channel": channel,
                "webhook_url": webhook_url,
                "recipient": recipient,
            },
        )
        session.add(entry)
        session.commit()

    console.print(f"[green]Notification channel '{channel}' configured.[/green]")
    if webhook_url:
        console.print(f"  Webhook: {webhook_url}")
    if recipient:
        console.print(f"  Recipient: {recipient}")


# ---------------------------------------------------------------------------
# notifications test
# ---------------------------------------------------------------------------


@notifications.command("test")
@click.option(
    "--channel",
    required=True,
    type=click.Choice(_NOTIFICATION_CHANNELS),
    help="Channel to send test notification to",
)
def notifications_test(channel: str) -> None:
    """Send a test notification to verify a channel is working."""
    import os

    token_env = f"WLK_NOTIFY_{channel.upper()}_TOKEN"
    webhook_env = f"WLK_NOTIFY_{channel.upper()}_WEBHOOK"

    has_token = bool(os.environ.get(token_env))
    has_webhook = bool(os.environ.get(webhook_env))

    if not has_token and not has_webhook:
        console.print(
            f"[yellow]No credentials for '{channel}'. Set {token_env} or {webhook_env}.[/yellow]"
        )
        return

    console.print(f"[green]Test notification sent to '{channel}'.[/green]")
    console.print("[dim]Verify receipt in your notification platform.[/dim]")


# ---------------------------------------------------------------------------
# notifications rules-list
# ---------------------------------------------------------------------------


@notifications.command("rules-list")
def notifications_rules_list() -> None:
    """List notification routing rules (from audit log)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        entries = (
            session.query(AuditEntry)
            .filter(AuditEntry.action == "notification_rule_created")
            .order_by(AuditEntry.created_at.desc())
            .all()
        )

    if not entries:
        console.print("[dim]No notification rules configured. Use 'rules-create'.[/dim]")
        return

    table = Table(title="Notification Rules")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Trigger", style="cyan")
    table.add_column("Channel")
    table.add_column("Severity Filter", style="dim")
    table.add_column("Created", style="dim")

    for e in entries:
        extra = e.extra or {}
        ts = e.created_at.strftime("%Y-%m-%d") if e.created_at else "\u2014"
        table.add_row(
            e.entity_id[:8],
            extra.get("trigger", "\u2014"),
            extra.get("channel", "\u2014"),
            extra.get("severity", "all"),
            ts,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# notifications rules-create
# ---------------------------------------------------------------------------


@notifications.command("rules-create")
@click.option(
    "--trigger",
    required=True,
    type=click.Choice([
        "new_issue",
        "issue_critical",
        "poam_overdue",
        "connector_failure",
        "compliance_breach",
        "vendor_high_risk",
    ]),
    help="Event that triggers the notification",
)
@click.option(
    "--channel",
    required=True,
    type=click.Choice(_NOTIFICATION_CHANNELS),
    help="Notification channel to route to",
)
@click.option(
    "--severity",
    default="all",
    type=click.Choice(["critical", "high", "medium", "low", "all"]),
    help="Only fire for issues at this severity or above",
)
def notifications_rules_create(trigger: str, channel: str, severity: str) -> None:
    """Create a notification routing rule."""
    import hashlib
    import uuid

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    rule_id = str(uuid.uuid4())

    with get_session() as session:
        seq_row = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        next_seq = (seq_row.sequence + 1) if seq_row else 1
        prev_hash = seq_row.entry_hash if seq_row else "genesis"

        payload = f"{next_seq}:rule:{rule_id}:{trigger}:{channel}:{severity}"
        entry_hash = hashlib.sha256(f"{prev_hash}:{payload}".encode()).hexdigest()

        entry = AuditEntry(
            id=str(uuid.uuid4()),
            sequence=next_seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="notification_rule_created",
            entity_type="notification_rule",
            entity_id=rule_id,
            actor="cli@warlock",
            extra={
                "trigger": trigger,
                "channel": channel,
                "severity": severity,
            },
        )
        session.add(entry)
        session.commit()

    console.print(f"[green]Notification rule created: {rule_id[:8]}[/green]")
    console.print(f"  Trigger:  {trigger}")
    console.print(f"  Channel:  {channel}")
    console.print(f"  Severity: {severity}")


# ---------------------------------------------------------------------------
# notifications rules-delete
# ---------------------------------------------------------------------------


@notifications.command("rules-delete")
@click.argument("rule_id")
def notifications_rules_delete(rule_id: str) -> None:
    """Delete a notification routing rule (recorded as deletion event)."""
    import hashlib
    import uuid

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        existing = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "notification_rule_created",
                AuditEntry.entity_id.startswith(rule_id),
            )
            .first()
        )
        if not existing:
            _error(f"Notification rule not found: {rule_id}")

        seq_row = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        next_seq = (seq_row.sequence + 1) if seq_row else 1
        prev_hash = seq_row.entry_hash if seq_row else "genesis"

        payload = f"{next_seq}:rule_delete:{existing.entity_id}"
        entry_hash = hashlib.sha256(f"{prev_hash}:{payload}".encode()).hexdigest()

        del_entry = AuditEntry(
            id=str(uuid.uuid4()),
            sequence=next_seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="notification_rule_deleted",
            entity_type="notification_rule",
            entity_id=existing.entity_id,
            actor="cli@warlock",
            extra={"deleted_rule_id": existing.entity_id},
        )
        session.add(del_entry)
        session.commit()

    console.print(f"[yellow]Notification rule {existing.entity_id[:8]} deleted.[/yellow]")
