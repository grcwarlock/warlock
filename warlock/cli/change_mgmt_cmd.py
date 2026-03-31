"""Change management commands: list, show, create, approve, reject, implement, emergency, report."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

import click
from rich.table import Table

from warlock.cli import _error, _get_actor, cli, console

# ---------------------------------------------------------------------------
# ChangeEvent is a read-only ingestion table (cloud audit logs, CI/CD, ITSM).
# Change management campaigns use AuditEntry with action="change_request"
# for the lifecycle workflow (create -> approve/reject -> implement).
# ---------------------------------------------------------------------------


def _load_change(session, change_id: str):
    """Load a change request AuditEntry by prefix or full ID."""
    from warlock.db.models import AuditEntry

    return (
        session.query(AuditEntry)
        .filter(
            AuditEntry.action == "change_request",
            AuditEntry.entity_type == "change_mgmt",
            AuditEntry.entity_id.startswith(change_id),
        )
        .first()
    )


def _next_sequence(session) -> int:
    """Return the next audit sequence number."""
    from sqlalchemy import func

    from warlock.db.models import AuditEntry

    return (session.query(func.max(AuditEntry.sequence)).scalar() or 0) + 1


def _make_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()


@cli.group("changes", invoke_without_command=True)
@click.pass_context
def changes(ctx: click.Context) -> None:
    """Manage change requests and the change management lifecycle."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@changes.command("create")
@click.option(
    "--type",
    "change_type",
    required=True,
    type=click.Choice(["standard", "normal", "emergency"]),
    help="Change type",
)
@click.option("--title", required=True, help="Change title")
@click.option(
    "--impact",
    required=True,
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Impact level",
)
@click.option("--description", required=True, help="Change description")
def changes_create(change_type: str, title: str, impact: str, description: str) -> None:
    """Create a new change request."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    actor = _get_actor()
    change_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc)

    with get_session() as session:
        entry = AuditEntry(
            id=uuid.uuid4().hex,
            sequence=_next_sequence(session),
            previous_hash="genesis",
            entry_hash=_make_hash(f"{change_id}:{change_type}:{title}"),
            action="change_request",
            entity_type="change_mgmt",
            entity_id=change_id,
            actor=actor,
            extra={
                "type": change_type,
                "title": title,
                "impact": impact,
                "description": description,
                "status": "pending",
                "created_by": actor,
                "created_at": now.isoformat(),
                "history": [
                    {
                        "action": "created",
                        "by": actor,
                        "at": now.isoformat(),
                    }
                ],
            },
        )
        session.add(entry)
        session.commit()

    console.print(f"[green]Change request created:[/green] [cyan]{change_id[:8]}[/cyan]")
    console.print(f"  Type:   {change_type}")
    console.print(f"  Title:  {title}")
    console.print(f"  Impact: {impact}")


@changes.command("list")
@click.option(
    "--status",
    default=None,
    type=click.Choice(["pending", "approved", "implemented", "rejected"]),
    help="Filter by status",
)
@click.option("--since", default=None, help="Show changes since date (YYYY-MM-DD)")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def changes_list(status: str | None, since: str | None, fmt: str) -> None:
    """List change requests."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        q = session.query(AuditEntry).filter(
            AuditEntry.action == "change_request",
            AuditEntry.entity_type == "change_mgmt",
        )
        if since:
            try:
                since_dt = datetime.strptime(since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                q = q.filter(AuditEntry.created_at >= since_dt)
            except ValueError:
                _error(f"Invalid date '{since}'. Expected YYYY-MM-DD.")
        rows = q.order_by(AuditEntry.created_at.desc()).all()

    if status:
        rows = [r for r in rows if (r.extra or {}).get("status") == status]

    if not rows:
        console.print("[dim]No change requests found.[/dim]")
        return

    if fmt == "json":
        data = [
            {
                "id": r.entity_id,
                "type": (r.extra or {}).get("type"),
                "title": (r.extra or {}).get("title"),
                "impact": (r.extra or {}).get("impact"),
                "status": (r.extra or {}).get("status"),
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Change Requests ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Type", style="cyan")
    table.add_column("Title", max_width=40)
    table.add_column("Impact")
    table.add_column("Status")
    table.add_column("Created")

    for r in rows:
        extra = r.extra or {}
        st = extra.get("status", "pending")
        status_style = {
            "pending": "yellow",
            "approved": "green",
            "implemented": "blue",
            "rejected": "red",
            "emergency": "red bold",
        }.get(st, "")
        impact_style = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
        }.get(extra.get("impact", ""), "")
        created = r.created_at.strftime("%Y-%m-%d") if r.created_at else "\u2014"
        table.add_row(
            r.entity_id[:8],
            extra.get("type", ""),
            (extra.get("title") or "")[:40],
            f"[{impact_style}]{extra.get('impact', '')}[/]",
            f"[{status_style}]{st}[/]",
            created,
        )

    console.print(table)


@changes.command("show")
@click.argument("change_id")
def changes_show(change_id: str) -> None:
    """Show full details for a change request."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        entry = _load_change(session, change_id)

    if not entry:
        _error(f"Change request not found: {change_id}")

    extra = entry.extra or {}
    console.print(f"\n[bold]Change Request[/bold] [cyan]{entry.entity_id[:8]}[/cyan]")
    console.print(f"  Type:        {extra.get('type', '')}")
    console.print(f"  Title:       {extra.get('title', '')}")
    console.print(f"  Impact:      {extra.get('impact', '')}")
    console.print(f"  Status:      {extra.get('status', '')}")
    console.print(f"  Description: {extra.get('description', '')}")

    history = extra.get("history", [])
    if history:
        console.print("\n[bold]History:[/bold]")
        for h in history:
            console.print(
                f"  [{h.get('at', '')[:10]}] {h.get('action', '')} by {h.get('by', '')} "
                + (f"— {h.get('note', '')}" if h.get("note") else "")
            )
    console.print()


@changes.command("approve")
@click.argument("change_id")
@click.option("--approver", required=True, help="Approver identity")
@click.option("--conditions", default=None, help="Optional approval conditions")
def changes_approve(change_id: str, approver: str, conditions: str | None) -> None:
    """Approve a change request."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        entry = _load_change(session, change_id)
        if not entry:
            _error(f"Change request not found: {change_id}")

        extra = dict(entry.extra or {})
        if extra.get("status") not in ("pending",):
            _error(f"Cannot approve a change in status '{extra.get('status')}'.")

        now = datetime.now(timezone.utc).isoformat()
        extra["status"] = "approved"
        extra["approved_by"] = approver
        extra["approved_at"] = now
        if conditions:
            extra["conditions"] = conditions
        history = list(extra.get("history", []))
        history.append(
            {
                "action": "approved",
                "by": approver,
                "at": now,
                "note": conditions or "",
            }
        )
        extra["history"] = history
        entry.extra = extra
        session.commit()

    console.print(f"[green]Change {change_id[:8]} approved by {approver}[/green]")
    if conditions:
        console.print(f"  Conditions: {conditions}")


@changes.command("reject")
@click.argument("change_id")
@click.option("--reason", required=True, help="Rejection reason")
def changes_reject(change_id: str, reason: str) -> None:
    """Reject a change request."""
    from warlock.db.engine import get_session, init_db

    init_db()
    actor = _get_actor()
    with get_session() as session:
        entry = _load_change(session, change_id)
        if not entry:
            _error(f"Change request not found: {change_id}")

        extra = dict(entry.extra or {})
        now = datetime.now(timezone.utc).isoformat()
        extra["status"] = "rejected"
        extra["rejected_by"] = actor
        extra["rejected_at"] = now
        extra["rejection_reason"] = reason
        history = list(extra.get("history", []))
        history.append({"action": "rejected", "by": actor, "at": now, "note": reason})
        extra["history"] = history
        entry.extra = extra
        session.commit()

    console.print(f"[red]Change {change_id[:8]} rejected.[/red]")
    console.print(f"  Reason: {reason}")


@changes.command("implement")
@click.argument("change_id")
@click.option("--notes", default=None, help="Implementation notes")
def changes_implement(change_id: str, notes: str | None) -> None:
    """Mark a change request as implemented."""
    from warlock.db.engine import get_session, init_db

    init_db()
    actor = _get_actor()
    with get_session() as session:
        entry = _load_change(session, change_id)
        if not entry:
            _error(f"Change request not found: {change_id}")

        extra = dict(entry.extra or {})
        if extra.get("status") not in ("approved", "emergency"):
            _error(
                f"Cannot implement a change in status '{extra.get('status')}'. "
                "Approve it first (or use 'emergency' for emergency changes)."
            )

        now = datetime.now(timezone.utc).isoformat()
        extra["status"] = "implemented"
        extra["implemented_by"] = actor
        extra["implemented_at"] = now
        if notes:
            extra["implementation_notes"] = notes
        history = list(extra.get("history", []))
        history.append({"action": "implemented", "by": actor, "at": now, "note": notes or ""})
        extra["history"] = history
        entry.extra = extra
        session.commit()

    console.print(f"[blue]Change {change_id[:8]} marked as implemented.[/blue]")


@changes.command("emergency")
@click.argument("change_id")
@click.option("--justification", required=True, help="Emergency justification")
def changes_emergency(change_id: str, justification: str) -> None:
    """Escalate a change request to emergency status (bypasses normal approval)."""
    from warlock.db.engine import get_session, init_db

    init_db()
    actor = _get_actor()
    with get_session() as session:
        entry = _load_change(session, change_id)
        if not entry:
            _error(f"Change request not found: {change_id}")

        extra = dict(entry.extra or {})
        now = datetime.now(timezone.utc).isoformat()
        extra["status"] = "emergency"
        extra["emergency_justified_by"] = actor
        extra["emergency_at"] = now
        extra["emergency_justification"] = justification
        history = list(extra.get("history", []))
        history.append(
            {
                "action": "emergency_escalation",
                "by": actor,
                "at": now,
                "note": justification,
            }
        )
        extra["history"] = history
        entry.extra = extra
        session.commit()

    console.print(f"[red bold]Change {change_id[:8]} escalated to EMERGENCY status.[/red bold]")
    console.print(f"  Justification: {justification}")
    console.print("[dim]Note: Emergency changes can be implemented without prior approval.[/dim]")


@changes.command("report")
@click.option("--since", default=None, help="Reporting period start (YYYY-MM-DD)")
@click.option(
    "--format",
    "fmt",
    default="md",
    type=click.Choice(["md", "json"]),
    help="Output format",
)
def changes_report(since: str | None, fmt: str) -> None:
    """Generate a change management summary report."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        q = session.query(AuditEntry).filter(
            AuditEntry.action == "change_request",
            AuditEntry.entity_type == "change_mgmt",
        )
        if since:
            try:
                since_dt = datetime.strptime(since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                q = q.filter(AuditEntry.created_at >= since_dt)
            except ValueError:
                _error(f"Invalid date '{since}'. Expected YYYY-MM-DD.")
        rows = q.order_by(AuditEntry.created_at.desc()).all()

    total = len(rows)
    by_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_impact: dict[str, int] = {}
    for r in rows:
        extra = r.extra or {}
        st = extra.get("status", "unknown")
        ct = extra.get("type", "unknown")
        imp = extra.get("impact", "unknown")
        by_status[st] = by_status.get(st, 0) + 1
        by_type[ct] = by_type.get(ct, 0) + 1
        by_impact[imp] = by_impact.get(imp, 0) + 1

    if fmt == "json":
        report = {
            "total": total,
            "since": since,
            "by_status": by_status,
            "by_type": by_type,
            "by_impact": by_impact,
        }
        console.print(json.dumps(report, indent=2))
        return

    period = f"since {since}" if since else "all time"
    console.print(f"# Change Management Report ({period})\n")
    console.print(f"**Total change requests:** {total}\n")
    console.print("## By Status")
    for st, count in sorted(by_status.items()):
        console.print(f"- {st}: {count}")
    console.print("\n## By Type")
    for ct, count in sorted(by_type.items()):
        console.print(f"- {ct}: {count}")
    console.print("\n## By Impact")
    for imp, count in sorted(by_impact.items()):
        console.print(f"- {imp}: {count}")
