"""Compliance calendar commands: list, add, overdue, next, export.

Calendar items are stored as AuditEntry records with action="calendar_item".
The `overdue` and `next` commands aggregate across POAM, EvidenceRequest,
Attestation, and PolicyOverride models to surface all upcoming deadlines
from every GRC domain.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

import click
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


CalendarItemType = Literal["audit", "renewal", "filing", "review", "deadline"]

_VALID_TYPES = ("audit", "renewal", "filing", "review", "deadline")
_VALID_RECURRENCES = ("annual", "quarterly", "monthly")


def _parse_date(value: str) -> datetime:
    """Parse a YYYY-MM-DD string into a timezone-aware datetime."""
    try:
        dt = datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        _error(f"Invalid date format '{value}'. Expected YYYY-MM-DD.")
    return dt.replace(tzinfo=timezone.utc)


def _make_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()


def _next_sequence(session) -> int:
    from sqlalchemy import func

    from warlock.db.models import AuditEntry

    return (session.query(func.max(AuditEntry.sequence)).scalar() or 0) + 1


# ---------------------------------------------------------------------------
# Cross-domain aggregation helpers
# ---------------------------------------------------------------------------


def _collect_poam_deadlines(session) -> list[dict]:
    """Return calendar items derived from POAM scheduled completions."""
    from warlock.db.models import POAM

    items = []
    rows = (
        session.query(POAM)
        .filter(
            POAM.scheduled_completion.isnot(None),
            POAM.status.notin_(["completed", "verified", "closed", "cancelled"]),
        )
        .all()
    )
    for p in rows:
        due = p.scheduled_completion
        if due and due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        items.append(
            {
                "source": "poam",
                "id": p.id[:8],
                "title": f"POA&M: {(p.weakness_description or '')[:60]}",
                "type": "deadline",
                "due_date": due,
                "detail": f"framework={p.framework} control={p.control_id} status={p.status}",
            }
        )
    return items


def _collect_evidence_request_deadlines(session) -> list[dict]:
    """Return calendar items from open EvidenceRequests (using updated_at as proxy due date)."""
    from warlock.db.models import EvidenceRequest

    items = []
    rows = (
        session.query(EvidenceRequest)
        .filter(EvidenceRequest.status.notin_(["fulfilled", "closed"]))
        .all()
    )
    for er in rows:
        # EvidenceRequest has no explicit due_date; use created_at + 14 days as a reasonable SLA
        base = er.created_at or datetime.now(timezone.utc)
        if base.tzinfo is None:
            base = base.replace(tzinfo=timezone.utc)
        due = base + timedelta(days=14)
        items.append(
            {
                "source": "evidence_request",
                "id": er.id[:8],
                "title": f"Evidence request: {(er.description or '')[:60]}",
                "type": "audit",
                "due_date": due,
                "detail": f"status={er.status} framework={er.framework or ''} control={er.control_id or ''}",
            }
        )
    return items


def _collect_attestation_deadlines(session) -> list[dict]:
    """Return calendar items from open Attestations."""
    from warlock.db.models import Attestation

    items = []
    rows = (
        session.query(Attestation).filter(Attestation.status.notin_(["approved", "rejected"])).all()
    )
    for att in rows:
        # Use updated_at + 7 days as a reasonable review SLA
        base = att.updated_at or att.created_at or datetime.now(timezone.utc)
        if base.tzinfo is None:
            base = base.replace(tzinfo=timezone.utc)
        due = base + timedelta(days=7)
        items.append(
            {
                "source": "attestation",
                "id": att.id[:8],
                "title": f"Attestation: {(att.statement or '')[:60]}",
                "type": "review",
                "due_date": due,
                "detail": f"status={att.status} framework={att.framework} control={att.control_id or ''}",
            }
        )
    return items


def _collect_exception_deadlines(session) -> list[dict]:
    """Return calendar items from expiring PolicyOverrides."""
    from warlock.db.models import AuditEntry, PolicyOverride

    items = []
    overrides = session.query(PolicyOverride).filter(PolicyOverride.is_active.is_(True)).all()
    meta_rows = (
        session.query(AuditEntry)
        .filter(
            AuditEntry.action == "policy_exception",
            AuditEntry.entity_type == "exception",
        )
        .order_by(AuditEntry.created_at.desc())
        .all()
    )
    meta_map: dict[str, dict] = {}
    for m in meta_rows:
        if m.entity_id not in meta_map:
            meta_map[m.entity_id] = m.extra or {}

    for ov in overrides:
        meta = meta_map.get(ov.id, {})
        expiry_str = meta.get("expiry")
        if not expiry_str:
            continue
        try:
            expiry = datetime.fromisoformat(expiry_str)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        items.append(
            {
                "source": "exception",
                "id": ov.id[:8],
                "title": f"Exception expiry: {(meta.get('policy') or ov.name or '')[:60]}",
                "type": "renewal",
                "due_date": expiry,
                "detail": f"approver={meta.get('approver', '')}",
            }
        )
    return items


def _collect_vendor_deadlines(session) -> list[dict]:
    """Return calendar items from vendor reassessment due dates and contract renewals."""
    from warlock.db.models import AuditEntry

    items = []
    # Vendor reassessment and contract dates stored as audit entries
    rows = (
        session.query(AuditEntry)
        .filter(
            AuditEntry.entity_type == "vendor",
            AuditEntry.action.in_(["vendor_created", "vendor_assessed", "vendor_contract_updated"]),
        )
        .order_by(AuditEntry.created_at.desc())
        .all()
    )
    seen: set[str] = set()
    for r in rows:
        if r.entity_id in seen:
            continue
        seen.add(r.entity_id)
        extra = r.extra or {}
        # Check for reassessment due date
        reassess = extra.get("next_reassessment") or extra.get("reassessment_due")
        if reassess:
            try:
                due = datetime.fromisoformat(reassess)
                if due.tzinfo is None:
                    due = due.replace(tzinfo=timezone.utc)
                items.append(
                    {
                        "source": "vendor",
                        "id": r.entity_id[:8],
                        "title": f"Vendor reassessment due: {extra.get('name', r.entity_id[:8])}",
                        "type": "review",
                        "due_date": due,
                        "detail": f"vendor={extra.get('name', '')}",
                    }
                )
            except ValueError:
                pass
        # Check for contract expiry
        contract_exp = extra.get("contract_expiry") or extra.get("contract_end")
        if contract_exp:
            try:
                due = datetime.fromisoformat(contract_exp)
                if due.tzinfo is None:
                    due = due.replace(tzinfo=timezone.utc)
                items.append(
                    {
                        "source": "vendor",
                        "id": r.entity_id[:8],
                        "title": f"Vendor contract expiry: {extra.get('name', r.entity_id[:8])}",
                        "type": "renewal",
                        "due_date": due,
                        "detail": f"vendor={extra.get('name', '')}",
                    }
                )
            except ValueError:
                pass
    return items


def _collect_training_deadlines(session) -> list[dict]:
    """Return calendar items from training due dates."""
    from warlock.db.models import Personnel

    items = []
    try:
        records = session.query(Personnel).all()
        for p in records:
            training = p.training_status or {}
            if isinstance(training, dict):
                for course, info in training.items():
                    if isinstance(info, dict):
                        due = info.get("due_date") or info.get("expiry")
                        if due:
                            try:
                                due_dt = (
                                    datetime.fromisoformat(due) if isinstance(due, str) else due
                                )
                                if due_dt.tzinfo is None:
                                    due_dt = due_dt.replace(tzinfo=timezone.utc)
                                items.append(
                                    {
                                        "source": "training",
                                        "id": p.id[:8],
                                        "title": f"Training due: {course} ({p.name or p.id[:8]})",
                                        "type": "deadline",
                                        "due_date": due_dt,
                                        "detail": f"employee={p.name or ''} course={course}",
                                    }
                                )
                            except (ValueError, TypeError):
                                pass
    except Exception:
        pass  # PersonnelRecord may not have training_status in all schemas
    return items


def _collect_calendar_items(session) -> list[dict]:
    """Return stored calendar items from AuditEntry."""
    from warlock.db.models import AuditEntry

    rows = (
        session.query(AuditEntry)
        .filter(
            AuditEntry.action == "calendar_item",
            AuditEntry.entity_type == "calendar",
        )
        .order_by(AuditEntry.created_at.desc())
        .all()
    )
    items = []
    for r in rows:
        extra = r.extra or {}
        due_str = extra.get("due_date")
        if not due_str:
            continue
        try:
            due = datetime.fromisoformat(due_str)
            if due.tzinfo is None:
                due = due.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        items.append(
            {
                "source": "calendar",
                "id": r.entity_id[:8],
                "title": extra.get("title", ""),
                "type": extra.get("type", "deadline"),
                "due_date": due,
                "detail": f"recurring={extra.get('recurring', 'none')}",
            }
        )
    return items


def _all_domain_items(session) -> list[dict]:
    """Aggregate calendar items from all GRC domains."""
    items: list[dict] = []
    items.extend(_collect_poam_deadlines(session))
    items.extend(_collect_evidence_request_deadlines(session))
    items.extend(_collect_attestation_deadlines(session))
    items.extend(_collect_exception_deadlines(session))
    items.extend(_collect_vendor_deadlines(session))
    items.extend(_collect_training_deadlines(session))
    items.extend(_collect_calendar_items(session))
    return items


def _format_due(due: datetime) -> str:
    return due.strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@cli.group("calendar", invoke_without_command=True)
@click.pass_context
def calendar(ctx: click.Context) -> None:
    """Compliance calendar — deadlines, audits, renewals, and reviews."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@calendar.command("list")
@click.option(
    "--type",
    "item_type",
    default=None,
    type=click.Choice(list(_VALID_TYPES)),
    help="Filter by item type",
)
@click.option("--since", default=None, help="Show items from this date (YYYY-MM-DD)")
@click.option("--until", default=None, help="Show items up to this date (YYYY-MM-DD)")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def calendar_list(item_type: str | None, since: str | None, until: str | None, fmt: str) -> None:
    """List compliance calendar items."""
    from warlock.db.engine import get_session, init_db

    init_db()

    since_dt: datetime | None = None
    until_dt: datetime | None = None
    if since:
        since_dt = _parse_date(since)
    if until:
        until_dt = _parse_date(until)

    with get_session() as session:
        items = _collect_calendar_items(session)

    if item_type:
        items = [i for i in items if i["type"] == item_type]
    if since_dt:
        items = [i for i in items if i["due_date"] >= since_dt]
    if until_dt:
        items = [i for i in items if i["due_date"] <= until_dt]

    items.sort(key=lambda x: x["due_date"])

    if not items:
        console.print("[dim]No calendar items found.[/dim]")
        return

    if fmt == "json":
        data = [
            {
                "id": i["id"],
                "title": i["title"],
                "type": i["type"],
                "due_date": _format_due(i["due_date"]),
                "detail": i.get("detail", ""),
            }
            for i in items
        ]
        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Compliance Calendar ({len(items)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Type", style="cyan")
    table.add_column("Title", max_width=50)
    table.add_column("Due Date")
    table.add_column("Detail", style="dim", max_width=30)

    now = datetime.now(timezone.utc)
    for i in items:
        due_color = "red" if i["due_date"] < now else ""
        table.add_row(
            i["id"],
            i["type"],
            i["title"][:50],
            f"[{due_color}]{_format_due(i['due_date'])}[/]"
            if due_color
            else _format_due(i["due_date"]),
            (i.get("detail") or "")[:30],
        )

    console.print(table)


@calendar.command("add")
@click.option("--title", required=True, help="Calendar item title")
@click.option(
    "--type",
    "item_type",
    required=True,
    type=click.Choice(list(_VALID_TYPES)),
    help="Item type",
)
@click.option("--due-date", "due_date", required=True, help="Due date (YYYY-MM-DD)")
@click.option(
    "--recurring",
    default=None,
    type=click.Choice(list(_VALID_RECURRENCES)),
    help="Recurrence pattern",
)
def calendar_add(title: str, item_type: str, due_date: str, recurring: str | None) -> None:
    """Add a compliance calendar item."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    due_dt = _parse_date(due_date)
    init_db()
    actor = _get_actor()
    item_id = uuid.uuid4().hex

    with get_session() as session:
        entry = AuditEntry(
            id=uuid.uuid4().hex,
            sequence=_next_sequence(session),
            previous_hash="genesis",
            entry_hash=_make_hash(f"{item_id}:{title}:{due_date}"),
            action="calendar_item",
            entity_type="calendar",
            entity_id=item_id,
            actor=actor,
            extra={
                "title": title,
                "type": item_type,
                "due_date": due_dt.isoformat(),
                "recurring": recurring,
                "created_by": actor,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        session.add(entry)
        session.commit()

    console.print(f"[green]Calendar item added:[/green] [cyan]{item_id[:8]}[/cyan]")
    console.print(f"  Title:     {title}")
    console.print(f"  Type:      {item_type}")
    console.print(f"  Due date:  {due_date}")
    if recurring:
        console.print(f"  Recurring: {recurring}")


@calendar.command("overdue")
def calendar_overdue() -> None:
    """Show all overdue items across every GRC domain."""
    from warlock.db.engine import get_session, init_db

    init_db()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        all_items = _all_domain_items(session)

    overdue = [i for i in all_items if i["due_date"] < now]
    overdue.sort(key=lambda x: x["due_date"])

    if not overdue:
        console.print("[green]No overdue items across any GRC domain.[/green]")
        return

    table = Table(title=f"Overdue Items — All Domains ({len(overdue)})")
    table.add_column("Source", style="cyan")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Type")
    table.add_column("Title", max_width=50)
    table.add_column("Was Due")
    table.add_column("Days Overdue", justify="right")

    for i in overdue:
        days_over = (now - i["due_date"]).days
        color = "red bold" if days_over > 30 else "red"
        table.add_row(
            i["source"],
            i["id"],
            i["type"],
            i["title"][:50],
            _format_due(i["due_date"]),
            f"[{color}]{days_over}[/]",
        )

    console.print(table)


@calendar.command("next")
@click.option("--days", default=30, help="Look-ahead window in days (default: 30)")
def calendar_next(days: int) -> None:
    """Show everything due within the next N days across all GRC domains."""
    from warlock.db.engine import get_session, init_db

    init_db()
    now = datetime.now(timezone.utc)
    cutoff = now + timedelta(days=days)

    with get_session() as session:
        all_items = _all_domain_items(session)

    upcoming = [i for i in all_items if now <= i["due_date"] <= cutoff]
    upcoming.sort(key=lambda x: x["due_date"])

    if not upcoming:
        console.print(f"[green]Nothing due in the next {days} days.[/green]")
        return

    table = Table(title=f"Upcoming in Next {days} Days ({len(upcoming)})")
    table.add_column("Source", style="cyan")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Type")
    table.add_column("Title", max_width=50)
    table.add_column("Due Date")
    table.add_column("Days Left", justify="right")

    for i in upcoming:
        days_left = (i["due_date"] - now).days
        color = "red" if days_left <= 7 else ("yellow" if days_left <= 14 else "green")
        table.add_row(
            i["source"],
            i["id"],
            i["type"],
            i["title"][:50],
            _format_due(i["due_date"]),
            f"[{color}]{days_left}[/]",
        )

    console.print(table)


@calendar.command("export")
@click.option(
    "--format",
    "fmt",
    default="csv",
    type=click.Choice(["ics", "csv"]),
    help="Export format (ics or csv)",
)
@click.option("--output", "-o", default=None, help="Write output to file instead of terminal")
def calendar_export(fmt: str, output: str | None) -> None:
    """Export the compliance calendar in ICS or CSV format."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        all_items = _all_domain_items(session)

    all_items.sort(key=lambda x: x["due_date"])

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=["id", "source", "type", "title", "due_date", "detail"]
        )
        writer.writeheader()
        for i in all_items:
            writer.writerow(
                {
                    "id": i["id"],
                    "source": i["source"],
                    "type": i["type"],
                    "title": i["title"],
                    "due_date": _format_due(i["due_date"]),
                    "detail": i.get("detail", ""),
                }
            )
        content = buf.getvalue()
        if output:
            with open(output, "w") as f:
                f.write(content)
            console.print(f"[green]Calendar exported to {output}[/green]")
        else:
            console.print(content)
        return

    # ICS format
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Warlock GRC//Compliance Calendar//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    now_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for i in all_items:
        due_str = i["due_date"].strftime("%Y%m%d")
        uid = f"{i['id']}@warlock.grc"
        lines += [
            "BEGIN:VEVENT",
            f"UID:{uid}",
            f"DTSTAMP:{now_stamp}",
            f"DTSTART;VALUE=DATE:{due_str}",
            f"DTEND;VALUE=DATE:{due_str}",
            f"SUMMARY:{i['title']}",
            f"DESCRIPTION:{i.get('detail', '')} [source={i['source']} type={i['type']}]",
            "STATUS:CONFIRMED",
            "END:VEVENT",
        ]
    lines.append("END:VCALENDAR")
    content = "\n".join(lines)
    if output:
        with open(output, "w") as f:
            f.write(content)
        console.print(f"[green]Calendar exported to {output}[/green]")
    else:
        console.print(content)
