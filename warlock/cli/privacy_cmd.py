"""CLI commands for privacy and GDPR compliance.

Sub-commands are organised into three nested groups:

    warlock privacy dsar     -- Data Subject Access Requests
    warlock privacy breach   -- Personal data breach management
    warlock privacy transfers -- Cross-border data transfer records

Top-level commands:

    warlock privacy data-map       -- Inventory of all data silos
    warlock privacy impact-assess  -- DPIA helper for a named system
    warlock privacy ropa           -- Record of Processing Activities

DSAR and breach records are stored as AuditEntry rows with structured data
in the ``extra`` JSON field (entity_type = "dsar" / "privacy_breach" /
"data_transfer").  This avoids schema migrations while giving a full audit
trail for every action.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from uuid import uuid4

import click
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@cli.group("privacy")
def privacy() -> None:
    """GDPR and privacy compliance commands."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_DSAR_STATUSES = ("open", "processing", "fulfilled", "overdue")
_DSAR_TYPES = ("access", "deletion", "portability", "rectification")
_BREACH_SEVERITIES = ("critical", "high", "medium", "low")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _fmt_date(dt: datetime | None) -> str:
    if dt is None:
        return "\u2014"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return dt
    return dt.strftime("%Y-%m-%d")


def _write_audit_entry(
    session,
    entity_type: str,
    entity_id: str,
    action: str,
    actor: str,
    extra: dict,
) -> None:
    """Append an AuditEntry row (does not commit -- caller must commit)."""
    from warlock.db.models import AuditEntry

    # Derive sequence and previous_hash from the last entry
    last = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
    sequence = (last.sequence + 1) if last else 1
    prev_hash = last.entry_hash if last else "genesis"

    import hashlib

    payload = f"{sequence}:{entity_type}:{entity_id}:{action}:{actor}"
    entry_hash = hashlib.sha256(payload.encode()).hexdigest()

    entry = AuditEntry(
        id=str(uuid4()),
        sequence=sequence,
        previous_hash=prev_hash,
        entry_hash=entry_hash,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        actor=actor,
        extra=extra,
    )
    session.add(entry)


def _load_dsar_records(session, status_filter: str | None = None) -> list[dict]:
    """Load DSAR records from AuditEntry (entity_type='dsar', action='dsar_created')."""
    from warlock.db.models import AuditEntry

    rows = (
        session.query(AuditEntry)
        .filter(AuditEntry.entity_type == "dsar", AuditEntry.action == "dsar_created")
        .order_by(AuditEntry.created_at.desc())
        .all()
    )

    # For each DSAR, get the latest status update
    status_updates: dict[str, str] = {}
    updates = (
        session.query(AuditEntry)
        .filter(AuditEntry.entity_type == "dsar", AuditEntry.action == "dsar_status_changed")
        .all()
    )
    for u in updates:
        eid = u.entity_id
        extra = u.extra or {}
        if eid not in status_updates:
            status_updates[eid] = extra.get("to_status", "open")

    records = []
    for r in rows:
        extra = r.extra or {}
        current_status = status_updates.get(r.entity_id, extra.get("status", "open"))
        # Check overdue
        deadline_str = extra.get("deadline")
        if deadline_str and current_status not in ("fulfilled",):
            try:
                deadline = datetime.fromisoformat(deadline_str)
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)
                if deadline < _utcnow():
                    current_status = "overdue"
            except ValueError:
                pass

        if status_filter and current_status != status_filter:
            continue

        records.append(
            {
                "id": r.entity_id,
                "subject": extra.get("subject", "\u2014"),
                "type": extra.get("type", "\u2014"),
                "status": current_status,
                "deadline": deadline_str,
                "actor": r.actor,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
        )
    return records


def _load_breach_records(session) -> list[dict]:
    """Load breach records from AuditEntry (entity_type='privacy_breach')."""
    from warlock.db.models import AuditEntry

    rows = (
        session.query(AuditEntry)
        .filter(
            AuditEntry.entity_type == "privacy_breach",
            AuditEntry.action == "breach_created",
        )
        .order_by(AuditEntry.created_at.desc())
        .all()
    )

    records = []
    for r in rows:
        extra = r.extra or {}
        records.append(
            {
                "id": r.entity_id,
                "title": extra.get("title", "\u2014"),
                "severity": extra.get("severity", "\u2014"),
                "discovery_date": extra.get("discovery_date"),
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "actor": r.actor,
            }
        )
    return records


# ---------------------------------------------------------------------------
# DSAR sub-group
# ---------------------------------------------------------------------------


@privacy.group("dsar")
def dsar() -> None:
    """Data Subject Access Request (DSAR) management."""


@dsar.command("create")
@click.option("--subject", required=True, help="Data subject identifier (email or pseudonym)")
@click.option(
    "--type",
    "request_type",
    required=True,
    type=click.Choice(list(_DSAR_TYPES)),
    help="DSAR type",
)
@click.option(
    "--deadline",
    required=True,
    help="Response deadline in YYYY-MM-DD format",
)
def dsar_create(subject: str, request_type: str, deadline: str) -> None:
    """Create a new DSAR record."""
    from warlock.db.engine import get_session, init_db

    init_db()

    try:
        dl = datetime.strptime(deadline, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        _error(f"Invalid date format '{deadline}'. Use YYYY-MM-DD.")

    actor = _get_actor()
    entity_id = str(uuid4())

    with get_session() as session:
        _write_audit_entry(
            session,
            entity_type="dsar",
            entity_id=entity_id,
            action="dsar_created",
            actor=actor,
            extra={
                "subject": subject,
                "type": request_type,
                "status": "open",
                "deadline": dl.isoformat(),
            },
        )
        session.commit()

    console.print(
        f"[green]DSAR created:[/green] [cyan]{entity_id[:8]}[/cyan] "
        f"({request_type} for {subject!r}, deadline {dl.date()})"
    )


@dsar.command("list")
@click.option(
    "--status",
    "-s",
    type=click.Choice(list(_DSAR_STATUSES)),
    default=None,
    help="Filter by status",
)
def dsar_list(status: str | None) -> None:
    """List DSAR records."""
    from warlock.db.engine import get_session, init_db

    init_db()

    with get_session() as session:
        records = _load_dsar_records(session, status_filter=status)

    if not records:
        console.print("[dim]No DSARs found.[/dim]")
        return

    table = Table(title=f"DSARs ({len(records)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Subject", max_width=35)
    table.add_column("Type", style="cyan")
    table.add_column("Status")
    table.add_column("Deadline")
    table.add_column("Created By", style="dim")

    _status_styles = {
        "open": "yellow",
        "processing": "cyan",
        "fulfilled": "green",
        "overdue": "red bold",
    }

    for r in records:
        st = r["status"]
        sty = _status_styles.get(st, "")
        table.add_row(
            r["id"][:8],
            r["subject"],
            r["type"],
            f"[{sty}]{st}[/{sty}]" if sty else st,
            _fmt_date(r["deadline"]),
            r["actor"],
        )

    console.print(table)


@dsar.command("show")
@click.argument("dsar_id")
def dsar_show(dsar_id: str) -> None:
    """Show full details of a DSAR."""
    from rich.panel import Panel

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()

    with get_session() as session:
        row = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == "dsar",
                AuditEntry.action == "dsar_created",
                AuditEntry.entity_id.startswith(dsar_id),
            )
            .first()
        )
        if not row:
            _error(f"DSAR not found: {dsar_id}")

        history = (
            session.query(AuditEntry)
            .filter(AuditEntry.entity_type == "dsar", AuditEntry.entity_id == row.entity_id)
            .order_by(AuditEntry.sequence.asc())
            .all()
        )

    extra = row.extra or {}
    console.print(
        Panel(
            f"ID: {row.entity_id}\n"
            f"Subject: {extra.get('subject', '\u2014')}\n"
            f"Type: {extra.get('type', '\u2014')}\n"
            f"Status: {extra.get('status', 'open')}\n"
            f"Deadline: {_fmt_date(extra.get('deadline'))}\n"
            f"Created by: {row.actor}  at {_fmt_date(row.created_at)}",
            title="[bold]DSAR[/bold]",
            border_style="cyan",
        )
    )

    if len(history) > 1:
        console.print("\n[bold]Activity log:[/bold]")
        for entry in history:
            e = entry.extra or {}
            note = e.get("notes") or e.get("reason") or ""
            console.print(
                f"  [{entry.created_at.strftime('%Y-%m-%d %H:%M')}] "
                f"[cyan]{entry.action}[/cyan]  by {entry.actor}" + (f"  -- {note}" if note else "")
            )


@dsar.command("fulfill")
@click.argument("dsar_id")
@click.option("--evidence-file", "evidence_file", default=None, help="Path to evidence file")
@click.option("--notes", default="", help="Fulfillment notes")
def dsar_fulfill(dsar_id: str, evidence_file: str | None, notes: str) -> None:
    """Mark a DSAR as fulfilled."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    actor = _get_actor()

    with get_session() as session:
        row = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == "dsar",
                AuditEntry.action == "dsar_created",
                AuditEntry.entity_id.startswith(dsar_id),
            )
            .first()
        )
        if not row:
            _error(f"DSAR not found: {dsar_id}")

        _write_audit_entry(
            session,
            entity_type="dsar",
            entity_id=row.entity_id,
            action="dsar_status_changed",
            actor=actor,
            extra={
                "from_status": "open",
                "to_status": "fulfilled",
                "evidence_file": evidence_file,
                "notes": notes,
                "fulfilled_at": _utcnow().isoformat(),
            },
        )
        session.commit()

    console.print(f"[green]DSAR {row.entity_id[:8]} marked as fulfilled.[/green]")


@dsar.command("escalate")
@click.argument("dsar_id")
@click.option("--reason", required=True, help="Escalation reason")
def dsar_escalate(dsar_id: str, reason: str) -> None:
    """Escalate a DSAR for manual review."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    actor = _get_actor()

    with get_session() as session:
        row = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == "dsar",
                AuditEntry.action == "dsar_created",
                AuditEntry.entity_id.startswith(dsar_id),
            )
            .first()
        )
        if not row:
            _error(f"DSAR not found: {dsar_id}")

        _write_audit_entry(
            session,
            entity_type="dsar",
            entity_id=row.entity_id,
            action="dsar_escalated",
            actor=actor,
            extra={"reason": reason, "escalated_at": _utcnow().isoformat()},
        )
        session.commit()

    console.print(f"[yellow]DSAR {row.entity_id[:8]} escalated by {actor}:[/yellow] {reason}")


@dsar.command("overdue")
def dsar_overdue() -> None:
    """List DSARs past their deadline with SLA countdown."""
    from warlock.db.engine import get_session, init_db

    init_db()
    now = _utcnow()

    with get_session() as session:
        records = _load_dsar_records(session, status_filter=None)

    overdue = []
    for r in records:
        if r["status"] == "fulfilled":
            continue
        deadline_str = r.get("deadline")
        if not deadline_str:
            continue
        try:
            dl = datetime.fromisoformat(deadline_str)
            if dl.tzinfo is None:
                dl = dl.replace(tzinfo=timezone.utc)
            if dl < now:
                days_over = (now - dl).days
                overdue.append((r, dl, days_over))
        except ValueError:
            pass

    if not overdue:
        console.print("[green]No overdue DSARs.[/green]")
        return

    table = Table(title=f"Overdue DSARs ({len(overdue)})", style="red")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Subject", max_width=35)
    table.add_column("Type", style="cyan")
    table.add_column("Deadline")
    table.add_column("Days Overdue", justify="right")
    table.add_column("SLA Breach")

    for r, dl, days_over in overdue:
        table.add_row(
            r["id"][:8],
            r["subject"],
            r["type"],
            dl.strftime("%Y-%m-%d"),
            f"[red]{days_over}[/red]",
            "[red bold]BREACHED[/red bold]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Breach sub-group
# ---------------------------------------------------------------------------


@privacy.group("breach")
def breach() -> None:
    """Personal data breach management."""


@breach.command("list")
@click.option("--severity", "-s", type=click.Choice(list(_BREACH_SEVERITIES)), default=None, help="Filter by severity")
@click.option("--limit", "-n", default=50, help="Max results")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]), help="Output format")
def breach_list(severity: str | None, limit: int, fmt: str) -> None:
    """List all recorded personal data breaches."""
    from warlock.db.engine import get_session, init_db

    init_db()

    with get_session() as session:
        records = _load_breach_records(session)

    if severity:
        records = [r for r in records if r.get("severity") == severity]
    records = records[:limit]

    if not records:
        console.print("[dim]No breach records found.[/dim]")
        return

    if fmt == "json":
        console.print_json(data=records)
        return

    _sev_styles = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}

    table = Table(title=f"Personal Data Breaches ({len(records)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Title", max_width=40)
    table.add_column("Severity")
    table.add_column("Discovered")
    table.add_column("Created By", style="dim")

    for r in records:
        sty = _sev_styles.get(r.get("severity", ""), "")
        table.add_row(
            r["id"][:8],
            r.get("title", "\u2014"),
            f"[{sty}]{r.get('severity', '\u2014')}[/{sty}]",
            _fmt_date(r.get("discovery_date")),
            r.get("actor", "\u2014"),
        )

    console.print(table)


@breach.command("create")
@click.option("--title", required=True, help="Brief title describing the breach")
@click.option(
    "--severity",
    required=True,
    type=click.Choice(list(_BREACH_SEVERITIES)),
    help="Breach severity",
)
@click.option(
    "--discovery-date", "discovery_date", required=True, help="Date discovered YYYY-MM-DD"
)
def breach_create(title: str, severity: str, discovery_date: str) -> None:
    """Record a new personal data breach."""
    from warlock.db.engine import get_session, init_db

    init_db()

    try:
        dd = datetime.strptime(discovery_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        _error(f"Invalid date format '{discovery_date}'. Use YYYY-MM-DD.")

    actor = _get_actor()
    entity_id = str(uuid4())

    with get_session() as session:
        _write_audit_entry(
            session,
            entity_type="privacy_breach",
            entity_id=entity_id,
            action="breach_created",
            actor=actor,
            extra={
                "title": title,
                "severity": severity,
                "discovery_date": dd.isoformat(),
                "notification_status": "pending",
            },
        )
        session.commit()

    _sev_styles = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
    sty = _sev_styles.get(severity, "")
    console.print(
        f"[green]Breach recorded:[/green] [cyan]{entity_id[:8]}[/cyan] "
        f"[{sty}]{severity}[/{sty}] -- {title!r} (discovered {dd.date()})"
    )
    # 72-hour deadline reminder
    notify_by = dd + timedelta(hours=72)
    if _utcnow() < notify_by:
        remaining = notify_by - _utcnow()
        hours_left = int(remaining.total_seconds() // 3600)
        console.print(
            f"[yellow]Regulatory notification due within 72 hours of discovery. "
            f"{hours_left}h remaining. Run: warlock privacy breach notify {entity_id[:8]}[/yellow]"
        )
    else:
        console.print("[red bold]WARNING: 72-hour notification window may have passed.[/red bold]")


@breach.command("show")
@click.argument("breach_id")
def breach_show(breach_id: str) -> None:
    """Show details of a recorded breach."""
    from rich.panel import Panel

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()

    with get_session() as session:
        row = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == "privacy_breach",
                AuditEntry.action == "breach_created",
                AuditEntry.entity_id.startswith(breach_id),
            )
            .first()
        )
        if not row:
            _error(f"Breach record not found: {breach_id}")

        history = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == "privacy_breach",
                AuditEntry.entity_id == row.entity_id,
            )
            .order_by(AuditEntry.sequence.asc())
            .all()
        )

    extra = row.extra or {}
    discovery = extra.get("discovery_date", "\u2014")
    notify_status = extra.get("notification_status", "pending")

    # Check for notification entry
    notifications = [h for h in history if h.action == "breach_notification_sent"]
    if notifications:
        notify_status = "notified"

    console.print(
        Panel(
            f"ID: {row.entity_id}\n"
            f"Title: {extra.get('title', '\u2014')}\n"
            f"Severity: {extra.get('severity', '\u2014')}\n"
            f"Discovery date: {_fmt_date(discovery)}\n"
            f"Notification status: {notify_status}\n"
            f"Recorded by: {row.actor}  at {_fmt_date(row.created_at)}",
            title="[bold red]Data Breach[/bold red]",
            border_style="red",
        )
    )

    if len(history) > 1:
        console.print("\n[bold]Activity log:[/bold]")
        for entry in history:
            e = entry.extra or {}
            note = e.get("authority") or e.get("notes") or ""
            console.print(
                f"  [{entry.created_at.strftime('%Y-%m-%d %H:%M')}] "
                f"[cyan]{entry.action}[/cyan]  by {entry.actor}" + (f"  -- {note}" if note else "")
            )


@breach.command("notify")
@click.argument("breach_id")
@click.option("--authority", required=True, help="Regulatory authority name (e.g. ICO, CNIL, DPA)")
def breach_notify(breach_id: str, authority: str) -> None:
    """Record that the regulatory authority has been notified."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    actor = _get_actor()

    with get_session() as session:
        row = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == "privacy_breach",
                AuditEntry.action == "breach_created",
                AuditEntry.entity_id.startswith(breach_id),
            )
            .first()
        )
        if not row:
            _error(f"Breach record not found: {breach_id}")

        extra_orig = row.extra or {}
        discovery_str = extra_orig.get("discovery_date")
        notified_at = _utcnow()
        hours_elapsed = None
        if discovery_str:
            try:
                dd = datetime.fromisoformat(discovery_str)
                if dd.tzinfo is None:
                    dd = dd.replace(tzinfo=timezone.utc)
                hours_elapsed = (notified_at - dd).total_seconds() / 3600
            except ValueError:
                pass

        _write_audit_entry(
            session,
            entity_type="privacy_breach",
            entity_id=row.entity_id,
            action="breach_notification_sent",
            actor=actor,
            extra={
                "authority": authority,
                "notified_at": notified_at.isoformat(),
                "hours_since_discovery": round(hours_elapsed, 1) if hours_elapsed else None,
            },
        )
        session.commit()

    colour = "green" if (hours_elapsed is None or hours_elapsed <= 72) else "red"
    elapsed_str = f" ({hours_elapsed:.1f}h since discovery)" if hours_elapsed else ""
    console.print(
        f"[{colour}]Notification to {authority!r} recorded for breach {row.entity_id[:8]}"
        f"{elapsed_str}.[/{colour}]"
    )


@breach.command("status")
@click.argument("breach_id")
def breach_status(breach_id: str) -> None:
    """Show notification status for a breach."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()

    with get_session() as session:
        row = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == "privacy_breach",
                AuditEntry.action == "breach_created",
                AuditEntry.entity_id.startswith(breach_id),
            )
            .first()
        )
        if not row:
            _error(f"Breach record not found: {breach_id}")

        notifications = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == "privacy_breach",
                AuditEntry.entity_id == row.entity_id,
                AuditEntry.action == "breach_notification_sent",
            )
            .order_by(AuditEntry.sequence.asc())
            .all()
        )

    extra = row.extra or {}
    console.print(f"\n[bold]Breach {row.entity_id[:8]}[/bold] -- {extra.get('title', '\u2014')}")
    console.print(f"Severity: {extra.get('severity', '\u2014')}")
    console.print(f"Discovery: {_fmt_date(extra.get('discovery_date'))}")

    if not notifications:
        console.print("[yellow]Notification status: PENDING -- no authority notified yet.[/yellow]")
        return

    table = Table(title="Notifications Sent")
    table.add_column("Authority", style="cyan")
    table.add_column("Notified At")
    table.add_column("Hours Since Discovery", justify="right")
    table.add_column("Within 72h?")
    table.add_column("Recorded By", style="dim")

    for n in notifications:
        ne = n.extra or {}
        hrs = ne.get("hours_since_discovery")
        within = "[green]Yes[/green]" if hrs is not None and hrs <= 72 else "[red]No[/red]"
        table.add_row(
            ne.get("authority", "\u2014"),
            _fmt_date(ne.get("notified_at")),
            f"{hrs:.1f}" if hrs is not None else "\u2014",
            within,
            n.actor,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Transfers sub-group
# ---------------------------------------------------------------------------


@privacy.group("transfers")
def transfers() -> None:
    """Cross-border data transfer records."""


@transfers.command("list")
@click.option("--mechanism", default=None, help="Filter by transfer mechanism (e.g. SCCs, BCRs)")
def transfers_list(mechanism: str | None) -> None:
    """List recorded data transfers."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()

    with get_session() as session:
        q = session.query(AuditEntry).filter(
            AuditEntry.entity_type == "data_transfer",
            AuditEntry.action == "transfer_recorded",
        )
        rows = q.order_by(AuditEntry.created_at.desc()).all()

    if mechanism:
        rows = [
            r for r in rows if (r.extra or {}).get("mechanism", "").lower() == mechanism.lower()
        ]

    if not rows:
        console.print("[dim]No data transfer records found.[/dim]")
        return

    table = Table(title=f"Data Transfers ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Destination", style="cyan")
    table.add_column("Mechanism")
    table.add_column("Data Categories")
    table.add_column("Recorded")
    table.add_column("By", style="dim")

    for r in rows:
        e = r.extra or {}
        cats = ", ".join(e.get("data_categories", [])) or "\u2014"
        table.add_row(
            r.entity_id[:8],
            e.get("destination", "\u2014"),
            e.get("mechanism", "\u2014"),
            cats[:50],
            _fmt_date(r.created_at),
            r.actor,
        )

    console.print(table)


@transfers.command("validate")
def transfers_validate() -> None:
    """Validate that all recorded transfers have an accepted mechanism."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()

    # Accepted mechanisms per GDPR Chapter V
    _VALID_MECHANISMS = {
        "adequacy_decision",
        "sccs",
        "bcrs",
        "derogation",
        "international_agreement",
        "approved_code",
    }

    with get_session() as session:
        rows = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == "data_transfer",
                AuditEntry.action == "transfer_recorded",
            )
            .all()
        )

    if not rows:
        console.print("[dim]No transfer records to validate.[/dim]")
        return

    valid = []
    invalid = []
    for r in rows:
        e = r.extra or {}
        mech = (e.get("mechanism") or "").lower().replace(" ", "_").replace("-", "_")
        if mech in _VALID_MECHANISMS:
            valid.append((r, mech))
        else:
            invalid.append((r, mech or "(none)"))

    console.print(f"\nTotal transfers: {len(rows)}")
    console.print(f"[green]Valid:   {len(valid)}[/green]")
    if invalid:
        console.print(f"[red]Invalid: {len(invalid)}[/red]")
        for r, mech in invalid:
            e = r.extra or {}
            console.print(
                f"  [red]{r.entity_id[:8]}[/red]  dest={e.get('destination', '?')}  "
                f"mechanism={mech!r}"
            )
    else:
        console.print("[green]All transfer mechanisms are valid.[/green]")


# ---------------------------------------------------------------------------
# Top-level privacy commands
# ---------------------------------------------------------------------------


@privacy.command("data-map")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def data_map(output_format: str) -> None:
    """Show inventory of all data silos (data map)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DataSilo

    init_db()

    with get_session() as session:
        rows = (
            session.query(DataSilo)
            .filter(DataSilo.is_active.is_(True))
            .order_by(DataSilo.data_classification, DataSilo.name)
            .all()
        )

    if not rows:
        console.print("[dim]No data silos found. Run the pipeline to discover data stores.[/dim]")
        return

    if output_format == "json":
        data = [
            {
                "id": s.id,
                "name": s.name,
                "type": s.silo_type,
                "provider": s.provider,
                "classification": s.data_classification,
                "contains_pii": s.contains_pii,
                "contains_phi": s.contains_phi,
                "contains_pci": s.contains_pci,
                "owner": s.owner,
                "team": s.team,
                "frameworks": s.applicable_frameworks,
            }
            for s in rows
        ]
        console.print(json.dumps(data, indent=2))
        return

    _cls_styles = {
        "restricted": "red bold",
        "confidential": "red",
        "internal": "yellow",
        "public": "green",
        "unknown": "dim",
    }

    table = Table(title=f"Data Map -- {len(rows)} Silo(s)")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", max_width=35)
    table.add_column("Type", style="cyan")
    table.add_column("Provider")
    table.add_column("Classification")
    table.add_column("PII")
    table.add_column("PHI")
    table.add_column("Owner", style="dim", max_width=25)
    table.add_column("Scan Status")

    for s in rows:
        cls = s.data_classification or "unknown"
        sty = _cls_styles.get(cls, "")
        table.add_row(
            s.id[:8],
            s.name[:35],
            s.silo_type,
            s.provider or "\u2014",
            f"[{sty}]{cls}[/{sty}]" if sty else cls,
            "[red]Yes[/red]" if s.contains_pii else "No",
            "[red]Yes[/red]" if s.contains_phi else "No",
            (s.owner or "\u2014")[:25],
            s.scan_status or "\u2014",
        )

    console.print(table)


@privacy.command("impact-assess")
@click.option("--system", required=True, help="System or silo name to assess")
def impact_assess(system: str) -> None:
    """Run a basic DPIA (Data Protection Impact Assessment) for a system.

    Queries the data silo inventory for the named system and surfaces
    privacy risk indicators that should be reviewed by a DPO.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DataSilo

    init_db()

    with get_session() as session:
        rows = (
            session.query(DataSilo)
            .filter(DataSilo.name.ilike(f"%{system}%"), DataSilo.is_active.is_(True))
            .all()
        )

    if not rows:
        console.print(f"[dim]No active data silos matching '{system}' found.[/dim]")
        return

    console.print(f"\n[bold]DPIA Summary for '{system}'[/bold]")
    console.print(f"Matching silos: {len(rows)}\n")

    risk_flags: list[str] = []

    for s in rows:
        console.print(f"[cyan]{s.name}[/cyan] ({s.silo_type} / {s.provider or 'unknown provider'})")
        console.print(f"  Classification: {s.data_classification}")

        flags = []
        if s.contains_pii:
            flags.append("contains PII")
        if s.contains_phi:
            flags.append("contains PHI (health data)")
        if s.contains_pci:
            flags.append("contains PCI data")
        if s.contains_credentials:
            flags.append("contains credentials")
        if s.encrypted_at_rest is False:
            flags.append("[red]NOT encrypted at rest[/red]")
        if s.encrypted_in_transit is False:
            flags.append("[red]NOT encrypted in transit[/red]")
        if s.access_logging_enabled is False:
            flags.append("[yellow]access logging disabled[/yellow]")
        if not s.retention_days:
            flags.append("[yellow]no retention policy set[/yellow]")

        if flags:
            for f in flags:
                console.print(f"  [yellow]![/yellow] {f}")
            risk_flags.extend(flags)
        else:
            console.print("  [green]No obvious risk flags[/green]")
        console.print()

    if risk_flags:
        console.print(
            f"[yellow]DPIA recommendation: {len(risk_flags)} risk indicator(s) found. "
            f"Review with DPO before processing.[/yellow]"
        )
    else:
        console.print("[green]No risk indicators found. Standard DPO sign-off may suffice.[/green]")


@privacy.command("ropa")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["md", "json"]),
    default="md",
    help="Output format",
)
def ropa(output_format: str) -> None:
    """Generate a Record of Processing Activities (ROPA) from the data map.

    The ROPA is derived from the DataSilo inventory and lists each active
    processing activity, its legal basis (inferred from applicable frameworks),
    and key risk attributes, as required by GDPR Article 30.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DataSilo

    init_db()

    with get_session() as session:
        rows = (
            session.query(DataSilo)
            .filter(DataSilo.is_active.is_(True))
            .order_by(DataSilo.name)
            .all()
        )

    if not rows:
        console.print("[dim]No active data silos found. The ROPA would be empty.[/dim]")
        return

    now = datetime.now(timezone.utc)

    if output_format == "json":
        ropa_data = {
            "generated_at": now.isoformat(),
            "article": "GDPR Article 30",
            "activities": [
                {
                    "name": s.name,
                    "type": s.silo_type,
                    "provider": s.provider,
                    "data_classification": s.data_classification,
                    "contains_pii": s.contains_pii,
                    "contains_phi": s.contains_phi,
                    "contains_pci": s.contains_pci,
                    "applicable_frameworks": s.applicable_frameworks or [],
                    "retention_days": s.retention_days,
                    "owner": s.owner,
                    "team": s.team,
                    "encrypted_at_rest": s.encrypted_at_rest,
                    "encrypted_in_transit": s.encrypted_in_transit,
                }
                for s in rows
            ],
        }
        console.print(json.dumps(ropa_data, indent=2))
        return

    # Markdown output
    lines = [
        "# Record of Processing Activities (ROPA)",
        "",
        f"> Generated: {now.date()}  |  GDPR Article 30",
        "",
        f"Total processing activities: **{len(rows)}**",
        "",
    ]

    for i, s in enumerate(rows, 1):
        lines.append(f"## {i}. {s.name}")
        lines.append(f"- **Type:** {s.silo_type}")
        lines.append(f"- **Provider:** {s.provider or 'N/A'}")
        lines.append(f"- **Data classification:** {s.data_classification}")
        lines.append(f"- **Contains PII:** {'Yes' if s.contains_pii else 'No'}")
        lines.append(f"- **Contains PHI:** {'Yes' if s.contains_phi else 'No'}")
        lines.append(
            f"- **Retention:** {str(s.retention_days) + ' days' if s.retention_days else 'Not defined'}"
        )
        lines.append(f"- **Owner:** {s.owner or 'N/A'}  |  **Team:** {s.team or 'N/A'}")
        lines.append(f"- **Encrypted at rest:** {s.encrypted_at_rest}")
        lines.append(f"- **Encrypted in transit:** {s.encrypted_in_transit}")
        frameworks = ", ".join(s.applicable_frameworks or []) or "None"
        lines.append(f"- **Applicable frameworks:** {frameworks}")
        lines.append("")

    console.print("\n".join(lines))
