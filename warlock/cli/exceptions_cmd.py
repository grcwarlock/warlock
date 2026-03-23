"""Exceptions commands: list, create, show, renew, expiring, report.

Policy exceptions are stored as PolicyOverride records supplemented with
lifecycle metadata (status, expiry, approver, justification) held in an
AuditEntry extra blob keyed by the PolicyOverride ID.  This avoids schema
changes while reusing the existing models.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import click
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


def _parse_date(value: str) -> datetime:
    """Parse YYYY-MM-DD string into a timezone-aware datetime."""
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


def _load_exception_meta(session, exception_id: str) -> dict:
    """Return the AuditEntry extra blob for a given PolicyOverride ID prefix."""
    from warlock.db.models import AuditEntry

    entry = (
        session.query(AuditEntry)
        .filter(
            AuditEntry.action == "policy_exception",
            AuditEntry.entity_type == "exception",
            AuditEntry.entity_id.startswith(exception_id),
        )
        .order_by(AuditEntry.created_at.desc())
        .first()
    )
    if entry is None:
        return {}
    return entry.extra or {}


def _derive_status(meta: dict) -> str:
    """Compute effective status from metadata."""
    stored = meta.get("status", "active")
    if stored in ("expired", "pending-renewal", "revoked"):
        return stored
    expiry_str = meta.get("expiry")
    if expiry_str:
        try:
            expiry = datetime.fromisoformat(expiry_str)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry < datetime.now(timezone.utc):
                return "expired"
        except ValueError:
            pass
    return stored


@cli.group("exceptions")
def exceptions() -> None:
    """Manage policy exceptions and compensating controls."""


@exceptions.command("list")
@click.option(
    "--status",
    default=None,
    type=click.Choice(["active", "expired", "pending-renewal"]),
    help="Filter by status",
)
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def exceptions_list(status: str | None, fmt: str) -> None:
    """List policy exceptions."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, PolicyOverride

    init_db()
    with get_session() as session:
        overrides = session.query(PolicyOverride).order_by(PolicyOverride.created_at.desc()).all()
        # Build meta map: override_id -> latest AuditEntry extra
        meta_rows = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "policy_exception",
                AuditEntry.entity_type == "exception",
            )
            .order_by(AuditEntry.created_at.desc())
            .all()
        )

    # Deduplicate: keep the latest meta per entity_id
    meta_map: dict[str, dict] = {}
    for m in meta_rows:
        if m.entity_id not in meta_map:
            meta_map[m.entity_id] = m.extra or {}

    # Filter by status
    results = []
    for ov in overrides:
        meta = meta_map.get(ov.id, {})
        effective_status = (
            _derive_status(meta) if meta else ("active" if ov.is_active else "expired")
        )
        if status and effective_status != status:
            continue
        results.append((ov, meta, effective_status))

    if not results:
        console.print("[dim]No policy exceptions found.[/dim]")
        return

    if fmt == "json":
        data = [
            {
                "id": ov.id,
                "name": ov.name,
                "description": ov.description,
                "status": effective_status,
                "policy": meta.get("policy"),
                "approver": meta.get("approver"),
                "expiry": meta.get("expiry"),
                "created_at": ov.created_at.isoformat() if ov.created_at else None,
            }
            for ov, meta, effective_status in results
        ]
        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Policy Exceptions ({len(results)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", max_width=30)
    table.add_column("Policy", max_width=30)
    table.add_column("Approver")
    table.add_column("Status")
    table.add_column("Expiry")

    for ov, meta, effective_status in results:
        expiry = meta.get("expiry", "\u2014")
        if expiry and expiry != "\u2014":
            try:
                expiry = datetime.fromisoformat(expiry).strftime("%Y-%m-%d")
            except ValueError:
                pass
        status_style = {
            "active": "green",
            "expired": "red",
            "pending-renewal": "yellow",
        }.get(effective_status, "")
        table.add_row(
            ov.id[:8],
            (ov.name or "")[:30],
            (meta.get("policy") or "")[:30],
            meta.get("approver", "\u2014"),
            f"[{status_style}]{effective_status}[/]",
            expiry,
        )

    console.print(table)


@exceptions.command("create")
@click.option("--policy", required=True, help="Policy or control being excepted")
@click.option("--justification", required=True, help="Justification for the exception")
@click.option("--approver", required=True, help="Approver actor identity")
@click.option("--expiry", required=True, help="Exception expiry date (YYYY-MM-DD)")
@click.option(
    "--compensating-control", "compensating_control", default=None, help="Compensating control ID"
)
def exceptions_create(
    policy: str,
    justification: str,
    approver: str,
    expiry: str,
    compensating_control: str | None,
) -> None:
    """Create a new policy exception."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, PolicyOverride

    expiry_dt = _parse_date(expiry)
    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)
    exception_id = uuid.uuid4().hex

    with get_session() as session:
        # Create the PolicyOverride record
        override = PolicyOverride(
            id=exception_id,
            name=f"Exception: {policy[:200]}",
            description=justification,
            policy_rego=f"# Exception for: {policy}\n# Justification: {justification}\n",
            is_active=True,
            created_by=actor,
        )
        session.add(override)

        # Store lifecycle metadata in AuditEntry
        entry = AuditEntry(
            id=uuid.uuid4().hex,
            sequence=_next_sequence(session),
            previous_hash="genesis",
            entry_hash=_make_hash(f"{exception_id}:{policy}:{expiry}"),
            action="policy_exception",
            entity_type="exception",
            entity_id=exception_id,
            actor=actor,
            extra={
                "policy": policy,
                "justification": justification,
                "approver": approver,
                "expiry": expiry_dt.isoformat(),
                "status": "active",
                "compensating_control": compensating_control,
                "created_at": now.isoformat(),
                "renewals": [],
            },
        )
        session.add(entry)
        session.commit()

    console.print(f"[green]Policy exception created:[/green] [cyan]{exception_id[:8]}[/cyan]")
    console.print(f"  Policy:   {policy}")
    console.print(f"  Approver: {approver}")
    console.print(f"  Expires:  {expiry}")
    if compensating_control:
        console.print(f"  Compensating control: {compensating_control}")


@exceptions.command("show")
@click.argument("exception_id")
def exceptions_show(exception_id: str) -> None:
    """Show full details for a policy exception."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import PolicyOverride

    init_db()
    with get_session() as session:
        ov = (
            session.query(PolicyOverride).filter(PolicyOverride.id.startswith(exception_id)).first()
        )
        if not ov:
            _error(f"Exception not found: {exception_id}")

        meta = _load_exception_meta(session, ov.id)

    effective_status = _derive_status(meta) if meta else ("active" if ov.is_active else "expired")

    console.print(f"\n[bold]Policy Exception[/bold] [cyan]{ov.id[:8]}[/cyan]")
    console.print(f"  Name:        {ov.name}")
    console.print(f"  Status:      {effective_status}")
    console.print(f"  Policy:      {meta.get('policy', '')}")
    console.print(f"  Justification: {meta.get('justification', ov.description or '')}")
    console.print(f"  Approver:    {meta.get('approver', '')}")
    expiry = meta.get("expiry", "\u2014")
    if expiry and expiry != "\u2014":
        try:
            expiry = datetime.fromisoformat(expiry).strftime("%Y-%m-%d")
        except ValueError:
            pass
    console.print(f"  Expires:     {expiry}")
    if meta.get("compensating_control"):
        console.print(f"  Compensating control: {meta['compensating_control']}")

    renewals = meta.get("renewals", [])
    if renewals:
        console.print("\n[bold]Renewals:[/bold]")
        for ren in renewals:
            console.print(
                f"  [{ren.get('renewed_at', '')[:10]}] "
                f"new expiry: {ren.get('new_expiry', '')[:10]} "
                f"— {ren.get('justification', '')}"
            )
    console.print()


@exceptions.command("renew")
@click.argument("exception_id")
@click.option("--justification", required=True, help="Renewal justification")
@click.option("--new-expiry", "new_expiry", required=True, help="New expiry date (YYYY-MM-DD)")
def exceptions_renew(exception_id: str, justification: str, new_expiry: str) -> None:
    """Renew a policy exception with a new expiry date."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, PolicyOverride

    new_expiry_dt = _parse_date(new_expiry)
    init_db()
    actor = _get_actor()

    with get_session() as session:
        ov = (
            session.query(PolicyOverride).filter(PolicyOverride.id.startswith(exception_id)).first()
        )
        if not ov:
            _error(f"Exception not found: {exception_id}")

        # Load existing meta entry
        existing = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "policy_exception",
                AuditEntry.entity_type == "exception",
                AuditEntry.entity_id == ov.id,
            )
            .order_by(AuditEntry.created_at.desc())
            .first()
        )

        now = datetime.now(timezone.utc)
        if existing:
            extra = dict(existing.extra or {})
            renewals = list(extra.get("renewals", []))
            renewals.append(
                {
                    "justification": justification,
                    "new_expiry": new_expiry_dt.isoformat(),
                    "renewed_by": actor,
                    "renewed_at": now.isoformat(),
                }
            )
            extra["expiry"] = new_expiry_dt.isoformat()
            extra["status"] = "active"
            extra["renewals"] = renewals
            existing.extra = extra
        else:
            # No existing meta; create a fresh one
            entry = AuditEntry(
                id=uuid.uuid4().hex,
                sequence=_next_sequence(session),
                previous_hash="genesis",
                entry_hash=_make_hash(f"{ov.id}:renewal:{new_expiry}"),
                action="policy_exception",
                entity_type="exception",
                entity_id=ov.id,
                actor=actor,
                extra={
                    "status": "active",
                    "expiry": new_expiry_dt.isoformat(),
                    "renewals": [
                        {
                            "justification": justification,
                            "new_expiry": new_expiry_dt.isoformat(),
                            "renewed_by": actor,
                            "renewed_at": now.isoformat(),
                        }
                    ],
                },
            )
            session.add(entry)
        session.commit()

    console.print(
        f"[green]Exception {exception_id[:8]} renewed.[/green] "
        f"New expiry: [cyan]{new_expiry}[/cyan]"
    )


@exceptions.command("expiring")
@click.option("--days", default=30, help="Show exceptions expiring within N days (default: 30)")
def exceptions_expiring(days: int) -> None:
    """List exceptions expiring within N days."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, PolicyOverride

    init_db()
    cutoff = datetime.now(timezone.utc) + timedelta(days=days)

    with get_session() as session:
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

    results = []
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
        now = datetime.now(timezone.utc)
        if now <= expiry <= cutoff:
            results.append((ov, meta, expiry))

    if not results:
        console.print(f"[green]No exceptions expiring within {days} days.[/green]")
        return

    table = Table(title=f"Exceptions Expiring Within {days} Days ({len(results)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Policy", max_width=40)
    table.add_column("Approver")
    table.add_column("Expiry")
    table.add_column("Days Left", justify="right")

    now = datetime.now(timezone.utc)
    for ov, meta, expiry in sorted(results, key=lambda x: x[2]):
        days_left = (expiry - now).days
        color = "red" if days_left <= 7 else "yellow"
        table.add_row(
            ov.id[:8],
            (meta.get("policy") or ov.name or "")[:40],
            meta.get("approver", "\u2014"),
            expiry.strftime("%Y-%m-%d"),
            f"[{color}]{days_left}[/]",
        )

    console.print(table)


@exceptions.command("report")
@click.option(
    "--format",
    "fmt",
    default="md",
    type=click.Choice(["md", "json"]),
    help="Output format",
)
def exceptions_report(fmt: str) -> None:
    """Generate a policy exceptions summary report."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, PolicyOverride

    init_db()
    with get_session() as session:
        overrides = session.query(PolicyOverride).order_by(PolicyOverride.created_at.desc()).all()
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

    statuses: dict[str, int] = {}
    expiring_soon = 0
    now = datetime.now(timezone.utc)
    cutoff_30 = now + timedelta(days=30)

    rows_data = []
    for ov in overrides:
        meta = meta_map.get(ov.id, {})
        st = _derive_status(meta) if meta else ("active" if ov.is_active else "expired")
        statuses[st] = statuses.get(st, 0) + 1

        expiry_str = meta.get("expiry")
        if expiry_str:
            try:
                expiry = datetime.fromisoformat(expiry_str)
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                if now <= expiry <= cutoff_30:
                    expiring_soon += 1
            except ValueError:
                pass

        rows_data.append(
            {
                "id": ov.id,
                "name": ov.name,
                "policy": meta.get("policy"),
                "status": st,
                "approver": meta.get("approver"),
                "expiry": meta.get("expiry"),
            }
        )

    if fmt == "json":
        report = {
            "total": len(overrides),
            "by_status": statuses,
            "expiring_within_30_days": expiring_soon,
            "exceptions": rows_data,
        }
        console.print(json.dumps(report, indent=2))
        return

    console.print("# Policy Exceptions Report\n")
    console.print(f"**Total exceptions:** {len(overrides)}\n")
    console.print("## By Status")
    for st, count in sorted(statuses.items()):
        console.print(f"- {st}: {count}")
    console.print(f"\n**Expiring within 30 days:** {expiring_soon}")
    console.print("\nRun `warlock exceptions expiring` for the full list.")
