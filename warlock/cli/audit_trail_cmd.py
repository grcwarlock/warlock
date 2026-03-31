"""CLI commands for the immutable audit trail.

NOTE: The existing audit_engagement_cmd.py registers the "audit" group.
This module registers "audit-trail" — different name, no collision.

Commands:
  warlock audit-trail list              -- list audit entries
  warlock audit-trail show              -- show a single entry
  warlock audit-trail verify            -- verify hash chain for a sequence range
  warlock audit-trail search            -- search entries by actor/action/entity
  warlock audit-trail timeline          -- show timeline for a specific entity
  warlock audit-trail stats             -- aggregate statistics
  warlock audit-trail export            -- export entries to JSON/CSV
  warlock audit-trail integrity-report  -- full hash chain integrity report
  warlock audit-trail tamper-detect     -- scan chain for breaks
  warlock audit-trail retention-status  -- show retention policy status
  warlock audit-trail user-activity     -- show activity by actor
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import click
from rich.table import Table

from warlock.cli import _error, cli, console


def _recompute_hash(entry) -> str:
    """Recompute SHA-256 for an AuditEntry using the same fields as audit.py record().

    Must match the serialization in ``AuditTrail.record()`` and
    ``AuditTrail.verify_chain()`` exactly: JSON with ``sort_keys=True``,
    no ``created_at`` (timestamp is deliberately excluded for deterministic
    recomputation).
    """
    content = json.dumps(
        {
            "sequence": int(entry.sequence),
            "previous_hash": entry.previous_hash,
            "action": entry.action,
            "entity_type": entry.entity_type,
            "entity_id": entry.entity_id,
            "actor": entry.actor,
            "evidence_sha256": entry.evidence_sha256 or "",
        },
        sort_keys=True,
    )
    return hashlib.sha256(content.encode()).hexdigest()


def _format_dt(dt: datetime | None) -> str:
    if dt is None:
        return "\u2014"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Top-level group
# ---------------------------------------------------------------------------


@cli.group("audit-trail", invoke_without_command=True)
@click.pass_context
def audit_trail_grp(ctx: click.Context) -> None:
    """Inspect and verify the immutable audit trail."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# audit-trail list
# ---------------------------------------------------------------------------


@audit_trail_grp.command("list")
@click.option("--action", "-a", default=None, help="Filter by action type")
@click.option("--actor", default=None, help="Filter by actor")
@click.option("--entity-type", default=None, help="Filter by entity type")
@click.option(
    "--since",
    default=None,
    help="Show entries since ISO date (e.g. 2026-01-01)",
)
@click.option("--limit", "-n", default=50, help="Max results")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def audit_trail_list(
    action: str | None,
    actor: str | None,
    entity_type: str | None,
    since: str | None,
    limit: int,
    fmt: str,
) -> None:
    """List recent audit trail entries."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        q = session.query(AuditEntry)
        if action:
            q = q.filter(AuditEntry.action == action)
        if actor:
            q = q.filter(AuditEntry.actor.ilike(f"%{actor}%"))
        if entity_type:
            q = q.filter(AuditEntry.entity_type == entity_type)
        if since:
            try:
                since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
                q = q.filter(AuditEntry.created_at >= since_dt)
            except ValueError:
                _error(f"Invalid date format: {since}. Use ISO format e.g. 2026-01-01")
        q = q.order_by(AuditEntry.sequence.desc()).limit(limit)
        rows = q.all()

    if fmt == "json":
        out = [
            {
                "id": e.id,
                "sequence": e.sequence,
                "action": e.action,
                "entity_type": e.entity_type,
                "entity_id": e.entity_id,
                "actor": e.actor,
                "entry_hash": e.entry_hash,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in rows
        ]
        console.print_json(json.dumps(out))
        return

    if not rows:
        console.print("[dim]No audit entries found.[/dim]")
        return

    table = Table(title=f"Audit Trail ({len(rows)} entries)")
    table.add_column("Seq", justify="right", style="dim")
    table.add_column("Action", style="cyan")
    table.add_column("Entity Type")
    table.add_column("Entity ID", style="dim", max_width=12)
    table.add_column("Actor", style="dim")
    table.add_column("Timestamp")

    for e in rows:
        table.add_row(
            str(e.sequence),
            e.action,
            e.entity_type,
            e.entity_id[:12],
            e.actor,
            _format_dt(e.created_at),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# audit-trail show
# ---------------------------------------------------------------------------


@audit_trail_grp.command("show")
@click.argument("entry_ref")
def audit_trail_show(entry_ref: str) -> None:
    """Show full details for a single audit entry (by ID or sequence number)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        # Try as sequence number first
        entry = None
        try:
            seq = int(entry_ref)
            entry = session.query(AuditEntry).filter(AuditEntry.sequence == seq).first()
        except ValueError:
            pass

        # Try as UUID prefix
        if entry is None:
            entry = session.query(AuditEntry).filter(AuditEntry.id.startswith(entry_ref)).first()

        if entry is None:
            _error(f"Audit entry '{entry_ref}' not found.")

        console.print(f"\n[bold cyan]Audit Entry #{entry.sequence}[/bold cyan]")
        console.print(f"  ID:             {entry.id}")
        console.print(f"  Sequence:       {entry.sequence}")
        console.print(f"  Action:         [cyan]{entry.action}[/cyan]")
        console.print(f"  Entity type:    {entry.entity_type}")
        console.print(f"  Entity ID:      {entry.entity_id}")
        console.print(f"  Actor:          {entry.actor}")
        console.print(f"  Previous hash:  {entry.previous_hash}")
        console.print(f"  Entry hash:     {entry.entry_hash}")
        console.print(f"  Evidence SHA:   {entry.evidence_sha256 or '—'}")
        console.print(f"  Created at:     {_format_dt(entry.created_at)}")

        if entry.extra:
            console.print("\n  [bold]Extra:[/bold]")
            console.print_json(json.dumps(entry.extra, default=str))


# ---------------------------------------------------------------------------
# audit-trail verify
# ---------------------------------------------------------------------------


@audit_trail_grp.command("verify")
@click.option("--from-seq", "from_seq", type=int, default=1, help="Start sequence (inclusive)")
@click.option(
    "--to-seq",
    "to_seq",
    type=int,
    default=None,
    help="End sequence (inclusive, default: latest)",
)
@click.option("--verbose", "-v", is_flag=True, help="Print each entry's verification result")
def audit_trail_verify(from_seq: int, to_seq: int | None, verbose: bool) -> None:
    """Verify hash chain integrity for a sequence range."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        q = session.query(AuditEntry).filter(AuditEntry.sequence >= from_seq)
        if to_seq is not None:
            q = q.filter(AuditEntry.sequence <= to_seq)
        entries = q.order_by(AuditEntry.sequence.asc()).all()

    if not entries:
        console.print("[dim]No entries found in the specified range.[/dim]")
        return

    console.print(
        f"[cyan]Verifying hash chain: sequences {from_seq} to "
        f"{entries[-1].sequence} ({len(entries)} entries)...[/cyan]"
    )

    breaks: list[dict[str, Any]] = []
    prev_hash = entries[0].previous_hash  # expected starting point

    for entry in entries:
        # Verify previous_hash linkage
        if entry.sequence > from_seq and entry.previous_hash != prev_hash:
            breaks.append(
                {
                    "sequence": entry.sequence,
                    "issue": "previous_hash mismatch",
                    "expected": prev_hash,
                    "found": entry.previous_hash,
                }
            )

        # Recompute entry hash
        computed = _recompute_hash(entry)
        if computed != entry.entry_hash:
            breaks.append(
                {
                    "sequence": entry.sequence,
                    "issue": "entry_hash mismatch",
                    "stored": entry.entry_hash,
                    "computed": computed,
                }
            )

        if verbose:
            ok = not any(b["sequence"] == entry.sequence for b in breaks)
            status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
            console.print(f"  seq={entry.sequence}  {status}")

        prev_hash = entry.entry_hash

    if breaks:
        console.print(f"\n[red]Chain BROKEN — {len(breaks)} integrity violation(s):[/red]")
        for b in breaks:
            console.print(f"  seq={b['sequence']}: {b['issue']}")
    else:
        console.print(f"[green]Chain INTACT — {len(entries)} entries verified.[/green]")


# ---------------------------------------------------------------------------
# audit-trail search
# ---------------------------------------------------------------------------


@audit_trail_grp.command("search")
@click.argument("query")
@click.option(
    "--field",
    type=click.Choice(["actor", "action", "entity_id", "entity_type", "all"]),
    default="all",
    help="Field to search",
)
@click.option("--limit", "-n", default=50, help="Max results")
def audit_trail_search(query: str, field: str, limit: int) -> None:
    """Search audit entries by text."""
    from sqlalchemy import or_

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        if field == "actor":
            q = session.query(AuditEntry).filter(AuditEntry.actor.ilike(f"%{query}%"))
        elif field == "action":
            q = session.query(AuditEntry).filter(AuditEntry.action.ilike(f"%{query}%"))
        elif field == "entity_id":
            q = session.query(AuditEntry).filter(AuditEntry.entity_id.ilike(f"%{query}%"))
        elif field == "entity_type":
            q = session.query(AuditEntry).filter(AuditEntry.entity_type.ilike(f"%{query}%"))
        else:
            q = session.query(AuditEntry).filter(
                or_(
                    AuditEntry.actor.ilike(f"%{query}%"),
                    AuditEntry.action.ilike(f"%{query}%"),
                    AuditEntry.entity_id.ilike(f"%{query}%"),
                    AuditEntry.entity_type.ilike(f"%{query}%"),
                )
            )
        rows = q.order_by(AuditEntry.sequence.desc()).limit(limit).all()

    if not rows:
        console.print(f"[dim]No entries matching '{query}'.[/dim]")
        return

    table = Table(title=f"Search Results: '{query}' ({len(rows)})")
    table.add_column("Seq", justify="right", style="dim")
    table.add_column("Action", style="cyan")
    table.add_column("Entity Type")
    table.add_column("Entity ID", style="dim")
    table.add_column("Actor", style="dim")
    table.add_column("Timestamp")

    for e in rows:
        table.add_row(
            str(e.sequence),
            e.action,
            e.entity_type,
            e.entity_id[:16],
            e.actor,
            _format_dt(e.created_at),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# audit-trail timeline
# ---------------------------------------------------------------------------


@audit_trail_grp.command("timeline")
@click.argument("entity_id")
@click.option("--entity-type", default=None, help="Narrow by entity type")
@click.option("--limit", "-n", default=50, help="Max results")
def audit_trail_timeline(entity_id: str, entity_type: str | None, limit: int) -> None:
    """Show timeline of audit events for a specific entity."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        q = session.query(AuditEntry).filter(AuditEntry.entity_id.startswith(entity_id))
        if entity_type:
            q = q.filter(AuditEntry.entity_type == entity_type)
        rows = q.order_by(AuditEntry.sequence.asc()).limit(limit).all()

    if not rows:
        console.print(f"[dim]No audit entries found for entity '{entity_id}'.[/dim]")
        return

    console.print(f"\n[bold]Timeline for entity {entity_id}[/bold]")
    table = Table()
    table.add_column("Seq", justify="right", style="dim")
    table.add_column("Timestamp")
    table.add_column("Action", style="cyan")
    table.add_column("Actor", style="dim")

    for e in rows:
        table.add_row(
            str(e.sequence),
            _format_dt(e.created_at),
            e.action,
            e.actor,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# audit-trail stats
# ---------------------------------------------------------------------------


@audit_trail_grp.command("stats")
def audit_trail_stats() -> None:
    """Aggregate statistics for the audit trail."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        total = session.query(AuditEntry).count()
        max_seq_row = (
            session.query(AuditEntry.sequence).order_by(AuditEntry.sequence.desc()).first()
        )
        min_seq_row = session.query(AuditEntry.sequence).order_by(AuditEntry.sequence.asc()).first()

        # By action
        action_counts = (
            session.query(AuditEntry.action, __import__("sqlalchemy").func.count(AuditEntry.id))
            .group_by(AuditEntry.action)
            .order_by(__import__("sqlalchemy").func.count(AuditEntry.id).desc())
            .limit(10)
            .all()
        )

        # By entity type
        entity_counts = (
            session.query(
                AuditEntry.entity_type,
                __import__("sqlalchemy").func.count(AuditEntry.id),
            )
            .group_by(AuditEntry.entity_type)
            .order_by(__import__("sqlalchemy").func.count(AuditEntry.id).desc())
            .all()
        )

    max_seq = max_seq_row[0] if max_seq_row else 0
    min_seq = min_seq_row[0] if min_seq_row else 0

    console.print("\n[bold]Audit Trail Statistics[/bold]")
    console.print(f"  Total entries:     {total:,}")
    console.print(f"  Sequence range:    {min_seq} — {max_seq}")

    if action_counts:
        table = Table(title="Top Actions")
        table.add_column("Action", style="cyan")
        table.add_column("Count", justify="right")
        for action, cnt in action_counts:
            table.add_row(action, str(cnt))
        console.print(table)

    if entity_counts:
        table = Table(title="By Entity Type")
        table.add_column("Entity Type", style="cyan")
        table.add_column("Count", justify="right")
        for entity_type, cnt in entity_counts:
            table.add_row(entity_type, str(cnt))
        console.print(table)


# ---------------------------------------------------------------------------
# audit-trail export
# ---------------------------------------------------------------------------


@audit_trail_grp.command("export")
@click.option("--from-seq", "from_seq", type=int, default=1, help="Start sequence")
@click.option("--to-seq", "to_seq", type=int, default=None, help="End sequence")
@click.option("--limit", "-n", default=1000, help="Max entries")
@click.option(
    "--format", "fmt", type=click.Choice(["json", "csv"]), default="json", help="Output format"
)
@click.option("--output", "-o", default=None, help="Output file (default: stdout)")
def audit_trail_export(
    from_seq: int,
    to_seq: int | None,
    limit: int,
    fmt: str,
    output: str | None,
) -> None:
    """Export audit trail entries to JSON or CSV."""
    import pathlib

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        q = session.query(AuditEntry).filter(AuditEntry.sequence >= from_seq)
        if to_seq is not None:
            q = q.filter(AuditEntry.sequence <= to_seq)
        rows = q.order_by(AuditEntry.sequence.asc()).limit(limit).all()

    if fmt == "json":
        data = [
            {
                "id": e.id,
                "sequence": e.sequence,
                "previous_hash": e.previous_hash,
                "entry_hash": e.entry_hash,
                "action": e.action,
                "entity_type": e.entity_type,
                "entity_id": e.entity_id,
                "actor": e.actor,
                "evidence_sha256": e.evidence_sha256,
                "extra": e.extra,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in rows
        ]
        text = json.dumps(data, indent=2, default=str)
    else:
        lines = ["sequence,action,entity_type,entity_id,actor,entry_hash,created_at"]
        for e in rows:
            created = e.created_at.isoformat() if e.created_at else ""
            lines.append(
                f"{e.sequence},{e.action},{e.entity_type},{e.entity_id},"
                f"{e.actor},{e.entry_hash},{created}"
            )
        text = "\n".join(lines)

    if output:
        pathlib.Path(output).write_text(text)
        console.print(f"[green]Exported {len(rows)} entries to {output}[/green]")
    else:
        console.print(text)


# ---------------------------------------------------------------------------
# audit-trail integrity-report
# ---------------------------------------------------------------------------


@audit_trail_grp.command("integrity-report")
@click.option(
    "--sample-size",
    type=int,
    default=None,
    help="Verify only a random sample of N entries (default: all)",
)
def audit_trail_integrity_report(sample_size: int | None) -> None:
    """Full hash chain integrity report."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        q = session.query(AuditEntry).order_by(AuditEntry.sequence.asc())
        entries = q.all()

    if not entries:
        console.print("[dim]No audit entries found.[/dim]")
        return

    if sample_size and sample_size < len(entries):
        import random

        entries = sorted(random.sample(entries, sample_size), key=lambda e: e.sequence)
        console.print(f"[dim](Sampling {sample_size} of {len(entries)} total entries)[/dim]")

    console.print(f"[cyan]Running integrity report on {len(entries)} entries...[/cyan]")

    chain_breaks: list[int] = []
    hash_mismatches: list[int] = []
    prev_hash = entries[0].previous_hash

    for entry in entries:
        if entry.sequence > entries[0].sequence and entry.previous_hash != prev_hash:
            chain_breaks.append(entry.sequence)

        computed = _recompute_hash(entry)
        if computed != entry.entry_hash:
            hash_mismatches.append(entry.sequence)

        prev_hash = entry.entry_hash

    total_checked = len(entries)
    issues = len(chain_breaks) + len(hash_mismatches)

    from rich.panel import Panel

    status_color = "green" if issues == 0 else "red"
    status_text = "INTACT" if issues == 0 else "COMPROMISED"

    console.print(
        Panel(
            f"[bold {status_color}]{status_text}[/bold {status_color}]\n\n"
            f"Entries checked:   {total_checked:,}\n"
            f"Chain breaks:      {len(chain_breaks)}\n"
            f"Hash mismatches:   {len(hash_mismatches)}\n"
            f"Total issues:      {issues}",
            title="Audit Trail Integrity Report",
            border_style=status_color,
        )
    )

    if chain_breaks:
        console.print(f"\n[red]Chain breaks at sequences:[/red] {chain_breaks[:20]}")
    if hash_mismatches:
        console.print(f"\n[red]Hash mismatches at sequences:[/red] {hash_mismatches[:20]}")

    if issues == 0:
        console.print(
            "\n[green]All entries verified. Hash chain is cryptographically intact.[/green]"
        )


# ---------------------------------------------------------------------------
# audit-trail tamper-detect
# ---------------------------------------------------------------------------


@audit_trail_grp.command("tamper-detect")
@click.option("--stop-on-first", is_flag=True, help="Stop at the first detected break")
def audit_trail_tamper_detect(stop_on_first: bool) -> None:
    """Scan hash chain for any tamper evidence (breaks or mismatches)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        entries = session.query(AuditEntry).order_by(AuditEntry.sequence.asc()).all()

    if not entries:
        console.print("[dim]No audit entries to scan.[/dim]")
        return

    console.print(f"[cyan]Scanning {len(entries):,} entries for tamper evidence...[/cyan]")

    prev_hash = entries[0].previous_hash
    findings: list[dict[str, Any]] = []

    for entry in entries:
        if entry.sequence > entries[0].sequence and entry.previous_hash != prev_hash:
            findings.append(
                {
                    "sequence": entry.sequence,
                    "type": "CHAIN_BREAK",
                    "detail": f"expected prev_hash={prev_hash[:16]}... got {entry.previous_hash[:16]}...",
                }
            )
            if stop_on_first:
                break

        computed = _recompute_hash(entry)
        if computed != entry.entry_hash:
            findings.append(
                {
                    "sequence": entry.sequence,
                    "type": "HASH_MISMATCH",
                    "detail": f"stored={entry.entry_hash[:16]}... computed={computed[:16]}...",
                }
            )
            if stop_on_first:
                break

        prev_hash = entry.entry_hash

    if not findings:
        console.print(f"[green]No tamper evidence detected in {len(entries):,} entries.[/green]")
        return

    console.print(f"\n[red bold]TAMPER EVIDENCE DETECTED ({len(findings)} finding(s)):[/red bold]")
    table = Table()
    table.add_column("Sequence", justify="right", style="red")
    table.add_column("Type", style="red bold")
    table.add_column("Detail")

    for f in findings[:50]:
        table.add_row(str(f["sequence"]), f["type"], f["detail"])

    if len(findings) > 50:
        console.print(f"[dim]... and {len(findings) - 50} more[/dim]")

    console.print(table)
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# audit-trail retention-status
# ---------------------------------------------------------------------------


@audit_trail_grp.command("retention-status")
def audit_trail_retention_status() -> None:
    """Show retention policy status for audit trail entries."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, Policy

    init_db()
    with get_session() as session:
        total = session.query(AuditEntry).count()
        oldest = session.query(AuditEntry.created_at).order_by(AuditEntry.created_at.asc()).first()
        newest = session.query(AuditEntry.created_at).order_by(AuditEntry.created_at.desc()).first()

        # Look up retention policy from Policy table
        retention_policy = (
            session.query(Policy)
            .filter(Policy.policy_type == "retention", Policy.enabled == True)  # noqa: E712
            .order_by(Policy.priority.desc())
            .first()
        )

    oldest_dt = oldest[0] if oldest else None
    newest_dt = newest[0] if newest else None

    console.print("\n[bold]Audit Trail Retention Status[/bold]")
    console.print(f"  Total entries:    {total:,}")
    console.print(f"  Oldest entry:     {_format_dt(oldest_dt)}")
    console.print(f"  Newest entry:     {_format_dt(newest_dt)}")

    if oldest_dt and newest_dt:
        span = newest_dt - oldest_dt
        console.print(f"  Span:             {span.days} days")

    if retention_policy:
        rules = retention_policy.rules or {}
        days = rules.get("days", "not set")
        console.print("\n[bold]Active Retention Policy:[/bold]")
        console.print(f"  Policy ID:     {retention_policy.id[:8]}")
        console.print(f"  Retention:     {days} days")
        console.print(f"  Created by:    {retention_policy.created_by}")

        if oldest_dt and isinstance(days, int):
            now = datetime.now(timezone.utc)
            age_days = (now - oldest_dt).days
            if age_days > days:
                console.print(
                    f"\n[yellow]Warning: oldest entry ({age_days} days) exceeds "
                    f"retention policy ({days} days).[/yellow]"
                )
            else:
                console.print(
                    f"\n[green]All entries within retention window ({age_days}/{days} days).[/green]"
                )
    else:
        console.print(
            "\n[dim]No retention policy configured. Use 'warlock policy set retention --days N'.[/dim]"
        )


# ---------------------------------------------------------------------------
# audit-trail user-activity
# ---------------------------------------------------------------------------


@audit_trail_grp.command("user-activity")
@click.option("--actor", "-u", default=None, help="Filter by specific actor")
@click.option("--since", default=None, help="Since ISO date (e.g. 2026-01-01)")
@click.option("--limit", "-n", default=20, help="Max actors to display")
def audit_trail_user_activity(actor: str | None, since: str | None, limit: int) -> None:
    """Show activity summary per actor."""
    import sqlalchemy

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        if actor:
            # Detailed view for a single actor
            q = session.query(AuditEntry).filter(AuditEntry.actor.ilike(f"%{actor}%"))
            if since:
                try:
                    since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
                    q = q.filter(AuditEntry.created_at >= since_dt)
                except ValueError:
                    _error(f"Invalid date format: {since}")
            rows = q.order_by(AuditEntry.sequence.desc()).limit(50).all()

            if not rows:
                console.print(f"[dim]No activity found for actor '{actor}'.[/dim]")
                return

            table = Table(title=f"Activity for {actor} ({len(rows)} entries)")
            table.add_column("Seq", justify="right", style="dim")
            table.add_column("Action", style="cyan")
            table.add_column("Entity Type")
            table.add_column("Entity ID", style="dim")
            table.add_column("Timestamp")

            for e in rows:
                table.add_row(
                    str(e.sequence),
                    e.action,
                    e.entity_type,
                    e.entity_id[:16],
                    _format_dt(e.created_at),
                )
            console.print(table)

        else:
            # Summary by actor
            q = (
                session.query(
                    AuditEntry.actor,
                    sqlalchemy.func.count(AuditEntry.id).label("count"),
                    sqlalchemy.func.max(AuditEntry.created_at).label("last_seen"),
                )
                .group_by(AuditEntry.actor)
                .order_by(sqlalchemy.func.count(AuditEntry.id).desc())
                .limit(limit)
            )
            if since:
                try:
                    since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
                    q = q.filter(AuditEntry.created_at >= since_dt)
                except ValueError:
                    _error(f"Invalid date format: {since}")
            rows = q.all()

            if not rows:
                console.print("[dim]No activity found.[/dim]")
                return

            table = Table(title=f"User Activity Summary (top {len(rows)})")
            table.add_column("Actor", style="cyan")
            table.add_column("Actions", justify="right")
            table.add_column("Last Seen")

            for actor_name, count, last_seen in rows:
                table.add_row(actor_name, str(count), _format_dt(last_seen))

            console.print(table)


# ---------------------------------------------------------------------------
# audit-trail anchor — publish / verify external chain anchor
# ---------------------------------------------------------------------------


@audit_trail_grp.command("anchor")
@click.option("--verify", is_flag=True, help="Verify existing anchor instead of publishing")
@click.option(
    "--path", default="", help="File path for anchor (default: warlock_chain_anchor.json)"
)
def anchor_cmd(verify: bool, path: str) -> None:
    """Publish or verify the audit trail hash chain anchor."""
    from rich.markup import escape as _esc

    from warlock.db.engine import get_read_session
    from warlock.export.chain_anchor import ChainAnchor

    anchor = ChainAnchor()

    with get_read_session() as session:
        if verify:
            result = anchor.verify_anchor(session, target="file", path=path)
            if result.get("valid"):
                console.print(
                    f"[green]Anchor verified[/green] at sequence "
                    f"{result['sequence']} — hash matches."
                )
            else:
                err = result.get("error", "unknown error")
                console.print(f"[red]Anchor verification FAILED:[/red] {_esc(str(err))}")
                raise SystemExit(1)
        else:
            try:
                result = anchor.publish(session, target="file", path=path)
                console.print(
                    f"[green]Anchor published[/green] — seq={result['sequence']}, "
                    f"hash={_esc(result['chain_head'][:16])}..."
                )
            except ValueError as exc:
                _error(str(exc))
