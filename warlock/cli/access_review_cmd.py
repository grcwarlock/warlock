"""Access review commands: create, list, show, certify, revoke, report, overdue."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import click
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


# ---------------------------------------------------------------------------
# Access review campaigns are stored as AuditEntry records with:
#   action="access_review_campaign"
#   entity_type="access_review"
#   extra={scope, reviewer, deadline, status, certifications: [...]}
# ---------------------------------------------------------------------------


def _parse_deadline(value: str) -> datetime:
    """Parse YYYY-MM-DD deadline string into an aware datetime."""
    try:
        dt = datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        _error(f"Invalid date format '{value}'. Expected YYYY-MM-DD.")
    return dt.replace(tzinfo=timezone.utc)


def _load_campaign(session, campaign_id: str):
    """Load a campaign AuditEntry by prefix or full ID."""
    from warlock.db.models import AuditEntry

    row = (
        session.query(AuditEntry)
        .filter(
            AuditEntry.action == "access_review_campaign",
            AuditEntry.entity_type == "access_review",
            AuditEntry.entity_id.startswith(campaign_id),
        )
        .first()
    )
    return row


def _campaign_status(entry) -> str:
    """Derive campaign status from AuditEntry extra data."""
    extra = entry.extra or {}
    deadline_str = extra.get("deadline")
    stored_status = extra.get("status", "active")
    if stored_status in ("completed", "cancelled"):
        return stored_status
    if deadline_str:
        try:
            dl = datetime.fromisoformat(deadline_str)
            if dl.tzinfo is None:
                dl = dl.replace(tzinfo=timezone.utc)
            if dl < datetime.now(timezone.utc):
                return "overdue"
        except ValueError:
            pass
    return "active"


def _compute_progress(extra: dict) -> tuple[int, int]:
    """Return (certified_count, total_count) from campaign extra."""
    certs = extra.get("certifications", [])
    return len(certs), extra.get("total_users", len(certs))


@cli.group("access-review")
def access_review() -> None:
    """Manage periodic access review campaigns."""


@access_review.command("create")
@click.option(
    "--scope",
    required=True,
    type=click.Choice(["system", "role", "department"]),
    help="Review scope",
)
@click.option("--reviewer", required=True, help="Reviewer user ID or email")
@click.option("--deadline", required=True, help="Campaign deadline (YYYY-MM-DD)")
def access_review_create(scope: str, reviewer: str, deadline: str) -> None:
    """Create a new access review campaign."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    deadline_dt = _parse_deadline(deadline)
    init_db()
    actor = _get_actor()
    campaign_id = uuid.uuid4().hex

    with get_session() as session:
        # Compute next sequence
        from sqlalchemy import func

        max_seq = session.query(func.max(AuditEntry.sequence)).scalar() or 0

        # Build entry hash from campaign content
        import hashlib

        payload = f"{campaign_id}:{scope}:{reviewer}:{deadline}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()

        entry = AuditEntry(
            id=uuid.uuid4().hex,
            sequence=max_seq + 1,
            previous_hash="genesis",
            entry_hash=entry_hash,
            action="access_review_campaign",
            entity_type="access_review",
            entity_id=campaign_id,
            actor=actor,
            extra={
                "scope": scope,
                "reviewer": reviewer,
                "deadline": deadline_dt.isoformat(),
                "status": "active",
                "certifications": [],
                "revocations": [],
                "total_users": 0,
            },
        )
        session.add(entry)
        session.commit()

    console.print(f"[green]Access review campaign created:[/green] [cyan]{campaign_id[:8]}[/cyan]")
    console.print(f"  Scope:    {scope}")
    console.print(f"  Reviewer: {reviewer}")
    console.print(f"  Deadline: {deadline}")


@access_review.command("list")
@click.option(
    "--status",
    default=None,
    type=click.Choice(["active", "completed", "overdue"]),
    help="Filter by status",
)
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def access_review_list(status: str | None, fmt: str) -> None:
    """List access review campaigns."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        rows = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "access_review_campaign",
                AuditEntry.entity_type == "access_review",
            )
            .order_by(AuditEntry.created_at.desc())
            .all()
        )

    if status:
        rows = [r for r in rows if _campaign_status(r) == status]

    if not rows:
        console.print("[dim]No access review campaigns found.[/dim]")
        return

    if fmt == "json":
        data = [
            {
                "id": r.entity_id,
                "status": _campaign_status(r),
                "scope": (r.extra or {}).get("scope"),
                "reviewer": (r.extra or {}).get("reviewer"),
                "deadline": (r.extra or {}).get("deadline"),
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Access Review Campaigns ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Scope", style="cyan")
    table.add_column("Reviewer")
    table.add_column("Deadline")
    table.add_column("Status")
    table.add_column("Progress")

    for r in rows:
        extra = r.extra or {}
        campaign_st = _campaign_status(r)
        certified, total = _compute_progress(extra)
        dl = extra.get("deadline", "\u2014")
        if dl and dl != "\u2014":
            try:
                dl = datetime.fromisoformat(dl).strftime("%Y-%m-%d")
            except ValueError:
                pass
        status_style = {
            "active": "green",
            "overdue": "red",
            "completed": "dim",
        }.get(campaign_st, "")
        table.add_row(
            r.entity_id[:8],
            extra.get("scope", ""),
            extra.get("reviewer", ""),
            dl,
            f"[{status_style}]{campaign_st}[/]",
            f"{certified}/{total}",
        )

    console.print(table)


@access_review.command("show")
@click.argument("campaign_id")
def access_review_show(campaign_id: str) -> None:
    """Show campaign progress and certification details."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        entry = _load_campaign(session, campaign_id)

    if not entry:
        _error(f"Campaign not found: {campaign_id}")

    extra = entry.extra or {}
    campaign_st = _campaign_status(entry)
    certified, total = _compute_progress(extra)

    console.print(f"\n[bold]Access Review Campaign[/bold] [cyan]{entry.entity_id[:8]}[/cyan]")
    console.print(f"  Status:   [{campaign_st}]{campaign_st}[/]")
    console.print(f"  Scope:    {extra.get('scope', '')}")
    console.print(f"  Reviewer: {extra.get('reviewer', '')}")
    dl = extra.get("deadline", "\u2014")
    if dl and dl != "\u2014":
        try:
            dl = datetime.fromisoformat(dl).strftime("%Y-%m-%d")
        except ValueError:
            pass
    console.print(f"  Deadline: {dl}")
    console.print(f"  Progress: {certified}/{total} certified")

    certs = extra.get("certifications", [])
    if certs:
        console.print("\n[bold]Certifications:[/bold]")
        cert_table = Table()
        cert_table.add_column("User", style="cyan")
        cert_table.add_column("Decision")
        cert_table.add_column("Justification")
        cert_table.add_column("Certified At")
        for c in certs:
            decision_style = "green" if c.get("decision") == "appropriate" else "red"
            cert_table.add_row(
                c.get("user_id", ""),
                f"[{decision_style}]{c.get('decision', '')}[/]",
                (c.get("justification") or "")[:50],
                c.get("certified_at", "")[:10],
            )
        console.print(cert_table)

    revocations = extra.get("revocations", [])
    if revocations:
        console.print("\n[bold]Revocations:[/bold]")
        rev_table = Table()
        rev_table.add_column("User", style="cyan")
        rev_table.add_column("Reason")
        rev_table.add_column("Revoked At")
        for rv in revocations:
            rev_table.add_row(
                rv.get("user_id", ""),
                (rv.get("reason") or "")[:60],
                rv.get("revoked_at", "")[:10],
            )
        console.print(rev_table)
    console.print()


@access_review.command("certify")
@click.argument("campaign_id")
@click.option("--user", "user_id", required=True, help="User ID being certified")
@click.option(
    "--decision",
    required=True,
    type=click.Choice(["appropriate", "revoke"]),
    help="Certification decision",
)
@click.option("--justification", default=None, help="Optional justification")
def access_review_certify(
    campaign_id: str, user_id: str, decision: str, justification: str | None
) -> None:
    """Record a certification decision for a user in a campaign."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        entry = _load_campaign(session, campaign_id)
        if not entry:
            _error(f"Campaign not found: {campaign_id}")

        extra = dict(entry.extra or {})
        certs = list(extra.get("certifications", []))
        certs.append(
            {
                "user_id": user_id,
                "decision": decision,
                "justification": justification,
                "certified_by": _get_actor(),
                "certified_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        extra["certifications"] = certs
        entry.extra = extra
        session.commit()

    decision_style = "green" if decision == "appropriate" else "red"
    console.print(
        f"[{decision_style}]Certification recorded:[/] user=[cyan]{user_id}[/cyan] "
        f"decision={decision} for campaign [cyan]{campaign_id[:8]}[/cyan]"
    )


@access_review.command("revoke")
@click.argument("campaign_id")
@click.option("--user", "user_id", required=True, help="User ID to revoke")
@click.option("--reason", required=True, help="Reason for revocation")
def access_review_revoke(campaign_id: str, user_id: str, reason: str) -> None:
    """Revoke a user's access in a campaign."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        entry = _load_campaign(session, campaign_id)
        if not entry:
            _error(f"Campaign not found: {campaign_id}")

        extra = dict(entry.extra or {})
        revocations = list(extra.get("revocations", []))
        revocations.append(
            {
                "user_id": user_id,
                "reason": reason,
                "revoked_by": _get_actor(),
                "revoked_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        extra["revocations"] = revocations
        entry.extra = extra
        session.commit()

    console.print(
        f"[red]Revocation recorded:[/red] user=[cyan]{user_id}[/cyan] "
        f"for campaign [cyan]{campaign_id[:8]}[/cyan]"
    )


@access_review.command("report")
@click.argument("campaign_id")
@click.option(
    "--format",
    "fmt",
    default="md",
    type=click.Choice(["md", "json"]),
    help="Output format",
)
def access_review_report(campaign_id: str, fmt: str) -> None:
    """Generate a report for an access review campaign."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        entry = _load_campaign(session, campaign_id)

    if not entry:
        _error(f"Campaign not found: {campaign_id}")

    extra = entry.extra or {}
    campaign_st = _campaign_status(entry)
    certs = extra.get("certifications", [])
    revocations = extra.get("revocations", [])
    certified, total = _compute_progress(extra)

    if fmt == "json":
        report = {
            "campaign_id": entry.entity_id,
            "status": campaign_st,
            "scope": extra.get("scope"),
            "reviewer": extra.get("reviewer"),
            "deadline": extra.get("deadline"),
            "certifications": certs,
            "revocations": revocations,
            "summary": {
                "certified": certified,
                "total": total,
                "revoke_decisions": sum(1 for c in certs if c.get("decision") == "revoke"),
                "appropriate_decisions": sum(
                    1 for c in certs if c.get("decision") == "appropriate"
                ),
            },
        }
        console.print(json.dumps(report, indent=2))
        return

    # Markdown format
    dl = extra.get("deadline", "")
    if dl:
        try:
            dl = datetime.fromisoformat(dl).strftime("%Y-%m-%d")
        except ValueError:
            pass

    console.print(f"# Access Review Report — Campaign {entry.entity_id[:8]}\n")
    console.print(f"**Status:** {campaign_st}  ")
    console.print(f"**Scope:** {extra.get('scope', '')}  ")
    console.print(f"**Reviewer:** {extra.get('reviewer', '')}  ")
    console.print(f"**Deadline:** {dl}  ")
    console.print(f"**Progress:** {certified}/{total} users reviewed\n")
    revoke_count = sum(1 for c in certs if c.get("decision") == "revoke")
    console.print(f"**Decisions:** {certified - revoke_count} appropriate, {revoke_count} revoke\n")
    if revocations:
        console.print("## Revocations\n")
        for rv in revocations:
            console.print(f"- **{rv.get('user_id')}** — {rv.get('reason')}\n")


@access_review.command("overdue")
def access_review_overdue() -> None:
    """List all campaigns past their deadline."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        rows = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "access_review_campaign",
                AuditEntry.entity_type == "access_review",
            )
            .order_by(AuditEntry.created_at.desc())
            .all()
        )

    overdue = [r for r in rows if _campaign_status(r) == "overdue"]

    if not overdue:
        console.print("[green]No overdue access review campaigns.[/green]")
        return

    table = Table(title=f"Overdue Access Review Campaigns ({len(overdue)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Scope", style="cyan")
    table.add_column("Reviewer")
    table.add_column("Deadline")
    table.add_column("Progress")

    for r in overdue:
        extra = r.extra or {}
        certified, total = _compute_progress(extra)
        dl = extra.get("deadline", "\u2014")
        if dl and dl != "\u2014":
            try:
                dl = datetime.fromisoformat(dl).strftime("%Y-%m-%d")
            except ValueError:
                pass
        table.add_row(
            r.entity_id[:8],
            extra.get("scope", ""),
            extra.get("reviewer", ""),
            f"[red]{dl}[/red]",
            f"{certified}/{total}",
        )

    console.print(table)
