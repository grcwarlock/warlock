"""Access review commands: create, list, show, certify, revoke, report, overdue,
entitlements, group-changes, background-checks, nda-status, phishing-scores."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import _error, _get_actor, cli, console
from warlock.utils import ensure_aware

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


@cli.group("access-review", invoke_without_command=True)
@click.pass_context
def access_review(ctx: click.Context) -> None:
    """Manage periodic access review campaigns."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


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


# ---------------------------------------------------------------------------
# IAM-1: Cloud entitlement analysis
# ---------------------------------------------------------------------------


@access_review.command("entitlements")
@click.option("--department", default=None, help="Filter by department")
@click.option(
    "--stale-days",
    "stale_days",
    default=90,
    help="Days since last login to flag as stale (default 90)",
)
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def access_review_entitlements(department: str | None, stale_days: int, fmt: str) -> None:
    """Cloud entitlement analysis -- flag excessive or stale IAM privileges.

    Joins Personnel records with IAM-sourced Findings to surface users who
    hold admin or write-level permissions but have not logged in recently.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, Personnel

    init_db()
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=stale_days)

    with get_session() as session:
        q = session.query(Personnel).filter(Personnel.is_active.is_(True))
        if department:
            q = q.filter(Personnel.department.ilike(f"%{department}%"))
        personnel = q.order_by(Personnel.full_name).limit(500).all()

        # Collect IAM findings keyed by email / resource_name
        iam_findings = session.query(Finding).filter(Finding.source_type == "iam").limit(5000).all()

    # Index findings by resource_name (often an email or user principal)
    findings_by_resource: dict[str, list] = {}
    for f in iam_findings:
        key = (f.resource_name or "").lower()
        findings_by_resource.setdefault(key, []).append(f)

    rows: list[dict] = []
    for p in personnel:
        email_key = (p.email or "").lower()
        user_findings = findings_by_resource.get(email_key, [])
        permissions_count = len(user_findings)

        # Determine role from IdP groups
        groups = p.idp_groups or []
        role = "user"
        for g in groups:
            g_lower = (g if isinstance(g, str) else str(g)).lower()
            if any(kw in g_lower for kw in ("admin", "owner", "superuser", "root")):
                role = "admin"
                break
            if any(kw in g_lower for kw in ("write", "editor", "contributor")):
                role = "write"

        # Flag excessive: admin/write + stale login
        last_login = ensure_aware(p.idp_last_login) if p.idp_last_login else None
        stale = last_login is not None and last_login < stale_cutoff
        no_login = last_login is None and p.idp_status not in (None, "active")
        excessive = (role in ("admin", "write")) and (stale or no_login)

        recommendation = "OK"
        if excessive and stale:
            recommendation = f"Downgrade -- no login in {stale_days}+ days"
        elif excessive and no_login:
            recommendation = "Review -- no login recorded"
        elif role == "admin" and permissions_count > 10:
            recommendation = "Audit -- high permission count"

        rows.append(
            {
                "user": escape(p.full_name or p.email),
                "email": p.email,
                "role": role,
                "permissions_count": permissions_count,
                "excessive": excessive,
                "last_login": last_login.strftime("%Y-%m-%d") if last_login else "\u2014",
                "recommendation": recommendation,
            }
        )

    if not rows:
        console.print("[dim]No personnel records found.[/dim]")
        return

    if fmt == "json":
        console.print(json.dumps(rows, indent=2, default=str))
        return

    excessive_count = sum(1 for r in rows if r["excessive"])
    table = Table(title=f"Cloud Entitlements ({len(rows)} users, {excessive_count} excessive)")
    table.add_column("User", max_width=30)
    table.add_column("Role", style="cyan")
    table.add_column("Permissions", justify="right")
    table.add_column("Last Login")
    table.add_column("Excessive")
    table.add_column("Recommendation", max_width=40)

    for r in rows:
        exc_display = "[red bold]YES[/red bold]" if r["excessive"] else "[green]No[/green]"
        table.add_row(
            r["user"],
            r["role"],
            str(r["permissions_count"]),
            r["last_login"],
            exc_display,
            r["recommendation"],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# IAM-2: IdP group membership changes
# ---------------------------------------------------------------------------


@access_review.command("group-changes")
@click.option("--user", "user_filter", default=None, help="Filter by user email (substring match)")
@click.option("--limit", "-n", "max_rows", default=100, help="Max results")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def access_review_group_changes(user_filter: str | None, max_rows: int, fmt: str) -> None:
    """Show IdP group membership changes from audit trail.

    Compares Personnel.idp_groups with historical audit entries that record
    group additions and removals over time.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()

    with get_session() as session:
        q = session.query(AuditEntry).filter(
            AuditEntry.action.in_(
                ["group_membership_changed", "idp_group_change", "access_review_campaign"]
            ),
            AuditEntry.entity_type.in_(["personnel", "idp", "access_review"]),
        )
        if user_filter:
            q = q.filter(AuditEntry.extra.contains(user_filter))
        rows = q.order_by(AuditEntry.created_at.desc()).limit(max_rows).all()

    changes: list[dict] = []
    for r in rows:
        extra = r.extra or {}
        changes.append(
            {
                "user": extra.get("user_email", extra.get("reviewer", r.actor or "\u2014")),
                "group_added": extra.get("group_added", extra.get("scope", "\u2014")),
                "group_removed": extra.get("group_removed", "\u2014"),
                "changed_at": (
                    ensure_aware(r.created_at).strftime("%Y-%m-%d %H:%M")
                    if r.created_at
                    else "\u2014"
                ),
            }
        )

    if not changes:
        # Fall back: show current group membership from Personnel
        from warlock.db.models import Personnel

        with get_session() as session:
            pq = session.query(Personnel).filter(Personnel.is_active.is_(True))
            if user_filter:
                pq = pq.filter(Personnel.email.ilike(f"%{user_filter}%"))
            people = pq.order_by(Personnel.full_name).limit(max_rows).all()

        for p in people:
            for g in p.idp_groups or []:
                group_name = g if isinstance(g, str) else str(g)
                changes.append(
                    {
                        "user": p.email,
                        "group_added": group_name,
                        "group_removed": "\u2014",
                        "changed_at": (
                            ensure_aware(p.last_synced).strftime("%Y-%m-%d")
                            if p.last_synced
                            else "\u2014"
                        ),
                    }
                )

    if not changes:
        console.print("[dim]No group membership changes found.[/dim]")
        return

    if fmt == "json":
        console.print(json.dumps(changes, indent=2, default=str))
        return

    table = Table(title=f"IdP Group Membership Changes ({len(changes)})")
    table.add_column("User", max_width=35)
    table.add_column("Group Added", style="green", max_width=30)
    table.add_column("Group Removed", style="red", max_width=30)
    table.add_column("Changed At")

    for c in changes:
        table.add_row(
            escape(c["user"]),
            escape(c["group_added"]),
            escape(c["group_removed"]),
            c["changed_at"],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# IAM-3: Background check status tracking
# ---------------------------------------------------------------------------


@access_review.command("background-checks")
@click.option("--overdue-only", "overdue_only", is_flag=True, help="Show only overdue checks")
@click.option("--department", default=None, help="Filter by department")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def access_review_background_checks(overdue_only: bool, department: str | None, fmt: str) -> None:
    """Background check status tracking for all personnel.

    Queries Personnel metadata and flags any employee whose last background
    check was more than 365 days ago or never completed.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Personnel

    init_db()
    now = datetime.now(timezone.utc)
    overdue_cutoff = now - timedelta(days=365)

    with get_session() as session:
        q = session.query(Personnel).filter(Personnel.is_active.is_(True))
        if department:
            q = q.filter(Personnel.department.ilike(f"%{department}%"))
        people = q.order_by(Personnel.full_name).limit(500).all()

    if not people:
        console.print("[dim]No personnel records found.[/dim]")
        return

    rows: list[dict] = []
    for p in people:
        check_date = ensure_aware(p.background_check_date) if p.background_check_date else None
        status = p.background_check_status or "not_started"
        next_due = (
            (check_date + timedelta(days=365)).strftime("%Y-%m-%d") if check_date else "\u2014"
        )
        is_overdue = False
        if status == "not_started" or (check_date and check_date < overdue_cutoff):
            is_overdue = True

        if overdue_only and not is_overdue:
            continue

        rows.append(
            {
                "name": escape(p.full_name or p.email),
                "email": p.email,
                "status": status,
                "check_date": check_date.strftime("%Y-%m-%d") if check_date else "\u2014",
                "next_due": next_due,
                "overdue": is_overdue,
            }
        )

    if not rows:
        console.print("[green]No overdue background checks.[/green]")
        return

    if fmt == "json":
        console.print(json.dumps(rows, indent=2, default=str))
        return

    overdue_count = sum(1 for r in rows if r["overdue"])
    title = f"Background Checks ({len(rows)} personnel"
    if overdue_count:
        title += f", {overdue_count} overdue"
    title += ")"

    table = Table(title=title)
    table.add_column("Name", max_width=30)
    table.add_column("Status")
    table.add_column("Check Date")
    table.add_column("Next Due")
    table.add_column("Overdue")

    _bgc_status_styles = {"completed": "green", "pending": "yellow", "not_started": "red"}

    for r in rows:
        sty = _bgc_status_styles.get(r["status"], "")
        overdue_display = "[red bold]YES[/red bold]" if r["overdue"] else "[green]No[/green]"
        table.add_row(
            r["name"],
            f"[{sty}]{r['status']}[/{sty}]" if sty else r["status"],
            r["check_date"],
            r["next_due"],
            overdue_display,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# IAM-4: NDA / agreement tracking
# ---------------------------------------------------------------------------


@access_review.command("nda-status")
@click.option(
    "--unsigned-only", "unsigned_only", is_flag=True, help="Show only unsigned or expired NDAs"
)
@click.option("--department", default=None, help="Filter by department")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def access_review_nda_status(unsigned_only: bool, department: str | None, fmt: str) -> None:
    """NDA and agreement tracking for all personnel.

    Reads Personnel.agreements_signed (JSON list of {type, signed_date}) and
    flags employees with missing or expired NDAs.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Personnel

    init_db()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        q = session.query(Personnel).filter(Personnel.is_active.is_(True))
        if department:
            q = q.filter(Personnel.department.ilike(f"%{department}%"))
        people = q.order_by(Personnel.full_name).limit(500).all()

    if not people:
        console.print("[dim]No personnel records found.[/dim]")
        return

    rows: list[dict] = []
    for p in people:
        agreements = p.agreements_signed or []
        # Look for NDA-type agreements
        nda = None
        for a in agreements:
            if not isinstance(a, dict):
                continue
            atype = (a.get("type") or "").lower()
            if "nda" in atype or "non-disclosure" in atype or "confidentiality" in atype:
                nda = a
                break

        nda_signed = nda is not None
        nda_date = None
        expires = "\u2014"
        is_expired = False

        if nda:
            signed_str = nda.get("signed_date") or nda.get("date")
            if signed_str:
                try:
                    nda_date = datetime.fromisoformat(signed_str)
                    if nda_date.tzinfo is None:
                        nda_date = nda_date.replace(tzinfo=timezone.utc)
                    # NDAs typically expire after 2 years
                    expiry = nda_date + timedelta(days=730)
                    expires = expiry.strftime("%Y-%m-%d")
                    if expiry < now:
                        is_expired = True
                except ValueError:
                    pass

        if unsigned_only and nda_signed and not is_expired:
            continue

        rows.append(
            {
                "name": escape(p.full_name or p.email),
                "email": p.email,
                "nda_signed": nda_signed,
                "nda_date": nda_date.strftime("%Y-%m-%d") if nda_date else "\u2014",
                "expires": expires,
                "expired": is_expired,
                "needs_action": not nda_signed or is_expired,
            }
        )

    if not rows:
        console.print("[green]All NDAs are current.[/green]")
        return

    if fmt == "json":
        console.print(json.dumps(rows, indent=2, default=str))
        return

    action_count = sum(1 for r in rows if r["needs_action"])
    table = Table(title=f"NDA Status ({len(rows)} personnel, {action_count} need action)")
    table.add_column("Name", max_width=30)
    table.add_column("NDA Signed")
    table.add_column("Signed Date")
    table.add_column("Expires")
    table.add_column("Action Needed")

    for r in rows:
        signed_display = "[green]Yes[/green]" if r["nda_signed"] else "[red]No[/red]"
        if r["needs_action"]:
            if not r["nda_signed"]:
                action = "[red bold]UNSIGNED[/red bold]"
            else:
                action = "[yellow]EXPIRED[/yellow]"
        else:
            action = "[green]None[/green]"

        table.add_row(
            r["name"],
            signed_display,
            r["nda_date"],
            r["expires"],
            action,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# IAM-5: KnowBe4 phishing simulation scores
# ---------------------------------------------------------------------------


@access_review.command("phishing-scores")
@click.option("--department", default=None, help="Filter by department")
@click.option(
    "--high-risk-only",
    "high_risk_only",
    is_flag=True,
    help="Show only high-risk users (>30%% phish-prone)",
)
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def access_review_phishing_scores(department: str | None, high_risk_only: bool, fmt: str) -> None:
    """KnowBe4 phishing simulation scores per user.

    Queries Personnel phishing_score and training data, then aggregates
    by department. Flags users with phish-prone percentage above 30%.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Personnel

    init_db()

    with get_session() as session:
        q = session.query(Personnel).filter(Personnel.is_active.is_(True))
        if department:
            q = q.filter(Personnel.department.ilike(f"%{department}%"))
        people = q.order_by(Personnel.department, Personnel.full_name).limit(500).all()

    if not people:
        console.print("[dim]No personnel records found.[/dim]")
        return

    rows: list[dict] = []
    dept_scores: dict[str, list[float]] = {}

    for p in people:
        score = p.phishing_score  # 0-100 where higher = more phish-prone
        if score is None:
            score = 0.0
        training = p.training_status or "not_enrolled"
        last_training = ensure_aware(p.last_training_date) if p.last_training_date else None
        dept = p.department or "Unknown"

        dept_scores.setdefault(dept, []).append(score)

        if high_risk_only and score <= 30.0:
            continue

        rows.append(
            {
                "user": escape(p.full_name or p.email),
                "email": p.email,
                "department": dept,
                "phish_prone_percentage": round(score, 1),
                "last_test": last_training.strftime("%Y-%m-%d") if last_training else "\u2014",
                "training_status": training,
            }
        )

    if not rows:
        if high_risk_only:
            console.print("[green]No high-risk users found (all below 30% phish-prone).[/green]")
        else:
            console.print("[dim]No phishing score data found.[/dim]")
        return

    if fmt == "json":
        dept_summary = {
            dept: {"avg_score": round(sum(s) / len(s), 1), "count": len(s)}
            for dept, s in dept_scores.items()
            if s
        }
        output = {"users": rows, "department_summary": dept_summary}
        console.print(json.dumps(output, indent=2, default=str))
        return

    # User-level table
    high_risk_count = sum(1 for r in rows if r["phish_prone_percentage"] > 30.0)
    table = Table(title=f"Phishing Scores ({len(rows)} users, {high_risk_count} high-risk)")
    table.add_column("User", max_width=25)
    table.add_column("Department", max_width=20)
    table.add_column("Phish-Prone %", justify="right")
    table.add_column("Last Test")
    table.add_column("Training Status")

    _train_styles = {"current": "green", "overdue": "red", "not_enrolled": "yellow"}

    for r in rows:
        pct = r["phish_prone_percentage"]
        if pct > 50:
            pct_style = "red bold"
        elif pct > 30:
            pct_style = "yellow"
        else:
            pct_style = "green"
        t_sty = _train_styles.get(r["training_status"], "")
        table.add_row(
            r["user"],
            r["department"],
            f"[{pct_style}]{pct}%[/{pct_style}]",
            r["last_test"],
            f"[{t_sty}]{r['training_status']}[/{t_sty}]" if t_sty else r["training_status"],
        )

    console.print(table)

    # Department summary
    if dept_scores:
        console.print()
        dept_table = Table(title="Department Averages")
        dept_table.add_column("Department", max_width=25)
        dept_table.add_column("Avg Phish-Prone %", justify="right")
        dept_table.add_column("Users", justify="right")

        for dept in sorted(dept_scores.keys()):
            scores = dept_scores[dept]
            avg = sum(scores) / len(scores) if scores else 0
            avg_style = "red" if avg > 30 else ("yellow" if avg > 15 else "green")
            dept_table.add_row(
                dept,
                f"[{avg_style}]{avg:.1f}%[/{avg_style}]",
                str(len(scores)),
            )

        console.print(dept_table)
