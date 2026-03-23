"""Incident management commands.

Uses the Issue model, which handles incidents via classification/severity.
Incidents are Issues with explicit severity and classification metadata.
"""

from __future__ import annotations

import json as _json
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
}

_STATUS_STYLES: dict[str, str] = {
    "open": "yellow",
    "assigned": "cyan",
    "in_progress": "blue",
    "remediated": "green",
    "verified": "green bold",
    "closed": "dim",
    "risk_accepted": "magenta",
}

_VALID_STATUSES = [
    "open",
    "assigned",
    "in_progress",
    "remediated",
    "verified",
    "closed",
    "risk_accepted",
]
_VALID_SEVERITIES = ["critical", "high", "medium", "low"]


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("incidents", invoke_without_command=True)
@click.pass_context
def incidents(ctx: click.Context) -> None:
    """Incident lifecycle management (create, track, resolve, report)."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


@incidents.command("create")
@click.option(
    "--severity",
    "-s",
    required=True,
    type=click.Choice(_VALID_SEVERITIES),
    help="Incident severity level",
)
@click.option("--classification", "-c", required=True, help="Incident classification/type")
@click.option("--title", "-t", required=True, help="Short incident title")
@click.option("--description", "-d", default=None, help="Full incident description")
def incidents_create(
    severity: str,
    classification: str,
    title: str,
    description: str | None,
) -> None:
    """Create a new incident."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, Issue

    import hashlib
    import uuid

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        issue = Issue(
            id=str(uuid.uuid4()),
            title=title,
            description=description,
            status="open",
            priority=severity,
            source="manual",
            tags=[classification],
            created_by=actor,
            created_at=now,
            updated_at=now,
        )
        session.add(issue)

        # Audit entry
        last = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        prev_hash = last.entry_hash if last else "genesis"
        seq = (last.sequence + 1) if last else 1
        payload = f"{seq}:{prev_hash}:incident_created:{issue.id}:{actor}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()

        audit = AuditEntry(
            id=str(uuid.uuid4()),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="incident_created",
            entity_type="issue",
            entity_id=issue.id,
            actor=actor,
            extra={
                "severity": severity,
                "classification": classification,
                "title": title,
            },
            created_at=now,
        )
        session.add(audit)
        session.commit()

        console.print(
            f"[green]Incident created:[/green] [cyan]{issue.id[:8]}[/cyan] "
            f"[{_SEVERITY_STYLES.get(severity, '')}]{severity}[/] — {escape(title)}"
        )


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@incidents.command("list")
@click.option("--severity", "-s", default=None, type=click.Choice(_VALID_SEVERITIES + [""]))
@click.option(
    "--status",
    default=None,
    type=click.Choice(_VALID_STATUSES + [""]),
    help="Filter by status",
)
@click.option("--since", default=None, help="ISO date lower bound (e.g. 2026-01-01)")
@click.option("--limit", "-n", default=50, help="Max results")
@click.option(
    "--format", "fmt", default="table", type=click.Choice(["table", "json"]), help="Output format"
)
def incidents_list(
    severity: str | None,
    status: str | None,
    since: str | None,
    limit: int,
    fmt: str,
) -> None:
    """List incidents (open/investigating by default)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    init_db()
    with get_session() as session:
        q = session.query(Issue)
        if status:
            q = q.filter(Issue.status == status)
        else:
            q = q.filter(Issue.status.notin_(["closed"]))
        if severity:
            q = q.filter(Issue.priority == severity)
        if since:
            try:
                since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
                q = q.filter(Issue.created_at >= since_dt)
            except ValueError:
                _error(f"Invalid --since date: {since}. Use ISO format e.g. 2026-01-01")
        rows = q.order_by(Issue.created_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No incidents found.[/dim]")
        return

    if fmt == "json":
        out = [
            {
                "id": i.id,
                "title": i.title,
                "severity": i.priority,
                "status": i.status,
                "classification": (i.tags or [None])[0],
                "created_at": i.created_at.isoformat() if i.created_at else None,
                "assigned_to": i.assigned_to,
            }
            for i in rows
        ]
        console.print(_json.dumps(out, indent=2, default=str))
        return

    table = Table(title=f"Incidents ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Title", max_width=50)
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Classification", style="dim")
    table.add_column("Assigned", style="dim")
    table.add_column("Created", style="dim")

    for i in rows:
        sev_style = _SEVERITY_STYLES.get(i.priority, "")
        st_style = _STATUS_STYLES.get(i.status, "")
        classification = (i.tags or [None])[0] or "\u2014"
        created = i.created_at.strftime("%Y-%m-%d") if i.created_at else "\u2014"
        table.add_row(
            i.id[:8],
            escape(i.title[:50]),
            f"[{sev_style}]{i.priority}[/]",
            f"[{st_style}]{i.status}[/]",
            escape(classification),
            escape(i.assigned_to or "\u2014"),
            created,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@incidents.command("show")
@click.argument("incident_id")
def incidents_show(incident_id: str) -> None:
    """Show full detail for an incident."""
    from rich.panel import Panel

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    init_db()
    with get_session() as session:
        issue = session.query(Issue).filter(Issue.id.startswith(incident_id)).first()
        if not issue:
            _error(f"Incident not found: {incident_id}")

        sev_style = _SEVERITY_STYLES.get(issue.priority, "")
        st_style = _STATUS_STYLES.get(issue.status, "")
        classification = (issue.tags or ["\u2014"])[0]

        console.print()
        console.print(
            Panel(
                f"[bold]{escape(issue.title)}[/bold]\n\n"
                f"ID: {issue.id}  |  Severity: [{sev_style}]{issue.priority}[/]  |  "
                f"Status: [{st_style}]{issue.status}[/]\n"
                f"Classification: {escape(classification)}  |  "
                f"Assigned: {escape(issue.assigned_to or 'unassigned')}\n"
                f"Created: {issue.created_at}  |  Updated: {issue.updated_at}",
                title="[bold red]Incident[/bold red]",
                border_style="red",
            )
        )

        if issue.description:
            console.print(f"\n[bold]Description:[/bold]\n{escape(issue.description)}")

        if issue.remediation_plan:
            console.print(f"\n[bold]Remediation Plan:[/bold]\n{escape(issue.remediation_plan)}")

        if issue.remediation_evidence:
            console.print("\n[bold]Evidence:[/bold]")
            for ev in issue.remediation_evidence:
                console.print(
                    f"  - {escape(ev.get('description', ''))} ({escape(ev.get('url', ''))})"
                )

        console.print(
            f"\n[dim]Framework: {issue.framework or 'n/a'}  "
            f"Control: {issue.control_id or 'n/a'}[/dim]"
        )
        console.print()


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------


@incidents.command("update")
@click.argument("incident_id")
@click.option(
    "--status",
    "-s",
    required=True,
    type=click.Choice(_VALID_STATUSES),
    help="New status",
)
@click.option("--note", default=None, help="Optional note to add alongside the status change")
def incidents_update(incident_id: str, status: str, note: str | None) -> None:
    """Update the status of an incident."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, Issue, IssueComment

    import hashlib
    import uuid

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        issue = session.query(Issue).filter(Issue.id.startswith(incident_id)).first()
        if not issue:
            _error(f"Incident not found: {incident_id}")

        old_status = issue.status
        issue.status = status
        issue.updated_at = now

        if note:
            comment = IssueComment(
                id=str(uuid.uuid4()),
                issue_id=issue.id,
                author=actor,
                content=note,
                comment_type="status_change",
                created_at=now,
            )
            session.add(comment)

        # Audit
        last = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        prev_hash = last.entry_hash if last else "genesis"
        seq = (last.sequence + 1) if last else 1
        payload = f"{seq}:{prev_hash}:incident_updated:{issue.id}:{actor}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()

        audit = AuditEntry(
            id=str(uuid.uuid4()),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="incident_updated",
            entity_type="issue",
            entity_id=issue.id,
            actor=actor,
            extra={"old_status": old_status, "new_status": status, "note": note},
            created_at=now,
        )
        session.add(audit)
        session.commit()

    st_style = _STATUS_STYLES.get(status, "")
    console.print(
        f"[green]Incident {incident_id[:8]} updated:[/green] "
        f"{old_status} \u2192 [{st_style}]{status}[/]"
    )


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


@incidents.command("close")
@click.argument("incident_id")
@click.option("--resolution", "-r", required=True, help="Resolution summary")
@click.option("--lessons-learned", default=None, help="Lessons learned from this incident")
def incidents_close(incident_id: str, resolution: str, lessons_learned: str | None) -> None:
    """Close an incident with a resolution and optional lessons learned."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, Issue, IssueComment

    import hashlib
    import uuid

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        issue = session.query(Issue).filter(Issue.id.startswith(incident_id)).first()
        if not issue:
            _error(f"Incident not found: {incident_id}")

        issue.status = "closed"
        issue.closed_at = now
        issue.updated_at = now
        issue.remediation_plan = resolution

        # Store lessons learned as a comment
        content = f"Resolution: {resolution}"
        if lessons_learned:
            content += f"\n\nLessons Learned: {lessons_learned}"

        comment = IssueComment(
            id=str(uuid.uuid4()),
            issue_id=issue.id,
            author=actor,
            content=content,
            comment_type="status_change",
            created_at=now,
        )
        session.add(comment)

        last = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        prev_hash = last.entry_hash if last else "genesis"
        seq = (last.sequence + 1) if last else 1
        payload = f"{seq}:{prev_hash}:incident_closed:{issue.id}:{actor}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()

        audit = AuditEntry(
            id=str(uuid.uuid4()),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="incident_closed",
            entity_type="issue",
            entity_id=issue.id,
            actor=actor,
            extra={"resolution": resolution, "lessons_learned": lessons_learned},
            created_at=now,
        )
        session.add(audit)
        session.commit()

    console.print(f"[green]Incident {incident_id[:8]} closed.[/green]")
    console.print(f"  Resolution: {escape(resolution)}")
    if lessons_learned:
        console.print(f"  Lessons learned: {escape(lessons_learned)}")


# ---------------------------------------------------------------------------
# timeline
# ---------------------------------------------------------------------------


@incidents.command("timeline")
@click.argument("incident_id")
def incidents_timeline(incident_id: str) -> None:
    """Show audit trail events for an incident."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, Issue

    init_db()
    with get_session() as session:
        issue = session.query(Issue).filter(Issue.id.startswith(incident_id)).first()
        if not issue:
            _error(f"Incident not found: {incident_id}")

        entries = (
            session.query(AuditEntry)
            .filter(AuditEntry.entity_id == issue.id)
            .order_by(AuditEntry.created_at.asc())
            .all()
        )

    if not entries:
        console.print("[dim]No audit trail events found for this incident.[/dim]")
        return

    table = Table(title=f"Timeline: Incident {issue.id[:8]}")
    table.add_column("Seq", style="dim", justify="right")
    table.add_column("Timestamp", style="dim")
    table.add_column("Action", style="cyan")
    table.add_column("Actor", style="dim")
    table.add_column("Details", max_width=60)

    for e in entries:
        ts = e.created_at.strftime("%Y-%m-%d %H:%M:%S") if e.created_at else "\u2014"
        details = _json.dumps(e.extra, default=str) if e.extra else ""
        table.add_row(str(e.sequence), ts, e.action, e.actor, escape(details[:60]))

    console.print(table)


# ---------------------------------------------------------------------------
# add-event
# ---------------------------------------------------------------------------


@incidents.command("add-event")
@click.argument("incident_id")
@click.option("--type", "event_type", required=True, help="Event type/action label")
@click.option("--description", "-d", required=True, help="Event description")
def incidents_add_event(incident_id: str, event_type: str, description: str) -> None:
    """Append a manual event to an incident's audit trail."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, Issue

    import hashlib
    import uuid

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        issue = session.query(Issue).filter(Issue.id.startswith(incident_id)).first()
        if not issue:
            _error(f"Incident not found: {incident_id}")

        last = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        prev_hash = last.entry_hash if last else "genesis"
        seq = (last.sequence + 1) if last else 1
        payload = f"{seq}:{prev_hash}:{event_type}:{issue.id}:{actor}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()

        audit = AuditEntry(
            id=str(uuid.uuid4()),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action=event_type,
            entity_type="issue",
            entity_id=issue.id,
            actor=actor,
            extra={"description": description},
            created_at=now,
        )
        session.add(audit)
        session.commit()

    console.print(
        f"[green]Event added to incident {incident_id[:8]}:[/green] {escape(event_type)} — {escape(description)}"
    )


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@incidents.command("report")
@click.argument("incident_id")
@click.option(
    "--format", "fmt", default="md", type=click.Choice(["md", "json"]), help="Output format"
)
def incidents_report(incident_id: str, fmt: str) -> None:
    """Generate a post-mortem report for an incident."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, Issue, IssueComment

    init_db()
    with get_session() as session:
        issue = session.query(Issue).filter(Issue.id.startswith(incident_id)).first()
        if not issue:
            _error(f"Incident not found: {incident_id}")

        comments = (
            session.query(IssueComment)
            .filter(IssueComment.issue_id == issue.id)
            .order_by(IssueComment.created_at.asc())
            .all()
        )
        entries = (
            session.query(AuditEntry)
            .filter(AuditEntry.entity_id == issue.id)
            .order_by(AuditEntry.created_at.asc())
            .all()
        )

    classification = (issue.tags or ["\u2014"])[0]

    if fmt == "json":
        report = {
            "id": issue.id,
            "title": issue.title,
            "severity": issue.priority,
            "classification": classification,
            "status": issue.status,
            "description": issue.description,
            "resolution": issue.remediation_plan,
            "created_at": issue.created_at.isoformat() if issue.created_at else None,
            "closed_at": issue.closed_at.isoformat() if issue.closed_at else None,
            "assigned_to": issue.assigned_to,
            "timeline": [
                {
                    "seq": e.sequence,
                    "timestamp": e.created_at.isoformat() if e.created_at else None,
                    "action": e.action,
                    "actor": e.actor,
                    "details": e.extra,
                }
                for e in entries
            ],
            "comments": [
                {
                    "author": c.author,
                    "content": c.content,
                    "type": c.comment_type,
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                }
                for c in comments
            ],
        }
        console.print(_json.dumps(report, indent=2, default=str))
        return

    # Markdown
    lines = [
        f"# Post-Mortem Report: {escape(issue.title)}",
        "",
        f"**ID:** {issue.id}  ",
        f"**Severity:** {issue.priority}  ",
        f"**Classification:** {escape(classification)}  ",
        f"**Status:** {issue.status}  ",
        f"**Created:** {issue.created_at}  ",
        f"**Closed:** {issue.closed_at or 'N/A'}  ",
        f"**Assigned to:** {issue.assigned_to or 'N/A'}  ",
        "",
        "## Description",
        "",
        escape(issue.description) if issue.description else "_No description provided._",
        "",
        "## Resolution",
        "",
        escape(issue.remediation_plan) if issue.remediation_plan else "_Not yet resolved._",
        "",
        "## Timeline",
        "",
    ]
    for e in entries:
        ts = e.created_at.strftime("%Y-%m-%d %H:%M:%S") if e.created_at else "?"
        details = _json.dumps(e.extra, default=str) if e.extra else ""
        lines.append(f"- `{ts}` **{escape(e.action)}** by {escape(e.actor)} — {escape(details)}")

    if comments:
        lines += ["", "## Comments", ""]
        for c in comments:
            ts = c.created_at.strftime("%Y-%m-%d %H:%M:%S") if c.created_at else "?"
            lines.append(f"- `{ts}` **{escape(c.author)}**: {escape(c.content)}")

    console.print("\n".join(lines))


# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------


@incidents.command("metrics")
@click.option("--since", default=None, help="ISO date lower bound (e.g. 2026-01-01)")
def incidents_metrics(since: str | None) -> None:
    """Show MTTR, frequency by category, and severity distribution."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    init_db()
    with get_session() as session:
        q = session.query(Issue)
        if since:
            try:
                since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
                q = q.filter(Issue.created_at >= since_dt)
            except ValueError:
                _error(f"Invalid --since date: {since}")
        rows = q.all()

    if not rows:
        console.print("[dim]No incidents found for the given period.[/dim]")
        return

    # MTTR (mean time to resolve)
    resolved = [
        i for i in rows if i.status in ("resolved", "closed") and i.created_at and i.updated_at
    ]
    if resolved:
        mttr_seconds = sum((i.updated_at - i.created_at).total_seconds() for i in resolved) / len(
            resolved
        )
        mttr_hours = mttr_seconds / 3600
        mttr_str = f"{mttr_hours:.1f}h"
    else:
        mttr_str = "\u2014"

    # Severity distribution
    sev_counts: dict[str, int] = {}
    for i in rows:
        sev_counts[i.priority] = sev_counts.get(i.priority, 0) + 1

    # Category frequency
    cat_counts: dict[str, int] = {}
    for i in rows:
        cat = (i.tags or ["uncategorized"])[0]
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    # Status distribution
    status_counts: dict[str, int] = {}
    for i in rows:
        status_counts[i.status] = status_counts.get(i.status, 0) + 1

    summary = Table(title="Incident Metrics")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value")
    summary.add_row("Total incidents", str(len(rows)))
    summary.add_row("Resolved/Closed", str(len(resolved)))
    summary.add_row("MTTR", mttr_str)
    console.print(summary)

    sev_table = Table(title="Severity Distribution")
    sev_table.add_column("Severity")
    sev_table.add_column("Count", justify="right")
    for sev in _VALID_SEVERITIES:
        count = sev_counts.get(sev, 0)
        style = _SEVERITY_STYLES.get(sev, "")
        sev_table.add_row(f"[{style}]{sev}[/]", str(count))
    console.print(sev_table)

    cat_table = Table(title="Frequency by Classification")
    cat_table.add_column("Classification")
    cat_table.add_column("Count", justify="right")
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        cat_table.add_row(escape(cat), str(count))
    console.print(cat_table)

    st_table = Table(title="Status Distribution")
    st_table.add_column("Status")
    st_table.add_column("Count", justify="right")
    for st, count in sorted(status_counts.items(), key=lambda x: -x[1]):
        style = _STATUS_STYLES.get(st, "")
        st_table.add_row(f"[{style}]{st}[/]", str(count))
    console.print(st_table)


# ---------------------------------------------------------------------------
# link
# ---------------------------------------------------------------------------


@incidents.command("link")
@click.argument("incident_id")
@click.option("--finding", required=True, help="Finding ID to link to this incident")
def incidents_link(incident_id: str, finding: str) -> None:
    """Link a finding to an incident."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    init_db()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        issue = session.query(Issue).filter(Issue.id.startswith(incident_id)).first()
        if not issue:
            _error(f"Incident not found: {incident_id}")

        issue.finding_id = finding
        issue.updated_at = now
        session.commit()

    console.print(f"[green]Incident {incident_id[:8]} linked to finding {finding[:8]}[/green]")


# ---------------------------------------------------------------------------
# responders
# ---------------------------------------------------------------------------


@incidents.command("responders")
@click.argument("incident_id")
@click.option("--add", "add_user", default=None, help="User ID/email to add as responder")
@click.option("--remove", "remove_user", default=None, help="User ID/email to remove as responder")
def incidents_responders(incident_id: str, add_user: str | None, remove_user: str | None) -> None:
    """Manage responders (assigned_to) for an incident.

    Without --add or --remove, shows the current responder.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    init_db()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        issue = session.query(Issue).filter(Issue.id.startswith(incident_id)).first()
        if not issue:
            _error(f"Incident not found: {incident_id}")

        if not add_user and not remove_user:
            console.print(f"[bold]Responder:[/bold] {issue.assigned_to or '[dim]unassigned[/dim]'}")
            return

        actor = _get_actor()

        if add_user:
            issue.assigned_to = add_user
            issue.assigned_by = actor
            issue.assigned_at = now
            issue.updated_at = now
            session.commit()
            console.print(f"[green]Incident {incident_id[:8]}:[/green] responder set to {add_user}")

        if remove_user:
            if issue.assigned_to != remove_user:
                console.print(
                    f"[yellow]{remove_user} is not the current responder "
                    f"(current: {issue.assigned_to or 'none'}).[/yellow]"
                )
            else:
                issue.assigned_to = None
                issue.updated_at = now
                session.commit()
                console.print(
                    f"[green]Incident {incident_id[:8]}:[/green] responder {remove_user} removed"
                )
