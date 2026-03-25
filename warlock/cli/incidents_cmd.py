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
@click.argument("incident_id", required=False, default=None)
@click.option(
    "--format", "fmt", default="md", type=click.Choice(["md", "json"]), help="Output format"
)
def incidents_report(incident_id: str | None, fmt: str) -> None:
    """Generate a post-mortem report for an incident.

    When INCIDENT_ID is omitted, shows a summary report of all incidents.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, Issue, IssueComment
    from warlock.utils import ensure_aware

    init_db()

    if incident_id is None:
        # Summary report of all incidents
        with get_session() as session:
            issues = session.query(Issue).order_by(Issue.created_at.desc()).limit(50).all()
        if not issues:
            console.print("[dim]No incidents found.[/dim]")
            return

        table = Table(title=f"Incident Summary ({len(issues)} most recent)")
        table.add_column("ID", style="dim", max_width=8)
        table.add_column("Title", max_width=50)
        table.add_column("Priority")
        table.add_column("Status")
        table.add_column("Created", style="dim")

        for i in issues:
            ts = ensure_aware(i.created_at).strftime("%Y-%m-%d") if i.created_at else "\u2014"
            table.add_row(
                i.id[:8],
                escape((i.title or "")[:50]),
                i.priority or "\u2014",
                i.status or "\u2014",
                ts,
            )
        console.print(table)
        return

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
# playbook — display playbook steps
# ---------------------------------------------------------------------------


@incidents.command("playbook")
@click.argument("incident_type", required=False, default=None)
def incidents_playbook(incident_type: str | None) -> None:
    """Display incident response playbook steps.

    Without INCIDENT_TYPE, lists all available playbooks.
    With INCIDENT_TYPE, shows the full playbook phases and steps.
    """
    from warlock.workflows.incident_playbooks import PlaybookLibrary

    lib = PlaybookLibrary()

    if not incident_type:
        # List all playbooks
        playbooks = lib.list_playbooks()
        table = Table(title="Available Incident Playbooks")
        table.add_column("Type", style="cyan")
        table.add_column("Name")
        table.add_column("Severity")
        table.add_column("Phases", justify="right")
        table.add_column("Steps", justify="right")
        table.add_column("Description", max_width=50)

        for pb in playbooks:
            sev_style = _SEVERITY_STYLES.get(pb["severity"], "")
            table.add_row(
                pb["type"],
                pb["name"],
                f"[{sev_style}]{pb['severity']}[/]",
                str(pb["phase_count"]),
                str(pb["total_steps"]),
                pb["description"][:50],
            )

        console.print(table)
        console.print(
            "\n[dim]Tip: run 'warlock incidents playbook <type>' to view full playbook steps.[/dim]"
        )
        return

    playbook = lib.get_playbook(incident_type)
    if not playbook:
        _error(
            f"Unknown playbook type: {incident_type}. "
            f"Available: {', '.join(t['type'] for t in lib.list_playbooks())}"
        )

    sev_style = _SEVERITY_STYLES.get(playbook["severity"], "")
    console.print(
        f"\n[bold]{escape(playbook['name'])}[/bold]  [{sev_style}]{playbook['severity']}[/]"
    )
    console.print(f"[dim]{escape(playbook['description'])}[/dim]\n")

    for pi, phase in enumerate(playbook["phases"]):
        console.print(f"[bold cyan]Phase {pi + 1}: {escape(phase['name'])}[/bold cyan]")

        for si, step in enumerate(phase["steps"]):
            console.print(
                f"  [{pi}.{si}] [bold]{escape(step['role'])}[/bold] ({escape(step['timeframe'])})"
            )
            console.print(f"        {escape(step['action'])}")
            for item in step.get("checklist", []):
                console.print(f"          [dim]- {escape(item)}[/dim]")
            console.print()


# ---------------------------------------------------------------------------
# playbook-progress — show execution progress
# ---------------------------------------------------------------------------


@incidents.command("playbook-progress")
@click.argument("incident_id")
@click.option(
    "--type",
    "playbook_type",
    required=True,
    type=click.Choice(["data_breach", "ransomware", "insider_threat", "ddos"]),
    help="Playbook type to check progress for",
)
def incidents_playbook_progress(incident_id: str, playbook_type: str) -> None:
    """Show playbook execution progress for an incident."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue
    from warlock.workflows.incident_playbooks import PlaybookLibrary

    init_db()
    lib = PlaybookLibrary()

    with get_session() as session:
        issue = session.query(Issue).filter(Issue.id.startswith(incident_id)).first()
        if not issue:
            _error(f"Incident not found: {incident_id}")

        progress = lib.get_progress(session, issue.id, playbook_type)

    console.print(
        f"\n[bold]{escape(progress['playbook_name'])}[/bold] -- Incident {incident_id[:8]}"
    )
    console.print(
        f"Progress: [cyan]{progress['completed_steps']}/{progress['total_steps']}[/cyan] "
        f"steps ({progress['percent_complete']}%)\n"
    )

    for phase in progress["phases"]:
        phase_label = (
            "[green]DONE[/green]"
            if phase["completed_steps"] == phase["total_steps"]
            else f"{phase['completed_steps']}/{phase['total_steps']}"
        )
        console.print(
            f"[bold]Phase {phase['phase_index'] + 1}: "
            f"{escape(phase['phase_name'])}[/bold] [{phase_label}]"
        )

        for step in phase["steps"]:
            if step["completed"]:
                icon = "[green]x[/green]"
                detail = f" (by {escape(step.get('actor', '?'))})"
            else:
                icon = "[dim]o[/dim]"
                detail = ""
            console.print(f"  [{icon}] {escape(step['role'])}: {escape(step['action'])}{detail}")
        console.print()


# ---------------------------------------------------------------------------
# communicate — render communication template
# ---------------------------------------------------------------------------


@incidents.command("communicate")
@click.argument("incident_id")
@click.option(
    "--template",
    "-t",
    "template_name",
    required=True,
    type=click.Choice(
        [
            "initial_notification",
            "status_update",
            "resolution_notice",
            "regulatory_notification",
        ]
    ),
    help="Communication template to render",
)
@click.option("--commander", default=None, help="Incident commander name")
@click.option("--contact", default=None, help="Contact info for response team")
@click.option("--update-number", default="1", help="Update sequence number (for status_update)")
def incidents_communicate(
    incident_id: str,
    template_name: str,
    commander: str | None,
    contact: str | None,
    update_number: str,
) -> None:
    """Render a crisis communication template for an incident."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue
    from warlock.workflows.incident_playbooks import render_template

    init_db()
    with get_session() as session:
        issue = session.query(Issue).filter(Issue.id.startswith(incident_id)).first()
        if not issue:
            _error(f"Incident not found: {incident_id}")

        classification = (issue.tags or ["unclassified"])[0]
        detected_at = (
            issue.created_at.strftime("%Y-%m-%d %H:%M UTC") if issue.created_at else "unknown"
        )

        context = {
            "incident_id": issue.id,
            "incident_title": issue.title,
            "severity": issue.priority or "unknown",
            "classification": classification,
            "status": issue.status,
            "description": issue.description or "No description provided.",
            "detected_at": detected_at,
            "commander": commander or issue.assigned_to or "unassigned",
            "contact": contact or "incident-response@organization.com",
            "update_interval": "2 hours",
            "update_number": update_number,
            "elapsed": "calculating...",
            "progress": "See incident timeline for details.",
            "current_actions": "See active playbook steps.",
            "next_steps": "Will be determined by incident commander.",
            "next_update_time": "Per update interval.",
            "duration": "calculating...",
            "resolved_at": (
                issue.closed_at.strftime("%Y-%m-%d %H:%M UTC") if issue.closed_at else "N/A"
            ),
            "root_cause": "To be determined in post-mortem.",
            "resolution": issue.remediation_plan or "Not yet resolved.",
            "impact_summary": "To be determined.",
            "preventive_measures": "To be determined in post-mortem.",
            "postmortem_deadline": "5 business days",
            "organization": "Organization",
            "contact_name": commander or "DPO",
            "contact_title": "Data Protection Officer",
            "contact_email": contact or "dpo@organization.com",
            "contact_phone": "[NOT PROVIDED]",
            "discovery_date": detected_at,
            "notification_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "deadline": "72 hours from discovery (GDPR) / 4 business days (SEC)",
            "regulation": "GDPR Article 33 / SEC Rule 10-K",
            "breach_description": issue.description or "See incident details.",
            "data_categories": "[NOT PROVIDED]",
            "affected_count": "[NOT PROVIDED]",
            "consequences": "[NOT PROVIDED]",
            "measures_taken": "See incident timeline.",
            "measures_proposed": "See remediation plan.",
        }

    try:
        rendered = render_template(template_name, context)
    except ValueError as exc:
        _error(str(exc))

    from rich.panel import Panel

    console.print(
        Panel(
            f"[bold]Subject:[/bold] {escape(rendered['subject'])}\n\n{escape(rendered['body'])}",
            title=f"[bold cyan]{escape(rendered['name'])}[/bold cyan]",
            border_style="cyan",
        )
    )


# ---------------------------------------------------------------------------
# mobile-approve — API stub (UX-9)
# ---------------------------------------------------------------------------


@incidents.command("mobile-approve")
@click.argument("incident_id")
def incidents_mobile_approve(incident_id: str) -> None:
    """Stub: mobile approval API endpoint for incident actions.

    This command displays the API endpoint that will be used for
    mobile-based incident approvals once the mobile gateway is deployed.
    """
    console.print(
        f"[bold]Mobile Approval API Endpoint:[/bold]\n"
        f"  POST /api/v1/incidents/{escape(incident_id)}/approve\n\n"
        f"[dim]Request body:[/dim]\n"
        f'  {{"approver": "<user_id>", "action": "approve|reject", '
        f'"comment": "<optional>"}}\n\n'
        f"[dim]Authentication: Bearer token (OAuth 2.0 / OIDC)\n"
        f"Push notification will be sent to assigned approvers.\n"
        f"This endpoint is not yet active -- pending mobile gateway deployment.[/dim]"
    )


# ---------------------------------------------------------------------------
# offline-collect — API stub (UX-10)
# ---------------------------------------------------------------------------


@incidents.command("offline-collect")
def incidents_offline_collect() -> None:
    """Stub: instructions for offline evidence collection and later sync.

    Provides guidance for collecting incident evidence in environments
    without network connectivity, with sync instructions for when
    connectivity is restored.
    """
    console.print(
        "[bold]Offline Evidence Collection[/bold]\n\n"
        "[bold]Step 1: Collect evidence locally[/bold]\n"
        "  Save evidence files to a designated local directory:\n"
        "    mkdir -p ./warlock-offline-evidence/<incident_id>/\n\n"
        "  For each evidence item, create a JSON manifest:\n"
        '    {"file": "screenshot.png", "type": "screenshot", '
        '"description": "...", "collected_by": "...", '
        '"collected_at": "ISO8601", "sha256": "..."}\n\n'
        "[bold]Step 2: Compute integrity hashes[/bold]\n"
        "  sha256sum ./warlock-offline-evidence/<incident_id>/* > checksums.sha256\n\n"
        "[bold]Step 3: Sync when connectivity is restored[/bold]\n"
        "  POST /api/v1/incidents/<incident_id>/evidence/bulk-upload\n"
        "  Content-Type: multipart/form-data\n"
        "  Include the manifest JSON and all evidence files.\n\n"
        "[bold]Step 4: Verify integrity[/bold]\n"
        "  warlock incidents show <incident_id>\n"
        "  Verify uploaded evidence SHA-256 hashes match local checksums.\n\n"
        "[dim]The bulk upload endpoint and offline sync agent are pending "
        "implementation. Evidence can currently be attached manually via:\n"
        "  warlock incidents add-event <incident_id> --type evidence_collected "
        '--description "..."[/dim]'
    )


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
