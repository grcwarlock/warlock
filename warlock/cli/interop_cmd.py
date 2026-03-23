"""Cross-domain interoperability linkage commands.

Group: ``link``

Commands that connect findings to vendors, incidents to breaches,
systems to controls, changes to compliance impact, and training to
access reviews.  Each command is a GRC practitioner workflow that
crosses domain boundaries.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import click
from rich.panel import Panel
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("link")
def link() -> None:
    """Cross-domain interoperability commands."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_style(severity: str | None) -> str:
    return {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }.get((severity or "").lower(), "")


def _fmt_dt(dt: datetime | None) -> str:
    if dt is None:
        return "\u2014"
    return dt.strftime("%Y-%m-%d %H:%M")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# IO-001: link finding-vendor
# ---------------------------------------------------------------------------


@link.command("finding-vendor")
@click.argument("finding_id")
@click.argument("vendor_id")
def finding_vendor(finding_id: str, vendor_id: str) -> None:
    """Link a finding to a vendor and update vendor risk score.

    \b
    FINDING_ID: finding UUID or prefix.
    VENDOR_ID:  vendor UUID or prefix.

    Looks up the finding's severity and adjusts the vendor's risk score
    based on linked findings.  Creates a vendor-finding association record.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, Vendor

    init_db()
    now = _utcnow()

    with get_session() as session:
        finding = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not finding:
            _error(f"Finding not found: {finding_id}")

        vendor = session.query(Vendor).filter(Vendor.id.startswith(vendor_id)).first()
        if not vendor:
            _error(f"Vendor not found: {vendor_id}")

        # Calculate risk adjustment based on severity
        severity_weights = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 0,
        }
        # Count existing findings linked to this vendor
        linked_findings = (
            session.query(Finding)
            .filter(Finding.vendor_id == vendor.id)
            .all()
        )
        existing_count = len(linked_findings)

        # Link finding to vendor
        finding.vendor_id = vendor.id
        finding.updated_at = now

        # Recalculate vendor risk score from all linked findings
        all_linked = linked_findings + [finding]
        total_weight = sum(
            severity_weights.get((f.severity or "").lower(), 5) for f in all_linked
        )
        # Normalize to 0-100 scale, capped
        new_score = min(100, total_weight)
        old_score = vendor.risk_score or 0
        vendor.risk_score = new_score
        vendor.updated_at = now

        session.commit()

    sev_sty = _severity_style(finding.severity)
    console.print(
        Panel(
            f"[bold]Finding linked to vendor[/bold]\n\n"
            f"Finding:  {finding.id[:8]} \u2014 {(finding.title or '')[:60]}\n"
            f"Severity: [{sev_sty}]{finding.severity}[/]\n"
            f"Vendor:   {vendor.id[:8]} \u2014 {vendor.name or '\u2014'}\n\n"
            f"Linked findings: [bold]{existing_count + 1}[/bold]\n"
            f"Risk score:      [yellow]{old_score}[/yellow] \u2192 [bold yellow]{new_score}[/bold yellow]",
            title="[bold cyan]Finding \u2192 Vendor Link[/bold cyan]",
            border_style="cyan",
        )
    )


# ---------------------------------------------------------------------------
# IO-002: link incident-breach
# ---------------------------------------------------------------------------


@link.command("incident-breach")
@click.argument("incident_id")
@click.option(
    "--personal-data/--no-personal-data",
    default=None,
    help="Override personal data assessment (auto-detected if omitted)",
)
def incident_breach(incident_id: str, personal_data: bool | None) -> None:
    """Assess if incident involves personal data, create breach record, start 72h clock.

    \b
    INCIDENT_ID: issue UUID or prefix (from 'warlock incidents list').

    Checks whether the incident involves personal data. If so, creates a
    breach record with the 72-hour notification deadline (GDPR Art. 33),
    and auto-generates DSAR entries for affected data subjects.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    init_db()
    now = _utcnow()
    actor = _get_actor()

    with get_session() as session:
        incident = session.query(Issue).filter(Issue.id.startswith(incident_id)).first()
        if not incident:
            _error(f"Incident (issue) not found: {incident_id}")

        # Assess personal data involvement
        title_lower = (incident.title or "").lower()
        detail_str = json.dumps(incident.detail or {}, default=str).lower()
        pii_keywords = [
            "personal data", "pii", "email", "ssn", "social security",
            "credit card", "health record", "patient", "employee record",
            "customer data", "user data", "gdpr", "name and address",
            "date of birth", "passport", "driver license",
        ]
        auto_detected = any(kw in title_lower or kw in detail_str for kw in pii_keywords)

        involves_personal = personal_data if personal_data is not None else auto_detected

        console.print(
            Panel(
                f"[bold]{incident.title}[/bold]\n\n"
                f"ID:       {incident.id[:8]}\n"
                f"Status:   {incident.status}\n"
                f"Priority: {incident.priority}\n"
                f"Created:  {_fmt_dt(incident.created_at)}\n\n"
                f"Personal data detected: [bold]{'Yes' if auto_detected else 'No'}[/bold]\n"
                f"Personal data override: [bold]{personal_data if personal_data is not None else 'none'}[/bold]",
                title="[bold cyan]Incident Assessment[/bold cyan]",
                border_style="cyan",
            )
        )

        if not involves_personal:
            console.print(
                "[green]No personal data involvement detected.[/green] "
                "No breach record needed. Use --personal-data to override."
            )
            return

        # Create breach record as a new Issue linked to the incident
        deadline = now + timedelta(hours=72)
        breach_id = str(uuid.uuid4())
        breach = Issue(
            id=breach_id,
            title=f"BREACH: {incident.title}",
            description=(
                f"Breach record auto-generated from incident {incident.id[:8]}. "
                f"72-hour notification deadline: {deadline.strftime('%Y-%m-%d %H:%M UTC')}."
            ),
            status="open",
            priority="critical",
            category="breach",
            finding_id=incident.finding_id,
            control_id=incident.control_id,
            framework=incident.framework,
            created_by=actor,
            created_at=now,
            updated_at=now,
            detail={
                "breach_source_incident": incident.id,
                "personal_data_involved": True,
                "notification_deadline": deadline.isoformat(),
                "notification_sent": False,
                "dsar_generated": True,
                "auto_detected": auto_detected,
            },
        )
        session.add(breach)

        # Generate DSAR placeholder entry
        dsar_id = str(uuid.uuid4())
        dsar = Issue(
            id=dsar_id,
            title=f"DSAR: Data subject notification for breach {breach_id[:8]}",
            description=(
                f"Auto-generated DSAR for breach {breach_id[:8]}. "
                f"Review affected data subjects and send notifications before "
                f"{deadline.strftime('%Y-%m-%d %H:%M UTC')}."
            ),
            status="open",
            priority="high",
            category="dsar",
            created_by=actor,
            created_at=now,
            updated_at=now,
            detail={
                "breach_id": breach_id,
                "incident_id": incident.id,
                "notification_type": "data_subject_notification",
            },
        )
        session.add(dsar)

        # Update incident to reference the breach
        incident.detail = incident.detail or {}
        incident.detail["breach_record_id"] = breach_id
        incident.detail["breach_detected_at"] = now.isoformat()
        incident.updated_at = now

        session.commit()

    console.print(
        Panel(
            f"[bold red]Breach record created[/bold red]\n\n"
            f"Breach ID:   [cyan]{breach_id[:8]}[/cyan]\n"
            f"Source:      incident {incident.id[:8]}\n"
            f"Deadline:    [bold red]{deadline.strftime('%Y-%m-%d %H:%M UTC')}[/bold red] (72h)\n\n"
            f"DSAR ID:     [cyan]{dsar_id[:8]}[/cyan]\n"
            f"Status:      [yellow]open \u2014 awaiting review[/yellow]",
            title="[bold red]72-Hour Breach Clock Started[/bold red]",
            border_style="red",
        )
    )
    console.print(
        "[yellow]Action required:[/yellow] Review affected data subjects and send "
        "notifications before the 72-hour deadline."
    )


# ---------------------------------------------------------------------------
# IO-003: link system-controls
# ---------------------------------------------------------------------------


@link.command("system-controls")
@click.argument("system_id")
@click.option("--framework", "-f", default=None, help="Filter by framework (e.g. nist_800_53)")
@click.option("--limit", "-n", default=50, help="Max controls to show")
def system_controls(system_id: str, framework: str | None, limit: int) -> None:
    """Show a system's applicable controls, inherited controls, and implementation status.

    \b
    SYSTEM_ID: system profile UUID, prefix, or acronym.

    Displays all controls mapped to the system, their compliance status,
    and which controls are inherited from parent systems.
    """
    from warlock.cli import _resolve_system_id
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, SystemProfile

    init_db()
    with get_session() as session:
        resolved_id = _resolve_system_id(session, system_id)
        system = session.query(SystemProfile).filter(SystemProfile.id == resolved_id).first()
        if not system:
            _error(f"System not found: {system_id}")

        q = session.query(ControlResult).filter(ControlResult.system_profile_id == system.id)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.order_by(ControlResult.framework, ControlResult.control_id).limit(limit).all()

    if not results:
        console.print(
            f"[dim]No control results for system {system.name or system.id[:8]}"
            f"{' in ' + framework if framework else ''}.[/dim]"
        )
        return

    # Summary panel
    status_counts: dict[str, int] = {}
    frameworks_seen: set[str] = set()
    inherited_count = 0
    for r in results:
        status_counts[r.status] = status_counts.get(r.status, 0) + 1
        frameworks_seen.add(r.framework)
        if getattr(r, "inherited", False):
            inherited_count += 1

    console.print(
        Panel(
            f"System:       [bold]{system.name or '\u2014'}[/bold] ({system.id[:8]})\n"
            f"Acronym:      {getattr(system, 'acronym', '\u2014') or '\u2014'}\n"
            f"Frameworks:   {', '.join(sorted(frameworks_seen))}\n"
            f"Total results: [bold]{len(results)}[/bold]\n"
            f"Inherited:     [bold]{inherited_count}[/bold]",
            title="[bold cyan]System Controls[/bold cyan]",
            border_style="cyan",
        )
    )

    # Status summary
    status_styles = {
        "compliant": "green",
        "non_compliant": "red",
        "partial": "yellow",
        "not_assessed": "dim",
        "risk_accepted": "magenta",
    }
    status_parts = []
    for st, cnt in sorted(status_counts.items()):
        sty = status_styles.get(st, "")
        status_parts.append(f"[{sty}]{st}: {cnt}[/]")
    console.print("  " + "  ".join(status_parts) + "\n")

    # Detail table
    table = Table(title=f"Controls for {system.name or system.id[:8]}")
    table.add_column("Framework", style="cyan")
    table.add_column("Control ID", style="cyan")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Assessor", style="dim")
    table.add_column("Inherited", justify="center")
    table.add_column("Assessed", style="dim")

    for r in results:
        st_style = status_styles.get(r.status, "")
        sev_sty = _severity_style(getattr(r, "severity", None))
        inherited = "Y" if getattr(r, "inherited", False) else "\u2014"
        table.add_row(
            r.framework,
            r.control_id,
            f"[{st_style}]{r.status}[/]",
            f"[{sev_sty}]{r.severity or '\u2014'}[/]",
            (r.assessor or "")[:25],
            inherited,
            _fmt_dt(r.assessed_at),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# IO-004: link change-compliance
# ---------------------------------------------------------------------------


@link.command("change-compliance")
@click.argument("change_id")
def change_compliance(change_id: str) -> None:
    """Analyze which controls are affected by a change request.

    \b
    CHANGE_ID: change event UUID or prefix (from 'warlock changes list').

    Looks up the change event, finds associated systems and control results,
    and shows which controls may need re-assessment after the change.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ChangeEvent, ControlResult, Finding

    init_db()
    with get_session() as session:
        change = session.query(ChangeEvent).filter(ChangeEvent.id.startswith(change_id)).first()
        if not change:
            _error(f"Change event not found: {change_id}")

        # Show change details
        console.print(
            Panel(
                f"[bold]{change.action or 'Change event'}[/bold]\n\n"
                f"ID:          {change.id[:8]}\n"
                f"Source:      {change.source or '\u2014'}\n"
                f"System:      {change.system_profile_id[:8] if change.system_profile_id else '\u2014'}\n"
                f"Occurred:    {_fmt_dt(change.occurred_at)}\n"
                f"Detail:      {json.dumps(change.detail or {}, default=str)[:200]}",
                title="[bold cyan]Change Event[/bold cyan]",
                border_style="cyan",
            )
        )

        # Find affected controls via the change's system
        affected_controls: list[ControlResult] = []
        if change.system_profile_id:
            affected_controls = (
                session.query(ControlResult)
                .filter(ControlResult.system_profile_id == change.system_profile_id)
                .order_by(ControlResult.framework, ControlResult.control_id)
                .limit(50)
                .all()
            )

        # Also look for findings around the same time window
        if change.occurred_at:
            window_start = change.occurred_at - timedelta(hours=24)
            window_end = change.occurred_at + timedelta(hours=24)
            nearby_findings = (
                session.query(Finding)
                .filter(Finding.observed_at.between(window_start, window_end))
                .limit(20)
                .all()
            )
        else:
            nearby_findings = []

    if not affected_controls and not nearby_findings:
        console.print("[dim]No controls or findings directly associated with this change.[/dim]")
        return

    if affected_controls:
        frameworks_affected = list({r.framework for r in affected_controls})
        non_compliant = [r for r in affected_controls if r.status == "non_compliant"]

        console.print(
            f"\n[bold]Controls potentially affected: {len(affected_controls)}[/bold]"
        )
        console.print(
            f"  Frameworks: {', '.join(sorted(frameworks_affected))}"
        )
        console.print(
            f"  Already non-compliant: [red]{len(non_compliant)}[/red]"
        )

        table = Table(title="Controls requiring re-assessment")
        table.add_column("Framework", style="cyan")
        table.add_column("Control ID", style="cyan")
        table.add_column("Current Status")
        table.add_column("Assessor", style="dim")
        table.add_column("Last Assessed", style="dim")

        status_styles = {
            "compliant": "green",
            "non_compliant": "red",
            "partial": "yellow",
            "not_assessed": "dim",
        }
        for r in affected_controls[:30]:
            st_sty = status_styles.get(r.status, "")
            table.add_row(
                r.framework,
                r.control_id,
                f"[{st_sty}]{r.status}[/]",
                (r.assessor or "")[:25],
                _fmt_dt(r.assessed_at),
            )
        console.print(table)
        if len(affected_controls) > 30:
            console.print(f"[dim]... and {len(affected_controls) - 30} more controls[/dim]")

    if nearby_findings:
        console.print(f"\n[bold]Findings within 24h of change: {len(nearby_findings)}[/bold]")
        f_table = Table(title="Nearby Findings")
        f_table.add_column("ID", style="dim", max_width=8)
        f_table.add_column("Title", max_width=50)
        f_table.add_column("Severity")
        f_table.add_column("Source", style="cyan")
        f_table.add_column("Observed", style="dim")

        for f in nearby_findings:
            sty = _severity_style(f.severity)
            f_table.add_row(
                f.id[:8],
                (f.title or "")[:50],
                f"[{sty}]{f.severity}[/]",
                f.source,
                _fmt_dt(f.observed_at),
            )
        console.print(f_table)


# ---------------------------------------------------------------------------
# IO-005: link training-access
# ---------------------------------------------------------------------------


@link.command("training-access")
@click.argument("user_id")
def training_access(user_id: str) -> None:
    """Check training status, flag overdue, trigger access review.

    \b
    USER_ID: personnel UUID or prefix (from 'warlock users list').

    Checks whether the user has completed required training. If any training
    is overdue, flags it and recommends an access review to determine if
    the user's current access should be restricted.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Personnel, TrainingRecord

    init_db()
    now = _utcnow()

    with get_session() as session:
        user = session.query(Personnel).filter(Personnel.id.startswith(user_id)).first()
        if not user:
            _error(f"User (personnel) not found: {user_id}")

        records = (
            session.query(TrainingRecord)
            .filter(TrainingRecord.personnel_id == user.id)
            .order_by(TrainingRecord.due_date.asc())
            .all()
        )

    if not records:
        console.print(
            f"[yellow]No training records found for {user.name or user.id[:8]}.[/yellow]\n"
            "[yellow]Recommendation: schedule required training and trigger access review.[/yellow]"
        )
        return

    completed = [r for r in records if r.status == "completed"]
    overdue = [
        r for r in records
        if r.status != "completed" and r.due_date and r.due_date < now
    ]
    pending = [
        r for r in records
        if r.status != "completed" and (not r.due_date or r.due_date >= now)
    ]

    console.print(
        Panel(
            f"User:       [bold]{user.name or '\u2014'}[/bold] ({user.id[:8]})\n"
            f"Email:      {getattr(user, 'email', '\u2014') or '\u2014'}\n"
            f"Role:       {getattr(user, 'role', '\u2014') or '\u2014'}\n\n"
            f"Completed:  [green]{len(completed)}[/green]\n"
            f"Pending:    [yellow]{len(pending)}[/yellow]\n"
            f"Overdue:    [red bold]{len(overdue)}[/red bold]",
            title="[bold cyan]Training Status[/bold cyan]",
            border_style="cyan",
        )
    )

    if overdue:
        table = Table(title="[red]Overdue Training[/red]", border_style="red")
        table.add_column("Record ID", style="dim", max_width=8)
        table.add_column("Course / Topic", max_width=45)
        table.add_column("Due Date", style="red")
        table.add_column("Days Overdue", style="red bold", justify="right")

        for r in overdue:
            days_over = (now - r.due_date).days if r.due_date else 0
            table.add_row(
                r.id[:8],
                (getattr(r, "course_name", None) or getattr(r, "title", None) or r.training_type or "\u2014")[:45],
                _fmt_dt(r.due_date),
                str(days_over),
            )
        console.print(table)

        console.print(
            "\n[red bold]Access review recommended.[/red bold] "
            f"User has [bold]{len(overdue)}[/bold] overdue training item(s).\n"
            "Consider restricting access until training is completed.\n"
            f"  [dim]warlock access-review create --user {user.id[:8]} "
            f'--reason "Overdue training ({len(overdue)} items)"[/dim]'
        )

    if pending:
        p_table = Table(title="Pending Training", border_style="yellow")
        p_table.add_column("Record ID", style="dim", max_width=8)
        p_table.add_column("Course / Topic", max_width=45)
        p_table.add_column("Due Date", style="yellow")
        p_table.add_column("Status")

        for r in pending:
            p_table.add_row(
                r.id[:8],
                (getattr(r, "course_name", None) or getattr(r, "title", None) or r.training_type or "\u2014")[:45],
                _fmt_dt(r.due_date),
                r.status or "\u2014",
            )
        console.print(p_table)

    if not overdue:
        console.print(
            "[green]All required training is current.[/green] No access review trigger needed."
        )
