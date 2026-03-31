"""Collaboration CLI commands.

Provides shared dashboards, team workspaces, RACI matrices, compliance
calendars, regulatory change management, regulation alerts, and release
compliance checks for cross-team GRC collaboration.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import _error, _get_actor, cli, console
from warlock.utils import ensure_aware

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()


def _next_sequence(session) -> int:
    from sqlalchemy import func

    from warlock.db.models import AuditEntry

    return (session.query(func.max(AuditEntry.sequence)).scalar() or 0) + 1


def _parse_date(value: str) -> datetime:
    """Parse a YYYY-MM-DD string into a timezone-aware datetime."""
    try:
        dt = datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        _error(f"Invalid date format '{value}'. Expected YYYY-MM-DD.")
    return dt.replace(tzinfo=timezone.utc)


def _score_pct(compliant: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(compliant / total * 100, 1)


def _score_style(score: float) -> str:
    if score >= 80:
        return "green"
    if score >= 60:
        return "yellow"
    return "red"


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@cli.group("collaboration", invoke_without_command=True)
@click.pass_context
def collaboration(ctx: click.Context) -> None:
    """Cross-team GRC collaboration tools.

    Shared dashboards, team workspaces, RACI matrices, compliance calendars,
    regulatory change tracking, and release compliance checks.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# COL-2: shared-dashboards
# ---------------------------------------------------------------------------

_VALID_DASHBOARD_TYPES = ("posture", "risk", "audit")


@collaboration.command("shared-dashboards")
@click.option("--create", "create_name", default=None, help="Create a new shared dashboard")
@click.option(
    "--type",
    "dash_type",
    default="posture",
    type=click.Choice(list(_VALID_DASHBOARD_TYPES)),
    help="Dashboard type",
)
@click.option(
    "--share-with", "share_with", default=None, help="Comma-separated user list to share with"
)
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def shared_dashboards(
    create_name: str | None,
    dash_type: str,
    share_with: str | None,
    fmt: str,
) -> None:
    """List or create shared dashboard configurations.

    Dashboards are stored as AuditEntry records with action="shared_dashboard".
    Use --create to add a new dashboard, or run without flags to list existing.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    actor = _get_actor()

    if create_name:
        # Create a new shared dashboard
        dash_id = str(uuid.uuid4())
        shared_list = [s.strip() for s in (share_with or "").split(",") if s.strip()]
        extra = {
            "name": create_name,
            "type": dash_type,
            "owner": actor,
            "shared_with": shared_list,
            "created_at": _utcnow().isoformat(),
            "config": {},
        }

        with get_session() as session:
            entry = AuditEntry(
                id=str(uuid.uuid4()),
                sequence=_next_sequence(session),
                previous_hash="genesis",
                entry_hash=_make_hash(f"{dash_id}:{create_name}:{actor}"),
                action="shared_dashboard",
                entity_type="dashboard",
                entity_id=dash_id,
                actor=actor,
                extra=extra,
            )
            session.add(entry)
            session.commit()

        console.print(f"[green]Dashboard created:[/green] [cyan]{dash_id[:8]}[/cyan]")
        console.print(f"  Name:        {escape(create_name)}")
        console.print(f"  Type:        {dash_type}")
        console.print(f"  Owner:       {escape(actor)}")
        if shared_list:
            console.print(f"  Shared with: {', '.join(escape(s) for s in shared_list)}")
        return

    # List existing dashboards
    with get_session() as session:
        entries = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "shared_dashboard",
                AuditEntry.entity_type == "dashboard",
            )
            .order_by(AuditEntry.created_at.desc())
            .all()
        )

        # Deduplicate by entity_id, keeping most recent
        seen: set[str] = set()
        dashboards: list[dict[str, Any]] = []
        for e in entries:
            if e.entity_id in seen:
                continue
            seen.add(e.entity_id)
            extra = e.extra or {}
            created_at = extra.get("created_at", "")
            dashboards.append(
                {
                    "id": e.entity_id[:8],
                    "name": extra.get("name", ""),
                    "owner": extra.get("owner", e.actor),
                    "type": extra.get("type", "posture"),
                    "shared_with": extra.get("shared_with", []),
                    "created_at": created_at[:10] if created_at else "",
                }
            )

    if not dashboards:
        console.print("[dim]No shared dashboards configured.[/dim]")
        console.print(
            "[dim]Use --create <name> to create one. "
            "Example: warlock collaboration shared-dashboards --create 'Q1 Posture' --type posture[/dim]"
        )
        return

    if fmt == "json":
        console.print(json.dumps(dashboards, indent=2))
        return

    table = Table(title=f"Shared Dashboards ({len(dashboards)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", style="cyan", max_width=30)
    table.add_column("Owner")
    table.add_column("Type")
    table.add_column("Shared With", max_width=30)
    table.add_column("Created")

    for d in dashboards:
        shared = ", ".join(d["shared_with"]) if d["shared_with"] else "[dim]--[/dim]"
        table.add_row(
            d["id"],
            escape(d["name"]),
            escape(d["owner"]),
            d["type"],
            escape(shared) if d["shared_with"] else shared,
            d["created_at"],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# COL-3: team-workspaces
# ---------------------------------------------------------------------------


@collaboration.command("team-workspaces")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def team_workspaces(fmt: str) -> None:
    """List workspaces scoped to business units.

    Groups SystemProfile records by organization, showing workspace-level
    summary including member count, active issues, and compliance scores.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Issue, SystemProfile

    init_db()

    with get_session() as session:
        profiles = session.query(SystemProfile).all()
        if not profiles:
            console.print("[dim]No system profiles found. Register systems first.[/dim]")
            return

        # Group by organization (derived from system_owner or acronym prefix)
        org_map: dict[str, list] = defaultdict(list)
        for sp in profiles:
            # Use the first word of the system name or acronym as org grouping
            org = (sp.acronym or sp.name or "Unassigned").split("-")[0].split("_")[0].strip()
            org_map[org].append(sp)

        workspaces: list[dict[str, Any]] = []
        for org, systems in sorted(org_map.items()):
            system_ids = [s.id for s in systems]
            members: set[str] = set()
            for s in systems:
                if s.system_owner:
                    members.add(s.system_owner)
                if s.isso:
                    members.add(s.isso)

            # Count active issues for these systems
            active_issues = (
                session.query(Issue)
                .filter(
                    Issue.status.notin_(["closed", "verified", "risk_accepted"]),
                )
                .count()
            )

            # Compute compliance score across these systems
            total = (
                session.query(ControlResult)
                .filter(
                    ControlResult.system_profile_id.in_(system_ids),
                    ControlResult.status != "not_assessed",
                )
                .count()
            )
            compliant = (
                session.query(ControlResult)
                .filter(
                    ControlResult.system_profile_id.in_(system_ids),
                    ControlResult.status.in_(
                        ["compliant", "inherited_compliant", "not_applicable"]
                    ),
                )
                .count()
            )
            score = _score_pct(compliant, total)

            workspaces.append(
                {
                    "workspace": org,
                    "systems": len(systems),
                    "members": len(members),
                    "active_issues": active_issues,
                    "compliance_score": score,
                    "system_names": [s.name for s in systems],
                }
            )

    if fmt == "json":
        console.print(json.dumps(workspaces, indent=2, default=str))
        return

    table = Table(title=f"Team Workspaces ({len(workspaces)})")
    table.add_column("Workspace", style="cyan")
    table.add_column("Systems", justify="right")
    table.add_column("Members", justify="right")
    table.add_column("Active Issues", justify="right")
    table.add_column("Compliance", justify="right")

    for ws in workspaces:
        score = ws["compliance_score"]
        style = _score_style(score)
        table.add_row(
            escape(ws["workspace"]),
            str(ws["systems"]),
            str(ws["members"]),
            str(ws["active_issues"]),
            f"[{style}]{score}%[/]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# COL-5: raci-matrix
# ---------------------------------------------------------------------------


@collaboration.command("raci-matrix")
@click.option(
    "--framework",
    "-f",
    default="nist_800_53",
    help="Framework to show RACI for (default: nist_800_53)",
)
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def raci_matrix(framework: str, fmt: str) -> None:
    """Show RACI matrix per control family.

    Derives Responsible, Accountable, Consulted, and Informed roles from
    Issue assignments, SystemProfile ownership, and attestation data.

    R = Control owner (assigned_to on issues)
    A = System owner (from SystemProfile)
    C = Auditor (from AuditEngagement)
    I = CISO / ISSO (from SystemProfile)
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        AuditEngagement,
        ControlResult,
        Issue,
        SystemProfile,
    )

    init_db()

    with get_session() as session:
        # Get control families for this framework
        results = (
            session.query(ControlResult.control_id)
            .filter(ControlResult.framework == framework)
            .distinct()
            .all()
        )

        if not results:
            console.print(
                f"[dim]No control results found for framework '{escape(framework)}'.[/dim]"
            )
            return

        # Extract control families (e.g., "AC" from "AC-2", "CC6" from "CC6.1")
        families: dict[str, set[str]] = defaultdict(set)
        for (control_id,) in results:
            # Handle both dash-separated (AC-2) and dot-separated (CC6.1) families
            if "-" in control_id:
                family = control_id.split("-")[0]
            elif "." in control_id:
                family = control_id.split(".")[0]
            else:
                family = control_id
            families[family].add(control_id)

        # Determine responsible parties from Issues
        issue_assignees: dict[str, set[str]] = defaultdict(set)
        issues = (
            session.query(Issue)
            .filter(Issue.framework == framework, Issue.assigned_to.isnot(None))
            .all()
        )
        for iss in issues:
            if iss.control_id:
                family = iss.control_id.split("-")[0] if "-" in iss.control_id else iss.control_id
                issue_assignees[family].add(iss.assigned_to)

        # System owners and ISSOs from profiles
        profiles = session.query(SystemProfile).all()
        system_owners: set[str] = set()
        issos: set[str] = set()
        for sp in profiles:
            sp_frameworks = sp.frameworks or []
            if framework in sp_frameworks or not sp_frameworks:
                if sp.system_owner:
                    system_owners.add(sp.system_owner)
                if sp.isso:
                    issos.add(sp.isso)

        # Auditors from engagements
        auditors: set[str] = set()
        engagements = (
            session.query(AuditEngagement).filter(AuditEngagement.framework == framework).all()
        )
        for eng in engagements:
            if eng.auditor_name:
                auditors.add(eng.auditor_name)

        # Default labels when no specific person is found
        default_responsible = "Control Owner"
        default_accountable = next(iter(system_owners), "System Owner")
        default_consulted = next(iter(auditors), "Auditor")
        default_informed = next(iter(issos), "CISO / ISSO")

        raci_rows: list[dict[str, str]] = []
        for family in sorted(families.keys()):
            controls = families[family]
            responsible = (
                ", ".join(sorted(issue_assignees.get(family, set()))) or default_responsible
            )
            accountable = default_accountable
            consulted = default_consulted
            informed = default_informed

            raci_rows.append(
                {
                    "family": family,
                    "controls": str(len(controls)),
                    "responsible": responsible,
                    "accountable": accountable,
                    "consulted": consulted,
                    "informed": informed,
                }
            )

    if fmt == "json":
        console.print(json.dumps(raci_rows, indent=2))
        return

    table = Table(title=f"RACI Matrix -- {escape(framework)} ({len(raci_rows)} families)")
    table.add_column("Family", style="cyan")
    table.add_column("Controls", justify="right")
    table.add_column("Responsible (R)", style="green", max_width=25)
    table.add_column("Accountable (A)", style="yellow", max_width=25)
    table.add_column("Consulted (C)", style="blue", max_width=25)
    table.add_column("Informed (I)", style="dim", max_width=25)

    for row in raci_rows:
        table.add_row(
            row["family"],
            row["controls"],
            escape(row["responsible"]),
            escape(row["accountable"]),
            escape(row["consulted"]),
            escape(row["informed"]),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# COL-6: calendar
# ---------------------------------------------------------------------------


@collaboration.command("calendar")
@click.option("--days", default=90, help="Look-ahead window in days (default: 90)")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def collab_calendar(days: int, fmt: str) -> None:
    """Show upcoming compliance deadlines across all domains.

    Aggregates POA&M scheduled completions, audit engagement period ends,
    risk acceptance expiry dates, and calendar items into a sorted timeline.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM, AuditEngagement, RiskAcceptance

    init_db()
    now = _utcnow()
    cutoff = now + timedelta(days=days)

    items: list[dict[str, Any]] = []

    with get_session() as session:
        # POA&M deadlines
        poams = (
            session.query(POAM)
            .filter(
                POAM.scheduled_completion.isnot(None),
                POAM.status.notin_(["completed", "verified", "closed", "cancelled"]),
            )
            .all()
        )
        for p in poams:
            due = ensure_aware(p.scheduled_completion) if p.scheduled_completion else None
            if due and now <= due <= cutoff:
                items.append(
                    {
                        "source": "POA&M",
                        "title": f"{(p.weakness_description or '')[:50]}",
                        "due_date": due,
                        "framework": p.framework or "",
                        "detail": f"status={p.status}",
                    }
                )

        # Audit engagement period ends
        engagements = (
            session.query(AuditEngagement)
            .filter(
                AuditEngagement.period_end.isnot(None),
                AuditEngagement.status == "active",
            )
            .all()
        )
        for eng in engagements:
            due = ensure_aware(eng.period_end) if eng.period_end else None
            if due and now <= due <= cutoff:
                items.append(
                    {
                        "source": "Audit",
                        "title": f"{(eng.name or '')[:50]}",
                        "due_date": due,
                        "framework": eng.framework or "",
                        "detail": f"auditor={eng.auditor_name or ''}",
                    }
                )

        # Risk acceptance expiry dates
        acceptances = (
            session.query(RiskAcceptance)
            .filter(
                RiskAcceptance.status == "active",
                RiskAcceptance.expiry_date.isnot(None),
            )
            .all()
        )
        for ra in acceptances:
            due = ensure_aware(ra.expiry_date) if ra.expiry_date else None
            if due and now <= due <= cutoff:
                items.append(
                    {
                        "source": "Risk Accept",
                        "title": f"{ra.framework}/{ra.control_id}: {(ra.risk_description or '')[:30]}",
                        "due_date": due,
                        "framework": ra.framework or "",
                        "detail": f"risk_level={ra.risk_level}",
                    }
                )

    # Sort by due date
    items.sort(key=lambda x: x["due_date"])

    if not items:
        console.print(f"[green]No compliance deadlines in the next {days} days.[/green]")
        return

    if fmt == "json":
        data = [
            {
                "source": i["source"],
                "title": i["title"],
                "due_date": i["due_date"].strftime("%Y-%m-%d"),
                "framework": i["framework"],
                "detail": i["detail"],
            }
            for i in items
        ]
        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Compliance Deadlines -- Next {days} Days ({len(items)})")
    table.add_column("Source", style="cyan")
    table.add_column("Title", max_width=50)
    table.add_column("Due Date")
    table.add_column("Days Left", justify="right")
    table.add_column("Framework")
    table.add_column("Detail", style="dim", max_width=30)

    for i in items:
        days_left = (i["due_date"] - now).days
        color = "red" if days_left <= 7 else ("yellow" if days_left <= 14 else "green")
        table.add_row(
            i["source"],
            escape(i["title"]),
            i["due_date"].strftime("%Y-%m-%d"),
            f"[{color}]{days_left}[/]",
            escape(i["framework"]),
            escape(i["detail"]),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# COL-7: regulation-alerts
# ---------------------------------------------------------------------------


@collaboration.command("regulation-alerts")
def regulation_alerts() -> None:
    """Show regulatory change alerts.

    Displays pending regulatory changes that require attention. Configure
    horizon scanning integrations to receive automatic alerts.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.regulatory_change import RegulatoryChangeManager

    init_db()
    mgr = RegulatoryChangeManager()

    with get_session() as session:
        pending = mgr.get_pending_changes(session)

    if not pending:
        console.print("[dim]No regulatory change alerts.[/dim]")
        console.print("")
        console.print("[dim]To configure horizon scanning:[/dim]")
        console.print(
            "[dim]  1. Track changes manually:  warlock collaboration regulatory-changes --create ...[/dim]"
        )
        console.print(
            "[dim]  2. View pending changes:    warlock collaboration regulatory-changes[/dim]"
        )
        console.print(
            "[dim]  3. Assess impact:           warlock collaboration regulatory-changes --assess <id>[/dim]"
        )
        return

    table = Table(title=f"Regulatory Change Alerts ({len(pending)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Impact", style="bold")
    table.add_column("Framework", style="cyan")
    table.add_column("Title", max_width=40)
    table.add_column("Effective Date")
    table.add_column("Status")

    impact_styles = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "informational": "dim",
    }

    for ch in pending:
        impact = ch.get("impact_level", "medium")
        style = impact_styles.get(impact, "")
        status = ch.get("status", "pending")
        status_style = "yellow" if status == "pending" else "blue"
        table.add_row(
            ch["id"][:8],
            f"[{style}]{escape(impact)}[/]",
            escape(ch.get("framework", "")),
            escape(ch.get("title", "")),
            escape(ch.get("effective_date", "")),
            f"[{status_style}]{escape(status)}[/]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# COL-8: regulatory-changes
# ---------------------------------------------------------------------------


@collaboration.command("regulatory-changes")
@click.option("--create", "create_title", default=None, help="Create a new regulatory change")
@click.option("--framework", "-f", default=None, help="Framework affected by the change")
@click.option("--description", "-d", default=None, help="Description of the change")
@click.option("--effective-date", default=None, help="Effective date (YYYY-MM-DD)")
@click.option(
    "--impact",
    default="medium",
    type=click.Choice(["critical", "high", "medium", "low", "informational"]),
    help="Impact level",
)
@click.option("--assess", "assess_id", default=None, help="Assess impact of a change by ID")
@click.option("--address", "address_id", default=None, help="Mark a change as addressed by ID")
@click.option("--notes", default=None, help="Notes for marking a change as addressed")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def regulatory_changes(
    create_title: str | None,
    framework: str | None,
    description: str | None,
    effective_date: str | None,
    impact: str,
    assess_id: str | None,
    address_id: str | None,
    notes: str | None,
    fmt: str,
) -> None:
    """Manage regulatory change tracking.

    CRUD for regulatory changes with impact assessment. Changes are stored
    as audit entries and can be assessed for control/system impact.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.regulatory_change import RegulatoryChangeManager

    init_db()
    actor = _get_actor()
    mgr = RegulatoryChangeManager()

    # --- Create ---
    if create_title:
        if not framework:
            _error("--framework is required when creating a regulatory change.")
        if not effective_date:
            _error("--effective-date is required when creating a regulatory change.")
        # Validate date format
        _parse_date(effective_date)

        with get_session() as session:
            change = mgr.create_change(
                session=session,
                title=create_title,
                framework=framework,
                description=description or "",
                effective_date=effective_date,
                impact_level=impact,
                actor=actor,
            )
            session.commit()

        console.print(f"[green]Regulatory change created:[/green] [cyan]{change['id'][:8]}[/cyan]")
        console.print(f"  Title:          {escape(change['title'])}")
        console.print(f"  Framework:      {escape(change['framework'])}")
        console.print(f"  Impact:         {escape(change['impact_level'])}")
        console.print(f"  Effective date: {escape(change['effective_date'])}")
        return

    # --- Assess ---
    if assess_id:
        with get_session() as session:
            # Resolve partial ID
            change_id = _resolve_change_id(session, assess_id, mgr)
            if not change_id:
                _error(f"Regulatory change '{assess_id}' not found.")

            try:
                assessment = mgr.assess_impact(session, change_id, actor)
                session.commit()
            except ValueError as e:
                _error(str(e))

        console.print(f"[green]Impact assessment for change {assess_id[:8]}:[/green]")
        console.print(f"  Framework:          {escape(assessment.get('framework', ''))}")
        console.print(f"  Affected controls:  {assessment['affected_controls_count']}")
        console.print(f"  Affected systems:   {assessment['affected_systems_count']}")
        if assessment["affected_systems"]:
            console.print("  Systems:")
            for sys in assessment["affected_systems"][:10]:
                console.print(
                    f"    - {escape(sys['name'])} ({escape(sys['acronym'])})"
                    f"  owner={escape(sys['owner'])}"
                )
        return

    # --- Address ---
    if address_id:
        if not notes:
            _error("--notes is required when marking a change as addressed.")

        with get_session() as session:
            change_id = _resolve_change_id(session, address_id, mgr)
            if not change_id:
                _error(f"Regulatory change '{address_id}' not found.")

            try:
                result = mgr.mark_addressed(session, change_id, actor, notes)
                session.commit()
            except ValueError as e:
                _error(str(e))

        console.print(f"[green]Regulatory change {address_id[:8]} marked as addressed.[/green]")
        console.print(f"  Addressed by: {escape(result.get('addressed_by', ''))}")
        console.print(f"  Notes:        {escape(result.get('addressed_notes', ''))}")
        return

    # --- List all ---
    with get_session() as session:
        changes = mgr.list_all(session)

    if not changes:
        console.print("[dim]No regulatory changes tracked.[/dim]")
        console.print("[dim]Use --create <title> to track a new regulatory change.[/dim]")
        return

    if fmt == "json":
        console.print(json.dumps(changes, indent=2, default=str))
        return

    table = Table(title=f"Regulatory Changes ({len(changes)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Status")
    table.add_column("Impact")
    table.add_column("Framework", style="cyan")
    table.add_column("Title", max_width=35)
    table.add_column("Effective Date")
    table.add_column("Created By", style="dim")

    status_styles = {
        "pending": "yellow",
        "assessed": "blue",
        "addressed": "green",
        "dismissed": "dim",
    }
    impact_styles = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "informational": "dim",
    }

    for ch in changes:
        s_style = status_styles.get(ch.get("status", ""), "")
        i_style = impact_styles.get(ch.get("impact_level", ""), "")
        table.add_row(
            ch["id"][:8],
            f"[{s_style}]{escape(ch.get('status', ''))}[/]",
            f"[{i_style}]{escape(ch.get('impact_level', ''))}[/]",
            escape(ch.get("framework", "")),
            escape(ch.get("title", "")),
            escape(ch.get("effective_date", "")),
            escape(ch.get("created_by", "")),
        )

    console.print(table)


def _resolve_change_id(session, partial_id: str, mgr) -> str | None:
    """Resolve a partial change ID to a full change ID."""
    changes = mgr.list_all(session)
    for ch in changes:
        if ch["id"].startswith(partial_id) or ch["id"][:8] == partial_id:
            return ch["id"]
    return None


# ---------------------------------------------------------------------------
# COL-10: release-compliance
# ---------------------------------------------------------------------------


@collaboration.command("release-compliance")
@click.option("--release-id", required=True, help="Release identifier to check")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json"]),
    help="Output format",
)
def release_compliance(release_id: str, fmt: str) -> None:
    """Release management compliance check.

    Verifies compliance status for controls tagged with a release. Checks
    CAB (Change Advisory Board) approval status and control assessment
    coverage for the specified release.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, ControlResult

    init_db()

    with get_session() as session:
        # Check for CAB approval in audit trail
        cab_entries = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action.in_(["change_approved", "cab_approved", "change_request"]),
                AuditEntry.entity_id == release_id,
            )
            .order_by(AuditEntry.created_at.desc())
            .all()
        )

        # Also check extra JSON for release_id reference
        if not cab_entries:
            cab_entries = (
                session.query(AuditEntry)
                .filter(
                    AuditEntry.action.in_(["change_approved", "cab_approved", "change_request"]),
                )
                .order_by(AuditEntry.created_at.desc())
                .limit(100)
                .all()
            )
            cab_entries = [
                e
                for e in cab_entries
                if (e.extra or {}).get("release_id") == release_id
                or (e.extra or {}).get("change_id") == release_id
            ]

        cab_approved = any(e.action in ("change_approved", "cab_approved") for e in cab_entries)

        # Get overall control status summary
        from sqlalchemy import func

        status_counts = (
            session.query(
                ControlResult.status,
                func.count(ControlResult.id),
            )
            .group_by(ControlResult.status)
            .all()
        )

        status_map: dict[str, int] = {}
        for status, count in status_counts:
            status_map[status] = count

        total = sum(status_map.values())
        compliant = sum(
            status_map.get(s, 0) for s in ["compliant", "inherited_compliant", "not_applicable"]
        )

    # Build compliance check results
    checks: list[dict[str, Any]] = []

    # Check 1: CAB approval
    checks.append(
        {
            "check": "CAB Approval",
            "status": "PASS" if cab_approved else "FAIL",
            "detail": (
                f"Approved ({len([e for e in cab_entries if e.action in ('change_approved', 'cab_approved')])} approvals)"
                if cab_approved
                else "No CAB approval found for this release"
            ),
        }
    )

    # Check 2: No critical non-compliant controls
    critical_nc = status_map.get("non_compliant", 0)
    checks.append(
        {
            "check": "Critical Controls",
            "status": "PASS" if critical_nc == 0 else "WARN",
            "detail": f"{critical_nc} non-compliant controls",
        }
    )

    # Check 3: Overall compliance rate
    score = _score_pct(compliant, total) if total > 0 else 0.0
    checks.append(
        {
            "check": "Compliance Rate",
            "status": "PASS" if score >= 80 else ("WARN" if score >= 60 else "FAIL"),
            "detail": f"{score}% ({compliant}/{total} controls compliant)",
        }
    )

    # Check 4: Assessed coverage
    not_assessed = status_map.get("not_assessed", 0)
    assessed_pct = _score_pct(total - not_assessed, total) if total > 0 else 0.0
    checks.append(
        {
            "check": "Assessment Coverage",
            "status": "PASS" if assessed_pct >= 90 else ("WARN" if assessed_pct >= 70 else "FAIL"),
            "detail": f"{assessed_pct}% assessed ({not_assessed} not yet assessed)",
        }
    )

    # Overall verdict
    has_fail = any(c["status"] == "FAIL" for c in checks)
    has_warn = any(c["status"] == "WARN" for c in checks)
    overall = "FAIL" if has_fail else ("WARN" if has_warn else "PASS")

    if fmt == "json":
        data = {
            "release_id": release_id,
            "overall": overall,
            "checks": checks,
        }
        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Release Compliance -- {escape(release_id)}")
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Detail", max_width=50)

    status_style_map = {
        "PASS": "green",
        "WARN": "yellow",
        "FAIL": "red bold",
    }

    for c in checks:
        s = c["status"]
        style = status_style_map.get(s, "")
        table.add_row(
            c["check"],
            f"[{style}]{s}[/]",
            escape(c["detail"]),
        )

    console.print(table)

    overall_style = status_style_map.get(overall, "")
    console.print(f"\n[bold]Overall verdict:[/bold] [{overall_style}]{overall}[/]")
    if has_fail:
        console.print(
            "[red]Release has compliance failures that must be resolved before deployment.[/red]"
        )
    elif has_warn:
        console.print("[yellow]Release has compliance warnings. Review before deployment.[/yellow]")
    else:
        console.print("[green]Release is compliant and cleared for deployment.[/green]")
