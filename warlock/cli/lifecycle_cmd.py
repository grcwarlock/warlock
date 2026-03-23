"""End-to-end lifecycle workflow commands.

Group: warlock lifecycle

Commands:
  audit --framework <fw> --date <date>  -- Full audit lifecycle workflow
  finding <finding_id>                  -- Finding lifecycle management
  vendor <vendor_id>                    -- Vendor lifecycle management
  conmon --framework <fw>               -- Continuous monitoring lifecycle
  risk-review                           -- Quarterly risk register review
  control-owners notify --status <s>    -- Control owner notification workflow
  policy                                -- Policy lifecycle management
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import click
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from warlock.cli import cli, console, _get_actor
from warlock.utils import ensure_aware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _status_color(status: str) -> str:
    return {
        "compliant": "green",
        "non_compliant": "red",
        "partial": "yellow",
        "not_assessed": "dim",
        "risk_accepted": "magenta",
        "inherited_compliant": "cyan",
    }.get(status, "white")


def _severity_color(sev: str) -> str:
    return {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }.get(sev, "white")


def _poam_color(status: str) -> str:
    return {
        "draft": "dim",
        "open": "yellow",
        "in_progress": "cyan",
        "completed": "green",
        "verified": "green bold",
        "closed": "dim",
    }.get(status, "white")


def _write_audit_entry(session, action: str, entity_type: str, entity_id: str, extra: dict) -> None:
    """Append a hash-chained audit entry."""
    from warlock.db.models import AuditEntry

    last = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
    prev_hash = last.entry_hash if last else "genesis"
    seq = (last.sequence + 1) if last else 1

    payload = json.dumps(
        {"action": action, "entity_type": entity_type, "entity_id": entity_id, "extra": extra},
        sort_keys=True,
    )
    entry_hash = hashlib.sha256(f"{prev_hash}:{payload}".encode()).hexdigest()

    entry = AuditEntry(
        id=str(uuid.uuid4()),
        sequence=seq,
        previous_hash=prev_hash,
        entry_hash=entry_hash,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        actor=_get_actor(),
        extra=extra,
    )
    session.add(entry)
    session.commit()


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("lifecycle")
def lifecycle() -> None:
    """End-to-end lifecycle workflows for GRC practitioners."""


# ---------------------------------------------------------------------------
# WF-001: audit lifecycle
# ---------------------------------------------------------------------------


@lifecycle.command("audit")
@click.option("--framework", "-f", required=True, help="Framework to audit (e.g. soc2, nist_800_53)")
@click.option("--date", "target_date_str", default=None, help="Target audit date (YYYY-MM-DD)")
@click.option("--interactive/--no-interactive", default=True)
def audit_lifecycle(framework: str, target_date_str: str | None, interactive: bool) -> None:
    """Full audit lifecycle: readiness -> gaps -> evidence -> engagement -> findings -> POA&M -> export.

    Walks through every phase of an audit engagement from initial readiness
    assessment to final OSCAL export, prompting for action at each step.

    \b
    Examples:
        warlock lifecycle audit --framework soc2 --date 2026-06-15
        warlock lifecycle audit -f nist_800_53 --no-interactive
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        AuditEngagement,
        ControlResult,
        EvidenceRequest,
        Issue,
        POAM,
    )

    init_db()

    if target_date_str:
        try:
            target_date = datetime.strptime(target_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            console.print("[red]Invalid date format. Use YYYY-MM-DD.[/red]")
            raise SystemExit(1)
    else:
        target_date = _utcnow() + timedelta(days=90)

    now = _utcnow()
    days_until = (target_date - now).days

    console.print(
        Panel(
            f"[bold]Audit Lifecycle — {framework.upper()}[/bold]\n\n"
            f"Target date: [cyan]{target_date.strftime('%Y-%m-%d')}[/cyan] "
            f"({days_until} days from today)\n"
            f"Actor: {_get_actor()}",
            title="[bold cyan]WF-001: Audit Lifecycle[/bold cyan]",
            border_style="cyan",
        )
    )

    with get_session() as session:
        # =================================================================
        # Phase 1: Readiness Assessment
        # =================================================================
        console.print("\n[bold cyan]Phase 1: Readiness Assessment[/bold cyan]")
        console.print("[dim]Evaluating current compliance posture...[/dim]\n")

        all_results = (
            session.query(ControlResult).filter(ControlResult.framework == framework).all()
        )

        if not all_results:
            console.print(
                f"  [yellow]No control results for '{framework}'. "
                "Run 'warlock collect' first.[/yellow]"
            )
            return

        total = len(all_results)
        by_status: dict[str, int] = {}
        for r in all_results:
            by_status[r.status] = by_status.get(r.status, 0) + 1

        compliant = by_status.get("compliant", 0) + by_status.get("inherited_compliant", 0)
        pct = compliant / total * 100 if total else 0

        posture_table = Table(title="Current Posture", show_lines=False)
        posture_table.add_column("Status")
        posture_table.add_column("Count", justify="right")
        posture_table.add_column("Pct", justify="right")
        for st, cnt in sorted(by_status.items(), key=lambda x: -x[1]):
            color = _status_color(st)
            posture_table.add_row(
                f"[{color}]{st}[/{color}]",
                str(cnt),
                f"{cnt / total * 100:.1f}%",
            )
        console.print(posture_table)
        console.print(f"  Compliance rate: [bold]{pct:.1f}%[/bold] ({compliant}/{total})")

        readiness_color = "green" if pct >= 80 else ("yellow" if pct >= 50 else "red")
        console.print(
            f"  Readiness: [{readiness_color}]{'READY' if pct >= 80 else 'AT RISK' if pct >= 50 else 'NOT READY'}[/{readiness_color}]"
        )

        # =================================================================
        # Phase 2: Gap Identification
        # =================================================================
        console.print("\n[bold cyan]Phase 2: Gap Identification[/bold cyan]")

        gap_results = [r for r in all_results if r.status in ("non_compliant", "partial", "not_assessed")]

        if not gap_results:
            console.print("  [green]No compliance gaps found.[/green]")
        else:
            by_severity: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}
            for r in gap_results:
                bucket = r.severity if r.severity in by_severity else "low"
                by_severity[bucket].append(r)

            console.print(f"  Total gaps: [bold]{len(gap_results)}[/bold]")
            for sev in ("critical", "high", "medium", "low"):
                if by_severity[sev]:
                    color = _severity_color(sev)
                    console.print(f"    [{color}]{sev}: {len(by_severity[sev])}[/{color}]")

            gap_table = Table(title="Top Gaps (critical/high)", show_lines=False)
            gap_table.add_column("Control")
            gap_table.add_column("Status")
            gap_table.add_column("Severity")
            gap_table.add_column("Last Assessed")
            top_gaps = (by_severity["critical"] + by_severity["high"])[:15]
            for r in top_gaps:
                gap_table.add_row(
                    r.control_id,
                    f"[{_status_color(r.status)}]{r.status}[/]",
                    f"[{_severity_color(r.severity)}]{r.severity}[/]",
                    r.assessed_at.strftime("%Y-%m-%d") if r.assessed_at else "---",
                )
            if top_gaps:
                console.print(gap_table)

        # =================================================================
        # Phase 3: Evidence Sprint
        # =================================================================
        console.print("\n[bold cyan]Phase 3: Evidence Sprint[/bold cyan]")

        stale_cutoff = now - timedelta(days=30)
        stale = [
            r for r in all_results
            if r.assessed_at and ensure_aware(r.assessed_at) < stale_cutoff
        ]
        fresh = len(all_results) - len(stale)
        console.print(
            f"  Evidence: [green]{fresh} fresh[/green]  [yellow]{len(stale)} stale (>30d)[/yellow]"
        )

        if interactive and stale:
            try:
                if Confirm.ask(
                    f"  Queue re-collection for {len(stale)} stale controls?",
                    default=False,
                ):
                    console.print(
                        f"  [dim]Run: warlock collect --framework {framework}[/dim]"
                    )
            except (KeyboardInterrupt, EOFError):
                console.print("\n  [dim]Skipped.[/dim]")

        # =================================================================
        # Phase 4: Engagement Creation / Status
        # =================================================================
        console.print("\n[bold cyan]Phase 4: Audit Engagement[/bold cyan]")

        engagement = (
            session.query(AuditEngagement)
            .filter(
                AuditEngagement.framework == framework,
                AuditEngagement.status == "active",
            )
            .first()
        )

        if engagement:
            console.print(
                f"  Active engagement: [bold]{engagement.name}[/bold]\n"
                f"  Period: {engagement.period_start.strftime('%Y-%m-%d')} to "
                f"{engagement.period_end.strftime('%Y-%m-%d')}\n"
                f"  Auditor: {engagement.auditor_name or '---'} ({engagement.auditor_firm or '---'})"
            )

            # Check evidence requests
            try:
                pending_reqs = (
                    session.query(EvidenceRequest)
                    .filter(
                        EvidenceRequest.engagement_id == engagement.id,
                        EvidenceRequest.status.in_(["requested", "in_progress"]),
                    )
                    .count()
                )
                console.print(f"  Pending evidence requests: [yellow]{pending_reqs}[/yellow]")
            except Exception:
                pass

        elif interactive:
            try:
                if Confirm.ask("  No active engagement found. Create one?", default=False):
                    console.print(
                        f"  [dim]Run: warlock audit-engagement create --framework {framework}[/dim]"
                    )
            except (KeyboardInterrupt, EOFError):
                console.print("\n  [dim]Skipped.[/dim]")
        else:
            console.print("  [yellow]No active engagement.[/yellow]")

        # =================================================================
        # Phase 5: Findings Tracking
        # =================================================================
        console.print("\n[bold cyan]Phase 5: Findings Tracking[/bold cyan]")

        open_issues = (
            session.query(Issue)
            .filter(
                Issue.framework == framework,
                Issue.status.notin_(["closed", "verified", "risk_accepted"]),
            )
            .all()
        )

        if not open_issues:
            console.print("  [green]No open issues for this framework.[/green]")
        else:
            issue_table = Table(title=f"Open Issues ({len(open_issues)})", show_lines=False)
            issue_table.add_column("ID", max_width=8)
            issue_table.add_column("Title", max_width=50)
            issue_table.add_column("Priority")
            issue_table.add_column("Status")
            issue_table.add_column("Assigned")
            for iss in open_issues[:10]:
                issue_table.add_row(
                    iss.id[:8],
                    (iss.title or "")[:50],
                    f"[{_severity_color(iss.priority)}]{iss.priority}[/]",
                    iss.status,
                    iss.assigned_to or "[dim]unassigned[/dim]",
                )
            console.print(issue_table)
            if len(open_issues) > 10:
                console.print(f"  [dim]... and {len(open_issues) - 10} more[/dim]")

        # =================================================================
        # Phase 6: POA&M Generation
        # =================================================================
        console.print("\n[bold cyan]Phase 6: POA&M Status[/bold cyan]")

        open_poams = (
            session.query(POAM)
            .filter(
                POAM.framework == framework,
                POAM.status.notin_(["completed", "verified", "closed", "cancelled"]),
            )
            .all()
        )

        overdue_poams = [
            p for p in open_poams
            if p.scheduled_completion and ensure_aware(p.scheduled_completion) < now
        ]

        console.print(
            f"  Open POA&Ms: [yellow]{len(open_poams)}[/yellow]   "
            f"Overdue: [red]{len(overdue_poams)}[/red]"
        )

        if overdue_poams:
            poam_table = Table(title="Overdue POA&Ms", show_lines=False)
            poam_table.add_column("ID", max_width=8)
            poam_table.add_column("Control")
            poam_table.add_column("Status")
            poam_table.add_column("Due")
            poam_table.add_column("Severity")
            for p in overdue_poams[:10]:
                due = p.scheduled_completion.strftime("%Y-%m-%d") if p.scheduled_completion else "---"
                poam_table.add_row(
                    p.id[:8],
                    p.control_id,
                    f"[{_poam_color(p.status)}]{p.status}[/]",
                    f"[red]{due}[/red]",
                    p.severity,
                )
            console.print(poam_table)

        if interactive and gap_results:
            nc_without_poam = []
            poam_control_ids = {p.control_id for p in open_poams}
            for r in gap_results:
                if r.control_id not in poam_control_ids and r.status == "non_compliant":
                    nc_without_poam.append(r)

            if nc_without_poam:
                console.print(
                    f"\n  [yellow]{len(nc_without_poam)} non-compliant control(s) lack a POA&M.[/yellow]"
                )
                try:
                    if Confirm.ask("  Create POA&Ms for uncovered gaps?", default=False):
                        console.print(
                            f"  [dim]Run: warlock poam create --framework {framework} --bulk[/dim]"
                        )
                except (KeyboardInterrupt, EOFError):
                    console.print("\n  [dim]Skipped.[/dim]")

        # =================================================================
        # Phase 7: OSCAL Export
        # =================================================================
        console.print("\n[bold cyan]Phase 7: OSCAL Export & Binder[/bold cyan]")

        # Calculate overall readiness
        scores = [
            pct,
            (fresh / total * 100) if total else 100,
            max(0, 100 - len(overdue_poams) * 10) if open_poams else 100,
        ]
        overall = sum(scores) / len(scores)
        overall_color = "green" if overall >= 80 else ("yellow" if overall >= 50 else "red")

        console.print(f"  Overall readiness: [{overall_color}][bold]{overall:.0f}/100[/bold][/{overall_color}]")

        if overall >= 80:
            console.print(
                f"\n  [green]Ready to export.[/green]\n"
                f"  [dim]Run: warlock export binder --framework {framework}[/dim]\n"
                f"  [dim]Run: warlock export oscal --framework {framework}[/dim]"
            )
        elif overall >= 50:
            console.print(
                "\n  [yellow]Address gaps before exporting the audit package.[/yellow]"
            )
        else:
            console.print(
                "\n  [red]Significant gaps remain. Resolve POA&Ms and evidence issues first.[/red]"
            )

        _write_audit_entry(
            session,
            "lifecycle_audit_review",
            "framework",
            framework,
            {
                "target_date": target_date.isoformat(),
                "compliance_pct": round(pct, 1),
                "gaps": len(gap_results) if gap_results else 0,
                "open_poams": len(open_poams),
                "readiness_score": round(overall, 1),
            },
        )

        console.print(
            "\n[dim]Audit trail entry recorded. Run 'warlock audit-trail list' to view.[/dim]"
        )


# ---------------------------------------------------------------------------
# WF-002: finding lifecycle
# ---------------------------------------------------------------------------


@lifecycle.command("finding")
@click.argument("finding_id")
@click.option("--interactive/--no-interactive", default=True)
def finding_lifecycle(finding_id: str, interactive: bool) -> None:
    """Finding lifecycle: state, issues, POA&Ms, evidence, remediation.

    Shows the full context of a finding and offers actions to progress it
    through its lifecycle.

    \b
    Examples:
        warlock lifecycle finding abc12345
        warlock lifecycle finding abc12345 --no-interactive
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        ControlResult,
        Finding,
        Issue,
        POAM,
    )

    init_db()

    with get_session() as session:
        finding = (
            session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        )
        if not finding:
            console.print(f"[red]Finding not found: '{finding_id}'[/red]")
            raise SystemExit(1)

        try:
            while True:
                # --- Finding detail ---
                sev_color = _severity_color(finding.severity)
                console.print()
                console.print(
                    Panel(
                        f"[bold]{finding.title}[/bold]\n\n"
                        f"ID: {finding.id[:8]}   "
                        f"Type: {finding.observation_type}   "
                        f"Severity: [{sev_color}]{finding.severity}[/{sev_color}]\n"
                        f"Source: {finding.source} / {finding.provider}   "
                        f"Resource: {finding.resource_type or '---'} / {finding.resource_id or '---'}\n"
                        f"Observed: {finding.observed_at.strftime('%Y-%m-%d %H:%M') if finding.observed_at else '---'}   "
                        f"Ingested: {finding.ingested_at.strftime('%Y-%m-%d %H:%M') if finding.ingested_at else '---'}",
                        title="[bold cyan]Finding Detail[/bold cyan]",
                        border_style="cyan",
                    )
                )

                # --- Linked control results ---
                results = (
                    session.query(ControlResult)
                    .filter(ControlResult.finding_id == finding.id)
                    .all()
                )
                if results:
                    cr_table = Table(title=f"Control Results ({len(results)})", show_lines=False)
                    cr_table.add_column("Framework")
                    cr_table.add_column("Control")
                    cr_table.add_column("Status")
                    cr_table.add_column("Assessed")
                    for cr in results[:10]:
                        cr_table.add_row(
                            cr.framework,
                            cr.control_id,
                            f"[{_status_color(cr.status)}]{cr.status}[/]",
                            cr.assessed_at.strftime("%Y-%m-%d") if cr.assessed_at else "---",
                        )
                    console.print(cr_table)
                else:
                    console.print("[dim]No control results linked.[/dim]")

                # --- Linked issues ---
                issues = (
                    session.query(Issue)
                    .filter(Issue.finding_id == finding.id)
                    .all()
                )
                if issues:
                    console.print(f"\n  Linked issues: [bold]{len(issues)}[/bold]")
                    for iss in issues[:5]:
                        console.print(
                            f"    [{_severity_color(iss.priority)}]{iss.priority}[/] "
                            f"{iss.id[:8]} — {(iss.title or '')[:50]}  status={iss.status}"
                        )
                else:
                    console.print("\n  [dim]No linked issues.[/dim]")

                # --- Linked POA&Ms ---
                poams = (
                    session.query(POAM)
                    .filter(POAM.finding_id == finding.id)
                    .all()
                )
                if poams:
                    console.print(f"\n  Linked POA&Ms: [bold]{len(poams)}[/bold]")
                    for p in poams[:5]:
                        due = p.scheduled_completion.strftime("%Y-%m-%d") if p.scheduled_completion else "---"
                        console.print(
                            f"    [{_poam_color(p.status)}]{p.status}[/] "
                            f"{p.id[:8]} — {p.control_id}  due={due}"
                        )
                else:
                    console.print("\n  [dim]No linked POA&Ms.[/dim]")

                if not interactive:
                    break

                # --- Action menu ---
                console.print()
                console.print(
                    "  [dim]i[/dim]=create issue  "
                    "[dim]p[/dim]=create POA&M  "
                    "[dim]a[/dim]=assign  "
                    "[dim]e[/dim]=add evidence  "
                    "[dim]v[/dim]=verify fixed  "
                    "[dim]q[/dim]=quit"
                )
                choice = Prompt.ask(
                    "Action",
                    choices=["i", "p", "a", "e", "v", "q"],
                    default="q",
                )

                if choice == "q":
                    console.print("[dim]Exiting finding lifecycle.[/dim]")
                    break

                elif choice == "i":
                    title = Prompt.ask(
                        "Issue title",
                        default=f"Remediate: {(finding.title or '')[:80]}",
                    )
                    priority = Prompt.ask(
                        "Priority",
                        choices=["critical", "high", "medium", "low"],
                        default=finding.severity if finding.severity in ("critical", "high", "medium", "low") else "medium",
                    )
                    issue = Issue(
                        id=str(uuid.uuid4()),
                        title=title,
                        description=f"Auto-created from finding {finding.id[:8]}: {finding.title}",
                        finding_id=finding.id,
                        priority=priority,
                        status="open",
                        source="manual",
                        tags=["lifecycle", finding.source],
                        created_by=_get_actor(),
                    )
                    session.add(issue)
                    session.commit()
                    console.print(f"  [green]Issue created: {issue.id[:8]}[/green]")

                elif choice == "p":
                    if not results:
                        console.print("  [yellow]No control results to create POA&M for.[/yellow]")
                        continue
                    cr = results[0]
                    desc = Prompt.ask(
                        "Weakness description",
                        default=f"Finding: {(finding.title or '')[:80]}",
                    )
                    days_str = Prompt.ask("Days to remediate", default="90")
                    try:
                        days_val = int(days_str)
                    except ValueError:
                        days_val = 90
                    poam = POAM(
                        id=str(uuid.uuid4()),
                        finding_id=finding.id,
                        control_result_id=cr.id,
                        framework=cr.framework,
                        control_id=cr.control_id,
                        weakness_description=desc,
                        severity=finding.severity,
                        status="open",
                        scheduled_completion=_utcnow() + timedelta(days=days_val),
                        created_by=_get_actor(),
                    )
                    session.add(poam)
                    session.commit()
                    console.print(f"  [green]POA&M created: {poam.id[:8]} due in {days_val}d[/green]")

                elif choice == "a":
                    if not issues:
                        console.print("  [yellow]Create an issue first.[/yellow]")
                        continue
                    assignee = Prompt.ask("Assign to (email)")
                    for iss in issues:
                        if iss.status == "open":
                            iss.assigned_to = assignee
                            iss.assigned_by = _get_actor()
                            iss.assigned_at = _utcnow()
                            iss.status = "assigned"
                    session.commit()
                    console.print(f"  [green]Assigned to {assignee}.[/green]")

                elif choice == "e":
                    evidence_desc = Prompt.ask("Evidence description")
                    if issues:
                        iss = issues[0]
                        existing = iss.remediation_evidence or []
                        existing.append({
                            "description": evidence_desc,
                            "uploaded_at": _utcnow().isoformat(),
                            "actor": _get_actor(),
                        })
                        iss.remediation_evidence = existing
                        session.commit()
                        console.print(f"  [green]Evidence added to issue {iss.id[:8]}.[/green]")
                    else:
                        console.print("  [yellow]Create an issue first to attach evidence.[/yellow]")

                elif choice == "v":
                    if issues:
                        for iss in issues:
                            if iss.status in ("in_progress", "remediated", "assigned"):
                                iss.status = "verified"
                                iss.verified_at = _utcnow()
                        session.commit()
                        console.print("  [green]Linked issues marked as verified.[/green]")
                    if poams:
                        for p in poams:
                            if p.status in ("in_progress", "completed"):
                                p.status = "verified"
                                p.actual_completion = _utcnow()
                        session.commit()
                        console.print("  [green]Linked POA&Ms marked as verified.[/green]")
                    if not issues and not poams:
                        console.print("  [yellow]Nothing to verify.[/yellow]")

        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Session ended.[/dim]")


# ---------------------------------------------------------------------------
# WF-003: vendor lifecycle
# ---------------------------------------------------------------------------


@lifecycle.command("vendor")
@click.argument("vendor_name_or_id")
@click.option("--interactive/--no-interactive", default=True)
def vendor_lifecycle(vendor_name_or_id: str, interactive: bool) -> None:
    """Vendor lifecycle: status, SOC 2, reassessment, risk trend, offboarding.

    Shows vendor profile with compliance artifacts and offers lifecycle
    management actions.

    \b
    Examples:
        warlock lifecycle vendor "Acme Corp"
        warlock lifecycle vendor abc12345
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, Vendor

    init_db()

    with get_session() as session:
        # Resolve vendor
        vendor = session.query(Vendor).filter(Vendor.id == vendor_name_or_id).first()
        if not vendor:
            vendor = session.query(Vendor).filter(Vendor.id.startswith(vendor_name_or_id)).first()
        if not vendor:
            vendor = session.query(Vendor).filter(Vendor.name.ilike(vendor_name_or_id)).first()
        if not vendor:
            vendor = session.query(Vendor).filter(Vendor.name.ilike(f"%{vendor_name_or_id}%")).first()

        if not vendor:
            console.print(f"[red]Vendor not found: '{vendor_name_or_id}'[/red]")
            raise SystemExit(1)

        now = _utcnow()
        meta = vendor.metadata_ or {}

        try:
            while True:
                # --- Profile ---
                tier_color = {"1": "red bold", "critical": "red bold", "2": "yellow", "high": "yellow"}.get(
                    (vendor.tier or "").lower(), "dim"
                )
                contract_exp = (
                    vendor.contract_expires.strftime("%Y-%m-%d") if vendor.contract_expires else "Unknown"
                )
                last_assessed = (
                    vendor.last_assessment.strftime("%Y-%m-%d") if vendor.last_assessment else "Never"
                )
                cadence = vendor.assessment_cadence_days or 365
                if vendor.last_assessment:
                    next_due = vendor.last_assessment + timedelta(days=cadence)
                    next_due_str = next_due.strftime("%Y-%m-%d")
                    overdue = ensure_aware(next_due) < now
                else:
                    next_due_str = "Overdue (never assessed)"
                    overdue = True

                soc2_status = meta.get("soc2_status", "not_requested")
                soc2_exp = meta.get("soc2_expires", "---")

                console.print()
                console.print(
                    Panel(
                        f"[bold]{vendor.name}[/bold]\n\n"
                        f"ID: {vendor.id[:8]}   "
                        f"Tier: [{tier_color}]{vendor.tier or 'unset'}[/{tier_color}]   "
                        f"Risk Score: {vendor.risk_score or 0:.1f}/100\n"
                        f"Category: {meta.get('category', '---')}   "
                        f"Contact: {meta.get('contact', '---')}\n"
                        f"Contract expires: {contract_exp}   "
                        f"Last assessed: {last_assessed}\n"
                        f"Next reassessment: {'[red]' if overdue else ''}{next_due_str}{'[/red]' if overdue else ''}   "
                        f"SOC 2: {soc2_status}   SOC 2 expires: {soc2_exp}",
                        title="[bold cyan]Vendor Lifecycle[/bold cyan]",
                        border_style="cyan",
                    )
                )

                # --- Linked findings ---
                linked = (
                    session.query(Finding)
                    .filter(Finding.source == vendor.name.lower().replace(" ", "_"))
                    .order_by(Finding.created_at.desc() if hasattr(Finding, 'created_at') else Finding.ingested_at.desc())
                    .limit(5)
                    .all()
                )
                if linked:
                    console.print(f"\n  Recent findings: [bold]{len(linked)}[/bold] (latest 5)")
                    for f in linked:
                        console.print(
                            f"    [{_severity_color(f.severity)}]{f.severity}[/] "
                            f"{f.id[:8]} — {(f.title or '')[:50]}"
                        )
                else:
                    console.print("\n  [dim]No linked findings.[/dim]")

                if not interactive:
                    break

                # --- Action menu ---
                console.print(
                    "\n  [dim]r[/dim]=reassess  "
                    "[dim]s[/dim]=review SOC 2  "
                    "[dim]q[/dim]=send questionnaire  "
                    "[dim]c[/dim]=update contract  "
                    "[dim]o[/dim]=offboard  "
                    "[dim]x[/dim]=exit"
                )
                choice = Prompt.ask(
                    "Action",
                    choices=["r", "s", "q", "c", "o", "x"],
                    default="x",
                )

                if choice == "x":
                    console.print("[dim]Exiting vendor lifecycle.[/dim]")
                    break

                elif choice == "r":
                    new_score_str = Prompt.ask(
                        "New risk score (0-100)",
                        default=str(int(vendor.risk_score or 0)),
                    )
                    try:
                        new_score = max(0.0, min(100.0, float(new_score_str)))
                    except ValueError:
                        new_score = vendor.risk_score or 0.0
                    old_score = vendor.risk_score
                    vendor.risk_score = new_score
                    vendor.last_assessment = now
                    session.commit()
                    _write_audit_entry(
                        session, "vendor_reassessed", "vendor", vendor.id,
                        {"old_score": old_score, "new_score": new_score},
                    )
                    console.print(
                        f"  [green]Reassessed. Score: {old_score:.1f} -> {new_score:.1f}[/green]"
                    )

                elif choice == "s":
                    soc2_new = Prompt.ask(
                        "SOC 2 status",
                        choices=["requested", "received", "reviewed", "expired"],
                        default="received",
                    )
                    meta_new = dict(meta)
                    meta_new["soc2_status"] = soc2_new
                    meta_new["soc2_updated_at"] = now.isoformat()
                    vendor.metadata_ = meta_new
                    meta = meta_new
                    session.commit()
                    _write_audit_entry(
                        session, "vendor_soc2_reviewed", "vendor", vendor.id,
                        {"soc2_status": soc2_new},
                    )
                    console.print(f"  [green]SOC 2 status: {soc2_new}[/green]")

                elif choice == "q":
                    meta_new = dict(meta)
                    meta_new["questionnaire_status"] = "sent"
                    meta_new["questionnaire_sent_at"] = now.isoformat()
                    vendor.metadata_ = meta_new
                    meta = meta_new
                    session.commit()
                    _write_audit_entry(
                        session, "vendor_questionnaire_sent", "vendor", vendor.id, {},
                    )
                    console.print(f"  [green]Questionnaire sent to {vendor.name}.[/green]")

                elif choice == "c":
                    date_str = Prompt.ask("New contract expiry (YYYY-MM-DD)")
                    try:
                        new_exp = datetime.strptime(date_str.strip(), "%Y-%m-%d").replace(
                            tzinfo=timezone.utc
                        )
                        vendor.contract_expires = new_exp
                        session.commit()
                        console.print(f"  [green]Contract expiry updated: {date_str}[/green]")
                    except ValueError:
                        console.print("  [red]Invalid date format.[/red]")

                elif choice == "o":
                    if not Confirm.ask(
                        f"Offboard '{vendor.name}'? This marks the vendor inactive.",
                        default=False,
                    ):
                        continue
                    meta_new = dict(meta)
                    meta_new["offboarded_at"] = now.isoformat()
                    meta_new["offboarded_by"] = _get_actor()
                    meta_new["is_active"] = False
                    vendor.metadata_ = meta_new
                    meta = meta_new
                    session.commit()
                    _write_audit_entry(
                        session, "vendor_offboarded", "vendor", vendor.id,
                        {"offboarded_by": _get_actor()},
                    )
                    console.print(f"  [green]{vendor.name} has been offboarded.[/green]")
                    break

        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Session ended.[/dim]")


# ---------------------------------------------------------------------------
# WF-004: conmon lifecycle
# ---------------------------------------------------------------------------


@lifecycle.command("conmon")
@click.option("--framework", "-f", required=True, help="Framework for continuous monitoring")
@click.option("--interactive/--no-interactive", default=True)
def conmon_lifecycle(framework: str, interactive: bool) -> None:
    """Continuous monitoring lifecycle: collect -> compare -> identify changes -> deliverables.

    Monthly ConMon automation that walks through evidence collection,
    month-over-month comparison, change identification, and deliverable
    generation.

    \b
    Examples:
        warlock lifecycle conmon --framework soc2
        warlock lifecycle conmon -f fedramp --no-interactive
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        ComplianceDrift,
        ConnectorRun,
        ControlResult,
        POAM,
        PostureSnapshot,
    )

    init_db()

    now = _utcnow()
    month_ago = now - timedelta(days=30)

    console.print(
        Panel(
            f"[bold]Continuous Monitoring — {framework.upper()}[/bold]\n\n"
            f"Period: {month_ago.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}\n"
            f"Actor: {_get_actor()}",
            title="[bold cyan]WF-004: ConMon Lifecycle[/bold cyan]",
            border_style="cyan",
        )
    )

    with get_session() as session:
        # =================================================================
        # Step 1: Evidence Collection Status
        # =================================================================
        console.print("\n[bold cyan]Step 1: Evidence Collection[/bold cyan]")

        recent_runs = (
            session.query(ConnectorRun)
            .filter(ConnectorRun.started_at >= month_ago)
            .all()
        )
        succeeded = sum(1 for r in recent_runs if r.status == "success")
        failed = sum(1 for r in recent_runs if r.status == "failure")

        console.print(
            f"  Connector runs (last 30d): [green]{succeeded} succeeded[/green]  "
            f"[red]{failed} failed[/red]  "
            f"Total: {len(recent_runs)}"
        )

        if failed > 0 and interactive:
            try:
                if Confirm.ask("  Re-run failed connectors?", default=False):
                    console.print(
                        f"  [dim]Run: warlock collect --framework {framework} --retry-failed[/dim]"
                    )
            except (KeyboardInterrupt, EOFError):
                console.print("\n  [dim]Skipped.[/dim]")

        # =================================================================
        # Step 2: Month-over-Month Comparison
        # =================================================================
        console.print("\n[bold cyan]Step 2: Month-over-Month Comparison[/bold cyan]")

        current_results = (
            session.query(ControlResult)
            .filter(ControlResult.framework == framework)
            .all()
        )
        total = len(current_results)
        if total == 0:
            console.print(f"  [yellow]No control results for '{framework}'.[/yellow]")
            return

        compliant_now = sum(1 for r in current_results if r.status in ("compliant", "inherited_compliant"))
        pct_now = compliant_now / total * 100

        # Check posture snapshots for comparison
        prev_snapshots = (
            session.query(PostureSnapshot)
            .filter(
                PostureSnapshot.framework == framework,
                PostureSnapshot.snapshot_date <= month_ago,
            )
            .order_by(PostureSnapshot.snapshot_date.desc())
            .limit(1)
            .all()
        )

        if prev_snapshots:
            snap = prev_snapshots[0]
            prev_pct = (snap.compliant_count / snap.total_count * 100) if snap.total_count else 0
            delta = pct_now - prev_pct
            delta_color = "green" if delta >= 0 else "red"
            console.print(
                f"  Current: [bold]{pct_now:.1f}%[/bold]   "
                f"Previous: {prev_pct:.1f}%   "
                f"Delta: [{delta_color}]{'+' if delta >= 0 else ''}{delta:.1f}%[/{delta_color}]"
            )
        else:
            console.print(
                f"  Current: [bold]{pct_now:.1f}%[/bold]   "
                "[dim]No prior snapshot for comparison.[/dim]"
            )

        # =================================================================
        # Step 3: Identify Changes (Drift)
        # =================================================================
        console.print("\n[bold cyan]Step 3: Change Identification[/bold cyan]")

        drifts = (
            session.query(ComplianceDrift)
            .filter(
                ComplianceDrift.framework == framework,
                ComplianceDrift.detected_at >= month_ago,
            )
            .order_by(ComplianceDrift.detected_at.desc())
            .all()
        )

        degraded = [d for d in drifts if d.drift_direction == "degraded"]
        improved = [d for d in drifts if d.drift_direction == "improved"]

        console.print(
            f"  Drifts detected: [bold]{len(drifts)}[/bold]   "
            f"Degraded: [red]{len(degraded)}[/red]   "
            f"Improved: [green]{len(improved)}[/green]"
        )

        if degraded:
            drift_table = Table(title="Degraded Controls", show_lines=False)
            drift_table.add_column("Control")
            drift_table.add_column("Previous")
            drift_table.add_column("Current")
            drift_table.add_column("Detected")
            for d in degraded[:10]:
                drift_table.add_row(
                    d.control_id,
                    f"[{_status_color(d.previous_status)}]{d.previous_status}[/]",
                    f"[{_status_color(d.new_status)}]{d.new_status}[/]",
                    d.detected_at.strftime("%Y-%m-%d") if d.detected_at else "---",
                )
            console.print(drift_table)

        # =================================================================
        # Step 4: Open POA&Ms
        # =================================================================
        console.print("\n[bold cyan]Step 4: POA&M Status[/bold cyan]")

        open_poams = (
            session.query(POAM)
            .filter(
                POAM.framework == framework,
                POAM.status.notin_(["completed", "verified", "closed", "cancelled"]),
            )
            .all()
        )
        overdue = [
            p for p in open_poams
            if p.scheduled_completion and ensure_aware(p.scheduled_completion) < now
        ]

        console.print(
            f"  Open: [yellow]{len(open_poams)}[/yellow]   "
            f"Overdue: [red]{len(overdue)}[/red]"
        )

        # =================================================================
        # Step 5: Generate Deliverables
        # =================================================================
        console.print("\n[bold cyan]Step 5: Deliverable Generation[/bold cyan]")

        console.print("  ConMon deliverables:")
        console.print(f"  [dim]1. warlock export binder --framework {framework} --period monthly[/dim]")
        console.print(f"  [dim]2. warlock reports compliance --framework {framework}[/dim]")
        console.print(f"  [dim]3. warlock reports drift --framework {framework}[/dim]")
        console.print(f"  [dim]4. warlock export oscal --framework {framework}[/dim]")

        if interactive:
            try:
                if Confirm.ask("\n  Mark this ConMon cycle as complete?", default=True):
                    _write_audit_entry(
                        session,
                        "conmon_cycle_completed",
                        "framework",
                        framework,
                        {
                            "period_start": month_ago.isoformat(),
                            "period_end": now.isoformat(),
                            "compliance_pct": round(pct_now, 1),
                            "drifts_degraded": len(degraded),
                            "drifts_improved": len(improved),
                            "open_poams": len(open_poams),
                        },
                    )
                    console.print("  [green]ConMon cycle recorded in audit trail.[/green]")
            except (KeyboardInterrupt, EOFError):
                console.print("\n  [dim]Skipped.[/dim]")


# ---------------------------------------------------------------------------
# WF-005: risk review
# ---------------------------------------------------------------------------


@lifecycle.command("risk-review")
@click.option("--interactive/--no-interactive", default=True)
def risk_review(interactive: bool) -> None:
    """Quarterly risk register review: walk entries, reassess, flag breaches.

    Reviews all active risk acceptances, checks for expiration, validates
    treatment plans, and flags appetite breaches.

    \b
    Examples:
        warlock lifecycle risk-review
        warlock lifecycle risk-review --no-interactive
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM, RiskAcceptance

    init_db()

    now = _utcnow()

    console.print(
        Panel(
            "[bold]Quarterly Risk Register Review[/bold]\n\n"
            f"Review date: {now.strftime('%Y-%m-%d')}\n"
            f"Reviewer: {_get_actor()}",
            title="[bold cyan]WF-005: Risk Review[/bold cyan]",
            border_style="cyan",
        )
    )

    with get_session() as session:
        # Load all active/approved risk acceptances
        acceptances = (
            session.query(RiskAcceptance)
            .filter(
                RiskAcceptance.status.in_(["approved", "active", "requested", "reviewed"])
            )
            .order_by(RiskAcceptance.expiry_date.asc())
            .all()
        )

        if not acceptances:
            console.print("\n[green]No active risk acceptances in the register.[/green]")
            # Still check high-risk POA&Ms
        else:
            console.print(f"\n  Active risk acceptances: [bold]{len(acceptances)}[/bold]")

            # Categorize
            expired = [a for a in acceptances if ensure_aware(a.expiry_date) < now]
            expiring_soon = [
                a for a in acceptances
                if ensure_aware(a.expiry_date) >= now
                and ensure_aware(a.expiry_date) < now + timedelta(days=30)
            ]
            active = [
                a for a in acceptances
                if ensure_aware(a.expiry_date) >= now + timedelta(days=30)
            ]

            summary_table = Table(title="Risk Register Summary", show_lines=False)
            summary_table.add_column("Category")
            summary_table.add_column("Count", justify="right")
            summary_table.add_row("[red]Expired[/red]", str(len(expired)))
            summary_table.add_row("[yellow]Expiring within 30d[/yellow]", str(len(expiring_soon)))
            summary_table.add_row("[green]Active[/green]", str(len(active)))
            console.print(summary_table)

            # Walk through each entry
            if expired:
                console.print(f"\n[bold red]Expired Acceptances ({len(expired)})[/bold red]")

            for ra in expired:
                console.print(
                    f"\n  [red]EXPIRED[/red] {ra.id[:8]}  "
                    f"{ra.framework}/{ra.control_id}  "
                    f"Level: {ra.risk_level}  "
                    f"Expired: {ra.expiry_date.strftime('%Y-%m-%d')}"
                )
                console.print(f"  Description: {(ra.risk_description or '')[:80]}")

                if interactive:
                    try:
                        action = Prompt.ask(
                            "  Action: [r]enew  [e]scalate  [c]lose  [s]kip",
                            choices=["r", "e", "c", "s"],
                            default="s",
                        )
                        if action == "r":
                            days_str = Prompt.ask("  Renew for how many days?", default="90")
                            try:
                                days_val = int(days_str)
                            except ValueError:
                                days_val = 90
                            ra.expiry_date = now + timedelta(days=days_val)
                            ra.status = "active"
                            session.commit()
                            console.print(
                                f"  [green]Renewed until {ra.expiry_date.strftime('%Y-%m-%d')}[/green]"
                            )
                        elif action == "e":
                            console.print(
                                f"  [dim]Run: warlock risk escalate {ra.id[:8]}[/dim]"
                            )
                        elif action == "c":
                            ra.status = "revoked"
                            session.commit()
                            console.print("  [green]Risk acceptance revoked.[/green]")
                    except (KeyboardInterrupt, EOFError):
                        console.print("\n  [dim]Skipped.[/dim]")

            # Risk appetite check
            console.print("\n[bold cyan]Risk Appetite Check[/bold cyan]")
            high_risk = [a for a in acceptances if a.risk_level in ("critical", "high")]
            if high_risk:
                console.print(
                    f"  [yellow]Warning: {len(high_risk)} critical/high risk acceptance(s) active.[/yellow]"
                )
                for ra in high_risk[:5]:
                    console.print(
                        f"    [{_severity_color(ra.risk_level)}]{ra.risk_level}[/] "
                        f"{ra.framework}/{ra.control_id} — "
                        f"{(ra.risk_description or '')[:60]}"
                    )
            else:
                console.print("  [green]No critical/high risk acceptances.[/green]")

        # POA&M risk overview
        console.print("\n[bold cyan]POA&M Risk Overview[/bold cyan]")
        overdue_poams = (
            session.query(POAM)
            .filter(
                POAM.status.notin_(["completed", "verified", "closed", "cancelled"]),
                POAM.scheduled_completion < now,
            )
            .all()
        )
        if overdue_poams:
            console.print(
                f"  [red]{len(overdue_poams)} overdue POA&M(s) represent unmitigated risk.[/red]"
            )
            for p in overdue_poams[:5]:
                due = p.scheduled_completion.strftime("%Y-%m-%d") if p.scheduled_completion else "---"
                console.print(
                    f"    {p.framework}/{p.control_id}  severity={p.severity}  "
                    f"due=[red]{due}[/red]  status={p.status}"
                )
        else:
            console.print("  [green]No overdue POA&Ms.[/green]")

        if interactive:
            try:
                if Confirm.ask("\n  Record this risk review in the audit trail?", default=True):
                    _write_audit_entry(
                        session,
                        "quarterly_risk_review",
                        "risk_register",
                        "all",
                        {
                            "review_date": now.isoformat(),
                            "total_acceptances": len(acceptances) if acceptances else 0,
                            "expired": len(expired) if acceptances else 0,
                            "overdue_poams": len(overdue_poams),
                        },
                    )
                    console.print("  [green]Risk review recorded.[/green]")
            except (KeyboardInterrupt, EOFError):
                console.print("\n  [dim]Skipped.[/dim]")


# ---------------------------------------------------------------------------
# WF-006: control-owners notify
# ---------------------------------------------------------------------------


@lifecycle.command("control-owners")
@click.option("--status", "-s", default="non_compliant", help="Control status to filter (default: non_compliant)")
@click.option("--framework", "-f", default=None, help="Limit to specific framework")
@click.option("--interactive/--no-interactive", default=True)
def control_owners_notify(status: str, framework: str | None, interactive: bool) -> None:
    """Identify failing controls, map to owners, simulate notification.

    Finds controls matching the given status, groups them by assigned owner,
    and displays a notification summary.

    \b
    Examples:
        warlock lifecycle control-owners --status non_compliant
        warlock lifecycle control-owners -s partial -f soc2
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Issue

    init_db()

    console.print(
        Panel(
            f"[bold]Control Owner Notification[/bold]\n\n"
            f"Filter: status=[cyan]{status}[/cyan]  "
            f"framework=[cyan]{framework or 'all'}[/cyan]",
            title="[bold cyan]WF-006: Control Owner Notify[/bold cyan]",
            border_style="cyan",
        )
    )

    with get_session() as session:
        # Find matching control results
        q = session.query(ControlResult).filter(ControlResult.status == status)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.all()

        if not results:
            console.print(f"\n  [green]No controls with status '{status}'.[/green]")
            return

        console.print(f"\n  Controls matching: [bold]{len(results)}[/bold]")

        # Map controls to owners via linked issues
        owner_map: dict[str, list[tuple[str, str, str]]] = {}  # owner -> [(fw, ctrl, severity)]

        for r in results:
            # Find assigned owner from issues
            issue = (
                session.query(Issue)
                .filter(
                    Issue.framework == r.framework,
                    Issue.control_id == r.control_id,
                    Issue.assigned_to.isnot(None),
                )
                .first()
            )
            owner = issue.assigned_to if issue else "unassigned"
            owner_map.setdefault(owner, []).append((r.framework, r.control_id, r.severity))

        # Display by owner
        owner_table = Table(title="Notification Summary by Owner", show_lines=True)
        owner_table.add_column("Owner")
        owner_table.add_column("Controls", justify="right")
        owner_table.add_column("Critical/High", justify="right")
        owner_table.add_column("Sample Controls")

        for owner, controls in sorted(owner_map.items(), key=lambda x: -len(x[1])):
            crit_high = sum(1 for _, _, sev in controls if sev in ("critical", "high"))
            samples = ", ".join(f"{fw}/{ctrl}" for fw, ctrl, _ in controls[:3])
            if len(controls) > 3:
                samples += f" +{len(controls) - 3} more"
            owner_table.add_row(
                owner if owner != "unassigned" else "[dim]unassigned[/dim]",
                str(len(controls)),
                f"[red]{crit_high}[/red]" if crit_high else "0",
                samples,
            )
        console.print(owner_table)

        # Notification simulation
        assigned_owners = {k: v for k, v in owner_map.items() if k != "unassigned"}
        unassigned_count = len(owner_map.get("unassigned", []))

        console.print(
            f"\n  Owners to notify: [bold]{len(assigned_owners)}[/bold]   "
            f"Unassigned controls: [yellow]{unassigned_count}[/yellow]"
        )

        if interactive and assigned_owners:
            try:
                if Confirm.ask("\n  Send notifications? (simulated)", default=False):
                    for owner, controls in assigned_owners.items():
                        crit_high = sum(1 for _, _, sev in controls if sev in ("critical", "high"))
                        console.print(
                            f"  [green]SENT[/green] -> {owner}: "
                            f"{len(controls)} control(s), {crit_high} critical/high"
                        )
                    _write_audit_entry(
                        session,
                        "control_owner_notifications",
                        "notification",
                        status,
                        {
                            "owners_notified": len(assigned_owners),
                            "total_controls": len(results),
                            "unassigned": unassigned_count,
                        },
                    )
                    console.print(
                        f"\n  [green]{len(assigned_owners)} notification(s) sent (simulated).[/green]"
                    )
            except (KeyboardInterrupt, EOFError):
                console.print("\n  [dim]Skipped.[/dim]")

        if unassigned_count > 0:
            console.print(
                f"\n  [yellow]Tip: {unassigned_count} control(s) have no owner. "
                "Assign via 'warlock issues assign'.[/yellow]"
            )


# ---------------------------------------------------------------------------
# WF-007: policy lifecycle
# ---------------------------------------------------------------------------


@lifecycle.command("policy")
@click.option("--interactive/--no-interactive", default=True)
def policy_lifecycle(interactive: bool) -> None:
    """Policy lifecycle: draft -> review -> approve -> publish, plus gap analysis.

    Walks through the full policy management workflow with review scheduling
    and compliance gap analysis.

    \b
    Examples:
        warlock lifecycle policy
        warlock lifecycle policy --no-interactive
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Policy, PolicyHistory

    init_db()

    now = _utcnow()

    console.print(
        Panel(
            "[bold]Policy Lifecycle Management[/bold]\n\n"
            f"Review date: {now.strftime('%Y-%m-%d')}\n"
            f"Actor: {_get_actor()}",
            title="[bold cyan]WF-007: Policy Lifecycle[/bold cyan]",
            border_style="cyan",
        )
    )

    with get_session() as session:
        # =================================================================
        # Step 1: Policy Inventory
        # =================================================================
        console.print("\n[bold cyan]Step 1: Policy Inventory[/bold cyan]")

        all_policies = session.query(Policy).all()

        if not all_policies:
            console.print("  [yellow]No policies found in the system.[/yellow]")
            if interactive:
                try:
                    if Confirm.ask("  Create a new policy?", default=True):
                        _create_policy_interactive(session, now)
                except (KeyboardInterrupt, EOFError):
                    console.print("\n  [dim]Skipped.[/dim]")
            return

        enabled = [p for p in all_policies if p.enabled]
        disabled = [p for p in all_policies if not p.enabled]

        console.print(
            f"  Total policies: [bold]{len(all_policies)}[/bold]   "
            f"Enabled: [green]{len(enabled)}[/green]   "
            f"Disabled: [dim]{len(disabled)}[/dim]"
        )

        # Group by type
        by_type: dict[str, list] = {}
        for p in all_policies:
            by_type.setdefault(p.policy_type, []).append(p)

        type_table = Table(title="Policies by Type", show_lines=False)
        type_table.add_column("Type")
        type_table.add_column("Count", justify="right")
        type_table.add_column("Enabled", justify="right")
        for ptype, policies in sorted(by_type.items()):
            en = sum(1 for p in policies if p.enabled)
            type_table.add_row(ptype, str(len(policies)), f"[green]{en}[/green]")
        console.print(type_table)

        # =================================================================
        # Step 2: Expiry / Review Check
        # =================================================================
        console.print("\n[bold cyan]Step 2: Policy Review Status[/bold cyan]")

        expired_policies = [
            p for p in enabled
            if p.expires_at and ensure_aware(p.expires_at) < now
        ]
        expiring_soon = [
            p for p in enabled
            if p.expires_at
            and ensure_aware(p.expires_at) >= now
            and ensure_aware(p.expires_at) < now + timedelta(days=30)
        ]

        if expired_policies:
            console.print(f"  [red]Expired: {len(expired_policies)} policy(ies)[/red]")
            for p in expired_policies[:5]:
                exp_str = p.expires_at.strftime("%Y-%m-%d") if p.expires_at else "---"
                console.print(
                    f"    [red]{p.policy_type}[/red] {p.id[:8]} — expired {exp_str}"
                )
        if expiring_soon:
            console.print(f"  [yellow]Expiring within 30d: {len(expiring_soon)}[/yellow]")
            for p in expiring_soon[:5]:
                exp_str = p.expires_at.strftime("%Y-%m-%d") if p.expires_at else "---"
                console.print(
                    f"    [yellow]{p.policy_type}[/yellow] {p.id[:8]} — expires {exp_str}"
                )
        if not expired_policies and not expiring_soon:
            console.print("  [green]All policies current.[/green]")

        # =================================================================
        # Step 3: Recent Changes
        # =================================================================
        console.print("\n[bold cyan]Step 3: Recent Policy Changes[/bold cyan]")

        thirty_days_ago = now - timedelta(days=30)
        recent_changes = (
            session.query(PolicyHistory)
            .filter(PolicyHistory.timestamp >= thirty_days_ago)
            .order_by(PolicyHistory.timestamp.desc())
            .limit(10)
            .all()
        )

        if recent_changes:
            change_table = Table(title="Recent Changes (30d)", show_lines=False)
            change_table.add_column("Policy", max_width=8)
            change_table.add_column("Action")
            change_table.add_column("Actor")
            change_table.add_column("Date")
            for ch in recent_changes:
                change_table.add_row(
                    ch.policy_id[:8],
                    ch.action,
                    ch.actor or "---",
                    ch.timestamp.strftime("%Y-%m-%d") if ch.timestamp else "---",
                )
            console.print(change_table)
        else:
            console.print("  [dim]No policy changes in the last 30 days.[/dim]")

        # =================================================================
        # Step 4: Gap Analysis
        # =================================================================
        console.print("\n[bold cyan]Step 4: Gap Analysis[/bold cyan]")

        expected_types = [
            "access_control",
            "data_classification",
            "incident_response",
            "change_management",
            "risk_management",
            "vendor_management",
            "acceptable_use",
            "backup_recovery",
        ]
        existing_types = set(by_type.keys())
        missing_types = [t for t in expected_types if t not in existing_types]

        if missing_types:
            console.print(f"  [yellow]Missing policy types ({len(missing_types)}):[/yellow]")
            for mt in missing_types:
                console.print(f"    [yellow]- {mt}[/yellow]")
        else:
            console.print("  [green]All expected policy types are covered.[/green]")

        # =================================================================
        # Step 5: Interactive Actions
        # =================================================================
        if interactive:
            console.print("\n[bold cyan]Step 5: Actions[/bold cyan]")

            try:
                while True:
                    console.print(
                        "\n  [dim]n[/dim]=new policy  "
                        "[dim]r[/dim]=review expired  "
                        "[dim]d[/dim]=disable policy  "
                        "[dim]q[/dim]=quit"
                    )
                    choice = Prompt.ask(
                        "Action",
                        choices=["n", "r", "d", "q"],
                        default="q",
                    )

                    if choice == "q":
                        break

                    elif choice == "n":
                        _create_policy_interactive(session, now)

                    elif choice == "r":
                        if not expired_policies:
                            console.print("  [green]No expired policies to review.[/green]")
                            continue
                        for p in expired_policies[:3]:
                            console.print(
                                f"\n  Policy: {p.policy_type} ({p.id[:8]})"
                            )
                            console.print(f"  Description: {(p.description or '')[:80]}")
                            renew = Confirm.ask("  Renew for 365 days?", default=True)
                            if renew:
                                p.expires_at = now + timedelta(days=365)
                                history = PolicyHistory(
                                    id=str(uuid.uuid4()),
                                    policy_id=p.id,
                                    action="renewed",
                                    old_rules=p.rules,
                                    new_rules=p.rules,
                                    actor=_get_actor(),
                                )
                                session.add(history)
                                session.commit()
                                console.print(
                                    f"  [green]Renewed until {p.expires_at.strftime('%Y-%m-%d')}[/green]"
                                )

                    elif choice == "d":
                        pid = Prompt.ask("Policy ID (prefix)")
                        policy = (
                            session.query(Policy).filter(Policy.id.startswith(pid.strip())).first()
                        )
                        if policy:
                            policy.enabled = False
                            session.commit()
                            console.print(
                                f"  [green]Policy {policy.id[:8]} ({policy.policy_type}) disabled.[/green]"
                            )
                        else:
                            console.print(f"  [yellow]Policy '{pid}' not found.[/yellow]")

            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Session ended.[/dim]")

        _write_audit_entry(
            session,
            "policy_lifecycle_review",
            "policy",
            "all",
            {
                "review_date": now.isoformat(),
                "total_policies": len(all_policies),
                "expired": len(expired_policies),
                "missing_types": missing_types,
            },
        )
        console.print("\n[dim]Policy review recorded in audit trail.[/dim]")


def _create_policy_interactive(session, now: datetime) -> None:
    """Helper: interactive policy creation wizard."""
    from warlock.db.models import Policy, PolicyHistory

    policy_type = Prompt.ask(
        "Policy type",
        choices=[
            "access_control",
            "data_classification",
            "incident_response",
            "change_management",
            "risk_management",
            "vendor_management",
            "acceptable_use",
            "backup_recovery",
            "other",
        ],
    )
    description = Prompt.ask("Description", default="")
    days_str = Prompt.ask("Valid for (days)", default="365")
    try:
        valid_days = int(days_str)
    except ValueError:
        valid_days = 365

    policy = Policy(
        id=str(uuid.uuid4()),
        policy_type=policy_type,
        scope={"org": "all"},
        rules={"version": "1.0", "status": "draft"},
        priority=0,
        enabled=True,
        created_by=_get_actor(),
        description=description,
        effective_at=now,
        expires_at=now + timedelta(days=valid_days),
    )
    session.add(policy)

    history = PolicyHistory(
        id=str(uuid.uuid4()),
        policy_id=policy.id,
        action="created",
        new_rules=policy.rules,
        actor=_get_actor(),
    )
    session.add(history)
    session.commit()

    console.print(
        f"  [green]Policy created: {policy.id[:8]} ({policy_type}) "
        f"expires {policy.expires_at.strftime('%Y-%m-%d')}[/green]"
    )
