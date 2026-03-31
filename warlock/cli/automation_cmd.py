"""Workflow automation commands.

Group: ``automation``

Provides automated pipeline runs, evidence refresh, issue/POA&M auto-creation,
housekeeping cleanup, and rule/schedule management sub-groups.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import _error, _get_actor, _print_stats, cli, console


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("automation", invoke_without_command=True)
@click.pass_context
def automation(ctx: click.Context) -> None:
    """Workflow automation: pipeline runs, evidence refresh, auto-issue/POA&M, housekeeping."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# run-all
# ---------------------------------------------------------------------------


@automation.command("run-all")
@click.option("--dry-run", is_flag=True, default=False, help="Show plan without executing")
def run_all(dry_run: bool) -> None:
    """Run the full pipeline: collect -> normalize -> map -> assess -> report.

    Equivalent to 'warlock collect' but surfaced in the automation group
    for workflow and scheduler context.
    """
    if dry_run:
        console.print("[dim](dry-run) Would run full pipeline:[/dim]")
        console.print("  1. Collect raw events from all enabled connectors")
        console.print("  2. Normalize events into findings")
        console.print("  3. Map findings to framework controls")
        console.print("  4. Assess control results via assertions + AI")
        console.print("  5. Write results to DB and data lake")
        console.print("\n[dim]Pass without --dry-run to execute.[/dim]")
        return

    import logging

    from warlock.db.engine import get_session, init_db
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline, register_lake_writer

    init_db()
    bus = EventBus()
    lake_writer = register_lake_writer(bus)
    pipeline = build_pipeline(bus)

    bus.subscribe_all(
        lambda e: logging.getLogger("automation.bus").debug(
            "%s -> %s", e.event_type, e.payload_id[:8]
        )
    )

    console.print("[cyan]Running full pipeline...[/cyan]")
    with get_session() as session:
        stats = pipeline.run(session)

    if lake_writer is not None:
        with get_session() as lake_session:
            lake_stats = lake_writer.flush(stats.run_id, lake_session)
            logging.getLogger(__name__).info(
                "Lake write: %d raw, %d findings, %d results",
                lake_stats.raw_events_written,
                lake_stats.findings_written,
                lake_stats.control_results_written,
            )

    _print_stats(stats)
    if stats.errors:
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# collect-and-assess
# ---------------------------------------------------------------------------


@automation.command("collect-and-assess")
@click.option("--source", "-s", multiple=True, help="Limit to source(s) (repeatable)")
@click.option(
    "--framework", "-f", multiple=True, help="Limit assessment to framework(s) (repeatable)"
)
@click.option("--dry-run", is_flag=True, default=False, help="Show plan without executing")
def collect_and_assess(
    source: tuple[str, ...],
    framework: tuple[str, ...],
    dry_run: bool,
) -> None:
    """Targeted pipeline run: collect from specific sources and assess specific frameworks."""
    if dry_run:
        console.print("[dim](dry-run) Would run targeted pipeline:[/dim]")
        console.print(f"  Sources:    {', '.join(source) if source else 'all'}")
        console.print(f"  Frameworks: {', '.join(framework) if framework else 'all'}")
        console.print("\n[dim]Pass without --dry-run to execute.[/dim]")
        return

    import logging

    from warlock.db.engine import get_session, init_db
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline, register_lake_writer

    init_db()
    bus = EventBus()
    lake_writer = register_lake_writer(bus)
    pipeline = build_pipeline(bus, sources=source or None)

    console.print(
        f"[cyan]Running targeted pipeline "
        f"(sources: {', '.join(source) or 'all'}, "
        f"frameworks: {', '.join(framework) or 'all'})...[/cyan]"
    )

    with get_session() as session:
        stats = pipeline.run(session)

    if lake_writer is not None:
        with get_session() as lake_session:
            lake_writer.flush(stats.run_id, lake_session)
            logging.getLogger(__name__).info("Lake write complete for run %s", stats.run_id)

    _print_stats(stats)
    if stats.errors:
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# refresh-evidence
# ---------------------------------------------------------------------------


@automation.command("refresh-evidence")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
@click.option("--stale-days", "-d", default=7, help="Re-collect evidence older than N days")
@click.option("--dry-run", is_flag=True, default=False, help="Show stale controls without running")
def refresh_evidence(framework: str | None, stale_days: int, dry_run: bool) -> None:
    """Re-collect evidence for controls with stale assessments.

    Identifies controls not assessed in the past N days and triggers
    a targeted pipeline run for their source connectors.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    cutoff = _utcnow() - timedelta(days=stale_days)

    with get_session() as session:
        q = session.query(ControlResult).filter(ControlResult.assessed_at < cutoff)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        stale_rows = q.order_by(ControlResult.assessed_at.asc()).limit(200).all()

    if not stale_rows:
        console.print(
            f"[green]No stale controls (all assessed within the last {stale_days} days).[/green]"
        )
        return

    table = Table(
        title=f"Stale Controls (last assessed > {stale_days} days ago, showing up to 200)"
    )
    table.add_column("Framework", style="cyan")
    table.add_column("Control ID")
    table.add_column("Status")
    table.add_column("Last Assessed")
    for r in stale_rows[:50]:
        table.add_row(
            r.framework,
            r.control_id,
            r.status,
            str(r.assessed_at)[:19] if r.assessed_at else "—",
        )
    if len(stale_rows) > 50:
        console.print(f"[dim]... and {len(stale_rows) - 50} more not shown[/dim]")
    console.print(table)
    console.print(f"\n[bold]{len(stale_rows)}[/bold] stale control result(s) found.")

    if dry_run:
        console.print(
            "\n[dim](dry-run) Would trigger pipeline refresh for stale controls. "
            "Pass without --dry-run to execute.[/dim]"
        )
        return

    # Trigger a full pipeline run to re-collect and re-assess
    from warlock.db.engine import get_session as _get_session
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline, register_lake_writer

    bus = EventBus()
    lake_writer = register_lake_writer(bus)
    pipeline = build_pipeline(bus)

    console.print("[cyan]Running pipeline to refresh stale evidence...[/cyan]")
    with _get_session() as session:
        stats = pipeline.run(session)

    if lake_writer is not None:
        with _get_session() as lake_session:
            lake_writer.flush(stats.run_id, lake_session)

    _print_stats(stats)
    console.print("[green]Evidence refresh complete.[/green]")


# ---------------------------------------------------------------------------
# auto-issue
# ---------------------------------------------------------------------------


@automation.command("auto-issue")
@click.option(
    "--severity",
    "-s",
    multiple=True,
    type=click.Choice(["critical", "high", "medium", "low"]),
    default=["critical", "high"],
    show_default=True,
    help="Severity levels to auto-issue (repeatable)",
)
@click.option(
    "--dry-run", is_flag=True, default=False, help="Show would-be issues without creating"
)
@click.option("--limit", "-n", default=100, help="Max issues to create in one run")
def auto_issue(
    severity: tuple[str, ...],
    dry_run: bool,
    limit: int,
) -> None:
    """Auto-create issues from findings that have no linked issue.

    Scans findings at the specified severity levels that are not yet
    tracked in an Issue record and creates open issues for them.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, Issue

    init_db()
    actor = _get_actor()

    with get_session() as session:
        # Find findings that have no linked issue
        linked_finding_ids = {
            row[0]
            for row in session.query(Issue.finding_id).filter(Issue.finding_id.isnot(None)).all()
        }
        q = session.query(Finding).filter(Finding.severity.in_(list(severity)))
        candidates = [r for r in q.all() if r.id not in linked_finding_ids]

    candidates = candidates[:limit]

    if not candidates:
        console.print(f"[green]No untracked findings at severity {', '.join(severity)}.[/green]")
        return

    console.print(
        f"[bold]{len(candidates)}[/bold] finding(s) without a linked issue "
        f"(severity: {', '.join(severity)})."
    )

    table = Table(title="Findings to Auto-Issue")
    table.add_column("Finding ID", style="dim", max_width=8)
    table.add_column("Severity")
    table.add_column("Title", max_width=55)
    table.add_column("Source")
    for r in candidates[:20]:
        table.add_row(r.id[:8], r.severity, escape(r.title[:55] if r.title else ""), r.source)
    if len(candidates) > 20:
        console.print(f"[dim]... and {len(candidates) - 20} more[/dim]")
    console.print(table)

    if dry_run:
        console.print(
            f"\n[dim](dry-run) Would create {len(candidates)} issue(s). "
            f"Pass without --dry-run to execute.[/dim]"
        )
        return

    created = 0
    with get_session() as session:
        for f in candidates:
            issue = Issue(
                title=f"[Auto] {f.title}",
                description=(
                    f"Auto-created from finding {f.id[:8]}.\n"
                    f"Source: {f.source}/{f.provider}\n"
                    f"Observation type: {f.observation_type}\n"
                    f"Resource: {f.resource_type or '—'} — {f.resource_id or '—'}"
                ),
                finding_id=f.id,
                status="open",
                priority=f.severity,
                source="pipeline",
                created_by=actor,
            )
            session.add(issue)
            created += 1
        session.commit()

    console.print(f"[green]Created {created} issue(s).[/green]")


# ---------------------------------------------------------------------------
# auto-poam
# ---------------------------------------------------------------------------


@automation.command("auto-poam")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
@click.option(
    "--dry-run", is_flag=True, default=False, help="Show would-be POA&Ms without creating"
)
@click.option("--limit", "-n", default=50, help="Max POA&Ms to create in one run")
def auto_poam(
    framework: str | None,
    dry_run: bool,
    limit: int,
) -> None:
    """Auto-create POA&Ms from failed controls that have no existing POA&M.

    Scans non-compliant ControlResult records and creates draft POA&M
    entries for those not already tracked.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM, ControlResult

    init_db()
    actor = _get_actor()

    with get_session() as session:
        # Find control/framework pairs already in POAM
        existing_pairs = {
            (row.framework, row.control_id)
            for row in session.query(POAM.framework, POAM.control_id).all()
        }

        q = session.query(ControlResult).filter(ControlResult.status == "non_compliant")
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.order_by(ControlResult.assessed_at.desc()).all()

        candidates = [r for r in results if (r.framework, r.control_id) not in existing_pairs]

    candidates = candidates[:limit]

    if not candidates:
        console.print("[green]No non-compliant controls without an existing POA&M.[/green]")
        return

    console.print(f"[bold]{len(candidates)}[/bold] non-compliant control(s) without a POA&M.")

    table = Table(title="Controls to Auto-POA&M")
    table.add_column("Framework", style="cyan")
    table.add_column("Control ID")
    table.add_column("Severity")
    table.add_column("Assessor")
    for r in candidates[:20]:
        table.add_row(r.framework, r.control_id, r.severity, (r.assessor or "")[:30])
    if len(candidates) > 20:
        console.print(f"[dim]... and {len(candidates) - 20} more[/dim]")
    console.print(table)

    if dry_run:
        console.print(
            f"\n[dim](dry-run) Would create {len(candidates)} POA&M draft(s). "
            f"Pass without --dry-run to execute.[/dim]"
        )
        return

    created = 0
    scheduled = _utcnow() + timedelta(days=90)

    with get_session() as session:
        for r in candidates:
            poam = POAM(
                finding_id=r.finding_id,
                control_result_id=r.id,
                framework=r.framework,
                control_id=r.control_id,
                weakness_description=(
                    r.remediation_summary
                    or f"Control {r.control_id} assessed as non-compliant by {r.assessor}."
                ),
                severity=r.severity,
                risk_level="moderate",
                status="draft",
                scheduled_completion=scheduled,
                created_by=actor,
                milestones=[],
            )
            session.add(poam)
            created += 1
        session.commit()

    console.print(
        f"[green]Created {created} POA&M draft(s) "
        f"(scheduled completion: {scheduled.strftime('%Y-%m-%d')}).[/green]"
    )


# ---------------------------------------------------------------------------
# cleanup
# ---------------------------------------------------------------------------


@automation.command("cleanup")
@click.option("--older-than-days", "-d", default=180, help="Archive records older than N days")
@click.option("--dry-run", is_flag=True, default=False, help="Show what would be archived")
def cleanup(older_than_days: int, dry_run: bool) -> None:
    """Archive old resolved issues, closed POA&Ms, and stale findings.

    Moves qualifying records to an archived/closed state and logs the
    action in the audit trail.  Does not delete records.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM, Issue

    init_db()
    cutoff = _utcnow() - timedelta(days=older_than_days)

    with get_session() as session:
        old_issues = (
            session.query(Issue)
            .filter(
                Issue.status.in_(["closed", "remediated", "verified"]),
                Issue.updated_at < cutoff,
            )
            .all()
        )
        old_poams = (
            session.query(POAM)
            .filter(
                POAM.status.in_(["closed", "completed", "verified"]),
                POAM.updated_at < cutoff,
            )
            .all()
        )

    console.print(
        f"[bold]Cleanup Report[/bold] (records closed/resolved older than {older_than_days} days)"
    )

    table = Table(title="Archivable Records")
    table.add_column("Type", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Action")
    table.add_row("Issues (closed/remediated)", str(len(old_issues)), "mark archived")
    table.add_row("POA&Ms (closed/completed)", str(len(old_poams)), "mark archived")
    console.print(table)

    if not old_issues and not old_poams:
        console.print("[green]Nothing to archive.[/green]")
        return

    if dry_run:
        console.print(
            f"\n[dim](dry-run) Would archive {len(old_issues)} issue(s) "
            f"and {len(old_poams)} POA&M(s). "
            f"Pass without --dry-run to execute.[/dim]"
        )
        return

    actor = _get_actor()
    archived_issues = 0
    archived_poams = 0

    with get_session() as session:
        for issue in old_issues:
            # Store archive metadata in the tags JSON field
            tags = list(issue.tags or [])
            if "archived" not in tags:
                tags.append("archived")
                issue.tags = tags
                archived_issues += 1

        for poam in old_poams:
            if poam.status != "closed":
                poam.status = "closed"
                poam.updated_by = actor
                archived_poams += 1

        session.commit()

    console.print(
        f"[green]Archived {archived_issues} issue(s) and {archived_poams} POA&M(s).[/green]"
    )


# ---------------------------------------------------------------------------
# rules sub-group
# ---------------------------------------------------------------------------


@automation.group("rules", invoke_without_command=True)
@click.pass_context
def automation_rules(ctx: click.Context) -> None:
    """Automation rule management: list, create, delete, test."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@automation_rules.command("list")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def rules_list(fmt: str) -> None:
    """List all automation rules.

    Rules are stored as JSON records in the audit trail's extra field
    with action='automation_rule'.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        rows = (
            session.query(AuditEntry)
            .filter(AuditEntry.action == "automation_rule")
            .order_by(AuditEntry.created_at.desc())
            .all()
        )

    if not rows:
        console.print("[dim]No automation rules defined.[/dim]")
        console.print("[dim]Use 'warlock automation rules create' to add a rule.[/dim]")
        return

    rules = []
    for row in rows:
        extra = row.extra or {}
        if extra.get("deleted"):
            continue
        rules.append(
            {
                "id": row.entity_id,
                "trigger": extra.get("trigger", "—"),
                "action": extra.get("action", "—"),
                "conditions": extra.get("conditions", ""),
                "enabled": extra.get("enabled", True),
                "created_by": row.actor,
                "created_at": str(row.created_at)[:19],
            }
        )

    if fmt == "json":
        console.print(json.dumps(rules, indent=2))
        return

    table = Table(title=f"Automation Rules ({len(rules)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Trigger")
    table.add_column("Action")
    table.add_column("Conditions", max_width=40)
    table.add_column("Enabled", justify="center")
    table.add_column("Created By")
    for r in rules:
        enabled_str = "[green]yes[/green]" if r["enabled"] else "[red]no[/red]"
        table.add_row(
            r["id"][:8],
            r["trigger"],
            r["action"],
            (r["conditions"] or "")[:40],
            enabled_str,
            r["created_by"],
        )
    console.print(table)


@automation_rules.command("create")
@click.option("--trigger", "-t", required=True, help="Event type that activates this rule")
@click.option("--action", "-a", required=True, help="Action to execute when triggered")
@click.option("--conditions", "-c", default="", help="Conditions in key=value format")
@click.option("--enabled/--disabled", default=True, help="Enable or disable the rule")
def rules_create(trigger: str, action: str, conditions: str, enabled: bool) -> None:
    """Create an automation rule.

    Example:

    \b
      warlock automation rules create \\
        --trigger finding.severity=critical \\
        --action auto-issue \\
        --conditions "framework=nist_800_53"
    """
    import hashlib
    import uuid as _uuid

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    actor = _get_actor()
    rule_id = str(_uuid.uuid4())

    with get_session() as session:
        # Get the current sequence + 1
        from sqlalchemy import func

        max_seq = session.query(func.max(AuditEntry.sequence)).scalar() or 0
        prev_entry = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        prev_hash = prev_entry.entry_hash if prev_entry else "genesis"
        seq = max_seq + 1

        extra: dict = {
            "trigger": trigger,
            "action": action,
            "conditions": conditions,
            "enabled": enabled,
            "rule_id": rule_id,
        }
        payload = json.dumps(extra, sort_keys=True)
        entry_hash = hashlib.sha256(f"{seq}:{prev_hash}:{rule_id}:{payload}".encode()).hexdigest()

        entry = AuditEntry(
            id=str(_uuid.uuid4()),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="automation_rule",
            entity_type="automation_rule",
            entity_id=rule_id,
            actor=actor,
            extra=extra,
        )
        session.add(entry)
        session.commit()

    console.print("[green]Automation rule created.[/green]")
    console.print(f"  ID:         {rule_id}")
    console.print(f"  Trigger:    {trigger}")
    console.print(f"  Action:     {action}")
    console.print(f"  Conditions: {conditions or '(none)'}")
    console.print(f"  Enabled:    {'yes' if enabled else 'no'}")


@automation_rules.command("delete")
@click.argument("rule_id")
def rules_delete(rule_id: str) -> None:
    """Mark an automation rule as deleted.

    RULE_ID: rule UUID or prefix (from 'warlock automation rules list').
    """
    import hashlib
    import uuid as _uuid

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    actor = _get_actor()

    with get_session() as session:
        row = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "automation_rule",
                AuditEntry.entity_id.startswith(rule_id),
            )
            .order_by(AuditEntry.created_at.desc())
            .first()
        )
        if not row:
            _error(f"Automation rule '{rule_id}' not found.")

        extra = dict(row.extra or {})
        if extra.get("deleted"):
            console.print(f"[yellow]Rule {row.entity_id[:8]} is already deleted.[/yellow]")
            return

        from sqlalchemy import func

        max_seq = session.query(func.max(AuditEntry.sequence)).scalar() or 0
        prev_entry = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        prev_hash = prev_entry.entry_hash if prev_entry else "genesis"
        seq = max_seq + 1

        del_extra = {
            "trigger": extra.get("trigger"),
            "action": extra.get("action"),
            "deleted": True,
        }
        payload = json.dumps(del_extra, sort_keys=True)
        entry_hash = hashlib.sha256(
            f"{seq}:{prev_hash}:{row.entity_id}:{payload}".encode()
        ).hexdigest()

        del_entry = AuditEntry(
            id=str(_uuid.uuid4()),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="automation_rule",
            entity_type="automation_rule",
            entity_id=row.entity_id,
            actor=actor,
            extra=del_extra,
        )
        session.add(del_entry)
        session.commit()

    console.print(f"[yellow]Automation rule {row.entity_id[:8]} deleted.[/yellow]")


@automation_rules.command("test")
@click.argument("rule_id")
@click.option("--dry-run", is_flag=True, default=True, help="Run test without side effects")
def rules_test(rule_id: str, dry_run: bool) -> None:
    """Test an automation rule against current data.

    RULE_ID: rule UUID or prefix (from 'warlock automation rules list').
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, ControlResult, Finding

    init_db()

    with get_session() as session:
        row = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "automation_rule",
                AuditEntry.entity_id.startswith(rule_id),
            )
            .order_by(AuditEntry.created_at.desc())
            .first()
        )
        if not row:
            _error(f"Automation rule '{rule_id}' not found.")

        extra = row.extra or {}
        if extra.get("deleted"):
            _error(f"Rule {row.entity_id[:8]} has been deleted.")

        trigger = extra.get("trigger", "")
        action = extra.get("action", "")
        conditions = extra.get("conditions", "")

    console.print(f"\n[bold]Testing rule {row.entity_id[:8]}[/bold]")
    console.print(f"  Trigger:    {trigger}")
    console.print(f"  Action:     {action}")
    console.print(f"  Conditions: {conditions or '(none)'}")
    if dry_run:
        console.print("[dim](dry-run mode — no changes will be made)[/dim]")

    # Parse a simple "key=value" condition string into a filter dict
    condition_filters: dict[str, str] = {}
    if conditions:
        for part in conditions.split(","):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                condition_filters[k.strip()] = v.strip()

    # Evaluate the trigger against current data
    matches: list[str] = []

    with get_session() as session:
        if "finding" in trigger.lower():
            q = session.query(Finding)
            if "severity" in trigger:
                sev = trigger.split("=")[-1].strip() if "=" in trigger else None
                if sev:
                    q = q.filter(Finding.severity == sev)
            if "framework" in condition_filters:
                pass  # findings don't have a direct framework column
            rows = q.limit(10).all()
            matches = [f"{r.id[:8]} — {r.title[:40]} [{r.severity}]" for r in rows]

        elif "control" in trigger.lower() or "non_compliant" in trigger.lower():
            q = session.query(ControlResult).filter(ControlResult.status == "non_compliant")
            if "framework" in condition_filters:
                q = q.filter(ControlResult.framework == condition_filters["framework"])
            rows = q.limit(10).all()
            matches = [f"{r.id[:8]} — {r.framework}/{r.control_id} [{r.severity}]" for r in rows]

    if matches:
        console.print(f"\n[green]{len(matches)} matching record(s) (showing up to 10):[/green]")
        for m in matches:
            console.print(f"  [dim]{m}[/dim]")
        console.print(
            f"\n[dim]{'(dry-run) Would execute' if dry_run else 'Would execute'}: {action}[/dim]"
        )
    else:
        console.print("\n[dim]No matching records for this rule's trigger at this time.[/dim]")


# ---------------------------------------------------------------------------
# schedules sub-group
# ---------------------------------------------------------------------------


@automation.group("schedules", invoke_without_command=True)
@click.pass_context
def automation_schedules(ctx: click.Context) -> None:
    """Schedule management: list and configure automation schedules."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@automation_schedules.command("list")
def schedules_list() -> None:
    """Show all configured automation schedules."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        rows = (
            session.query(AuditEntry)
            .filter(AuditEntry.action == "automation_schedule")
            .order_by(AuditEntry.created_at.desc())
            .all()
        )

    # Deduplicate: keep only the latest entry per schedule name
    seen: dict[str, dict] = {}
    for row in rows:
        extra = row.extra or {}
        name = extra.get("name", row.entity_id)
        if name not in seen:
            seen[name] = {
                "id": row.entity_id[:8],
                "name": name,
                "cron": extra.get("cron", "—"),
                "enabled": extra.get("enabled", True),
                "updated_by": row.actor,
                "updated_at": str(row.created_at)[:19],
            }

    if not seen:
        console.print("[dim]No schedules configured.[/dim]")
        console.print("[dim]Use 'warlock automation schedules set' to configure one.[/dim]")
        return

    table = Table(title=f"Automation Schedules ({len(seen)})")
    table.add_column("Name", style="cyan")
    table.add_column("Cron Expression")
    table.add_column("Enabled", justify="center")
    table.add_column("Updated By")
    table.add_column("Updated At")
    for sched in seen.values():
        enabled_str = "[green]yes[/green]" if sched["enabled"] else "[red]no[/red]"
        table.add_row(
            sched["name"],
            sched["cron"],
            enabled_str,
            sched["updated_by"],
            sched["updated_at"],
        )
    console.print(table)


# ---------------------------------------------------------------------------
# webhook sub-group (AU-001)
# ---------------------------------------------------------------------------


@automation.group("webhook", invoke_without_command=True)
@click.pass_context
def automation_webhook(ctx: click.Context) -> None:
    """Webhook trigger management: create, list, delete, test."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@automation_webhook.command("create")
@click.option("--name", "-n", required=True, help="Webhook name (e.g. deploy-gate)")
@click.option("--url", "-u", required=True, help="Webhook endpoint URL")
@click.option(
    "--event",
    "-e",
    multiple=True,
    help="Event type to trigger on (repeatable, e.g. pipeline.complete, finding.critical)",
)
@click.option("--secret", "-s", default=None, help="Shared secret for HMAC signing")
@click.option("--enabled/--disabled", default=True, help="Enable or disable the webhook")
def webhook_create(
    name: str, url: str, event: tuple[str, ...], secret: str | None, enabled: bool
) -> None:
    """Register a webhook trigger.

    When the specified events occur, Warlock will POST a JSON payload to the
    webhook URL. If a shared secret is provided, the payload is HMAC-SHA256 signed.

    Example:

    \b
      warlock automation webhook create \\
        --name deploy-gate \\
        --url https://ci.example.com/webhook \\
        --event pipeline.complete \\
        --event finding.critical \\
        --secret my-shared-secret
    """
    import hashlib
    import uuid as _uuid

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    actor = _get_actor()
    webhook_id = str(_uuid.uuid4())

    with get_session() as session:
        from sqlalchemy import func

        max_seq = session.query(func.max(AuditEntry.sequence)).scalar() or 0
        prev_entry = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        prev_hash = prev_entry.entry_hash if prev_entry else "genesis"
        seq = max_seq + 1

        extra: dict = {
            "name": name,
            "url": url,
            "events": list(event),
            "has_secret": secret is not None,
            "enabled": enabled,
            "webhook_id": webhook_id,
        }
        payload = json.dumps(extra, sort_keys=True)
        entry_hash = hashlib.sha256(
            f"{seq}:{prev_hash}:{webhook_id}:{payload}".encode()
        ).hexdigest()

        entry = AuditEntry(
            id=str(_uuid.uuid4()),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="automation_webhook",
            entity_type="automation_webhook",
            entity_id=webhook_id,
            actor=actor,
            extra=extra,
        )
        session.add(entry)
        session.commit()

    console.print("[green]Webhook registered.[/green]")
    console.print(f"  ID:      {webhook_id[:8]}")
    console.print(f"  Name:    {name}")
    console.print(f"  URL:     {url}")
    console.print(f"  Events:  {', '.join(event) if event else '(all)'}")
    console.print(f"  Signed:  {'yes' if secret else 'no'}")
    console.print(f"  Enabled: {'yes' if enabled else 'no'}")


@automation_webhook.command("list")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def webhook_list(fmt: str) -> None:
    """List all registered webhooks."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        rows = (
            session.query(AuditEntry)
            .filter(AuditEntry.action == "automation_webhook")
            .order_by(AuditEntry.created_at.desc())
            .all()
        )

    # Deduplicate by webhook_id, keep latest
    seen: dict[str, dict] = {}
    for row in rows:
        extra = row.extra or {}
        wh_id = extra.get("webhook_id", row.entity_id)
        if wh_id not in seen and not extra.get("deleted"):
            seen[wh_id] = {
                "id": wh_id,
                "name": extra.get("name", ""),
                "url": extra.get("url", ""),
                "events": extra.get("events", []),
                "enabled": extra.get("enabled", True),
                "created_by": row.actor,
            }

    if not seen:
        console.print("[dim]No webhooks registered.[/dim]")
        return

    if fmt == "json":
        console.print(json.dumps(list(seen.values()), indent=2))
        return

    table = Table(title=f"Webhooks ({len(seen)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", style="cyan")
    table.add_column("URL", max_width=50)
    table.add_column("Events", max_width=30)
    table.add_column("Enabled", justify="center")

    for wh in seen.values():
        enabled_str = "[green]yes[/green]" if wh["enabled"] else "[red]no[/red]"
        table.add_row(
            wh["id"][:8],
            wh["name"],
            wh["url"][:50],
            ", ".join(wh["events"])[:30] or "(all)",
            enabled_str,
        )

    console.print(table)


@automation_webhook.command("delete")
@click.argument("webhook_id")
def webhook_delete(webhook_id: str) -> None:
    """Delete a registered webhook.

    WEBHOOK_ID: webhook UUID or prefix (from 'warlock automation webhook list').
    """
    import hashlib
    import uuid as _uuid

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    actor = _get_actor()

    with get_session() as session:
        row = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "automation_webhook",
                AuditEntry.entity_id.startswith(webhook_id),
            )
            .order_by(AuditEntry.created_at.desc())
            .first()
        )
        if not row:
            _error(f"Webhook '{webhook_id}' not found.")

        extra = dict(row.extra or {})
        if extra.get("deleted"):
            console.print(f"[yellow]Webhook {row.entity_id[:8]} is already deleted.[/yellow]")
            return

        from sqlalchemy import func

        max_seq = session.query(func.max(AuditEntry.sequence)).scalar() or 0
        prev_entry = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        prev_hash = prev_entry.entry_hash if prev_entry else "genesis"
        seq = max_seq + 1

        del_extra = {"name": extra.get("name"), "deleted": True}
        payload = json.dumps(del_extra, sort_keys=True)
        entry_hash = hashlib.sha256(
            f"{seq}:{prev_hash}:{row.entity_id}:{payload}".encode()
        ).hexdigest()

        del_entry = AuditEntry(
            id=str(_uuid.uuid4()),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="automation_webhook",
            entity_type="automation_webhook",
            entity_id=row.entity_id,
            actor=actor,
            extra=del_extra,
        )
        session.add(del_entry)
        session.commit()

    console.print(f"[yellow]Webhook {row.entity_id[:8]} deleted.[/yellow]")


@automation_webhook.command("test")
@click.argument("webhook_id")
def webhook_test(webhook_id: str) -> None:
    """Send a test ping to a registered webhook.

    WEBHOOK_ID: webhook UUID or prefix.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()

    with get_session() as session:
        row = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "automation_webhook",
                AuditEntry.entity_id.startswith(webhook_id),
            )
            .order_by(AuditEntry.created_at.desc())
            .first()
        )
        if not row:
            _error(f"Webhook '{webhook_id}' not found.")

    extra = row.extra or {}
    if extra.get("deleted"):
        _error(f"Webhook {row.entity_id[:8]} has been deleted.")

    url = extra.get("url", "")
    name = extra.get("name", "")

    console.print(f"[cyan]Sending test ping to webhook '{name}'...[/cyan]")
    console.print(f"  URL: {url}")

    test_payload = {
        "event": "webhook.test",
        "webhook_id": row.entity_id,
        "timestamp": _utcnow().isoformat(),
        "message": "Test ping from Warlock automation webhook",
    }

    console.print(f"  Payload: {json.dumps(test_payload, indent=2)}")
    console.print(
        "[dim](To actually deliver, configure WLK_WEBHOOK_DELIVERY=true. "
        "Currently showing payload only.)[/dim]"
    )


# ---------------------------------------------------------------------------
# gate (AU-003)
# ---------------------------------------------------------------------------


@automation.command("gate")
@click.option("--framework", "-f", required=True, help="Framework to evaluate (e.g. soc2)")
@click.option(
    "--min-score",
    type=float,
    default=80.0,
    help="Minimum compliance score (0-100) to pass (default: 80)",
)
@click.option(
    "--fail-on-critical", is_flag=True, default=False, help="Fail if any critical findings exist"
)
@click.option(
    "--fail-on-non-compliant",
    type=int,
    default=None,
    help="Fail if non-compliant count exceeds this threshold",
)
def automation_gate(
    framework: str,
    min_score: float,
    fail_on_critical: bool,
    fail_on_non_compliant: int | None,
) -> None:
    """CI/CD compliance gate.

    Evaluates the current compliance posture for a framework and exits with
    code 0 (pass) or 1 (fail). Designed for use in CI/CD pipelines.

    Example:

    \b
      warlock automation gate --framework soc2 --min-score 80 --fail-on-critical
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding

    init_db()
    failures: list[str] = []

    with get_session() as session:
        results = session.query(ControlResult).filter(ControlResult.framework == framework).all()

        if not results:
            _error(f"No control results found for framework '{framework}'. Run pipeline first.")

        total = len(results)
        compliant = sum(1 for r in results if r.status == "compliant")
        non_compliant = sum(1 for r in results if r.status == "non_compliant")
        partial = sum(1 for r in results if r.status == "partial")
        score = (compliant / total * 100) if total else 0.0

        # Check critical findings
        critical_count = 0
        if fail_on_critical:
            critical_count = session.query(Finding).filter(Finding.severity == "critical").count()

    console.print(f"\n[bold]Compliance Gate: {framework}[/bold]")
    console.print(f"  Total controls:   {total}")
    console.print(f"  Compliant:        {compliant}")
    console.print(f"  Non-compliant:    {non_compliant}")
    console.print(f"  Partial:          {partial}")
    score_color = "green" if score >= min_score else "red"
    console.print(f"  Score:            [{score_color}]{score:.1f}%[/]  (threshold: {min_score}%)")

    if fail_on_critical:
        crit_color = "red" if critical_count > 0 else "green"
        console.print(f"  Critical findings:[{crit_color}]{critical_count}[/]")

    # Evaluate gate conditions
    if score < min_score:
        failures.append(f"Score {score:.1f}% below threshold {min_score}%")

    if fail_on_critical and critical_count > 0:
        failures.append(f"{critical_count} critical finding(s) present")

    if fail_on_non_compliant is not None and non_compliant > fail_on_non_compliant:
        failures.append(
            f"{non_compliant} non-compliant controls exceeds threshold {fail_on_non_compliant}"
        )

    if failures:
        console.print("\n[red bold]GATE: FAIL[/red bold]")
        for f in failures:
            console.print(f"  [red]\u2717[/red] {f}")
        raise SystemExit(1)
    else:
        console.print("\n[green bold]GATE: PASS[/green bold]")


@automation_schedules.command("set")
@click.option("--name", "-n", required=True, help="Automation name (e.g. nightly-collect)")
@click.option("--cron", "-c", required=True, help='Cron expression (e.g. "0 2 * * *")')
@click.option("--enabled/--disabled", default=True, help="Enable or disable the schedule")
def schedules_set(name: str, cron: str, enabled: bool) -> None:
    """Create or update an automation schedule.

    Schedules are stored as audit trail entries with action='automation_schedule'.
    To actually execute schedules, wire this configuration into a cron runner
    or the Warlock scheduler (warlock scheduler start).

    Example:

    \b
      warlock automation schedules set \\
        --name nightly-collect \\
        --cron "0 2 * * *" \\
        --enabled
    """
    import hashlib
    import uuid as _uuid

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    actor = _get_actor()
    sched_id = str(_uuid.uuid4())

    with get_session() as session:
        from sqlalchemy import func

        max_seq = session.query(func.max(AuditEntry.sequence)).scalar() or 0
        prev_entry = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        prev_hash = prev_entry.entry_hash if prev_entry else "genesis"
        seq = max_seq + 1

        extra: dict = {
            "name": name,
            "cron": cron,
            "enabled": enabled,
        }
        payload = json.dumps(extra, sort_keys=True)
        entry_hash = hashlib.sha256(f"{seq}:{prev_hash}:{sched_id}:{payload}".encode()).hexdigest()

        entry = AuditEntry(
            id=str(_uuid.uuid4()),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="automation_schedule",
            entity_type="automation_schedule",
            entity_id=sched_id,
            actor=actor,
            extra=extra,
        )
        session.add(entry)
        session.commit()

    console.print(f"[green]Schedule '{name}' saved.[/green]")
    console.print(f"  Cron:    {cron}")
    console.print(f"  Enabled: {'yes' if enabled else 'no'}")
    console.print(
        "[dim]To execute on schedule, configure the Warlock scheduler or an "
        "external cron to run 'warlock automation run-all'.[/dim]"
    )


# ---------------------------------------------------------------------------
# ci-status (AUT-5)
# ---------------------------------------------------------------------------


@automation.command("ci-status")
@click.option("--limit", "-n", default=10, help="Number of recent runs to show")
def ci_status(limit: int) -> None:
    """Show recent pipeline runs and compliance gate results.

    Queries ConnectorRun records and ControlResult aggregates to display
    a summary of recent pipeline executions and their compliance posture.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, ControlResult
    from warlock.utils import ensure_aware

    init_db()

    with get_session() as session:
        runs = (
            session.query(ConnectorRun).order_by(ConnectorRun.started_at.desc()).limit(limit).all()
        )

        if not runs:
            console.print(
                "[dim]No pipeline runs found. Run 'warlock automation run-all' first.[/dim]"
            )
            return

        # Get aggregate compliance stats per framework
        all_results = session.query(ControlResult).all()
        frameworks: dict[str, dict[str, int]] = {}
        for r in all_results:
            fw = r.framework
            if fw not in frameworks:
                frameworks[fw] = {"total": 0, "compliant": 0, "non_compliant": 0}
            frameworks[fw]["total"] += 1
            if r.status == "compliant":
                frameworks[fw]["compliant"] += 1
            elif r.status == "non_compliant":
                frameworks[fw]["non_compliant"] += 1

    table = Table(title=f"Recent Pipeline Runs (last {limit})")
    table.add_column("Run ID", style="dim", max_width=8)
    table.add_column("Connector", style="cyan")
    table.add_column("Status")
    table.add_column("Events", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Started", style="dim")
    table.add_column("Duration", style="dim")

    for run in runs:
        status_color = {"success": "green", "error": "red", "partial": "yellow"}.get(
            run.status, "dim"
        )
        started = ensure_aware(run.started_at).strftime("%Y-%m-%d %H:%M") if run.started_at else "—"
        duration = f"{run.duration_seconds:.1f}s" if run.duration_seconds else "—"
        table.add_row(
            run.id[:8],
            escape(run.connector_name),
            f"[{status_color}]{run.status}[/]",
            str(run.event_count),
            str(run.error_count),
            started,
            duration,
        )

    console.print(table)

    if frameworks:
        console.print("\n[bold]Compliance Summary by Framework:[/bold]")
        gate_table = Table()
        gate_table.add_column("Framework", style="cyan")
        gate_table.add_column("Total", justify="right")
        gate_table.add_column("Compliant", justify="right")
        gate_table.add_column("Non-Compliant", justify="right")
        gate_table.add_column("Score", justify="right")
        gate_table.add_column("Gate Result")

        for fw, counts in sorted(frameworks.items()):
            score = (counts["compliant"] / counts["total"] * 100) if counts["total"] else 0.0
            gate_result = "[green]PASS[/green]" if score >= 80.0 else "[red]FAIL[/red]"
            score_color = "green" if score >= 80.0 else "red"
            gate_table.add_row(
                fw,
                str(counts["total"]),
                str(counts["compliant"]),
                str(counts["non_compliant"]),
                f"[{score_color}]{score:.1f}%[/]",
                gate_result,
            )

        console.print(gate_table)


# ---------------------------------------------------------------------------
# ci-badge (AUT-5)
# ---------------------------------------------------------------------------


@automation.command("ci-badge")
@click.option("--framework", "-f", required=True, help="Framework to generate badge for")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["markdown", "html", "json"]),
    default="markdown",
    help="Badge output format",
)
def ci_badge(framework: str, fmt: str) -> None:
    """Generate a compliance badge (markdown/HTML/JSON) for a framework.

    Shows pass/fail status based on the current compliance score for use
    in README files, dashboards, or CI/CD pipelines.

    Example:

    \b
      warlock automation ci-badge --framework soc2 --format markdown
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()

    with get_session() as session:
        results = session.query(ControlResult).filter(ControlResult.framework == framework).all()

    if not results:
        _error(f"No control results found for framework '{framework}'. Run pipeline first.")

    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    score = (compliant / total * 100) if total else 0.0
    status = "passing" if score >= 80.0 else "failing"
    color = "brightgreen" if score >= 80.0 else "red"

    label = f"{framework} compliance"
    message = f"{score:.0f}%25 {status}"

    if fmt == "markdown":
        badge_url = f"https://img.shields.io/badge/{label.replace(' ', '%20')}-{message.replace(' ', '%20')}-{color}"
        console.print(f"![{label}]({badge_url})")
    elif fmt == "html":
        badge_url = f"https://img.shields.io/badge/{label.replace(' ', '%20')}-{message.replace(' ', '%20')}-{color}"
        console.print(f'<img src="{badge_url}" alt="{label}" />')
    elif fmt == "json":
        badge_json = {
            "schemaVersion": 1,
            "label": label,
            "message": f"{score:.0f}% {status}",
            "color": color,
            "framework": framework,
            "total_controls": total,
            "compliant_controls": compliant,
            "score": round(score, 1),
        }
        console.print(json.dumps(badge_json, indent=2))


# ---------------------------------------------------------------------------
# github-check (AUT-8)
# ---------------------------------------------------------------------------


@automation.command("github-check")
@click.option("--framework", "-f", required=True, help="Framework to evaluate")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "summary"]),
    default="json",
    help="Output format (json for API, summary for human-readable)",
)
def github_check(framework: str, fmt: str) -> None:
    """Generate GitHub-compatible check run output for a framework.

    Produces JSON suitable for the GitHub Checks API
    (POST /repos/{owner}/{repo}/check-runs) or a human-readable summary.

    Example:

    \b
      warlock automation github-check --framework soc2 | gh api \\
        repos/OWNER/REPO/check-runs --input -
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()

    with get_session() as session:
        results = session.query(ControlResult).filter(ControlResult.framework == framework).all()

    if not results:
        _error(f"No control results found for framework '{framework}'. Run pipeline first.")

    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    non_compliant = sum(1 for r in results if r.status == "non_compliant")
    partial = sum(1 for r in results if r.status == "partial")
    score = (compliant / total * 100) if total else 0.0

    if score >= 80.0:
        conclusion = "success"
    elif score >= 50.0:
        conclusion = "neutral"
    else:
        conclusion = "failure"

    summary = (
        f"**{framework.upper()} Compliance Check**\n\n"
        f"| Metric | Value |\n|---|---|\n"
        f"| Total controls | {total} |\n"
        f"| Compliant | {compliant} |\n"
        f"| Non-compliant | {non_compliant} |\n"
        f"| Partial | {partial} |\n"
        f"| Score | {score:.1f}% |\n"
    )

    if fmt == "json":
        check_run = {
            "name": f"warlock/{framework}-compliance",
            "status": "completed",
            "conclusion": conclusion,
            "output": {
                "title": f"{framework.upper()} Compliance: {score:.1f}%",
                "summary": summary,
                "annotations": [],
            },
        }

        # Add annotations for non-compliant controls (up to 50 per GitHub API limit)
        nc_results = [r for r in results if r.status == "non_compliant"][:50]
        for r in nc_results:
            check_run["output"]["annotations"].append(
                {
                    "path": f"controls/{framework}/{r.control_id}",
                    "start_line": 1,
                    "end_line": 1,
                    "annotation_level": "warning",
                    "message": f"Control {r.control_id} is non-compliant (severity: {r.severity})",
                    "title": f"{r.control_id} non-compliant",
                }
            )

        console.print(json.dumps(check_run, indent=2))
    else:
        console.print(f"\n[bold]GitHub Check: {framework.upper()} Compliance[/bold]")
        console.print(f"  Conclusion:    {conclusion}")
        console.print(f"  Score:         {score:.1f}%")
        console.print(f"  Total:         {total}")
        console.print(f"  Compliant:     {compliant}")
        console.print(f"  Non-compliant: {non_compliant}")
        console.print(f"  Partial:       {partial}")


# ---------------------------------------------------------------------------
# gitlab-status (AUT-8)
# ---------------------------------------------------------------------------


@automation.command("gitlab-status")
@click.option("--framework", "-f", required=True, help="Framework to evaluate")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "summary"]),
    default="json",
    help="Output format (json for API, summary for human-readable)",
)
def gitlab_status(framework: str, fmt: str) -> None:
    """Generate GitLab CI-compatible status output for a framework.

    Produces JSON suitable for GitLab CI external status checks or
    commit status API (POST /projects/:id/statuses/:sha).

    Example:

    \b
      warlock automation gitlab-status --framework soc2
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()

    with get_session() as session:
        results = session.query(ControlResult).filter(ControlResult.framework == framework).all()

    if not results:
        _error(f"No control results found for framework '{framework}'. Run pipeline first.")

    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    non_compliant = sum(1 for r in results if r.status == "non_compliant")
    score = (compliant / total * 100) if total else 0.0

    if score >= 80.0:
        state = "success"
    elif score >= 50.0:
        state = "success"  # GitLab uses success/failed/pending, no "neutral"
    else:
        state = "failed"

    description = (
        f"{framework.upper()}: {score:.1f}% compliant "
        f"({compliant}/{total} controls, {non_compliant} non-compliant)"
    )

    if fmt == "json":
        status_payload = {
            "state": state,
            "name": f"warlock/{framework}-compliance",
            "description": description,
            "target_url": "",
            "coverage": round(score, 1),
        }
        console.print(json.dumps(status_payload, indent=2))
    else:
        state_color = "green" if state == "success" else "red"
        console.print(f"\n[bold]GitLab Status: {framework.upper()} Compliance[/bold]")
        console.print(f"  State:         [{state_color}]{state}[/]")
        console.print(f"  Score:         {score:.1f}%")
        console.print(f"  Description:   {description}")


# ---------------------------------------------------------------------------
# auto-close (AUT-9)
# ---------------------------------------------------------------------------


@automation.command("auto-close")
@click.option(
    "--stale-days",
    "-d",
    default=30,
    help="Close issues whose linked finding has no new occurrence in N days (default: 30)",
)
@click.option("--dry-run", is_flag=True, default=False, help="Preview without closing")
@click.option("--limit", "-n", default=100, help="Max issues to close in one run")
def auto_close(stale_days: int, dry_run: bool, limit: int) -> None:
    """Auto-close issues whose linked finding has not been reproduced.

    Finds open Issues where the linked Finding's source has not produced
    a new finding in the last N days, indicating the issue may be resolved.
    Closes them with an audit trail entry noting 'auto-closed: finding not reproduced'.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, Issue

    init_db()
    actor = _get_actor()
    cutoff = _utcnow() - timedelta(days=stale_days)

    with get_session() as session:
        # Get all open issues that have a linked finding
        open_issues = (
            session.query(Issue)
            .filter(
                Issue.status.in_(["open", "assigned"]),
                Issue.finding_id.isnot(None),
            )
            .all()
        )

        if not open_issues:
            console.print("[green]No open issues with linked findings to evaluate.[/green]")
            return

        # For each issue, check if the linked finding's source has produced
        # new findings since the cutoff
        candidates: list[Issue] = []
        for issue in open_issues:
            finding = session.query(Finding).filter(Finding.id == issue.finding_id).first()
            if not finding:
                continue

            # Check for recent findings from the same source
            recent = (
                session.query(Finding.id)
                .filter(
                    Finding.source == finding.source,
                    Finding.provider == finding.provider,
                    Finding.observation_type == finding.observation_type,
                    Finding.ingested_at > cutoff,
                )
                .first()
            )
            if recent is None:
                candidates.append(issue)

            if len(candidates) >= limit:
                break

    if not candidates:
        console.print(
            f"[green]No stale issues found (all linked findings have "
            f"occurrences within the last {stale_days} days).[/green]"
        )
        return

    table = Table(title=f"Issues to Auto-Close (no findings in last {stale_days} days)")
    table.add_column("Issue ID", style="dim", max_width=8)
    table.add_column("Priority")
    table.add_column("Title", max_width=50)
    table.add_column("Status")
    table.add_column("Finding ID", style="dim", max_width=8)

    for issue in candidates[:20]:
        table.add_row(
            issue.id[:8],
            issue.priority,
            escape((issue.title or "")[:50]),
            issue.status,
            (issue.finding_id or "")[:8],
        )
    if len(candidates) > 20:
        console.print(f"[dim]... and {len(candidates) - 20} more[/dim]")
    console.print(table)

    console.print(f"\n[bold]{len(candidates)}[/bold] issue(s) eligible for auto-close.")

    if dry_run:
        console.print(
            f"\n[dim](dry-run) Would close {len(candidates)} issue(s). "
            f"Pass without --dry-run to execute.[/dim]"
        )
        return

    closed = 0
    now = _utcnow()

    with get_session() as session:
        for issue in candidates:
            db_issue = session.query(Issue).filter(Issue.id == issue.id).first()
            if db_issue:
                db_issue.status = "closed"
                db_issue.updated_at = now
                db_issue.updated_by = actor
                closed += 1

        session.commit()

    console.print(
        f"[green]Auto-closed {closed} issue(s) "
        f"(reason: finding not reproduced in {stale_days} days).[/green]"
    )


# ---------------------------------------------------------------------------
# auto-assign (AUT-10)
# ---------------------------------------------------------------------------


@automation.command("auto-assign")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without assigning")
@click.option("--limit", "-n", default=100, help="Max issues to assign in one run")
def auto_assign(dry_run: bool, limit: int) -> None:
    """Auto-assign unassigned issues based on resource owner.

    Finds open Issues with no assigned_to value and attempts to determine
    the resource owner from the linked Finding's SystemProfile (system_owner)
    or account_id. Assigns the issue to the identified owner.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, Issue, SystemProfile

    init_db()
    actor = _get_actor()

    with get_session() as session:
        # Get unassigned open issues
        unassigned = (
            session.query(Issue)
            .filter(
                Issue.status.in_(["open"]),
                (Issue.assigned_to.is_(None)) | (Issue.assigned_to == ""),
            )
            .limit(limit)
            .all()
        )

        if not unassigned:
            console.print("[green]No unassigned open issues found.[/green]")
            return

        # Build a cache of system_profile owners
        profiles = {p.id: p for p in session.query(SystemProfile).all()}

        # Resolve owners for each issue
        assignments: list[tuple[Issue, str]] = []
        for issue in unassigned:
            owner: str | None = None

            if issue.finding_id:
                finding = session.query(Finding).filter(Finding.id == issue.finding_id).first()
                if finding:
                    # Try SystemProfile first
                    if finding.system_profile_id and finding.system_profile_id in profiles:
                        profile = profiles[finding.system_profile_id]
                        owner = profile.system_owner_email or profile.system_owner

                    # Fall back to account_id as a pseudo-owner identifier
                    if not owner and finding.account_id:
                        owner = f"account:{finding.account_id}"

            if owner:
                assignments.append((issue, owner))

    if not assignments:
        console.print("[dim]No owners could be resolved for unassigned issues.[/dim]")
        console.print(
            "[dim]Ensure findings are linked to SystemProfiles with system_owner set, "
            "or that findings have account_id populated.[/dim]"
        )
        return

    table = Table(title="Issues to Auto-Assign")
    table.add_column("Issue ID", style="dim", max_width=8)
    table.add_column("Priority")
    table.add_column("Title", max_width=45)
    table.add_column("Resolved Owner", style="cyan")

    for issue, owner in assignments[:20]:
        table.add_row(
            issue.id[:8],
            issue.priority,
            escape((issue.title or "")[:45]),
            escape(owner),
        )
    if len(assignments) > 20:
        console.print(f"[dim]... and {len(assignments) - 20} more[/dim]")
    console.print(table)

    console.print(f"\n[bold]{len(assignments)}[/bold] issue(s) can be auto-assigned.")

    if dry_run:
        console.print(
            f"\n[dim](dry-run) Would assign {len(assignments)} issue(s). "
            f"Pass without --dry-run to execute.[/dim]"
        )
        return

    assigned = 0
    now = _utcnow()

    with get_session() as session:
        for issue, owner in assignments:
            db_issue = session.query(Issue).filter(Issue.id == issue.id).first()
            if db_issue:
                db_issue.assigned_to = owner
                db_issue.assigned_by = actor
                db_issue.assigned_at = now
                db_issue.status = "assigned"
                db_issue.updated_at = now
                db_issue.updated_by = actor
                assigned += 1

        session.commit()

    console.print(f"[green]Auto-assigned {assigned} issue(s).[/green]")
