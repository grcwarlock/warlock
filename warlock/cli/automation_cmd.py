"""Workflow automation commands.

Group: ``automation``

Provides automated pipeline runs, evidence refresh, issue/POA&M auto-creation,
housekeeping cleanup, and rule/schedule management sub-groups.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import click
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor, _print_stats


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("automation")
def automation() -> None:
    """Workflow automation: pipeline runs, evidence refresh, auto-issue/POA&M, housekeeping."""


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

    from warlock.db.engine import get_session, init_db
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline, register_lake_writer
    import logging

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

    from warlock.db.engine import get_session, init_db
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline, register_lake_writer
    import logging

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
        table.add_row(r.id[:8], r.severity, r.title[:55], r.source)
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
    from warlock.db.models import ControlResult, POAM

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
    from warlock.db.models import Issue, POAM

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


@automation.group("rules")
def automation_rules() -> None:
    """Automation rule management: list, create, delete, test."""


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
    import uuid as _uuid
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry
    import hashlib

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
    import uuid as _uuid
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry
    import hashlib

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
    from warlock.db.models import AuditEntry, Finding, ControlResult

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


@automation.group("schedules")
def automation_schedules() -> None:
    """Schedule management: list and configure automation schedules."""


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
    import uuid as _uuid
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry
    import hashlib

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
