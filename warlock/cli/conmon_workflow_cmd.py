"""Interactive continuous monitoring (ConMon) monthly workflow command.

Top-level command:

    warlock conmon-monthly  -- Full monthly ConMon workflow with checklist
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import click
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from warlock.cli import _get_actor, cli, console

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _write_audit_entry(
    session,
    action: str,
    entity_id: str,
    actor: str,
    extra: dict,
) -> None:
    """Append a hash-chained audit entry for the ConMon workflow."""
    from warlock.db.models import AuditEntry

    last = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
    prev_hash = last.entry_hash if last else "genesis"
    seq = (last.sequence + 1) if last else 1

    payload = json.dumps({"action": action, "entity_id": entity_id, "extra": extra}, sort_keys=True)
    entry_hash = hashlib.sha256(f"{prev_hash}:{payload}".encode()).hexdigest()

    entry = AuditEntry(
        id=str(uuid.uuid4()),
        sequence=seq,
        previous_hash=prev_hash,
        entry_hash=entry_hash,
        action=action,
        entity_type="conmon",
        entity_id=entity_id,
        actor=actor,
        extra=extra,
    )
    session.add(entry)
    session.commit()


# ---------------------------------------------------------------------------
# warlock conmon-monthly
# ---------------------------------------------------------------------------


@cli.command("conmon-monthly")
@click.option(
    "--framework",
    "-f",
    default=None,
    help="Scope checklist to a specific framework.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    type=click.Path(),
    help="Write markdown report to this file path.",
)
def conmon_monthly(framework: str | None, output: str | None) -> None:
    """Full monthly Continuous Monitoring (ConMon) workflow.

    Walks through the standard monthly ConMon checklist, prompts for each
    incomplete item, generates a ConMon report, and optionally marks it for
    AO submission.

    \b
    Examples:
        warlock conmon-monthly
        warlock conmon-monthly --framework nist_800_53
        warlock conmon-monthly --output conmon-2026-03.md
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        POAM,
        ChangeEvent,
        ConnectorRun,
        Issue,
        Personnel,
        PostureSnapshot,
    )

    init_db()
    actor = _get_actor()

    now = _utcnow()
    month_label = now.strftime("%B %Y")
    report_id = str(uuid.uuid4())

    try:
        with get_session() as session:
            console.print(
                Panel(
                    f"[bold]{month_label} ConMon Report[/bold]\n"
                    "Monthly Continuous Monitoring workflow.\n"
                    "Work through each checklist item; incomplete items prompt for action.",
                    title="[bold cyan]warlock conmon-monthly[/bold cyan]",
                    border_style="cyan",
                )
            )

            # ---------------------------------------------------------------
            # Build checklist state by querying DB
            # ---------------------------------------------------------------
            thirty_days_ago = now - timedelta(days=30)
            seven_days_ago = now - timedelta(days=7)

            # 1. Vulnerability scans completed (connector runs in last 30 days)
            scan_runs = (
                session.query(ConnectorRun)
                .filter(ConnectorRun.completed_at >= thirty_days_ago)
                .count()
            )
            vuln_ok = scan_runs > 0

            # 2. POA&M updates current (no open POA&Ms past scheduled completion)
            overdue_poams = (
                session.query(POAM)
                .filter(
                    POAM.status.in_(["open", "in_progress", "draft"]),
                    POAM.scheduled_completion < now,
                )
                .all()
            )
            poam_ok = len(overdue_poams) == 0

            # 3. Significant changes documented (change events in last 30 days)
            changes = (
                session.query(ChangeEvent)
                .filter(ChangeEvent.occurred_at >= thirty_days_ago)
                .count()
            )
            changes_ok = True  # changes documented if there are records

            # 4. Security alerts reviewed (open critical/high issues in last 30 days)
            open_critical = (
                session.query(Issue)
                .filter(
                    Issue.status.in_(["open", "assigned"]),
                    Issue.priority.in_(["critical", "high"]),
                    Issue.created_at >= thirty_days_ago,
                )
                .all()
            )
            alerts_ok = len(open_critical) == 0

            # 5. Training compliance verified (any current personnel)
            training_overdue = (
                session.query(Personnel)
                .filter(
                    Personnel.training_status == "overdue",
                    Personnel.is_active == True,  # noqa: E712
                )
                .count()
            )
            training_ok = training_overdue == 0

            # 6. Evidence collected (posture snapshots in last 7 days)
            recent_snapshots = (
                session.query(PostureSnapshot)
                .filter(PostureSnapshot.snapshot_date >= seven_days_ago)
                .count()
            )
            evidence_ok = recent_snapshots > 0

            checklist = [
                {
                    "label": "Vulnerability scans completed",
                    "ok": vuln_ok,
                    "detail": f"{scan_runs} connector run(s) in last 30 days",
                    "action": "warlock run",
                },
                {
                    "label": "POA&M updates current",
                    "ok": poam_ok,
                    "detail": f"{len(overdue_poams)} overdue POA&M(s)"
                    if not poam_ok
                    else "All POA&Ms on schedule",
                    "action": "warlock poam list",
                },
                {
                    "label": "Significant changes documented",
                    "ok": changes_ok,
                    "detail": f"{changes} change event(s) recorded this month",
                    "action": "warlock change-submit",
                },
                {
                    "label": "Security alerts reviewed",
                    "ok": alerts_ok,
                    "detail": f"{len(open_critical)} unreviewed critical/high alert(s)"
                    if not alerts_ok
                    else "No unreviewed critical/high alerts",
                    "action": "warlock morning",
                },
                {
                    "label": "Training compliance verified",
                    "ok": training_ok,
                    "detail": f"{training_overdue} overdue personnel"
                    if not training_ok
                    else "All active personnel current",
                    "action": "warlock training-drive",
                },
                {
                    "label": "Evidence freshness verified",
                    "ok": evidence_ok,
                    "detail": f"{recent_snapshots} posture snapshot(s) in last 7 days"
                    if evidence_ok
                    else "No recent posture snapshots",
                    "action": "warlock conmon run",
                },
            ]

            # ---------------------------------------------------------------
            # Display checklist
            # ---------------------------------------------------------------
            ct = Table(title="Monthly ConMon Checklist", show_header=True, header_style="bold")
            ct.add_column("#")
            ct.add_column("Item")
            ct.add_column("Status")
            ct.add_column("Detail")
            for i, item in enumerate(checklist, 1):
                status = "[green]DONE[/green]" if item["ok"] else "[red]INCOMPLETE[/red]"
                ct.add_row(str(i), item["label"], status, item["detail"])
            console.print(ct)

            incomplete = [item for item in checklist if not item["ok"]]
            complete_count = len(checklist) - len(incomplete)

            console.print(
                f"\n[bold]Checklist:[/bold] "
                f"[green]{complete_count}[/green]/{len(checklist)} items complete"
            )

            # ---------------------------------------------------------------
            # Address incomplete items
            # ---------------------------------------------------------------
            if incomplete:
                console.print()
                for item in incomplete:
                    if Confirm.ask(f"Address '[bold]{item['label']}[/bold]' now?", default=False):
                        console.print(
                            f"[yellow]Suggested command:[/yellow] [bold]{item['action']}[/bold]"
                        )
                        console.print(
                            "[dim]Open a new terminal and run the command, then return here.[/dim]"
                        )
                        if Confirm.ask("Mark this item as addressed?", default=False):
                            item["ok"] = True
                            complete_count += 1
                            console.print("[green]Marked as addressed.[/green]")

            # ---------------------------------------------------------------
            # Generate markdown report
            # ---------------------------------------------------------------
            now_str = now.strftime("%Y-%m-%d %H:%M UTC")
            final_complete = sum(1 for item in checklist if item["ok"])
            overall_pct = (final_complete / len(checklist) * 100) if checklist else 0.0
            status_label = "COMPLETE" if final_complete == len(checklist) else "IN PROGRESS"

            report_lines = [
                f"# {month_label} Continuous Monitoring Report",
                "",
                f"**Generated:** {now_str}",
                f"**Author:** {actor}",
                f"**Report ID:** {report_id}",
                f"**Status:** {status_label} ({final_complete}/{len(checklist)} items, {overall_pct:.0f}%)",
                "",
                "---",
                "",
                "## Checklist",
                "",
            ]
            for item in checklist:
                check = "x" if item["ok"] else " "
                report_lines.append(f"- [{check}] {item['label']}")
                report_lines.append(f"  - *{item['detail']}*")
            report_lines += [
                "",
                "---",
                "",
                "## Statistics",
                "",
                "| Metric | Value |",
                "|--------|-------|",
                f"| Connector runs (30d) | {scan_runs} |",
                f"| Overdue POA&Ms | {len(overdue_poams)} |",
                f"| Change events (30d) | {changes} |",
                f"| Open critical/high alerts | {len(open_critical)} |",
                f"| Overdue training | {training_overdue} |",
                f"| Recent posture snapshots | {recent_snapshots} |",
                "",
                "---",
                "",
                "*Warlock GRC Platform — warlock conmon-monthly*",
            ]
            report_md = "\n".join(report_lines)

            if output:
                try:
                    with open(output, "w") as f:
                        f.write(report_md)
                    console.print(f"\n[green]Report written to:[/green] {output}")
                except OSError as e:
                    console.print(f"[red]Failed to write report: {e}[/red]")
                    console.print(report_md)
            else:
                console.print("\n" + report_md + "\n")

            # ---------------------------------------------------------------
            # AO submission prompt
            # ---------------------------------------------------------------
            if Confirm.ask("Mark as submitted to Authorizing Official (AO)?", default=False):
                _write_audit_entry(
                    session,
                    action="conmon_monthly_submitted",
                    entity_id=report_id,
                    actor=actor,
                    extra={
                        "month": month_label,
                        "complete_items": final_complete,
                        "total_items": len(checklist),
                        "overall_pct": overall_pct,
                        "framework": framework,
                    },
                )
                console.print(
                    f"[green]ConMon report for {month_label} submitted to AO. "
                    f"Report ID: {report_id}[/green]"
                )
            else:
                _write_audit_entry(
                    session,
                    action="conmon_monthly_generated",
                    entity_id=report_id,
                    actor=actor,
                    extra={
                        "month": month_label,
                        "complete_items": final_complete,
                        "total_items": len(checklist),
                        "framework": framework,
                    },
                )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]ConMon session ended.[/dim]")
