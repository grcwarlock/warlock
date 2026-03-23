"""Interactive training campaign management workflow command.

Top-level command:

    warlock training-drive  -- Training campaign management dashboard
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone

import click
from rich.panel import Panel
from rich.prompt import Prompt
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
    """Append a hash-chained audit entry for a training workflow action."""
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
        entity_type="personnel",
        entity_id=entity_id,
        actor=actor,
        extra=extra,
    )
    session.add(entry)
    session.commit()


# ---------------------------------------------------------------------------
# warlock training-drive
# ---------------------------------------------------------------------------


@cli.command("training-drive")
@click.option(
    "--department",
    "-d",
    default=None,
    help="Filter to a specific department.",
)
def training_drive(department: str | None) -> None:
    """Training campaign management: completion rates, overdue personnel, escalations.

    Shows overall and per-department training compliance, lists overdue personnel,
    and provides actions to send reminders, escalate, or generate a report.

    \b
    Examples:
        warlock training-drive
        warlock training-drive --department Engineering
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Personnel

    init_db()
    actor = _get_actor()

    try:
        with get_session() as session:
            q = session.query(Personnel).filter(
                Personnel.is_active == True  # noqa: E712
            )
            if department:
                q = q.filter(Personnel.department.ilike(f"%{department}%"))
            all_personnel = q.all()

            if not all_personnel:
                console.print(
                    "[dim]No active personnel records found. Run the pipeline to sync HR data.[/dim]"
                )
                return

            total = len(all_personnel)
            current = [p for p in all_personnel if p.training_status == "current"]
            overdue = [p for p in all_personnel if p.training_status == "overdue"]
            not_enrolled = [p for p in all_personnel if p.training_status == "not_enrolled"]
            completion_rate = (len(current) / total * 100) if total else 0.0
            rate_color = (
                "green" if completion_rate >= 95 else ("yellow" if completion_rate >= 80 else "red")
            )

            # Per-department breakdown
            dept_stats: dict[str, dict[str, int]] = defaultdict(
                lambda: {"total": 0, "current": 0, "overdue": 0}
            )
            for p in all_personnel:
                dept = p.department or "Unknown"
                dept_stats[dept]["total"] += 1
                if p.training_status == "current":
                    dept_stats[dept]["current"] += 1
                elif p.training_status == "overdue":
                    dept_stats[dept]["overdue"] += 1

            while True:
                console.print()
                console.print(
                    Panel(
                        f"[bold]Training Compliance Dashboard[/bold]\n\n"
                        f"Overall completion: [{rate_color}]{completion_rate:.1f}%[/{rate_color}]  "
                        f"({len(current)}/{total})\n"
                        f"[red]Overdue:[/red] {len(overdue)}  |  "
                        f"[dim]Not enrolled:[/dim] {len(not_enrolled)}",
                        title="[bold cyan]warlock training-drive[/bold cyan]",
                        border_style="cyan",
                    )
                )

                # Department breakdown
                if dept_stats:
                    dt = Table(title="By Department", show_header=True, header_style="bold")
                    dt.add_column("Department")
                    dt.add_column("Total", justify="right")
                    dt.add_column("Current", justify="right")
                    dt.add_column("Overdue", justify="right")
                    dt.add_column("Rate", justify="right")
                    for dept, counts in sorted(dept_stats.items()):
                        rate = counts["current"] / counts["total"] * 100 if counts["total"] else 0.0
                        rate_c = "green" if rate >= 95 else ("yellow" if rate >= 80 else "red")
                        dt.add_row(
                            dept,
                            str(counts["total"]),
                            f"[green]{counts['current']}[/green]",
                            f"[red]{counts['overdue']}[/red]" if counts["overdue"] else "0",
                            f"[{rate_c}]{rate:.1f}%[/{rate_c}]",
                        )
                    console.print(dt)

                # Overdue personnel
                if overdue:
                    ot = Table(
                        title=f"Overdue Personnel ({min(len(overdue), 10)} shown)",
                        show_header=True,
                        header_style="bold",
                    )
                    ot.add_column("Name")
                    ot.add_column("Email")
                    ot.add_column("Department")
                    ot.add_column("Manager")
                    ot.add_column("Last Training")
                    for p in overdue[:10]:
                        last_t = (
                            p.last_training_date.strftime("%Y-%m-%d")
                            if p.last_training_date
                            else "[red]Never[/red]"
                        )
                        ot.add_row(
                            p.full_name,
                            p.email,
                            p.department or "—",
                            p.manager_email or "—",
                            last_t,
                        )
                    console.print(ot)

                console.print()
                choice = Prompt.ask(
                    "Actions",
                    choices=["s", "e", "r", "q"],
                    default="q",
                    show_choices=False,
                )
                console.print("[dim]  s=send reminders  e=escalate overdue  r=report  q=quit[/dim]")

                if choice == "q":
                    break

                elif choice == "s":
                    # Generate reminder list
                    if not overdue:
                        console.print("[green]No overdue personnel — no reminders needed.[/green]")
                    else:
                        console.print(f"\n[bold]Reminder List ({len(overdue)} personnel):[/bold]")
                        for p in overdue:
                            console.print(
                                f"  [yellow]REMINDER[/yellow]  To: {p.email}  "
                                f"({p.full_name}, {p.department or '—'})  "
                                f"-- Security awareness training is overdue."
                            )
                        # Record audit entry per person (batch)
                        for p in overdue:
                            _write_audit_entry(
                                session,
                                action="training_reminder_sent",
                                entity_id=p.id,
                                actor=actor,
                                extra={"email": p.email, "department": p.department},
                            )
                        console.print(
                            f"\n[green]{len(overdue)} reminder(s) generated and recorded.[/green]"
                        )

                elif choice == "e":
                    # Escalate — flag manager of each overdue person
                    if not overdue:
                        console.print("[green]No overdue personnel to escalate.[/green]")
                    else:
                        managers: dict[str, list[str]] = defaultdict(list)
                        for p in overdue:
                            if p.manager_email:
                                managers[p.manager_email].append(p.full_name)

                        if not managers:
                            console.print(
                                "[yellow]No manager emails found for overdue personnel.[/yellow]"
                            )
                        else:
                            console.print(
                                f"\n[bold]Escalation List ({len(managers)} manager(s)):[/bold]"
                            )
                            for mgr, names in sorted(managers.items()):
                                console.print(
                                    f"  [red]ESCALATION[/red]  To: {mgr}  "
                                    f"-- Direct report(s) overdue: {', '.join(names)}"
                                )
                            for p in overdue:
                                _write_audit_entry(
                                    session,
                                    action="training_escalated",
                                    entity_id=p.id,
                                    actor=actor,
                                    extra={
                                        "email": p.email,
                                        "manager_email": p.manager_email,
                                        "escalated_by": actor,
                                    },
                                )
                            console.print(
                                f"\n[green]Escalation for {len(overdue)} person(s) recorded.[/green]"
                            )

                elif choice == "r":
                    # Generate markdown report
                    now_str = _utcnow().strftime("%Y-%m-%d %H:%M UTC")
                    lines = [
                        "# Training Compliance Report",
                        "",
                        f"Generated: {now_str}",
                        f"Actor: {actor}",
                        "",
                        "## Summary",
                        "",
                        "| Metric | Value |",
                        "|--------|-------|",
                        f"| Total personnel | {total} |",
                        f"| Current | {len(current)} |",
                        f"| Overdue | {len(overdue)} |",
                        f"| Not enrolled | {len(not_enrolled)} |",
                        f"| Completion rate | {completion_rate:.1f}% |",
                        "",
                        "## Department Breakdown",
                        "",
                        "| Department | Total | Current | Overdue | Rate |",
                        "|------------|-------|---------|---------|------|",
                    ]
                    for dept, counts in sorted(dept_stats.items()):
                        rate = counts["current"] / counts["total"] * 100 if counts["total"] else 0.0
                        lines.append(
                            f"| {dept} | {counts['total']} | {counts['current']} | "
                            f"{counts['overdue']} | {rate:.1f}% |"
                        )
                    lines += [
                        "",
                        "## Overdue Personnel",
                        "",
                        "| Name | Email | Department | Manager | Last Training |",
                        "|------|-------|------------|---------|---------------|",
                    ]
                    for p in overdue:
                        last_t = (
                            p.last_training_date.strftime("%Y-%m-%d")
                            if p.last_training_date
                            else "Never"
                        )
                        lines.append(
                            f"| {p.full_name} | {p.email} | "
                            f"{p.department or '—'} | {p.manager_email or '—'} | {last_t} |"
                        )
                    report = "\n".join(lines)
                    console.print("\n" + report + "\n")
                    console.print(
                        "[dim]Report printed above. Pipe to a file: warlock training-drive > report.md[/dim]"
                    )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Training drive session ended.[/dim]")
