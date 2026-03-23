"""CLI commands for security awareness training tracking.

Group: warlock training
Commands:
  status     -- completion rates by department/role
  overdue    -- personnel with overdue training
  campaigns  -- list training campaigns
  report     -- formatted training report
"""

from __future__ import annotations

import click
from rich.table import Table

from warlock.cli import cli, console


@cli.group("training")
def training() -> None:
    """Track security awareness training completion and campaigns."""
    pass


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@training.command("status")
@click.option("--department", "-d", default=None, help="Filter by department")
@click.option("--role", "-r", default=None, help="Filter by employee type/role")
@click.option(
    "--format", "output_format", default="table", type=click.Choice(["table", "json"])
)
def training_status(
    department: str | None,
    role: str | None,
    output_format: str,
) -> None:
    """Show training completion rates, optionally by department or role."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Personnel

    init_db()
    with get_session() as session:
        q = session.query(
            Personnel.department,
            Personnel.employee_type,
            Personnel.training_status,
            Personnel.email,
        ).filter(Personnel.is_active == True)  # noqa: E712

        if department:
            q = q.filter(Personnel.department.ilike(f"%{department}%"))
        if role:
            q = q.filter(Personnel.employee_type.ilike(f"%{role}%"))

        rows = q.all()

    if not rows:
        console.print("[dim]No personnel found.[/dim]")
        return

    # Aggregate: (department, training_status) -> count
    dept_status: dict[str, dict[str, int]] = {}
    for dept, emp_type, t_status, email in rows:
        key = dept or "(no department)"
        if key not in dept_status:
            dept_status[key] = {}
        s = t_status or "unknown"
        dept_status[key][s] = dept_status[key].get(s, 0) + 1

    # Compute summary
    total = len(rows)
    status_totals: dict[str, int] = {}
    for s_map in dept_status.values():
        for s, c in s_map.items():
            status_totals[s] = status_totals.get(s, 0) + c

    current = status_totals.get("current", 0)
    overdue = status_totals.get("overdue", 0)
    not_enrolled = status_totals.get("not_enrolled", 0)
    pct = f"{current / total * 100:.1f}%" if total else "N/A"

    if output_format == "json":
        import json

        out = {
            "summary": {
                "total": total,
                "current": current,
                "overdue": overdue,
                "not_enrolled": not_enrolled,
                "completion_rate": pct,
            },
            "by_department": dept_status,
        }
        console.print(json.dumps(out, indent=2))
        return

    # Summary line
    console.print(
        f"\n[bold]Training Completion:[/bold] "
        f"[green]{current}[/green] current / "
        f"[red]{overdue}[/red] overdue / "
        f"[dim]{not_enrolled}[/dim] not enrolled "
        f"| [bold]{pct}[/bold] completion rate "
        f"({total} active personnel)\n"
    )

    table = Table(title="Training Status by Department")
    table.add_column("Department", style="cyan")
    table.add_column("Current", justify="right", style="green")
    table.add_column("Overdue", justify="right", style="red")
    table.add_column("Not Enrolled", justify="right")
    table.add_column("Total", justify="right")
    table.add_column("Rate", justify="right")

    for dept, s_map in sorted(dept_status.items()):
        cur = s_map.get("current", 0)
        ov = s_map.get("overdue", 0)
        ne = s_map.get("not_enrolled", 0)
        tot = sum(s_map.values())
        rate = f"{cur / tot * 100:.1f}%" if tot else "N/A"
        table.add_row(dept[:40], str(cur), str(ov), str(ne), str(tot), rate)

    console.print(table)


# ---------------------------------------------------------------------------
# overdue
# ---------------------------------------------------------------------------


@training.command("overdue")
@click.option(
    "--days",
    "-d",
    default=0,
    help="Include personnel overdue by at least N days (0 = all overdue)",
)
@click.option("--department", default=None, help="Filter by department")
@click.option(
    "--format", "output_format", default="table", type=click.Choice(["table", "json"])
)
def overdue_training(days: int, department: str | None, output_format: str) -> None:
    """List personnel with overdue training."""
    from datetime import datetime, timedelta, timezone
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Personnel

    init_db()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days) if days else None

    with get_session() as session:
        q = session.query(Personnel).filter(
            Personnel.is_active == True,  # noqa: E712
            Personnel.training_status == "overdue",
        )
        if department:
            q = q.filter(Personnel.department.ilike(f"%{department}%"))
        if cutoff and days:
            # Only include if last_training_date is older than cutoff or missing
            q = q.filter(
                (Personnel.last_training_date < cutoff)
                | (Personnel.last_training_date.is_(None))
            )
        rows = q.order_by(Personnel.last_training_date.asc().nullsfirst()).all()

        data = [
            {
                "email": r.email,
                "full_name": r.full_name,
                "department": r.department or "",
                "employee_type": r.employee_type or "",
                "last_training_date": str(r.last_training_date)[:10] if r.last_training_date else "\u2014",
                "phishing_score": f"{r.phishing_score:.1f}" if r.phishing_score is not None else "\u2014",
                "manager_email": r.manager_email or "",
            }
            for r in rows
        ]

    if not data:
        console.print("[green]No overdue training found.[/green]")
        return

    if output_format == "json":
        import json

        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Overdue Training ({len(data)} personnel)")
    table.add_column("Name", max_width=25)
    table.add_column("Email", max_width=30)
    table.add_column("Department", max_width=20)
    table.add_column("Type")
    table.add_column("Last Trained")
    table.add_column("Phishing Score", justify="right")
    table.add_column("Manager", max_width=25)

    for r in data:
        table.add_row(
            r["full_name"][:25],
            r["email"][:30],
            r["department"][:20],
            r["employee_type"],
            f"[red]{r['last_training_date']}[/red]",
            r["phishing_score"],
            r["manager_email"][:25],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# campaigns
# ---------------------------------------------------------------------------


@training.command("campaigns")
@click.option("--status", "-s", default=None, help="Filter by campaign status (e.g. completed, active)")
@click.option(
    "--format", "output_format", default="table", type=click.Choice(["table", "json"])
)
def campaigns_list(status: str | None, output_format: str) -> None:
    """List training campaigns derived from personnel completion records.

    Campaigns are extracted from the training_completions JSON field on
    Personnel records.  Each unique campaign name is aggregated to show
    completion counts.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Personnel

    init_db()
    with get_session() as session:
        rows = (
            session.query(
                Personnel.training_completions,
                Personnel.training_status,
                Personnel.is_active,
            )
            .filter(Personnel.is_active == True)  # noqa: E712
            .all()
        )

    # Aggregate campaign completion counts
    campaign_completions: dict[str, int] = {}
    campaign_dates: dict[str, str] = {}

    for (completions, t_status, _) in rows:
        for entry in completions or []:
            name = entry.get("campaign") or entry.get("name") or ""
            if not name:
                continue
            if status and status.lower() not in (entry.get("status") or "completed").lower():
                continue
            campaign_completions[name] = campaign_completions.get(name, 0) + 1
            completed_date = entry.get("completed_date") or ""
            # Track the latest completion date
            if completed_date > campaign_dates.get(name, ""):
                campaign_dates[name] = completed_date

    if not campaign_completions:
        console.print("[dim]No campaign completion records found.[/dim]")
        return

    data = [
        {
            "campaign": name,
            "completions": count,
            "latest_completion": campaign_dates.get(name, "\u2014"),
        }
        for name, count in sorted(campaign_completions.items(), key=lambda x: -x[1])
    ]

    if output_format == "json":
        import json

        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Training Campaigns ({len(data)})")
    table.add_column("Campaign", style="cyan")
    table.add_column("Completions", justify="right")
    table.add_column("Latest Completion")

    for r in data:
        table.add_row(r["campaign"], str(r["completions"]), r["latest_completion"])

    console.print(table)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@training.command("report")
@click.option(
    "--format", "output_format", default="table", type=click.Choice(["table", "json", "md"])
)
def training_report(output_format: str) -> None:
    """Generate a full training compliance report."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Personnel

    init_db()
    with get_session() as session:
        rows = (
            session.query(
                Personnel.department,
                Personnel.employee_type,
                Personnel.training_status,
                Personnel.phishing_score,
                Personnel.last_training_date,
                Personnel.is_active,
            )
            .filter(Personnel.is_active == True)  # noqa: E712
            .all()
        )

    if not rows:
        console.print("[dim]No active personnel found.[/dim]")
        return

    total = len(rows)
    status_counts: dict[str, int] = {}
    dept_counts: dict[str, dict[str, int]] = {}
    phishing_scores: list[float] = []

    for dept, emp_type, t_status, phishing, last_date, _ in rows:
        s = t_status or "unknown"
        status_counts[s] = status_counts.get(s, 0) + 1

        d = dept or "(no department)"
        if d not in dept_counts:
            dept_counts[d] = {}
        dept_counts[d][s] = dept_counts[d].get(s, 0) + 1

        if phishing is not None:
            phishing_scores.append(phishing)

    current = status_counts.get("current", 0)
    overdue = status_counts.get("overdue", 0)
    not_enrolled = status_counts.get("not_enrolled", 0)
    completion_rate = f"{current / total * 100:.1f}%" if total else "N/A"
    avg_phishing = (
        f"{sum(phishing_scores) / len(phishing_scores):.1f}"
        if phishing_scores
        else "N/A"
    )

    if output_format == "json":
        import json

        out = {
            "total_personnel": total,
            "training_current": current,
            "training_overdue": overdue,
            "not_enrolled": not_enrolled,
            "completion_rate": completion_rate,
            "avg_phishing_score": avg_phishing,
            "by_department": dept_counts,
            "by_status": status_counts,
        }
        console.print(json.dumps(out, indent=2))
        return

    if output_format == "md":
        console.print("# Training Compliance Report\n")
        console.print(f"**Total Active Personnel:** {total}")
        console.print(f"**Completion Rate:** {completion_rate}")
        console.print(f"**Current:** {current} | **Overdue:** {overdue} | **Not Enrolled:** {not_enrolled}")
        console.print(f"**Avg Phishing Score:** {avg_phishing}\n")
        console.print("## By Department\n")
        for dept, s_map in sorted(dept_counts.items()):
            tot = sum(s_map.values())
            cur = s_map.get("current", 0)
            rate = f"{cur / tot * 100:.1f}%" if tot else "N/A"
            console.print(f"- **{dept}**: {cur}/{tot} ({rate})")
        return

    # table mode: summary panel + per-department breakdown
    from rich.panel import Panel

    console.print(
        Panel(
            f"[bold]Total Personnel:[/bold] {total}\n"
            f"[green]Current:[/green] {current}  |  "
            f"[red]Overdue:[/red] {overdue}  |  "
            f"[dim]Not Enrolled:[/dim] {not_enrolled}\n"
            f"[bold]Completion Rate:[/bold] {completion_rate}  |  "
            f"[bold]Avg Phishing Score:[/bold] {avg_phishing}",
            title="[bold]Training Compliance Summary[/bold]",
            border_style="cyan",
        )
    )

    table = Table(title="By Department")
    table.add_column("Department", style="cyan")
    table.add_column("Current", justify="right", style="green")
    table.add_column("Overdue", justify="right", style="red")
    table.add_column("Not Enrolled", justify="right")
    table.add_column("Total", justify="right")
    table.add_column("Rate", justify="right")

    for dept, s_map in sorted(dept_counts.items()):
        cur = s_map.get("current", 0)
        ov = s_map.get("overdue", 0)
        ne = s_map.get("not_enrolled", 0)
        tot = sum(s_map.values())
        rate = f"{cur / tot * 100:.1f}%" if tot else "N/A"
        table.add_row(dept[:40], str(cur), str(ov), str(ne), str(tot), rate)

    console.print(table)
