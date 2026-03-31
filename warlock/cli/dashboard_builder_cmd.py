"""Custom dashboard builder — compose and save dashboard views.

MVP: Create, list, and render custom dashboards from widget presets.
Widgets: posture, kri, poams, findings, alerts, trends.
Dashboard configs stored in saved_queries table with type='dashboard'.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

import click
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from warlock.cli import _error, cli, console
from warlock.utils import ensure_aware

WIDGET_TYPES = {
    "posture": "Framework compliance posture",
    "kri": "Key risk indicators",
    "poams": "Open POA&Ms by status",
    "findings": "Findings severity breakdown",
    "alerts": "Active alerts summary",
    "trends": "Compliance trends over time",
}


# ---------------------------------------------------------------------------
# Widget renderers
# ---------------------------------------------------------------------------


def _render_posture_widget(session) -> Panel:
    """Render framework compliance posture widget."""
    from sqlalchemy import func

    from warlock.db.models import ControlResult

    rows = (
        session.query(
            ControlResult.framework,
            ControlResult.status,
            func.count(ControlResult.id).label("count"),
        )
        .group_by(ControlResult.framework, ControlResult.status)
        .all()
    )

    by_fw: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in rows:
        by_fw[r.framework][r.status] += r.count

    table = Table(show_header=True, expand=True)
    table.add_column("Framework", style="cyan")
    table.add_column("Pass", justify="right", style="green")
    table.add_column("Fail", justify="right", style="red")
    table.add_column("Rate", justify="right")

    for fw in sorted(by_fw, key=lambda f: -sum(by_fw[f].values()))[:10]:
        s = by_fw[fw]
        total = sum(s.values())
        compliant = s.get("compliant", 0) + s.get("inherited_compliant", 0)
        rate = (compliant / total * 100) if total else 0
        color = "green" if rate >= 80 else "yellow" if rate >= 60 else "red"
        table.add_row(
            fw, str(compliant), str(s.get("non_compliant", 0)), f"[{color}]{rate:.0f}%[/{color}]"
        )

    return Panel(table, title="Compliance Posture", border_style="cyan")


def _render_kri_widget(session) -> Panel:
    """Render key risk indicators widget."""
    from sqlalchemy import func

    from warlock.db.models import POAM, ControlResult, Finding

    critical = (
        session.query(func.count(Finding.id)).filter(Finding.severity == "critical").scalar() or 0
    )
    high = session.query(func.count(Finding.id)).filter(Finding.severity == "high").scalar() or 0
    open_poams = (
        session.query(func.count(POAM.id))
        .filter(POAM.status.in_(["draft", "open", "in_progress"]))
        .scalar()
        or 0
    )
    total_controls = session.query(func.count(ControlResult.id)).scalar() or 0
    non_compliant = (
        session.query(func.count(ControlResult.id))
        .filter(ControlResult.status == "non_compliant")
        .scalar()
        or 0
    )

    table = Table(show_header=True, expand=True)
    table.add_column("Indicator", style="cyan")
    table.add_column("Value", justify="right")
    table.add_column("Status")

    # Critical findings
    crit_color = "red bold" if critical > 0 else "green"
    table.add_row(
        "Critical findings",
        str(critical),
        f"[{crit_color}]{'ALERT' if critical > 0 else 'OK'}[/{crit_color}]",
    )

    # High findings
    high_color = "red" if high > 10 else "yellow" if high > 0 else "green"
    table.add_row(
        "High findings", str(high), f"[{high_color}]{'ALERT' if high > 10 else 'OK'}[/{high_color}]"
    )

    # Open POA&Ms
    poam_color = "yellow" if open_poams > 5 else "green"
    table.add_row(
        "Open POA&Ms",
        str(open_poams),
        f"[{poam_color}]{'WARN' if open_poams > 5 else 'OK'}[/{poam_color}]",
    )

    # Non-compliance rate
    nc_rate = (non_compliant / total_controls * 100) if total_controls else 0
    nc_color = "red" if nc_rate > 20 else "yellow" if nc_rate > 10 else "green"
    table.add_row(
        "Non-compliance rate",
        f"{nc_rate:.1f}%",
        f"[{nc_color}]{'ALERT' if nc_rate > 20 else 'OK'}[/{nc_color}]",
    )

    return Panel(table, title="Key Risk Indicators", border_style="yellow")


def _render_poams_widget(session) -> Panel:
    """Render open POA&Ms widget."""
    from sqlalchemy import func

    from warlock.db.models import POAM

    rows = (
        session.query(POAM.status, func.count(POAM.id).label("count")).group_by(POAM.status).all()
    )

    table = Table(show_header=True, expand=True)
    table.add_column("Status", style="cyan")
    table.add_column("Count", justify="right")

    status_colors = {
        "draft": "dim",
        "open": "yellow",
        "in_progress": "cyan",
        "remediated": "green",
        "verified": "green bold",
        "completed": "green",
        "risk_accepted": "yellow",
        "cancelled": "dim",
    }

    for r in sorted(rows, key=lambda x: x.count, reverse=True):
        color = status_colors.get(r.status, "")
        label = f"[{color}]{escape(r.status)}[/{color}]" if color else escape(r.status)
        table.add_row(label, str(r.count))

    if not rows:
        table.add_row("[dim]No POA&Ms found[/dim]", "0")

    return Panel(table, title="POA&M Status", border_style="magenta")


def _render_findings_widget(session) -> Panel:
    """Render findings severity breakdown widget."""
    from sqlalchemy import func

    from warlock.db.models import Finding

    rows = (
        session.query(Finding.severity, func.count(Finding.id).label("count"))
        .group_by(Finding.severity)
        .all()
    )

    table = Table(show_header=True, expand=True)
    table.add_column("Severity", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Bar")

    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }
    counts = {r.severity: r.count for r in rows}
    max_count = max(counts.values()) if counts else 1

    for sev in sev_order:
        count = counts.get(sev, 0)
        color = sev_colors.get(sev, "")
        bar_len = int(count / max_count * 20) if max_count else 0
        bar = "\u2588" * bar_len
        label = f"[{color}]{sev}[/{color}]" if color else sev
        table.add_row(label, str(count), f"[{color}]{bar}[/{color}]" if color else bar)

    return Panel(table, title="Findings by Severity", border_style="red")


def _render_alerts_widget(session) -> Panel:
    """Render active alerts widget."""
    from sqlalchemy import func

    from warlock.db.models import Alert

    rows = (
        session.query(Alert.severity, func.count(Alert.id).label("count"))
        .filter(Alert.status.in_(["active", "triggered"]))
        .group_by(Alert.severity)
        .all()
    )

    table = Table(show_header=True, expand=True)
    table.add_column("Severity", style="cyan")
    table.add_column("Active", justify="right")

    sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
    for r in sorted(rows, key=lambda x: x.count, reverse=True):
        color = sev_colors.get(r.severity, "")
        label = f"[{color}]{escape(r.severity)}[/{color}]" if color else escape(r.severity)
        table.add_row(label, str(r.count))

    if not rows:
        table.add_row("[green]No active alerts[/green]", "0")

    return Panel(table, title="Active Alerts", border_style="green")


def _render_trends_widget(session) -> Panel:
    """Render compliance trends widget (last 7 days from posture snapshots)."""
    from sqlalchemy import func

    from warlock.db.models import PostureSnapshot

    since = datetime.now(timezone.utc) - timedelta(days=7)

    # Aggregate posture scores by framework and snapshot date
    rows = (
        session.query(
            PostureSnapshot.framework,
            func.strftime("%Y-%m-%d", PostureSnapshot.snapshot_date).label("day"),
            func.avg(PostureSnapshot.posture_score).label("avg_score"),
        )
        .filter(PostureSnapshot.snapshot_date >= since)
        .group_by(PostureSnapshot.framework, "day")
        .order_by(func.strftime("%Y-%m-%d", PostureSnapshot.snapshot_date).desc())
        .limit(20)
        .all()
    )

    table = Table(show_header=True, expand=True)
    table.add_column("Date", style="cyan")
    table.add_column("Framework")
    table.add_column("Score", justify="right")

    if rows:
        for r in rows:
            score = r.avg_score if r.avg_score is not None else 0.0
            color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
            table.add_row(str(r.day), escape(str(r.framework)), f"[{color}]{score:.1f}%[/{color}]")
    else:
        table.add_row("[dim]No snapshots yet[/dim]", "", "")

    return Panel(table, title="Compliance Trends (7d)", border_style="blue")


_WIDGET_RENDERERS = {
    "posture": _render_posture_widget,
    "kri": _render_kri_widget,
    "poams": _render_poams_widget,
    "findings": _render_findings_widget,
    "alerts": _render_alerts_widget,
    "trends": _render_trends_widget,
}


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


@cli.group("custom", invoke_without_command=True)
@click.pass_context
def custom(ctx: click.Context) -> None:
    """Custom dashboard builder — compose and save dashboard views."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@custom.command("create")
@click.option("--name", "-n", required=True, help="Dashboard name")
@click.option(
    "--widgets",
    "-w",
    required=True,
    help="Comma-separated widget list: posture,kri,poams,findings,alerts,trends",
)
@click.option("--description", "-d", default="", help="Dashboard description")
def custom_create(name: str, widgets: str, description: str) -> None:
    """Create a custom dashboard from widget presets.

    Example:
        warlock custom create --name "My View" --widgets "posture,kri,poams,findings"
    """
    from uuid import uuid4

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SavedQuery

    widget_list = [w.strip() for w in widgets.split(",") if w.strip()]
    invalid = [w for w in widget_list if w not in WIDGET_TYPES]
    if invalid:
        _error(
            f"Invalid widget(s): {', '.join(invalid)}. Available: {', '.join(WIDGET_TYPES.keys())}"
        )

    if not widget_list:
        _error("At least one widget required.")

    init_db()
    with get_session() as session:
        # Check for duplicate name
        existing = (
            session.query(SavedQuery)
            .filter(SavedQuery.query_type == "dashboard", SavedQuery.name == name)
            .first()
        )
        if existing:
            _error(f"Dashboard '{name}' already exists. Use a different name.")

        record = SavedQuery(
            id=str(uuid4()),
            name=name,
            description=description,
            sql_text="",
            query_type="dashboard",
            parameters={
                "widgets": widget_list,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
            shared=True,
            created_by="cli@warlock",
        )
        session.add(record)

    console.print(
        f"[green]Dashboard '{escape(name)}' created with {len(widget_list)} widgets.[/green]"
    )
    for w in widget_list:
        console.print(f"  [cyan]{w}[/cyan] - {WIDGET_TYPES[w]}")


@custom.command("list")
@click.option(
    "--format", "fmt", default="table", type=click.Choice(["table", "json"]), help="Output format"
)
def custom_list(fmt: str) -> None:
    """List saved custom dashboards."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import SavedQuery

    init_db()
    with get_read_session() as session:
        rows = (
            session.query(SavedQuery)
            .filter(SavedQuery.query_type == "dashboard")
            .order_by(SavedQuery.created_at.desc())
            .all()
        )

    if not rows:
        console.print(
            "[dim]No custom dashboards found. Create one with 'warlock custom create'.[/dim]"
        )
        return

    if fmt == "json":
        import json as _json

        data = []
        for r in rows:
            params = r.parameters or {}
            data.append(
                {
                    "name": r.name,
                    "widgets": params.get("widgets", []),
                    "description": r.description or "",
                    "created_at": r.created_at.isoformat() if r.created_at else "",
                }
            )
        console.print(_json.dumps(data, indent=2))
        return

    table = Table(title="Custom Dashboards")
    table.add_column("Name", style="cyan")
    table.add_column("Widgets")
    table.add_column("Description")
    table.add_column("Created")

    for r in rows:
        params = r.parameters or {}
        widgets = ", ".join(params.get("widgets", []))
        created = ensure_aware(r.created_at).strftime("%Y-%m-%d") if r.created_at else ""
        table.add_row(
            escape(r.name),
            widgets,
            escape(r.description or ""),
            created,
        )
    console.print(table)


@custom.command("show")
@click.argument("name")
def custom_show(name: str) -> None:
    """Render a saved custom dashboard.

    Example:
        warlock custom show "My View"
    """

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SavedQuery

    init_db()
    with get_session() as session:
        record = (
            session.query(SavedQuery)
            .filter(SavedQuery.query_type == "dashboard", SavedQuery.name == name)
            .first()
        )

        if not record:
            _error(f"Dashboard '{name}' not found.")

        params = record.parameters or {}
        widget_names = params.get("widgets", [])

        if not widget_names:
            console.print("[dim]Dashboard has no widgets configured.[/dim]")
            return

        console.print(f"\n[bold cyan]Dashboard: {escape(name)}[/bold cyan]\n")

        # Render each widget
        panels: list[Panel] = []
        for w in widget_names:
            renderer = _WIDGET_RENDERERS.get(w)
            if renderer:
                try:
                    panel = renderer(session)
                    panels.append(panel)
                except Exception as exc:
                    panels.append(
                        Panel(
                            f"[red]Error rendering {w}: {escape(str(exc))}[/red]",
                            title=w,
                            border_style="red",
                        )
                    )

        # Print panels (2 per row when possible)
        for panel in panels:
            console.print(panel)


@custom.command("delete")
@click.argument("name")
@click.option("--yes", is_flag=True, help="Skip confirmation")
def custom_delete(name: str, yes: bool) -> None:
    """Delete a saved custom dashboard."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SavedQuery

    init_db()
    with get_session() as session:
        record = (
            session.query(SavedQuery)
            .filter(SavedQuery.query_type == "dashboard", SavedQuery.name == name)
            .first()
        )

        if not record:
            _error(f"Dashboard '{name}' not found.")

        if not yes:
            click.confirm(f"Delete dashboard '{name}'?", abort=True)

        session.delete(record)

    console.print(f"[green]Dashboard '{escape(name)}' deleted.[/green]")
