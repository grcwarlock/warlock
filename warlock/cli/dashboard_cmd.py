"""Live dashboards and KRI engine CLI commands.

Provides real-time compliance dashboards, board-level executive views,
security and operations panels, GRC program health, and Key Risk Indicator
(KRI) management with alerting.
"""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import click
from rich.table import Table

from warlock.cli import cli, console, _error


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@cli.group("dashboard")
def dashboard() -> None:
    """Live dashboards and Key Risk Indicator (KRI) management."""


# ---------------------------------------------------------------------------
# Nested groups
# ---------------------------------------------------------------------------


@dashboard.group("kri")
def kri() -> None:
    """Key Risk Indicator management and threshold configuration."""


@dashboard.group("alerts")
def alerts() -> None:
    """Alert management: list, acknowledge, configure, and review history."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _rag_color(value: float, warning: float, critical: float) -> str:
    """Return Rich colour tag for a red/amber/green RAG status."""
    if value >= critical:
        return "red bold"
    if value >= warning:
        return "yellow"
    return "green"


def _severity_style(severity: str) -> str:
    return {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }.get(severity.lower(), "")


def _posture_score(session, framework: str | None = None) -> dict[str, Any]:
    """Compute a simple compliance posture summary from control results."""
    from warlock.db.models import ControlResult
    from sqlalchemy import func

    q = session.query(
        ControlResult.framework,
        ControlResult.status,
        func.count(ControlResult.id).label("count"),
    )
    if framework:
        q = q.filter(ControlResult.framework == framework)
    rows = q.group_by(ControlResult.framework, ControlResult.status).all()

    by_fw: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in rows:
        by_fw[row.framework][row.status] += row.count

    result: dict[str, Any] = {}
    for fw, statuses in by_fw.items():
        total = sum(statuses.values())
        compliant = statuses.get("compliant", 0) + statuses.get("inherited_compliant", 0)
        pass_rate = (compliant / total * 100) if total else 0.0
        result[fw] = {
            "total": total,
            "compliant": compliant,
            "non_compliant": statuses.get("non_compliant", 0),
            "partial": statuses.get("partial", 0),
            "not_assessed": statuses.get("not_assessed", 0),
            "pass_rate": pass_rate,
        }
    return result


def _build_posture_table(posture: dict[str, Any], title: str = "Compliance Posture") -> Table:
    table = Table(title=title)
    table.add_column("Framework", style="cyan")
    table.add_column("Pass Rate", justify="right")
    table.add_column("Compliant", justify="right", style="green")
    table.add_column("Non-compliant", justify="right", style="red")
    table.add_column("Partial", justify="right", style="yellow")
    table.add_column("Total", justify="right")

    for fw, stats in sorted(posture.items(), key=lambda x: -x[1]["pass_rate"]):
        rate = stats["pass_rate"]
        color = "green" if rate >= 80 else "yellow" if rate >= 60 else "red"
        table.add_row(
            fw,
            f"[{color}]{rate:.1f}%[/{color}]",
            f"{stats['compliant']:,}",
            f"{stats['non_compliant']:,}",
            f"{stats['partial']:,}",
            f"{stats['total']:,}",
        )
    return table


# ---------------------------------------------------------------------------
# live
# ---------------------------------------------------------------------------


@dashboard.command("live")
@click.option(
    "--refresh",
    "refresh_seconds",
    type=int,
    default=10,
    show_default=True,
    help="Refresh interval in seconds",
)
def dashboard_live(refresh_seconds: int) -> None:
    """Real-time compliance dashboard (Rich Live display). Press Ctrl-C to exit."""
    from rich.live import Live
    from rich.panel import Panel

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, Finding
    from sqlalchemy import func

    init_db()

    def _render() -> Panel:
        with get_session() as session:
            # Findings in last hour
            since_1h = _utcnow() - timedelta(hours=1)
            recent_findings = session.query(Finding).filter(Finding.ingested_at >= since_1h).count()
            total_findings = session.query(Finding).count()

            # Severity breakdown
            sev_rows = (
                session.query(Finding.severity, func.count(Finding.id).label("cnt"))
                .group_by(Finding.severity)
                .all()
            )
            sev_map = {r.severity: r.cnt for r in sev_rows}

            # Connector health
            since_24h = _utcnow() - timedelta(hours=24)
            conn_rows = (
                session.query(ConnectorRun.status, func.count(ConnectorRun.id).label("cnt"))
                .filter(ConnectorRun.started_at >= since_24h)
                .group_by(ConnectorRun.status)
                .all()
            )
            conn_map = {r.status: r.cnt for r in conn_rows}

            # Overall pass rate
            posture = _posture_score(session)

        overall_total = sum(p["total"] for p in posture.values())
        overall_compliant = sum(p["compliant"] for p in posture.values())
        overall_rate = (overall_compliant / overall_total * 100) if overall_total else 0.0

        rate_color = "green" if overall_rate >= 80 else "yellow" if overall_rate >= 60 else "red"

        lines = [
            f"[bold]Overall Compliance[/bold]  [{rate_color}]{overall_rate:.1f}%[/{rate_color}]   "
            f"[dim]{_utcnow().strftime('%H:%M:%S UTC')}[/dim]\n",
            f"Total findings: [cyan]{total_findings:,}[/cyan]   "
            f"Last hour: [cyan]{recent_findings:,}[/cyan]\n",
        ]

        # Severity
        for sev in ("critical", "high", "medium", "low"):
            count = sev_map.get(sev, 0)
            style = _severity_style(sev)
            lines.append(f"  [{style}]{sev.upper():10s}[/{style}]  {count:,}")

        lines.append("")
        # Connector health
        success = conn_map.get("success", 0)
        error = conn_map.get("error", 0)
        partial = conn_map.get("partial", 0)
        lines.append(
            f"Connectors (24h)  [green]{success}[/green] OK  "
            f"[yellow]{partial}[/yellow] partial  [red]{error}[/red] failed"
        )

        # Framework summary
        lines.append("\n[bold]Framework Compliance[/bold]")
        for fw, stats in sorted(posture.items(), key=lambda x: -x[1]["pass_rate"])[:5]:
            r = stats["pass_rate"]
            c = "green" if r >= 80 else "yellow" if r >= 60 else "red"
            lines.append(f"  {fw:20s}  [{c}]{r:.1f}%[/{c}]")

        return Panel(
            "\n".join(lines),
            title="[bold cyan]Warlock GRC — Live Dashboard[/bold cyan]",
            subtitle=f"[dim]Refreshing every {refresh_seconds}s — Ctrl-C to quit[/dim]",
        )

    try:
        with Live(_render(), refresh_per_second=1, screen=False) as live:
            while True:
                time.sleep(refresh_seconds)
                live.update(_render())
    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard stopped.[/dim]")


# ---------------------------------------------------------------------------
# posture
# ---------------------------------------------------------------------------


@dashboard.command("posture")
@click.option("--framework", "-f", default=None, multiple=True, help="Filter by framework")
def dashboard_posture(framework: tuple[str, ...]) -> None:
    """Current compliance posture summary across all or selected frameworks."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        fw = framework[0] if len(framework) == 1 else None
        posture = _posture_score(session, framework=fw)

        if framework and len(framework) > 1:
            posture = {k: v for k, v in posture.items() if k in framework}

    if not posture:
        console.print("[yellow]No control results found.[/yellow]")
        return

    table = _build_posture_table(posture)
    console.print(table)

    overall_total = sum(p["total"] for p in posture.values())
    overall_compliant = sum(p["compliant"] for p in posture.values())
    overall_rate = (overall_compliant / overall_total * 100) if overall_total else 0.0
    color = "green" if overall_rate >= 80 else "yellow" if overall_rate >= 60 else "red"
    console.print(f"\nOverall pass rate: [{color}]{overall_rate:.1f}%[/{color}]")


# ---------------------------------------------------------------------------
# executive
# ---------------------------------------------------------------------------


@dashboard.command("executive")
def dashboard_executive() -> None:
    """Board-level summary: overall score, top risks, trending items, and open actions."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, POAM, Issue

    init_db()
    with get_session() as session:
        posture = _posture_score(session)

        # Top risks: critical findings
        since_30d = _utcnow() - timedelta(days=30)
        critical_count = (
            session.query(Finding)
            .filter(Finding.severity == "critical", Finding.ingested_at >= since_30d)
            .count()
        )
        high_count = (
            session.query(Finding)
            .filter(Finding.severity == "high", Finding.ingested_at >= since_30d)
            .count()
        )

        # Open POA&Ms
        open_poams = session.query(POAM).filter(POAM.status.in_(["open", "in_progress"])).count()
        overdue_poams = (
            session.query(POAM)
            .filter(
                POAM.status.in_(["open", "in_progress"]),
                POAM.scheduled_completion < _utcnow(),
            )
            .count()
        )

        # Open issues
        open_issues = session.query(Issue).filter(Issue.status.in_(["open", "in_progress"])).count()

    overall_total = sum(p["total"] for p in posture.values())
    overall_compliant = sum(p["compliant"] for p in posture.values())
    overall_rate = (overall_compliant / overall_total * 100) if overall_total else 0.0

    rate_color = "green" if overall_rate >= 80 else "yellow" if overall_rate >= 60 else "red"

    # Executive summary panel
    console.print("\n[bold cyan]Executive Compliance Summary[/bold cyan]")
    console.print(f"As of: [dim]{_utcnow().strftime('%Y-%m-%d %H:%M UTC')}[/dim]\n")

    summary = Table(show_header=False, box=None)
    summary.add_column("", style="cyan")
    summary.add_column("")
    summary.add_row("Overall Compliance Score", f"[{rate_color}]{overall_rate:.1f}%[/{rate_color}]")
    summary.add_row("Frameworks Assessed", str(len(posture)))
    summary.add_row("Critical Findings (30d)", f"[red bold]{critical_count:,}[/red bold]")
    summary.add_row("High Findings (30d)", f"[red]{high_count:,}[/red]")
    summary.add_row("Open POA&Ms", f"{open_poams:,}")
    summary.add_row(
        "Overdue POA&Ms",
        f"[red]{overdue_poams:,}[/red]" if overdue_poams else "[green]0[/green]",
    )
    summary.add_row("Open Issues", f"{open_issues:,}")
    console.print(summary)

    # Framework detail
    console.print()
    table = _build_posture_table(posture, title="Framework Compliance")
    console.print(table)


# ---------------------------------------------------------------------------
# security
# ---------------------------------------------------------------------------


@dashboard.command("security")
def dashboard_security() -> None:
    """Security-focused view: vulnerability counts, MTTR, and active incidents."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, Issue
    from sqlalchemy import func

    init_db()
    since_30d = _utcnow() - timedelta(days=30)

    with get_session() as session:
        # Vuln counts by severity
        vuln_rows = (
            session.query(Finding.severity, func.count(Finding.id).label("count"))
            .filter(
                Finding.observation_type == "vulnerability",
                Finding.ingested_at >= since_30d,
            )
            .group_by(Finding.severity)
            .all()
        )
        vuln_map = {r.severity: r.count for r in vuln_rows}

        # Misconfigurations
        misconfig_count = (
            session.query(Finding)
            .filter(
                Finding.observation_type == "misconfiguration",
                Finding.ingested_at >= since_30d,
            )
            .count()
        )

        # Active incidents (issues with security-related observation types)
        active_incidents = (
            session.query(Issue).filter(Issue.status.in_(["open", "in_progress"])).count()
        )

        # Top sources (vulns)
        top_sources = (
            session.query(Finding.source, func.count(Finding.id).label("count"))
            .filter(
                Finding.observation_type == "vulnerability",
                Finding.ingested_at >= since_30d,
            )
            .group_by(Finding.source)
            .order_by(func.count(Finding.id).desc())
            .limit(5)
            .all()
        )

    console.print("[bold cyan]Security Dashboard[/bold cyan]")
    console.print(f"[dim]{_utcnow().strftime('%Y-%m-%d %H:%M UTC')} — last 30 days[/dim]\n")

    vuln_table = Table(title="Vulnerabilities by Severity")
    vuln_table.add_column("Severity", style="cyan")
    vuln_table.add_column("Count", justify="right")

    for sev in ("critical", "high", "medium", "low", "info"):
        count = vuln_map.get(sev, 0)
        style = _severity_style(sev)
        vuln_table.add_row(f"[{style}]{sev}[/{style}]", f"{count:,}")
    console.print(vuln_table)

    summary = Table(show_header=False, box=None)
    summary.add_column("", style="cyan")
    summary.add_column("")
    summary.add_row("Misconfigurations (30d)", f"{misconfig_count:,}")
    summary.add_row(
        "Active Incidents",
        f"[red]{active_incidents:,}[/red]" if active_incidents else "[green]0[/green]",
    )
    console.print(summary)

    src_table = Table(title="Top Vulnerability Sources (30d)")
    src_table.add_column("Source", style="cyan")
    src_table.add_column("Count", justify="right")
    for row in top_sources:
        src_table.add_row(row.source, f"{row.count:,}")
    console.print(src_table)


# ---------------------------------------------------------------------------
# operations
# ---------------------------------------------------------------------------


@dashboard.command("operations")
def dashboard_operations() -> None:
    """Ops-focused view: connector health, pipeline status, data freshness, and errors."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, RawEvent
    from sqlalchemy import func

    init_db()
    since_24h = _utcnow() - timedelta(hours=24)

    with get_session() as session:
        # Connector health
        conn_rows = (
            session.query(
                ConnectorRun.connector_name,
                ConnectorRun.status,
                func.count(ConnectorRun.id).label("runs"),
                func.sum(ConnectorRun.event_count).label("events"),
                func.max(ConnectorRun.started_at).label("last_run"),
            )
            .filter(ConnectorRun.started_at >= since_24h)
            .group_by(ConnectorRun.connector_name, ConnectorRun.status)
            .order_by(ConnectorRun.connector_name)
            .all()
        )

        # Overall counts
        total_runs = (
            session.query(ConnectorRun).filter(ConnectorRun.started_at >= since_24h).count()
        )
        error_runs = (
            session.query(ConnectorRun)
            .filter(ConnectorRun.started_at >= since_24h, ConnectorRun.status == "error")
            .count()
        )

        # Data freshness
        latest_raw = session.query(func.max(RawEvent.ingested_at)).scalar()

    console.print("[bold cyan]Operations Dashboard[/bold cyan]")
    console.print(f"[dim]{_utcnow().strftime('%Y-%m-%d %H:%M UTC')} — last 24 hours[/dim]\n")

    # Pipeline health summary
    health_color = "green" if error_runs == 0 else "red"
    summary = Table(show_header=False, box=None)
    summary.add_column("", style="cyan")
    summary.add_column("")
    summary.add_row("Connector runs (24h)", f"{total_runs:,}")
    summary.add_row("Failed runs", f"[{health_color}]{error_runs:,}[/{health_color}]")
    if latest_raw:
        delta = _utcnow() - latest_raw
        freshness = f"{delta.total_seconds() / 3600:.1f}h ago"
        fresh_color = (
            "green"
            if delta.total_seconds() < 3600
            else "yellow"
            if delta.total_seconds() < 86400
            else "red"
        )
        summary.add_row("Latest ingestion", f"[{fresh_color}]{freshness}[/{fresh_color}]")
    else:
        summary.add_row("Latest ingestion", "[red]never[/red]")
    console.print(summary)

    if conn_rows:
        table = Table(title="Connector Health (24h)")
        table.add_column("Connector", style="cyan")
        table.add_column("Status")
        table.add_column("Runs", justify="right")
        table.add_column("Events", justify="right")
        table.add_column("Last Run")

        now = _utcnow()
        for row in conn_rows:
            status_color = {
                "success": "green",
                "error": "red",
                "partial": "yellow",
                "running": "cyan",
            }.get(row.status, "")
            last_run = row.last_run
            age = f"{(now - last_run).total_seconds() / 3600:.1f}h ago" if last_run else "—"
            table.add_row(
                row.connector_name,
                f"[{status_color}]{row.status}[/{status_color}]",
                f"{row.runs:,}",
                f"{row.events or 0:,}",
                age,
            )
        console.print(table)


# ---------------------------------------------------------------------------
# program
# ---------------------------------------------------------------------------


@dashboard.command("program")
def dashboard_program() -> None:
    """GRC program health: training, attestation coverage, evidence freshness, POA&M aging."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM, Finding, ControlResult

    init_db()
    now = _utcnow()
    since_90d = now - timedelta(days=90)

    with get_session() as session:
        # POA&M aging
        total_poams = session.query(POAM).count()
        open_poams = (
            session.query(POAM).filter(POAM.status.in_(["open", "in_progress", "draft"])).count()
        )
        overdue_poams = (
            session.query(POAM)
            .filter(
                POAM.status.in_(["open", "in_progress"]),
                POAM.scheduled_completion < now,
            )
            .count()
        )

        # Evidence freshness: findings with observed_at in last 90 days
        fresh_findings = session.query(Finding).filter(Finding.observed_at >= since_90d).count()
        total_findings = session.query(Finding).count()

        # Control assessment coverage
        assessed_controls = session.query(ControlResult.control_id).distinct().count()
        not_assessed = (
            session.query(ControlResult).filter(ControlResult.status == "not_assessed").count()
        )
    console.print("[bold cyan]GRC Program Health[/bold cyan]")
    console.print(f"[dim]{now.strftime('%Y-%m-%d %H:%M UTC')}[/dim]\n")

    table = Table(show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_column("Status")

    def status_rag(good: bool) -> str:
        return "[green]OK[/green]" if good else "[red]ATTENTION[/red]"

    evidence_pct = (fresh_findings / total_findings * 100) if total_findings else 0
    table.add_row(
        "Evidence freshness (90d)",
        f"{evidence_pct:.1f}%",
        status_rag(evidence_pct >= 70),
    )
    table.add_row("Total findings", f"{total_findings:,}", "")
    table.add_row("Distinct controls assessed", f"{assessed_controls:,}", "")
    table.add_row(
        "Not-assessed results",
        f"{not_assessed:,}",
        status_rag(not_assessed == 0),
    )
    table.add_row("Total POA&Ms", f"{total_poams:,}", "")
    table.add_row("Open POA&Ms", f"{open_poams:,}", status_rag(open_poams == 0))
    table.add_row(
        "Overdue POA&Ms",
        f"{overdue_poams:,}",
        status_rag(overdue_poams == 0),
    )
    console.print(table)


# ===========================================================================
# kri subgroup
# ===========================================================================

# KRI definitions are stored in memory for this implementation.
# In a production system these would live in the database.
_KRI_REGISTRY: dict[str, dict[str, Any]] = {
    "critical_finding_rate": {
        "description": "Critical findings per day (30d avg)",
        "unit": "findings/day",
        "warning": 5.0,
        "critical": 20.0,
        "query": "critical_findings_per_day",
    },
    "connector_error_rate": {
        "description": "Connector run failure rate (24h)",
        "unit": "%",
        "warning": 5.0,
        "critical": 20.0,
        "query": "connector_error_rate",
    },
    "compliance_pass_rate": {
        "description": "Overall control pass rate",
        "unit": "%",
        "warning": 70.0,
        "critical": 50.0,
        "query": "compliance_pass_rate",
        "invert": True,  # lower is worse
    },
    "overdue_poam_count": {
        "description": "Number of overdue POA&Ms",
        "unit": "count",
        "warning": 1.0,
        "critical": 5.0,
        "query": "overdue_poam_count",
    },
    "data_freshness_hours": {
        "description": "Hours since last data ingestion",
        "unit": "hours",
        "warning": 2.0,
        "critical": 24.0,
        "query": "data_freshness_hours",
    },
}


def _evaluate_kri(name: str, kri_def: dict[str, Any]) -> float:
    """Compute current KRI value by running the corresponding query."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, Finding, POAM, RawEvent
    from sqlalchemy import func

    init_db()
    query_key = kri_def.get("query", "")
    now = _utcnow()

    with get_session() as session:
        if query_key == "critical_findings_per_day":
            since = now - timedelta(days=30)
            count = (
                session.query(Finding)
                .filter(Finding.severity == "critical", Finding.ingested_at >= since)
                .count()
            )
            return count / 30.0

        if query_key == "connector_error_rate":
            since = now - timedelta(hours=24)
            total = session.query(ConnectorRun).filter(ConnectorRun.started_at >= since).count()
            errors = (
                session.query(ConnectorRun)
                .filter(ConnectorRun.started_at >= since, ConnectorRun.status == "error")
                .count()
            )
            return (errors / total * 100) if total else 0.0

        if query_key == "compliance_pass_rate":
            total = session.query(Finding).count()
            if total == 0:
                return 0.0
            from warlock.db.models import ControlResult

            compliant = (
                session.query(ControlResult)
                .filter(ControlResult.status.in_(["compliant", "inherited_compliant"]))
                .count()
            )
            total_results = session.query(ControlResult).count()
            return (compliant / total_results * 100) if total_results else 0.0

        if query_key == "overdue_poam_count":
            return float(
                session.query(POAM)
                .filter(
                    POAM.status.in_(["open", "in_progress"]),
                    POAM.scheduled_completion < now,
                )
                .count()
            )

        if query_key == "data_freshness_hours":
            latest = session.query(func.max(RawEvent.ingested_at)).scalar()
            if not latest:
                return 9999.0
            delta = now - latest
            return delta.total_seconds() / 3600

    return 0.0


def _kri_status(value: float, kri_def: dict[str, Any]) -> tuple[str, str]:
    """Return (label, color) for a KRI value."""
    warning = kri_def.get("warning", 0.0)
    critical_val = kri_def.get("critical", 0.0)
    invert = kri_def.get("invert", False)

    if invert:
        # For inverted KRIs (e.g. pass rate), lower value = worse
        if value <= critical_val:
            return "RED", "red bold"
        if value <= warning:
            return "AMBER", "yellow"
        return "GREEN", "green"
    else:
        if value >= critical_val:
            return "RED", "red bold"
        if value >= warning:
            return "AMBER", "yellow"
        return "GREEN", "green"


@kri.command("list")
def kri_list() -> None:
    """List all Key Risk Indicators with current values and threshold status."""
    table = Table(title="Key Risk Indicators")
    table.add_column("KRI", style="cyan")
    table.add_column("Description")
    table.add_column("Current", justify="right")
    table.add_column("Unit")
    table.add_column("Warning", justify="right")
    table.add_column("Critical", justify="right")
    table.add_column("Status")

    for name, kri_def in _KRI_REGISTRY.items():
        try:
            value = _evaluate_kri(name, kri_def)
        except Exception:
            value = float("nan")

        label, color = _kri_status(value, kri_def) if value == value else ("UNKNOWN", "dim")
        value_str = f"{value:.1f}" if value == value else "ERR"

        table.add_row(
            name,
            kri_def.get("description", ""),
            value_str,
            kri_def.get("unit", ""),
            str(kri_def.get("warning", "")),
            str(kri_def.get("critical", "")),
            f"[{color}]{label}[/{color}]",
        )

    console.print(table)


@kri.command("show")
@click.argument("name")
def kri_show(name: str) -> None:
    """Show KRI detail with current value and thresholds."""
    if name not in _KRI_REGISTRY:
        _error(f"Unknown KRI: {name!r}. Run 'warlock dashboard kri list' to see available KRIs.")

    kri_def = _KRI_REGISTRY[name]
    try:
        value = _evaluate_kri(name, kri_def)
    except Exception as exc:
        _error(f"Failed to evaluate KRI: {exc}")

    label, color = _kri_status(value, kri_def)

    table = Table(title=f"KRI: {name}", show_header=False)
    table.add_column("Field", style="dim")
    table.add_column("Value")

    table.add_row("Name", name)
    table.add_row("Description", kri_def.get("description", ""))
    table.add_row("Unit", kri_def.get("unit", ""))
    table.add_row("Current value", f"{value:.2f}")
    table.add_row("Warning threshold", str(kri_def.get("warning", "")))
    table.add_row("Critical threshold", str(kri_def.get("critical", "")))
    table.add_row("Status", f"[{color}]{label}[/{color}]")
    table.add_row("Invert logic", "Yes (lower is worse)" if kri_def.get("invert") else "No")

    console.print(table)


@kri.command("set-threshold")
@click.argument("name")
@click.option("--warning", "warning_val", required=True, type=float, help="Warning threshold value")
@click.option(
    "--critical", "critical_val", required=True, type=float, help="Critical threshold value"
)
def kri_set_threshold(name: str, warning_val: float, critical_val: float) -> None:
    """Update warning and critical thresholds for a KRI."""
    if name not in _KRI_REGISTRY:
        _error(f"Unknown KRI: {name!r}. Run 'warlock dashboard kri list' to see available KRIs.")

    _KRI_REGISTRY[name]["warning"] = warning_val
    _KRI_REGISTRY[name]["critical"] = critical_val

    console.print(f"[green]Updated thresholds for [bold]{name}[/bold]:[/green]")
    console.print(f"  Warning:  {warning_val}")
    console.print(f"  Critical: {critical_val}")
    console.print(
        "[dim]Note: thresholds are in-process only. Restart the CLI to reset to defaults.[/dim]"
    )


@kri.command("evaluate")
def kri_evaluate() -> None:
    """Evaluate all KRIs against thresholds and show red/amber/green status."""
    table = Table(title="KRI Evaluation — Red/Amber/Green")
    table.add_column("KRI", style="cyan")
    table.add_column("Value", justify="right")
    table.add_column("Unit")
    table.add_column("RAG")
    table.add_column("Description")

    red_count = 0
    amber_count = 0
    green_count = 0

    for name, kri_def in _KRI_REGISTRY.items():
        try:
            value = _evaluate_kri(name, kri_def)
            label, color = _kri_status(value, kri_def)
            value_str = f"{value:.2f}"
        except Exception:
            label, color, value_str = "ERROR", "red", "ERR"

        if label == "RED":
            red_count += 1
        elif label == "AMBER":
            amber_count += 1
        else:
            green_count += 1

        table.add_row(
            name,
            value_str,
            kri_def.get("unit", ""),
            f"[{color}]{label}[/{color}]",
            kri_def.get("description", ""),
        )

    console.print(table)
    console.print(
        f"\n[red bold]{red_count} RED[/red bold]  "
        f"[yellow]{amber_count} AMBER[/yellow]  "
        f"[green]{green_count} GREEN[/green]"
    )


@kri.command("trend")
@click.option("--days", type=int, default=7, show_default=True, help="Lookback window in days")
def kri_trend(days: int) -> None:
    """Show KRI trend summary as sparklines (terminal-based mini charts)."""
    # Evaluate current values and show a trend indicator based on
    # direction vs. thresholds (since we don't store historical KRI snapshots
    # in this implementation, we show the current RAG per KRI).
    table = Table(title=f"KRI Trend — Last {days} Days (current snapshot)")
    table.add_column("KRI", style="cyan")
    table.add_column("Current", justify="right")
    table.add_column("Warning", justify="right")
    table.add_column("Critical", justify="right")
    table.add_column("RAG")
    table.add_column("Sparkline")

    for name, kri_def in _KRI_REGISTRY.items():
        try:
            value = _evaluate_kri(name, kri_def)
            label, color = _kri_status(value, kri_def)
            # Simple sparkline: draw blocks proportional to value vs critical
            crit = kri_def.get("critical", 100.0)
            invert = kri_def.get("invert", False)

            if not invert:
                fill_pct = min(value / crit, 1.0) if crit else 0.0
            else:
                # For inverted (higher is better), flip the bar
                fill_pct = 1.0 - (min(value / 100.0, 1.0))

            bar_len = 10
            filled = int(fill_pct * bar_len)
            bar = f"[{color}]{'|' * filled}[/{color}][dim]{'.' * (bar_len - filled)}[/dim]"

            table.add_row(
                name,
                f"{value:.1f}",
                str(kri_def.get("warning", "")),
                str(kri_def.get("critical", "")),
                f"[{color}]{label}[/{color}]",
                bar,
            )
        except Exception:
            table.add_row(name, "ERR", "", "", "[red]ERROR[/red]", "")

    console.print(table)
    console.print(
        "[dim]Sparkline fills toward the critical threshold. Full bar = at/above critical.[/dim]"
    )


# ===========================================================================
# alerts subgroup
# ===========================================================================

# In-process alert store (in a production system this would persist to the DB)
_ALERTS: list[dict[str, Any]] = []


def _generate_kri_alerts() -> list[dict[str, Any]]:
    """Generate alert records for KRIs currently in RED or AMBER state."""
    generated = []
    now = _utcnow()
    for name, kri_def in _KRI_REGISTRY.items():
        try:
            value = _evaluate_kri(name, kri_def)
            label, _ = _kri_status(value, kri_def)
            if label in ("RED", "AMBER"):
                generated.append(
                    {
                        "id": f"kri-{name}-{now.strftime('%Y%m%d%H%M')}",
                        "kri": name,
                        "value": value,
                        "status": "active",
                        "severity": "critical" if label == "RED" else "warning",
                        "message": (
                            f"KRI '{name}' is {label}: {value:.2f} "
                            f"(critical={kri_def.get('critical')}, warning={kri_def.get('warning')})"
                        ),
                        "created_at": now.isoformat(),
                        "acknowledged_by": None,
                        "channel": None,
                    }
                )
        except Exception:
            pass
    return generated


@alerts.command("list")
@click.option(
    "--status",
    "alert_status",
    type=click.Choice(["active", "acknowledged", "resolved"]),
    default="active",
    show_default=True,
    help="Filter by alert status",
)
def alerts_list(alert_status: str) -> None:
    """List alerts filtered by status."""
    live_alerts = _generate_kri_alerts()
    all_alerts = live_alerts + [a for a in _ALERTS if a not in live_alerts]

    filtered = [a for a in all_alerts if a.get("status") == alert_status]

    if not filtered:
        console.print(f"[green]No {alert_status} alerts.[/green]")
        return

    table = Table(title=f"Alerts — {alert_status.upper()} ({len(filtered)})")
    table.add_column("ID", style="dim")
    table.add_column("KRI", style="cyan")
    table.add_column("Severity")
    table.add_column("Value", justify="right")
    table.add_column("Message")
    table.add_column("Created At")

    for alert in filtered:
        sev = alert.get("severity", "")
        sev_color = "red bold" if sev == "critical" else "yellow"
        table.add_row(
            alert["id"][:20],
            alert.get("kri", "—"),
            f"[{sev_color}]{sev}[/{sev_color}]",
            f"{alert.get('value', 0.0):.2f}",
            alert.get("message", "")[:60],
            str(alert.get("created_at", ""))[:16],
        )
    console.print(table)


@alerts.command("acknowledge")
@click.argument("alert_id")
def alerts_acknowledge(alert_id: str) -> None:
    """Acknowledge an active alert by ID."""
    from warlock.cli import _get_actor

    actor = _get_actor()
    # Find in the in-process store
    for alert in _ALERTS:
        if alert["id"] == alert_id or alert["id"].startswith(alert_id):
            alert["status"] = "acknowledged"
            alert["acknowledged_by"] = actor
            alert["acknowledged_at"] = _utcnow().isoformat()
            console.print(f"[green]Alert [bold]{alert_id}[/bold] acknowledged by {actor}.[/green]")
            return

    # Try live alerts
    live_alerts = _generate_kri_alerts()
    for alert in live_alerts:
        if alert["id"] == alert_id or alert["id"].startswith(alert_id):
            alert["status"] = "acknowledged"
            alert["acknowledged_by"] = actor
            alert["acknowledged_at"] = _utcnow().isoformat()
            _ALERTS.append(alert)
            console.print(f"[green]Alert [bold]{alert_id}[/bold] acknowledged by {actor}.[/green]")
            return

    _error(f"Alert not found: {alert_id!r}")


@alerts.command("configure")
@click.option("--kri", "kri_name", required=True, help="KRI name to configure alerting for")
@click.option(
    "--channel",
    type=click.Choice(["slack", "email"]),
    required=True,
    help="Notification channel",
)
@click.option(
    "--threshold",
    type=click.Choice(["warning", "critical"]),
    default="critical",
    show_default=True,
    help="Threshold level that triggers the alert",
)
def alerts_configure(kri_name: str, channel: str, threshold: str) -> None:
    """Configure alert notifications for a KRI."""
    if kri_name not in _KRI_REGISTRY:
        _error(
            f"Unknown KRI: {kri_name!r}. Run 'warlock dashboard kri list' to see available KRIs."
        )

    _KRI_REGISTRY[kri_name]["alert_channel"] = channel
    _KRI_REGISTRY[kri_name]["alert_threshold"] = threshold

    console.print(
        f"[green]Alert configured:[/green] KRI [cyan]{kri_name}[/cyan] will notify via "
        f"[bold]{channel}[/bold] when [bold]{threshold}[/bold] threshold is breached."
    )
    console.print(
        "[dim]Note: channel dispatch is a placeholder — integrate with your webhook.[/dim]"
    )


@alerts.command("history")
@click.option("--days", type=int, default=7, show_default=True, help="Lookback window in days")
def alerts_history(days: int) -> None:
    """Show alert history for the past N days."""
    since = _utcnow() - timedelta(days=days)

    historical = [
        a
        for a in _ALERTS
        if a.get("created_at") and datetime.fromisoformat(a["created_at"]) >= since
    ]

    if not historical:
        console.print(f"[dim]No alert history in the past {days} days.[/dim]")
        console.print(
            "[dim]Note: alert history is in-process only in this build. "
            "No alerts have been acknowledged in this session.[/dim]"
        )
        return

    table = Table(title=f"Alert History — Last {days} Days ({len(historical)} alerts)")
    table.add_column("ID", style="dim")
    table.add_column("KRI", style="cyan")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Acknowledged By")
    table.add_column("Created At")

    for alert in sorted(historical, key=lambda a: a.get("created_at", ""), reverse=True):
        sev = alert.get("severity", "")
        sev_color = "red bold" if sev == "critical" else "yellow"
        status_color = "green" if alert.get("status") == "acknowledged" else "red"
        table.add_row(
            alert["id"][:20],
            alert.get("kri", "—"),
            f"[{sev_color}]{sev}[/{sev_color}]",
            f"[{status_color}]{alert.get('status', '—')}[/{status_color}]",
            alert.get("acknowledged_by") or "—",
            str(alert.get("created_at", ""))[:16],
        )
    console.print(table)
