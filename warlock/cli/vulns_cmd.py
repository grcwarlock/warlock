"""Vulnerability management commands: dashboard, SLA breach, trends, accept, aging,
by-scanner, remediation-rate, report.

All commands operate on Finding records filtered to observation_type='vulnerability'.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import click
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor

# SLA thresholds (days) per severity — industry standard
_SLA_DAYS: dict[str, int] = {
    "critical": 15,
    "high": 30,
    "medium": 90,
    "low": 180,
}

_SEVERITY_STYLES: dict[str, str] = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
    "info": "blue",
}


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("vulns")
def vulns() -> None:
    """Vulnerability management: dashboard, SLA tracking, trends, and reporting."""


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------


@vulns.command("dashboard")
@click.option("--source", "-s", default=None, help="Filter by source (e.g. tenable, wiz)")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def vulns_dashboard(source: str | None, framework: str | None) -> None:
    """Show vulnerability posture dashboard."""
    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        q = session.query(Finding).filter(Finding.observation_type == "vulnerability")
        if source:
            q = q.filter(Finding.source == source)

        total = q.count()
        if total == 0:
            console.print("[dim]No vulnerability findings found.[/dim]")
            return

        by_severity = dict(
            session.query(Finding.severity, func.count(Finding.id))
            .filter(Finding.observation_type == "vulnerability")
            .group_by(Finding.severity)
            .all()
        )
        by_source = dict(
            session.query(Finding.source, func.count(Finding.id))
            .filter(Finding.observation_type == "vulnerability")
            .group_by(Finding.source)
            .order_by(func.count(Finding.id).desc())
            .limit(10)
            .all()
        )

        # SLA breach count
        now = datetime.now(timezone.utc)
        sla_breach_count = 0
        for sev, days in _SLA_DAYS.items():
            cutoff = now - timedelta(days=days)
            breach = (
                session.query(Finding)
                .filter(
                    Finding.observation_type == "vulnerability",
                    Finding.severity == sev,
                    Finding.observed_at < cutoff,
                )
                .count()
            )
            sla_breach_count += breach

    console.print("\n[bold cyan]Vulnerability Dashboard[/bold cyan]\n")

    summary = Table(title="Summary")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", justify="right")
    summary.add_row("Total vulnerabilities", str(total))
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = by_severity.get(sev, 0)
        style = _SEVERITY_STYLES.get(sev, "")
        summary.add_row(f"  {sev.capitalize()}", f"[{style}]{cnt}[/{style}]")
    summary.add_row("SLA breaches", f"[red]{sla_breach_count}[/red]")
    console.print(summary)

    if by_source:
        src_table = Table(title="Top Sources")
        src_table.add_column("Source", style="cyan")
        src_table.add_column("Count", justify="right")
        for src, cnt in by_source.items():
            src_table.add_row(src, str(cnt))
        console.print(src_table)


# ---------------------------------------------------------------------------
# sla-breach
# ---------------------------------------------------------------------------


@vulns.command("sla-breach")
@click.option("--source", "-s", default=None, help="Filter by source")
@click.option("--severity", default=None, help="Filter by severity (critical, high, medium, low)")
@click.option("--limit", "-n", default=50, help="Max results")
def vulns_sla_breach(source: str | None, severity: str | None, limit: int) -> None:
    """List vulnerabilities that have breached their SLA thresholds.

    SLA thresholds: critical=15d, high=30d, medium=90d, low=180d.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    now = datetime.now(timezone.utc)

    results: list[tuple[Finding, int]] = []  # (finding, days_over_sla)

    with get_session() as session:
        sevs = [severity] if severity else list(_SLA_DAYS.keys())
        for sev in sevs:
            days = _SLA_DAYS.get(sev, 90)
            cutoff = now - timedelta(days=days)
            q = (
                session.query(Finding)
                .filter(
                    Finding.observation_type == "vulnerability",
                    Finding.severity == sev,
                    Finding.observed_at < cutoff,
                )
            )
            if source:
                q = q.filter(Finding.source == source)
            rows = q.order_by(Finding.observed_at.asc()).all()
            for r in rows:
                age_days = (now - r.observed_at).days
                over_sla = age_days - days
                results.append((r, over_sla))

    results.sort(key=lambda x: x[1], reverse=True)
    results = results[:limit]

    if not results:
        console.print("[green]No SLA breaches found.[/green]")
        return

    table = Table(title=f"SLA Breaches ({len(results)} findings)")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Source")
    table.add_column("Provider")
    table.add_column("Severity")
    table.add_column("SLA (days)", justify="right")
    table.add_column("Age (days)", justify="right")
    table.add_column("Over SLA", justify="right")
    table.add_column("Title", max_width=40)

    for finding, over in results:
        sev_style = _SEVERITY_STYLES.get(finding.severity, "")
        sla = _SLA_DAYS.get(finding.severity, 90)
        age = (now - finding.observed_at).days
        table.add_row(
            finding.id[:8],
            finding.source,
            finding.provider,
            f"[{sev_style}]{finding.severity}[/{sev_style}]",
            str(sla),
            str(age),
            f"[red]+{over}[/red]",
            finding.title[:40],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# trends
# ---------------------------------------------------------------------------


@vulns.command("trends")
@click.option("--days", "-d", default=30, help="Lookback window in days")
@click.option("--source", "-s", default=None, help="Filter by source")
def vulns_trends(days: int, source: str | None) -> None:
    """Show vulnerability discovery trends over the last N days."""
    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)

    with get_session() as session:
        q = session.query(
            func.date(Finding.observed_at).label("day"),
            Finding.severity,
            func.count(Finding.id).label("cnt"),
        ).filter(
            Finding.observation_type == "vulnerability",
            Finding.observed_at >= cutoff,
        )
        if source:
            q = q.filter(Finding.source == source)
        rows = q.group_by(func.date(Finding.observed_at), Finding.severity).all()

    if not rows:
        console.print("[dim]No vulnerability data in the specified period.[/dim]")
        return

    # Group by day
    by_day: dict[str, dict[str, int]] = {}
    for row in rows:
        day_str = str(row.day)
        by_day.setdefault(day_str, {})
        by_day[day_str][row.severity] = row.cnt

    table = Table(title=f"Vulnerability Trends (last {days} days)")
    table.add_column("Date", style="cyan")
    table.add_column("Critical", justify="right", style="red bold")
    table.add_column("High", justify="right", style="red")
    table.add_column("Medium", justify="right", style="yellow")
    table.add_column("Low", justify="right", style="dim")
    table.add_column("Total", justify="right")

    for day in sorted(by_day.keys())[-14:]:  # show last 14 days
        sev_counts = by_day[day]
        total = sum(sev_counts.values())
        table.add_row(
            day,
            str(sev_counts.get("critical", 0)),
            str(sev_counts.get("high", 0)),
            str(sev_counts.get("medium", 0)),
            str(sev_counts.get("low", 0)),
            str(total),
        )

    console.print(table)
    if len(by_day) > 14:
        console.print(f"[dim](showing last 14 of {len(by_day)} days)[/dim]")


# ---------------------------------------------------------------------------
# accept
# ---------------------------------------------------------------------------


@vulns.command("accept")
@click.argument("finding_id")
@click.option("--reason", "-r", required=True, help="Justification for accepting this vulnerability")
@click.option(
    "--actor",
    default=None,
    envvar="WLK_CLI_ACTOR",
    help="Actor identity for audit trail",
)
def vulns_accept(finding_id: str, reason: str, actor: str | None) -> None:
    """Accept (risk-accept) a vulnerability finding.

    FINDING_ID: Finding ID or prefix to accept.
    """
    import os

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    if actor:
        os.environ["WLK_CLI_ACTOR"] = actor

    init_db()
    with get_session() as session:
        finding = (
            session.query(Finding)
            .filter(
                Finding.id.startswith(finding_id),
                Finding.observation_type == "vulnerability",
            )
            .first()
        )
        if not finding:
            _error(f"Vulnerability finding not found: {finding_id}")

        actor_name = _get_actor()
        # Record acceptance in the finding's detail JSON
        detail = dict(finding.detail or {})
        detail["risk_accepted"] = {
            "reason": reason,
            "accepted_by": actor_name,
            "accepted_at": datetime.now(timezone.utc).isoformat(),
        }
        finding.detail = detail
        session.commit()

    console.print(
        f"[green]Vulnerability {finding_id[:8]} risk-accepted by {actor_name}.[/green]"
    )


# ---------------------------------------------------------------------------
# aging
# ---------------------------------------------------------------------------


@vulns.command("aging")
@click.option("--min-age", default=30, help="Minimum age in days to include")
@click.option("--source", "-s", default=None, help="Filter by source")
@click.option("--limit", "-n", default=30, help="Max results")
def vulns_aging(min_age: int, source: str | None, limit: int) -> None:
    """Show oldest open vulnerabilities exceeding a minimum age."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=min_age)

    with get_session() as session:
        q = session.query(Finding).filter(
            Finding.observation_type == "vulnerability",
            Finding.observed_at <= cutoff,
        )
        if source:
            q = q.filter(Finding.source == source)
        rows = q.order_by(Finding.observed_at.asc()).limit(limit).all()

    if not rows:
        console.print(f"[green]No vulnerabilities older than {min_age} days found.[/green]")
        return

    table = Table(title=f"Aging Vulnerabilities (>{min_age} days old)")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Severity")
    table.add_column("Source")
    table.add_column("Resource", max_width=25)
    table.add_column("Age (days)", justify="right")
    table.add_column("Title", max_width=45)

    for finding in rows:
        age = (now - finding.observed_at).days
        sev_style = _SEVERITY_STYLES.get(finding.severity, "")
        table.add_row(
            finding.id[:8],
            f"[{sev_style}]{finding.severity}[/{sev_style}]",
            finding.source,
            (finding.resource_name or finding.resource_id or "")[:25],
            str(age),
            finding.title[:45],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# by-scanner
# ---------------------------------------------------------------------------


@vulns.command("by-scanner")
def vulns_by_scanner() -> None:
    """Show vulnerability counts broken down by scanner/source."""
    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        rows = (
            session.query(
                Finding.source,
                Finding.provider,
                Finding.severity,
                func.count(Finding.id).label("cnt"),
            )
            .filter(Finding.observation_type == "vulnerability")
            .group_by(Finding.source, Finding.provider, Finding.severity)
            .order_by(Finding.source, Finding.provider)
            .all()
        )

    if not rows:
        console.print("[dim]No vulnerability findings found.[/dim]")
        return

    table = Table(title="Vulnerabilities by Scanner")
    table.add_column("Source", style="cyan")
    table.add_column("Provider")
    table.add_column("Critical", justify="right", style="red bold")
    table.add_column("High", justify="right", style="red")
    table.add_column("Medium", justify="right", style="yellow")
    table.add_column("Low", justify="right", style="dim")
    table.add_column("Total", justify="right")

    # Group into (source, provider) buckets
    buckets: dict[tuple[str, str], dict[str, int]] = {}
    for row in rows:
        key = (row.source, row.provider)
        buckets.setdefault(key, {})
        buckets[key][row.severity] = row.cnt

    for (src, prov), sev_map in sorted(buckets.items()):
        total = sum(sev_map.values())
        table.add_row(
            src,
            prov,
            str(sev_map.get("critical", 0)),
            str(sev_map.get("high", 0)),
            str(sev_map.get("medium", 0)),
            str(sev_map.get("low", 0)),
            str(total),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# remediation-rate
# ---------------------------------------------------------------------------


@vulns.command("remediation-rate")
@click.option("--days", "-d", default=30, help="Period in days to measure remediation rate")
@click.option("--source", "-s", default=None, help="Filter by source")
def vulns_remediation_rate(days: int, source: str | None) -> None:
    """Show vulnerability remediation rate for the given period.

    Computes: # findings observed in the window vs # with associated compliant control results.
    """

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding

    init_db()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)

    with get_session() as session:
        q_total = session.query(Finding).filter(
            Finding.observation_type == "vulnerability",
            Finding.observed_at >= cutoff,
        )
        if source:
            q_total = q_total.filter(Finding.source == source)
        total = q_total.count()

        # Findings that have at least one compliant control result
        q_remediated = (
            session.query(Finding)
            .join(Finding.control_mappings)
            .join(ControlResult, ControlResult.control_mapping_id == ControlResult.control_mapping_id)
            .filter(
                Finding.observation_type == "vulnerability",
                Finding.observed_at >= cutoff,
                ControlResult.status == "compliant",
            )
        )
        if source:
            q_remediated = q_remediated.filter(Finding.source == source)
        remediated = q_remediated.distinct(Finding.id).count()

    rate = (remediated / total * 100) if total > 0 else 0.0

    console.print(f"\n[bold]Vulnerability Remediation Rate ({days}-day window)[/bold]\n")
    table = Table()
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("Total vulns observed", str(total))
    table.add_row("With compliant result", str(remediated))
    rate_style = "green" if rate >= 80 else ("yellow" if rate >= 50 else "red")
    table.add_row("Remediation rate", f"[{rate_style}]{rate:.1f}%[/{rate_style}]")
    console.print(table)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@vulns.command("report")
@click.option("--output", "-o", default=None, help="Output file path (default: display)")
@click.option("--source", "-s", default=None, help="Filter by source")
@click.option("--days", "-d", default=30, help="Lookback window in days")
def vulns_report(output: str | None, source: str | None, days: int) -> None:
    """Generate a vulnerability management report."""
    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)

    with get_session() as session:
        q = session.query(Finding).filter(Finding.observation_type == "vulnerability")
        if source:
            q = q.filter(Finding.source == source)

        total = q.count()
        period_new = q.filter(Finding.observed_at >= cutoff).count()

        by_sev = dict(
            session.query(Finding.severity, func.count(Finding.id))
            .filter(Finding.observation_type == "vulnerability")
            .group_by(Finding.severity)
            .all()
        )

        # SLA status
        sla_ok = 0
        sla_breach = 0
        for sev, sla_days in _SLA_DAYS.items():
            breach_cutoff = now - timedelta(days=sla_days)
            breach_cnt = (
                session.query(Finding)
                .filter(
                    Finding.observation_type == "vulnerability",
                    Finding.severity == sev,
                    Finding.observed_at < breach_cutoff,
                )
                .count()
            )
            within_sla = by_sev.get(sev, 0) - breach_cnt
            sla_ok += max(within_sla, 0)
            sla_breach += breach_cnt

    lines: list[str] = [
        "Vulnerability Management Report",
        "=" * 50,
        f"Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Period: last {days} days",
        "",
        "SUMMARY",
        f"  Total vulnerabilities: {total}",
        f"  New this period:       {period_new}",
        f"  SLA compliant:         {sla_ok}",
        f"  SLA breached:          {sla_breach}",
        "",
        "BY SEVERITY",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = by_sev.get(sev, 0)
        sla = _SLA_DAYS.get(sev, 180)
        lines.append(f"  {sev.capitalize():10s}: {cnt:>6} (SLA: {sla}d)")

    report_text = "\n".join(lines)

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(report_text)
        console.print(f"[green]Report written to {output}[/green]")
    else:
        console.print(report_text)
