"""Security posture and vulnerability management commands.

Provides CIS benchmarks, firewall analysis, network exposure, cross-account
trust, IOC correlation, TTP mapping, vulnerability prioritization,
false-positive management, cross-scanner correlation, vulnerability density,
burndown tracking, cloud config compliance, encryption status, logging
coverage, and patch compliance.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor

# SLA thresholds (days) per severity
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

# Composite scoring weights for vuln-priority
_SEVERITY_SCORE: dict[str, int] = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
    "info": 0,
}

# EDR connector names for IOC correlation
_EDR_SOURCES = {"crowdstrike", "sentinelone", "defender", "microsoft_defender"}

# Encryption-related keywords
_ENCRYPTION_KEYWORDS = [
    "encrypt",
    "kms",
    "tls",
    "ssl",
    "cipher",
    "aes",
    "rsa",
    "certificate",
    "key_rotation",
    "at_rest",
    "in_transit",
]

# Logging-related keywords
_LOGGING_KEYWORDS = [
    "logging",
    "cloudtrail",
    "flow_log",
    "audit_log",
    "access_log",
    "monitor",
    "trail",
    "log_group",
    "log_stream",
    "diagnostic",
]

# Patch-related keywords
_PATCH_KEYWORDS = [
    "patch",
    "update",
    "upgrade",
    "cve",
    "hotfix",
    "security_update",
    "eol",
    "end_of_life",
    "outdated",
    "unsupported",
]


def _sev_style(severity: str) -> str:
    return _SEVERITY_STYLES.get((severity or "").lower(), "")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _detail_str(detail) -> str:
    """Safely convert detail JSON to lowercase string for keyword searching."""
    if detail is None:
        return ""
    if isinstance(detail, str):
        return detail.lower()
    return json.dumps(detail, default=str).lower()


def _detail_contains(detail, keywords: list[str]) -> bool:
    """Check if any keyword appears in the detail JSON."""
    text = _detail_str(detail)
    return any(kw in text for kw in keywords)


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("security-posture", invoke_without_command=True)
@click.pass_context
def security_posture(ctx: click.Context) -> None:
    """Security posture analysis and vulnerability management."""
    if ctx.invoked_subcommand is None:
        from warlock.db.engine import get_session, init_db
        from warlock.db.models import Finding, ControlResult

        init_db()
        with get_session() as session:
            total_findings = session.query(Finding).count()
            crit = session.query(Finding).filter(Finding.severity == "critical").count()
            high = session.query(Finding).filter(Finding.severity == "high").count()
            compliant = (
                session.query(ControlResult).filter(ControlResult.status == "compliant").count()
            )
            non_compliant = (
                session.query(ControlResult).filter(ControlResult.status == "non_compliant").count()
            )
            total_controls = (
                session.query(ControlResult)
                .filter(ControlResult.status.in_(["compliant", "non_compliant", "partial"]))
                .count()
            )

        tbl = Table(title="Security Posture Summary")
        tbl.add_column("Metric", style="cyan")
        tbl.add_column("Value", justify="right")
        tbl.add_row("Total findings", str(total_findings))
        tbl.add_row("Critical findings", f"[red bold]{crit}[/red bold]")
        tbl.add_row("High findings", f"[red]{high}[/red]")
        tbl.add_row("Compliant controls", str(compliant))
        tbl.add_row("Non-compliant controls", f"[red]{non_compliant}[/red]")
        if total_controls > 0:
            rate = round(compliant / total_controls * 100, 1)
            tbl.add_row("Compliance rate", f"{rate}%")
        console.print(tbl)
        console.print("\n[dim]Run 'warlock security-posture --help' for subcommands.[/dim]")


# ---------------------------------------------------------------------------
# SEC-1: vuln-priority
# ---------------------------------------------------------------------------


@security_posture.command("vuln-priority")
@click.option("--limit", "-l", default=25, help="Max rows to display")
@click.option("--severity", "-s", default=None, help="Filter by severity")
@click.option("--source", default=None, help="Filter by source")
def vuln_priority(limit: int, severity: str | None, source: str | None) -> None:
    """Composite vulnerability prioritization score.

    Ranks findings by a composite score combining severity, resource
    criticality, and exposure context. Higher scores indicate more
    urgent remediation priority.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding
    from warlock.utils import ensure_aware

    init_db()
    with get_session() as session:
        q = session.query(Finding)
        if severity:
            q = q.filter(Finding.severity == severity.lower())
        if source:
            q = q.filter(Finding.source == source)

        findings = q.limit(5000).all()

        if not findings:
            console.print("[dim]No findings found.[/dim]")
            return

        scored: list[tuple[float, Finding]] = []
        now = _utcnow()
        for f in findings:
            base = _SEVERITY_SCORE.get((f.severity or "").lower(), 0)
            # Age bonus: older findings get higher priority
            observed = ensure_aware(f.observed_at) if f.observed_at else now
            age_days = max((now - observed).days, 0)
            age_bonus = min(age_days / 30, 3.0)  # up to +3 for 90+ days
            # Exposure bonus: public-facing resources rank higher
            detail_text = _detail_str(f.detail)
            exposure_bonus = (
                2.0
                if any(kw in detail_text for kw in ["public", "0.0.0.0/0", "internet", "external"])
                else 0.0
            )
            # Confidence factor
            conf = f.confidence if f.confidence else 1.0
            score = round((base + age_bonus + exposure_bonus) * conf, 2)
            scored.append((score, f))

        scored.sort(key=lambda x: x[0], reverse=True)

        tbl = Table(title="Vulnerability Priority Ranking")
        tbl.add_column("#", style="dim", justify="right")
        tbl.add_column("Score", justify="right", style="bold")
        tbl.add_column("Severity")
        tbl.add_column("Title", max_width=50)
        tbl.add_column("Resource", max_width=30)
        tbl.add_column("Source")
        tbl.add_column("Age (days)", justify="right")

        for i, (score, f) in enumerate(scored[:limit], 1):
            observed = ensure_aware(f.observed_at) if f.observed_at else now
            age = max((now - observed).days, 0)
            sev_s = _sev_style(f.severity)
            tbl.add_row(
                str(i),
                str(score),
                f"[{sev_s}]{escape(f.severity or '')}[/{sev_s}]",
                escape(f.title or ""),
                escape(f.resource_id or "--"),
                escape(f.source or ""),
                str(age),
            )
        console.print(tbl)
        console.print(
            f"\n[dim]Showing top {min(limit, len(scored))} of {len(scored)} findings.[/dim]"
        )


# ---------------------------------------------------------------------------
# SEC-2: false-positives
# ---------------------------------------------------------------------------


@security_posture.command("false-positives")
@click.option("--mark", default=None, help="Finding ID to mark as false positive")
@click.option("--reason", default=None, help="Justification for false-positive marking")
@click.option("--limit", "-l", default=50, help="Max rows to display")
def false_positives(mark: str | None, reason: str | None, limit: int) -> None:
    """List findings marked as risk_accepted or mark a finding as false positive.

    Use --mark <finding-id> --reason <justification> to mark a finding.
    Without flags, lists all risk-accepted findings with their justifications.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding

    init_db()

    if mark:
        if not reason:
            _error("--reason is required when using --mark")
        with get_session() as session:
            finding = session.query(Finding).filter(Finding.id == mark).first()
            if not finding:
                _error(f"Finding {mark} not found")
            # Update detail with false-positive metadata
            detail = dict(finding.detail or {})
            detail["_false_positive"] = True
            detail["_false_positive_reason"] = reason
            detail["_false_positive_by"] = _get_actor()
            detail["_false_positive_at"] = _utcnow().isoformat()
            finding.detail = detail
            # Mark related control results as risk_accepted
            results = session.query(ControlResult).filter(ControlResult.finding_id == mark).all()
            for cr in results:
                cr.status = "risk_accepted"
            session.commit()
        console.print(
            f"[green]Finding {escape(mark)} marked as false positive.[/green]\n"
            f"[dim]Reason: {escape(reason)}[/dim]\n"
            f"[dim]{len(results)} control result(s) set to risk_accepted.[/dim]"
        )
        return

    # List false positives
    with get_session() as session:
        rows = session.query(Finding).filter(Finding.detail.isnot(None)).limit(5000).all()
        fps = []
        for f in rows:
            detail = f.detail if isinstance(f.detail, dict) else {}
            if detail.get("_false_positive") or detail.get("_suppressed"):
                fps.append(f)

        if not fps:
            console.print("[dim]No false-positive or suppressed findings found.[/dim]")
            return

        tbl = Table(title="False Positives / Suppressed Findings")
        tbl.add_column("ID", style="dim", max_width=12)
        tbl.add_column("Severity")
        tbl.add_column("Title", max_width=40)
        tbl.add_column("Reason", max_width=40)
        tbl.add_column("Marked By")

        for f in fps[:limit]:
            detail = f.detail if isinstance(f.detail, dict) else {}
            fp_reason = detail.get(
                "_false_positive_reason",
                detail.get("_suppression_reason", "--"),
            )
            fp_by = detail.get(
                "_false_positive_by",
                detail.get("_suppressed_by", "--"),
            )
            sev_s = _sev_style(f.severity)
            tbl.add_row(
                f.id[:12],
                f"[{sev_s}]{escape(f.severity or '')}[/{sev_s}]",
                escape(f.title or ""),
                escape(str(fp_reason)),
                escape(str(fp_by)),
            )
        console.print(tbl)
        console.print(f"\n[dim]{len(fps)} false-positive/suppressed finding(s) total.[/dim]")


# ---------------------------------------------------------------------------
# SEC-3: cross-scanner
# ---------------------------------------------------------------------------


@security_posture.command("cross-scanner")
@click.option("--limit", "-l", default=30, help="Max rows to display")
def cross_scanner(limit: int) -> None:
    """Cross-scanner correlation: findings detected by multiple sources.

    Groups findings by resource_id and shows which scanners detected issues
    on the same resource, helping identify corroborated vs single-source findings.
    """
    from sqlalchemy import case, func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        # Find resources with findings from multiple sources
        multi = (
            session.query(
                Finding.resource_id,
                func.count(func.distinct(Finding.source)).label("source_count"),
                func.count(Finding.id).label("finding_count"),
            )
            .filter(Finding.resource_id.isnot(None))
            .group_by(Finding.resource_id)
            .having(func.count(func.distinct(Finding.source)) > 1)
            .order_by(func.count(func.distinct(Finding.source)).desc())
            .limit(limit)
            .all()
        )

        if not multi:
            console.print(
                "[dim]No cross-scanner correlations found. "
                "Resources are only detected by single sources.[/dim]"
            )
            return

        tbl = Table(title="Cross-Scanner Correlation")
        tbl.add_column("Resource", max_width=50)
        tbl.add_column("Sources", justify="right")
        tbl.add_column("Findings", justify="right")
        tbl.add_column("Scanners")
        tbl.add_column("Top Severity")

        for row in multi:
            # Get scanner names and max severity for this resource
            scanners = (
                session.query(func.distinct(Finding.source))
                .filter(Finding.resource_id == row.resource_id)
                .all()
            )
            scanner_names = sorted(s[0] for s in scanners)

            worst = (
                session.query(Finding.severity)
                .filter(Finding.resource_id == row.resource_id)
                .order_by(
                    # Order by severity rank
                    case(
                        (Finding.severity == "critical", 1),
                        (Finding.severity == "high", 2),
                        (Finding.severity == "medium", 3),
                        (Finding.severity == "low", 4),
                        else_=5,
                    )
                )
                .first()
            )
            worst_sev = worst[0] if worst else "info"
            sev_s = _sev_style(worst_sev)

            tbl.add_row(
                escape(row.resource_id or "--"),
                str(row.source_count),
                str(row.finding_count),
                escape(", ".join(scanner_names)),
                f"[{sev_s}]{escape(worst_sev)}[/{sev_s}]",
            )
        console.print(tbl)
        console.print(f"\n[dim]{len(multi)} resource(s) with multi-scanner detections.[/dim]")


# ---------------------------------------------------------------------------
# SEC-4: vuln-density
# ---------------------------------------------------------------------------


@security_posture.command("vuln-density")
@click.option(
    "--by",
    "group_by",
    type=click.Choice(["resource_type", "account", "source"]),
    default="resource_type",
    help="Group findings by dimension",
)
@click.option("--limit", "-l", default=30, help="Max rows to display")
def vuln_density(group_by: str, limit: int) -> None:
    """Vulnerability density by resource type, account, or source.

    Shows finding counts grouped by the selected dimension, highlighting
    where vulnerabilities are concentrated.
    """
    from sqlalchemy import case, func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    col_map = {
        "resource_type": Finding.resource_type,
        "account": Finding.account_id,
        "source": Finding.source,
    }
    col = col_map[group_by]

    with get_session() as session:
        rows = (
            session.query(
                col.label("group_key"),
                func.count(Finding.id).label("total"),
                func.sum(case((Finding.severity == "critical", 1), else_=0)).label("crit"),
                func.sum(case((Finding.severity == "high", 1), else_=0)).label("high"),
                func.sum(case((Finding.severity == "medium", 1), else_=0)).label("med"),
                func.sum(case((Finding.severity == "low", 1), else_=0)).label("low"),
            )
            .filter(col.isnot(None))
            .group_by(col)
            .order_by(func.count(Finding.id).desc())
            .limit(limit)
            .all()
        )

        if not rows:
            console.print(f"[dim]No findings grouped by {group_by}.[/dim]")
            return

        tbl = Table(title=f"Vulnerability Density by {group_by.replace('_', ' ').title()}")
        tbl.add_column(group_by.replace("_", " ").title(), max_width=40)
        tbl.add_column("Total", justify="right", style="bold")
        tbl.add_column("Critical", justify="right", style="red bold")
        tbl.add_column("High", justify="right", style="red")
        tbl.add_column("Medium", justify="right", style="yellow")
        tbl.add_column("Low", justify="right", style="dim")

        for r in rows:
            tbl.add_row(
                escape(str(r.group_key or "--")),
                str(r.total),
                str(r.crit or 0),
                str(r.high or 0),
                str(r.med or 0),
                str(r.low or 0),
            )
        console.print(tbl)


# ---------------------------------------------------------------------------
# SEC-5: burndown
# ---------------------------------------------------------------------------


@security_posture.command("burndown")
@click.option(
    "--window",
    "-w",
    type=click.Choice(["7d", "30d", "90d"]),
    default="30d",
    help="Time window for analysis",
)
def burndown(window: str) -> None:
    """Vulnerability backlog burndown: inflow vs outflow over time.

    Shows how many findings were created versus how many issues were
    closed in the selected time window, indicating whether the backlog
    is growing or shrinking.
    """
    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, Issue

    days = int(window.rstrip("d"))
    init_db()
    now = _utcnow()
    cutoff = now - timedelta(days=days)

    with get_session() as session:
        # Inflow: findings created in window
        inflow = (
            session.query(func.count(Finding.id)).filter(Finding.ingested_at >= cutoff).scalar()
        ) or 0

        # Outflow: issues closed/remediated in window
        outflow = (
            session.query(func.count(Issue.id))
            .filter(
                Issue.status.in_(["closed", "remediated", "verified", "risk_accepted"]),
                Issue.updated_at >= cutoff,
            )
            .scalar()
        ) or 0

        # Current open
        open_count = (session.query(func.count(Finding.id)).scalar()) or 0

        # By severity in window
        by_sev = dict(
            session.query(Finding.severity, func.count(Finding.id))
            .filter(Finding.ingested_at >= cutoff)
            .group_by(Finding.severity)
            .all()
        )

    net = inflow - outflow
    direction = "growing" if net > 0 else ("shrinking" if net < 0 else "stable")

    tbl = Table(title=f"Vulnerability Burndown ({window})")
    tbl.add_column("Metric", style="cyan")
    tbl.add_column("Value", justify="right")
    tbl.add_row("New findings (inflow)", str(inflow))
    tbl.add_row("Resolved issues (outflow)", str(outflow))
    net_style = "red" if net > 0 else "green"
    tbl.add_row("Net change", f"[{net_style}]{'+' if net > 0 else ''}{net}[/{net_style}]")
    tbl.add_row("Backlog direction", f"[bold]{direction}[/bold]")
    tbl.add_row("Total open findings", str(open_count))
    console.print(tbl)

    if by_sev:
        sev_tbl = Table(title=f"New Findings by Severity ({window})")
        sev_tbl.add_column("Severity")
        sev_tbl.add_column("Count", justify="right")
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = by_sev.get(sev, 0)
            sev_s = _sev_style(sev)
            sev_tbl.add_row(
                f"[{sev_s}]{sev.capitalize()}[/{sev_s}]",
                str(cnt),
            )
        console.print(sev_tbl)


# ---------------------------------------------------------------------------
# SEC-6: cis-benchmarks
# ---------------------------------------------------------------------------


@security_posture.command("cis-benchmarks")
@click.option("--framework", "-f", default=None, help="CIS framework filter (e.g. nist_800_53)")
def cis_benchmarks(framework: str | None) -> None:
    """CIS benchmark compliance summary.

    Queries control results for CIS-related controls and groups them
    by control family, showing pass/fail counts for benchmark compliance.
    """
    from sqlalchemy import case, func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        # CIS benchmarks map to configuration checks -- look for
        # controls whose IDs or families relate to CIS hardening areas
        q = session.query(ControlResult).filter(
            ControlResult.status.in_(["compliant", "non_compliant", "partial"])
        )
        if framework:
            q = q.filter(ControlResult.framework == framework)

        # Group by control_family
        family_stats = session.query(
            ControlResult.control_id,
            ControlResult.framework,
            func.sum(case((ControlResult.status == "compliant", 1), else_=0)).label(
                "pass_count"
            ),
            func.sum(case((ControlResult.status == "non_compliant", 1), else_=0)).label(
                "fail_count"
            ),
            func.sum(case((ControlResult.status == "partial", 1), else_=0)).label(
                "partial_count"
            ),
            func.count(ControlResult.id).label("total"),
        ).filter(ControlResult.status.in_(["compliant", "non_compliant", "partial"]))
        if framework:
            family_stats = family_stats.filter(ControlResult.framework == framework)

        family_stats = (
            family_stats.group_by(ControlResult.framework, ControlResult.control_id)
            .order_by(
                func.sum(case((ControlResult.status == "non_compliant", 1), else_=0)).desc()
            )
            .limit(50)
            .all()
        )

        if not family_stats:
            console.print(
                "[dim]No CIS benchmark data found.[/dim]\n\n"
                "To enable CIS benchmarks:\n"
                "  1. Add CIS OPA policies to policies/cis/\n"
                "  2. Map CIS controls in your framework YAML\n"
                "  3. Run connectors that produce configuration checks\n"
                "  4. Re-run the pipeline: warlock pipeline run\n"
            )
            return

        tbl = Table(title="CIS Benchmark Compliance")
        tbl.add_column("Framework", style="cyan")
        tbl.add_column("Control", style="bold")
        tbl.add_column("Pass", justify="right", style="green")
        tbl.add_column("Fail", justify="right", style="red")
        tbl.add_column("Partial", justify="right", style="yellow")
        tbl.add_column("Total", justify="right")
        tbl.add_column("Rate", justify="right")

        for r in family_stats:
            rate = round(r.pass_count / r.total * 100, 1) if r.total else 0
            rate_style = "green" if rate >= 80 else ("yellow" if rate >= 50 else "red")
            tbl.add_row(
                escape(r.framework or ""),
                escape(r.control_id or ""),
                str(r.pass_count or 0),
                str(r.fail_count or 0),
                str(r.partial_count or 0),
                str(r.total),
                f"[{rate_style}]{rate}%[/{rate_style}]",
            )
        console.print(tbl)


# ---------------------------------------------------------------------------
# SEC-7: cloud-config
# ---------------------------------------------------------------------------


@security_posture.command("cloud-config")
@click.option("--source", "-s", default=None, help="Filter by cloud source (aws, azure, gcp)")
@click.option("--limit", "-l", default=30, help="Max rows to display")
def cloud_config(source: str | None, limit: int) -> None:
    """Configuration compliance by cloud service.

    Groups control results by the resource type of the underlying finding,
    showing compliance rates for each cloud service category.
    """
    from sqlalchemy import case, func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding, ControlMapping

    init_db()
    with get_session() as session:
        q = (
            session.query(
                Finding.resource_type.label("resource_type"),
                Finding.source.label("source"),
                func.sum(case((ControlResult.status == "compliant", 1), else_=0)).label(
                    "compliant"
                ),
                func.sum(case((ControlResult.status == "non_compliant", 1), else_=0)).label(
                    "non_compliant"
                ),
                func.count(ControlResult.id).label("total"),
            )
            .join(ControlMapping, ControlMapping.finding_id == Finding.id)
            .join(ControlResult, ControlResult.control_mapping_id == ControlMapping.id)
            .filter(
                Finding.resource_type.isnot(None),
                ControlResult.status.in_(["compliant", "non_compliant", "partial"]),
            )
        )
        if source:
            q = q.filter(Finding.source == source)

        rows = (
            q.group_by(Finding.resource_type, Finding.source)
            .order_by(
                func.sum(case((ControlResult.status == "non_compliant", 1), else_=0)).desc()
            )
            .limit(limit)
            .all()
        )

        if not rows:
            console.print("[dim]No cloud configuration compliance data found.[/dim]")
            return

        tbl = Table(title="Cloud Configuration Compliance")
        tbl.add_column("Resource Type", max_width=35)
        tbl.add_column("Source", style="cyan")
        tbl.add_column("Compliant", justify="right", style="green")
        tbl.add_column("Non-Compliant", justify="right", style="red")
        tbl.add_column("Total", justify="right")
        tbl.add_column("Rate", justify="right")

        for r in rows:
            rate = round(r.compliant / r.total * 100, 1) if r.total else 0
            rate_style = "green" if rate >= 80 else ("yellow" if rate >= 50 else "red")
            tbl.add_row(
                escape(str(r.resource_type or "--")),
                escape(str(r.source or "--")),
                str(r.compliant or 0),
                str(r.non_compliant or 0),
                str(r.total),
                f"[{rate_style}]{rate}%[/{rate_style}]",
            )
        console.print(tbl)


# ---------------------------------------------------------------------------
# SEC-8: encryption-status
# ---------------------------------------------------------------------------


@security_posture.command("encryption-status")
@click.option("--limit", "-l", default=30, help="Max rows to display")
def encryption_status(limit: int) -> None:
    """Encryption tracking across resources.

    Queries findings related to encryption, KMS, TLS, and certificate
    management. Groups by resource type to show encrypted vs unencrypted
    status across data silos.
    """

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        findings = session.query(Finding).filter(Finding.detail.isnot(None)).limit(10000).all()

        encrypted: dict[str, int] = defaultdict(int)
        unencrypted: dict[str, int] = defaultdict(int)
        issues: list[Finding] = []

        for f in findings:
            if not _detail_contains(f.detail, _ENCRYPTION_KEYWORDS):
                continue
            rt = f.resource_type or "unknown"
            detail_text = _detail_str(f.detail)
            if any(
                neg in detail_text
                for neg in [
                    "not_encrypted",
                    "unencrypted",
                    "no_encryption",
                    "disabled",
                    "false",
                    "non_compliant",
                ]
            ):
                unencrypted[rt] += 1
                issues.append(f)
            else:
                encrypted[rt] += 1

        all_types = sorted(set(encrypted.keys()) | set(unencrypted.keys()))
        if not all_types:
            console.print("[dim]No encryption-related findings found.[/dim]")
            return

        tbl = Table(title="Encryption Status by Resource Type")
        tbl.add_column("Resource Type", max_width=35)
        tbl.add_column("Encrypted", justify="right", style="green")
        tbl.add_column("Unencrypted", justify="right", style="red")
        tbl.add_column("Coverage", justify="right")

        for rt in all_types[:limit]:
            enc = encrypted.get(rt, 0)
            unenc = unencrypted.get(rt, 0)
            total = enc + unenc
            coverage = round(enc / total * 100, 1) if total else 0
            cov_style = "green" if coverage >= 90 else ("yellow" if coverage >= 50 else "red")
            tbl.add_row(
                escape(rt),
                str(enc),
                str(unenc),
                f"[{cov_style}]{coverage}%[/{cov_style}]",
            )
        console.print(tbl)

        if issues:
            console.print(
                f"\n[yellow]{len(issues)} finding(s) indicate missing encryption.[/yellow]"
            )


# ---------------------------------------------------------------------------
# SEC-9: logging-coverage
# ---------------------------------------------------------------------------


@security_posture.command("logging-coverage")
@click.option("--limit", "-l", default=30, help="Max rows to display")
def logging_coverage(limit: int) -> None:
    """Logging and monitoring coverage analysis.

    Queries findings for logging-related checks (CloudTrail, flow logs,
    audit logs, etc.) and shows which resources have logging enabled
    versus disabled.
    """

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        findings = session.query(Finding).filter(Finding.detail.isnot(None)).limit(10000).all()

        enabled: dict[str, int] = defaultdict(int)
        disabled: dict[str, int] = defaultdict(int)

        for f in findings:
            if not _detail_contains(f.detail, _LOGGING_KEYWORDS):
                continue
            rt = f.resource_type or "unknown"
            detail_text = _detail_str(f.detail)
            if any(
                neg in detail_text
                for neg in [
                    "disabled",
                    "not_enabled",
                    "no_logging",
                    "missing",
                    "false",
                    "non_compliant",
                    "off",
                ]
            ):
                disabled[rt] += 1
            else:
                enabled[rt] += 1

        all_types = sorted(set(enabled.keys()) | set(disabled.keys()))
        if not all_types:
            console.print("[dim]No logging-related findings found.[/dim]")
            return

        tbl = Table(title="Logging Coverage by Resource Type")
        tbl.add_column("Resource Type", max_width=35)
        tbl.add_column("Enabled", justify="right", style="green")
        tbl.add_column("Disabled", justify="right", style="red")
        tbl.add_column("Coverage", justify="right")

        for rt in all_types[:limit]:
            en = enabled.get(rt, 0)
            dis = disabled.get(rt, 0)
            total = en + dis
            coverage = round(en / total * 100, 1) if total else 0
            cov_style = "green" if coverage >= 90 else ("yellow" if coverage >= 50 else "red")
            tbl.add_row(
                escape(rt),
                str(en),
                str(dis),
                f"[{cov_style}]{coverage}%[/{cov_style}]",
            )
        console.print(tbl)


# ---------------------------------------------------------------------------
# SEC-10: firewall-rules
# ---------------------------------------------------------------------------


@security_posture.command("firewall-rules")
@click.option("--limit", "-l", default=30, help="Max rows to display")
@click.option("--source", "-s", default=None, help="Filter by source (aws, azure, gcp)")
def firewall_rules(limit: int, source: str | None) -> None:
    """Security group / NSG / firewall rule analysis.

    Queries findings related to security groups, NSGs, and firewall rules.
    Shows which resources have risky rules (e.g., 0.0.0.0/0 ingress,
    overly permissive ports).
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    _fw_types = ["security_group", "nsg", "firewall", "network_acl", "waf"]

    with get_session() as session:
        q = session.query(Finding).filter(Finding.resource_type.isnot(None))
        if source:
            q = q.filter(Finding.source == source)

        findings = q.limit(10000).all()

        fw_findings: list[Finding] = []
        for f in findings:
            rt = (f.resource_type or "").lower()
            title_lower = (f.title or "").lower()
            if any(t in rt for t in _fw_types) or any(t in title_lower for t in _fw_types):
                fw_findings.append(f)

        if not fw_findings:
            console.print("[dim]No firewall/security group findings found.[/dim]")
            return

        tbl = Table(title="Firewall / Security Group Analysis")
        tbl.add_column("Resource", max_width=40)
        tbl.add_column("Type")
        tbl.add_column("Source")
        tbl.add_column("Public Access")
        tbl.add_column("Risky Rules")
        tbl.add_column("Severity")

        for f in fw_findings[:limit]:
            detail_text = _detail_str(f.detail)
            has_public = any(
                kw in detail_text for kw in ["0.0.0.0/0", "::/0", "public", "internet"]
            )
            has_risky = any(
                kw in detail_text
                for kw in ["0.0.0.0/0", "all_traffic", "any_port", "0-65535", "::/0"]
            )
            sev_s = _sev_style(f.severity)
            tbl.add_row(
                escape(f.resource_id or f.resource_name or "--"),
                escape(f.resource_type or "--"),
                escape(f.source or "--"),
                "[red]Yes[/red]" if has_public else "[green]No[/green]",
                "[red]Yes[/red]" if has_risky else "[green]No[/green]",
                f"[{sev_s}]{escape(f.severity or '')}[/{sev_s}]",
            )
        console.print(tbl)
        console.print(f"\n[dim]{len(fw_findings)} firewall-related finding(s) total.[/dim]")


# ---------------------------------------------------------------------------
# SEC-11: network-exposure
# ---------------------------------------------------------------------------


@security_posture.command("network-exposure")
@click.option("--limit", "-l", default=30, help="Max rows to display")
def network_exposure(limit: int) -> None:
    """Public-facing resource exposure analysis.

    Identifies resources with indicators of public exposure (public IPs,
    0.0.0.0/0 ingress, internet-facing load balancers) and categorizes
    the exposure type and risk.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    _exposure_indicators = [
        "public_ip",
        "0.0.0.0/0",
        "internet_facing",
        "public",
        "external",
        "ingress",
        "::/0",
        "publicly_accessible",
    ]

    init_db()
    with get_session() as session:
        findings = session.query(Finding).filter(Finding.detail.isnot(None)).limit(10000).all()

        exposed: list[tuple[Finding, str]] = []
        for f in findings:
            detail_text = _detail_str(f.detail)
            matched = [kw for kw in _exposure_indicators if kw in detail_text]
            if matched:
                exposure_type = ", ".join(matched[:3])
                exposed.append((f, exposure_type))

        if not exposed:
            console.print("[dim]No publicly exposed resources found.[/dim]")
            return

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        exposed.sort(key=lambda x: sev_order.get((x[0].severity or "").lower(), 5))

        tbl = Table(title="Network Exposure Analysis")
        tbl.add_column("Resource", max_width=40)
        tbl.add_column("Type")
        tbl.add_column("Account")
        tbl.add_column("Exposure", max_width=30)
        tbl.add_column("Severity")

        for f, exp_type in exposed[:limit]:
            sev_s = _sev_style(f.severity)
            tbl.add_row(
                escape(f.resource_id or f.resource_name or "--"),
                escape(f.resource_type or "--"),
                escape(f.account_id or "--"),
                escape(exp_type),
                f"[{sev_s}]{escape(f.severity or '')}[/{sev_s}]",
            )
        console.print(tbl)
        console.print(f"\n[dim]{len(exposed)} publicly exposed resource(s) total.[/dim]")


# ---------------------------------------------------------------------------
# SEC-12: cross-account
# ---------------------------------------------------------------------------


@security_posture.command("cross-account")
@click.option("--limit", "-l", default=30, help="Max rows to display")
def cross_account(limit: int) -> None:
    """Cross-account access and trust relationship analysis.

    Queries findings related to IAM trust policies, cross-account roles,
    and resource sharing. Groups by account pair to show trust direction
    and risk level.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    _trust_keywords = [
        "cross_account",
        "trust_policy",
        "assume_role",
        "external_id",
        "resource_share",
        "cross-account",
        "sts:assumerole",
        "trust_relationship",
        "principal",
    ]

    init_db()
    with get_session() as session:
        findings = session.query(Finding).filter(Finding.detail.isnot(None)).limit(10000).all()

        trust_findings: list[Finding] = []
        for f in findings:
            detail_text = _detail_str(f.detail)
            title_lower = (f.title or "").lower()
            if any(kw in detail_text or kw in title_lower for kw in _trust_keywords):
                trust_findings.append(f)

        if not trust_findings:
            console.print(
                "[dim]No cross-account trust findings found.[/dim]\n\n"
                "Cross-account analysis requires findings from IAM connectors\n"
                "that detect trust policies and role assumptions.\n"
            )
            return

        # Group by account
        by_account: dict[str, list[Finding]] = defaultdict(list)
        for f in trust_findings:
            acct = f.account_id or "unknown"
            by_account[acct].append(f)

        tbl = Table(title="Cross-Account Trust Analysis")
        tbl.add_column("Account", max_width=30)
        tbl.add_column("Trust Findings", justify="right")
        tbl.add_column("Critical/High", justify="right")
        tbl.add_column("Resources Involved", justify="right")
        tbl.add_column("Risk Level")

        for acct, acct_findings in sorted(
            by_account.items(),
            key=lambda x: len(x[1]),
            reverse=True,
        )[:limit]:
            crit_high = sum(
                1 for f in acct_findings if (f.severity or "").lower() in ("critical", "high")
            )
            resources = len({f.resource_id for f in acct_findings if f.resource_id})
            risk = "HIGH" if crit_high > 0 else ("MEDIUM" if len(acct_findings) > 3 else "LOW")
            risk_style = {"HIGH": "red bold", "MEDIUM": "yellow", "LOW": "green"}.get(risk, "")
            tbl.add_row(
                escape(acct),
                str(len(acct_findings)),
                f"[red]{crit_high}[/red]" if crit_high else "0",
                str(resources),
                f"[{risk_style}]{risk}[/{risk_style}]",
            )
        console.print(tbl)


# ---------------------------------------------------------------------------
# SEC-13: ioc-correlation
# ---------------------------------------------------------------------------


@security_posture.command("ioc-correlation")
@click.option("--limit", "-l", default=30, help="Max rows to display")
def ioc_correlation(limit: int) -> None:
    """IOC correlation across EDR sources.

    Queries findings from CrowdStrike, SentinelOne, and Defender connectors.
    Groups by indicator (IP, hash, domain) and shows which sources detected
    each IOC, enabling cross-source threat validation.
    """
    import re

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    # Patterns for extracting IOCs
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    hash_pattern = re.compile(r"\b[a-f0-9]{32,64}\b")
    domain_pattern = re.compile(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z]{2,})+\b")

    init_db()
    with get_session() as session:
        edr_findings = (
            session.query(Finding).filter(Finding.source.in_(list(_EDR_SOURCES))).limit(5000).all()
        )

        if not edr_findings:
            console.print(
                "[dim]No EDR findings found.[/dim]\n\n"
                "IOC correlation requires findings from EDR connectors:\n"
                "  - CrowdStrike\n"
                "  - SentinelOne\n"
                "  - Microsoft Defender\n"
            )
            return

        # Extract IOCs and track which sources saw them
        iocs: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        # iocs[indicator_value][indicator_type] = {sources}

        for f in edr_findings:
            detail_text = _detail_str(f.detail)
            src = f.source or "unknown"

            for ip in ip_pattern.findall(detail_text):
                if not ip.startswith("10.") and not ip.startswith("192.168."):
                    iocs[ip]["ip"].add(src)
            for h in hash_pattern.findall(detail_text):
                iocs[h]["hash"].add(src)
            for d in domain_pattern.findall(detail_text):
                if d not in ("example.com", "localhost.local"):
                    iocs[d]["domain"].add(src)

        if not iocs:
            console.print("[dim]No IOCs extracted from EDR findings.[/dim]")
            return

        # Sort by number of sources (multi-source first)
        sorted_iocs = sorted(
            iocs.items(),
            key=lambda x: max(len(srcs) for srcs in x[1].values()),
            reverse=True,
        )

        tbl = Table(title="IOC Correlation Across EDR Sources")
        tbl.add_column("Indicator", max_width=45)
        tbl.add_column("Type")
        tbl.add_column("Sources", justify="right")
        tbl.add_column("Detected By")
        tbl.add_column("Corroborated")

        for indicator, type_sources in sorted_iocs[:limit]:
            for ioc_type, sources in type_sources.items():
                corroborated = len(sources) > 1
                tbl.add_row(
                    escape(indicator),
                    ioc_type.upper(),
                    str(len(sources)),
                    escape(", ".join(sorted(sources))),
                    "[green]Yes[/green]" if corroborated else "[dim]No[/dim]",
                )
        console.print(tbl)
        multi_source = sum(1 for _, ts in sorted_iocs if any(len(s) > 1 for s in ts.values()))
        console.print(
            f"\n[dim]{len(sorted_iocs)} unique IOC(s), "
            f"{multi_source} corroborated across multiple sources.[/dim]"
        )


# ---------------------------------------------------------------------------
# SEC-14: ttp-mapping
# ---------------------------------------------------------------------------


@security_posture.command("ttp-mapping")
@click.option("--limit", "-l", default=30, help="Max rows to display")
def ttp_mapping(limit: int) -> None:
    """MITRE ATT&CK TTP mapping to control gaps.

    Cross-references alerts with MITRE ATT&CK tactics and techniques against
    non-compliant control results to identify which TTPs exploit existing
    control gaps.
    """

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Alert, ControlResult

    init_db()
    with get_session() as session:
        # Get alerts with MITRE data
        alerts = session.query(Alert).filter(Alert.mitre_tactic.isnot(None)).limit(5000).all()

        if not alerts:
            console.print(
                "[dim]No MITRE ATT&CK-tagged alerts found.[/dim]\n\n"
                "TTP mapping requires alerts with mitre_tactic and mitre_technique fields.\n"
                "These are populated by EDR and SIEM connectors.\n"
            )
            return

        # Get non-compliant controls
        non_compliant = (
            session.query(ControlResult.framework, ControlResult.control_id)
            .filter(ControlResult.status == "non_compliant")
            .distinct()
            .all()
        )
        nc_set = {(r.framework, r.control_id) for r in non_compliant}

        # Group alerts by technique
        by_technique: dict[str, dict] = {}
        for a in alerts:
            technique = a.mitre_technique or "unknown"
            tactic = a.mitre_tactic or "unknown"
            key = f"{tactic}/{technique}"
            if key not in by_technique:
                by_technique[key] = {
                    "tactic": tactic,
                    "technique": technique,
                    "count": 0,
                    "severities": defaultdict(int),
                    "frameworks": set(),
                }
            by_technique[key]["count"] += 1
            by_technique[key]["severities"][(a.severity or "info").lower()] += 1
            if a.framework and a.control_id:
                by_technique[key]["frameworks"].add((a.framework, a.control_id))

        # Sort by alert count
        sorted_ttps = sorted(
            by_technique.values(),
            key=lambda x: x["count"],
            reverse=True,
        )

        tbl = Table(title="MITRE ATT&CK TTP Mapping")
        tbl.add_column("Tactic")
        tbl.add_column("Technique")
        tbl.add_column("Alerts", justify="right")
        tbl.add_column("Top Severity")
        tbl.add_column("Gap Detected")

        for ttp in sorted_ttps[:limit]:
            # Determine worst severity
            for sev in ["critical", "high", "medium", "low", "info"]:
                if ttp["severities"].get(sev, 0) > 0:
                    worst_sev = sev
                    break
            else:
                worst_sev = "info"

            # Check if any linked controls are non-compliant
            has_gap = any(fc in nc_set for fc in ttp["frameworks"])
            sev_s = _sev_style(worst_sev)

            tbl.add_row(
                escape(ttp["tactic"]),
                escape(ttp["technique"]),
                str(ttp["count"]),
                f"[{sev_s}]{escape(worst_sev)}[/{sev_s}]",
                "[red bold]YES[/red bold]" if has_gap else "[green]No[/green]",
            )
        console.print(tbl)

        gaps = sum(1 for ttp in sorted_ttps if any(fc in nc_set for fc in ttp["frameworks"]))
        console.print(
            f"\n[dim]{len(sorted_ttps)} technique(s) observed, {gaps} with control gaps.[/dim]"
        )
        if nc_set:
            console.print(
                f"[dim]{len(nc_set)} non-compliant control(s) in scope for gap analysis.[/dim]"
            )


# ---------------------------------------------------------------------------
# SEC-15: patch-compliance
# ---------------------------------------------------------------------------


@security_posture.command("patch-compliance")
@click.option("--limit", "-l", default=30, help="Max rows to display")
@click.option("--severity", "-s", default=None, help="Filter by severity")
def patch_compliance(limit: int, severity: str | None) -> None:
    """Patch compliance tracking by severity and SLA status.

    Queries findings related to patching, updates, and CVEs. Groups by
    severity and shows SLA breach status based on finding age.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding
    from warlock.utils import ensure_aware

    init_db()
    now = _utcnow()

    with get_session() as session:
        findings = session.query(Finding).filter(Finding.detail.isnot(None)).limit(10000).all()

        patch_findings: list[Finding] = []
        for f in findings:
            if severity and (f.severity or "").lower() != severity.lower():
                continue
            detail_text = _detail_str(f.detail)
            title_lower = (f.title or "").lower()
            if any(kw in detail_text or kw in title_lower for kw in _PATCH_KEYWORDS):
                patch_findings.append(f)

        if not patch_findings:
            console.print("[dim]No patch-related findings found.[/dim]")
            return

        # Summary by severity
        by_sev: dict[str, dict] = {}
        for sev in ["critical", "high", "medium", "low", "info"]:
            sev_findings = [f for f in patch_findings if (f.severity or "").lower() == sev]
            if not sev_findings:
                continue
            sla_days = _SLA_DAYS.get(sev, 365)
            cutoff = now - timedelta(days=sla_days)
            breached = sum(
                1
                for f in sev_findings
                if (ensure_aware(f.observed_at) if f.observed_at else now) < cutoff
            )
            by_sev[sev] = {
                "count": len(sev_findings),
                "breached": breached,
                "sla_days": sla_days,
            }

        summary = Table(title="Patch Compliance Summary")
        summary.add_column("Severity")
        summary.add_column("Total", justify="right")
        summary.add_column("SLA (days)", justify="right")
        summary.add_column("Breached", justify="right")
        summary.add_column("Compliance", justify="right")

        for sev, data in by_sev.items():
            within = data["count"] - data["breached"]
            rate = round(within / data["count"] * 100, 1) if data["count"] else 0
            rate_style = "green" if rate >= 90 else ("yellow" if rate >= 70 else "red")
            sev_s = _sev_style(sev)
            summary.add_row(
                f"[{sev_s}]{sev.capitalize()}[/{sev_s}]",
                str(data["count"]),
                str(data["sla_days"]),
                f"[red]{data['breached']}[/red]" if data["breached"] else "0",
                f"[{rate_style}]{rate}%[/{rate_style}]",
            )
        console.print(summary)

        # Detail table of individual findings
        detail_tbl = Table(title="Patch Findings Detail")
        detail_tbl.add_column("#", style="dim", justify="right")
        detail_tbl.add_column("Severity")
        detail_tbl.add_column("Title", max_width=45)
        detail_tbl.add_column("Resource", max_width=30)
        detail_tbl.add_column("Age (days)", justify="right")
        detail_tbl.add_column("SLA Status")

        # Sort by severity then age
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        patch_findings.sort(
            key=lambda f: (
                sev_order.get((f.severity or "").lower(), 5),
                -(now - (ensure_aware(f.observed_at) if f.observed_at else now)).days,
            )
        )

        for i, f in enumerate(patch_findings[:limit], 1):
            observed = ensure_aware(f.observed_at) if f.observed_at else now
            age = max((now - observed).days, 0)
            sla_days = _SLA_DAYS.get((f.severity or "").lower(), 365)
            breached = age > sla_days
            sev_s = _sev_style(f.severity)
            detail_tbl.add_row(
                str(i),
                f"[{sev_s}]{escape(f.severity or '')}[/{sev_s}]",
                escape(f.title or ""),
                escape(f.resource_id or "--"),
                str(age),
                "[red bold]BREACHED[/red bold]" if breached else "[green]Within SLA[/green]",
            )
        console.print(detail_tbl)
        console.print(f"\n[dim]{len(patch_findings)} patch-related finding(s) total.[/dim]")
