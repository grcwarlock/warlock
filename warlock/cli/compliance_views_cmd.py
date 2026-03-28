"""Compliance views CLI commands.

Provides cross-cutting compliance posture views: by deployment model,
by org unit, peer benchmarking, finding diffs, usage statistics,
compliance forecasting, multi-cloud posture, ATO health dashboards,
Pareto analysis, AI confidence distribution, platform health, and
common evidence providers.
"""

from __future__ import annotations

import json as _json
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console
from warlock.utils import ensure_aware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _score_pct(compliant: int, total: int) -> float:
    """Return compliance score as a percentage, 0.0 if total is zero."""
    if total == 0:
        return 0.0
    return round(compliant / total * 100, 1)


def _score_style(score: float) -> str:
    """Return Rich colour tag for a compliance score."""
    if score >= 80:
        return "green"
    if score >= 60:
        return "yellow"
    return "red"


def _format_output(data: list[dict], fmt: str, table: Table) -> None:
    """Print either a Rich table or JSON depending on format flag."""
    if fmt == "json":
        console.print_json(_json.dumps(data, default=str))
    else:
        console.print(table)


def _deployment_bucket(resource_type: str | None) -> str:
    """Categorise a resource_type into a deployment model."""
    if not resource_type:
        return "unknown"
    rt = resource_type.lower()
    cloud_keywords = (
        "ec2",
        "s3",
        "lambda",
        "rds",
        "azure",
        "gcp",
        "cloud",
        "iam",
        "vpc",
        "eks",
        "ecs",
        "fargate",
        "sqs",
        "sns",
        "dynamodb",
        "kinesis",
        "redshift",
        "elasticache",
    )
    onprem_keywords = (
        "server",
        "workstation",
        "dc_",
        "ad_",
        "ldap",
        "on_prem",
        "datacenter",
        "vmware",
        "hyperv",
    )
    for kw in cloud_keywords:
        if kw in rt:
            return "cloud"
    for kw in onprem_keywords:
        if kw in rt:
            return "on-premise"
    return "hybrid"


def _cloud_bucket(provider: str | None) -> str:
    """Map a provider string to a cloud platform."""
    if not provider:
        return "unknown"
    p = provider.lower()
    if "aws" in p or "amazon" in p:
        return "AWS"
    if "azure" in p or "microsoft" in p:
        return "Azure"
    if "gcp" in p or "google" in p:
        return "GCP"
    return provider


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@cli.group("compliance-views", invoke_without_command=True)
@click.pass_context
def compliance_views(ctx: click.Context) -> None:
    """Cross-cutting compliance posture views and analytics."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# CPV-1: by-deployment
# ---------------------------------------------------------------------------


@compliance_views.command("by-deployment")
@click.option("--framework", default=None, help="Filter to a specific framework.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def by_deployment(framework: str | None, fmt: str) -> None:
    """Compliance posture grouped by deployment model (cloud/on-premise/hybrid)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding

    init_db()
    with get_session() as session:
        query = session.query(
            Finding.resource_type,
            ControlResult.framework,
            ControlResult.status,
        ).join(Finding, ControlResult.finding_id == Finding.id)
        if framework:
            query = query.filter(ControlResult.framework == framework)

        rows = query.limit(500_000).all()

    if not rows:
        console.print("[dim]No control results found.[/dim]")
        return

    # Aggregate: (deployment_model, framework) -> {total, compliant, non_compliant}
    agg: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"total": 0, "compliant": 0, "non_compliant": 0}
    )
    for resource_type, fw, status in rows:
        bucket = _deployment_bucket(resource_type)
        key = (bucket, fw)
        agg[key]["total"] += 1
        if status == "compliant":
            agg[key]["compliant"] += 1
        elif status == "non_compliant":
            agg[key]["non_compliant"] += 1

    table = Table(title="Compliance by Deployment Model")
    table.add_column("Deployment", style="bold")
    table.add_column("Framework")
    table.add_column("Total", justify="right")
    table.add_column("Compliant", justify="right", style="green")
    table.add_column("Non-Compliant", justify="right", style="red")
    table.add_column("Score %", justify="right")

    data: list[dict] = []
    for (dep, fw), counts in sorted(agg.items()):
        score = _score_pct(counts["compliant"], counts["total"])
        table.add_row(
            escape(dep),
            escape(fw),
            str(counts["total"]),
            str(counts["compliant"]),
            str(counts["non_compliant"]),
            f"[{_score_style(score)}]{score}%[/{_score_style(score)}]",
        )
        data.append(
            {
                "deployment_model": dep,
                "framework": fw,
                **counts,
                "score_pct": score,
            }
        )

    _format_output(data, fmt, table)


# ---------------------------------------------------------------------------
# CPV-2: by-org-unit
# ---------------------------------------------------------------------------


@compliance_views.command("by-org-unit")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def by_org_unit(fmt: str) -> None:
    """Compliance posture by organizational unit (system profile)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, SystemProfile

    init_db()
    with get_session() as session:
        query = (
            session.query(
                SystemProfile.name,
                ControlResult.framework,
                ControlResult.status,
            )
            .join(SystemProfile, ControlResult.system_profile_id == SystemProfile.id)
            .limit(500_000)
        )
        rows = query.all()

    if not rows:
        console.print("[dim]No control results linked to system profiles found.[/dim]")
        return

    agg: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"controls": 0, "compliant": 0}
    )
    for sys_name, fw, status in rows:
        key = (sys_name or "Unassigned", fw)
        agg[key]["controls"] += 1
        if status == "compliant":
            agg[key]["compliant"] += 1

    table = Table(title="Compliance by Org Unit / System")
    table.add_column("Org Unit", style="bold")
    table.add_column("Framework")
    table.add_column("Controls", justify="right")
    table.add_column("Compliant", justify="right", style="green")
    table.add_column("Score %", justify="right")

    data: list[dict] = []
    for (unit, fw), counts in sorted(agg.items()):
        score = _score_pct(counts["compliant"], counts["controls"])
        table.add_row(
            escape(unit),
            escape(fw),
            str(counts["controls"]),
            str(counts["compliant"]),
            f"[{_score_style(score)}]{score}%[/{_score_style(score)}]",
        )
        data.append(
            {
                "org_unit": unit,
                "framework": fw,
                **counts,
                "score_pct": score,
            }
        )

    _format_output(data, fmt, table)


# ---------------------------------------------------------------------------
# CPV-3: peer-benchmark
# ---------------------------------------------------------------------------

_INDUSTRY_BENCHMARKS: dict[str, float] = {
    "healthcare": 72.0,
    "finance": 81.0,
    "tech": 68.0,
    "government": 75.0,
    "retail": 65.0,
}


@compliance_views.command("peer-benchmark")
@click.option(
    "--industry",
    type=click.Choice(list(_INDUSTRY_BENCHMARKS.keys())),
    default="tech",
    help="Industry vertical for comparison.",
)
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def peer_benchmark(industry: str, fmt: str) -> None:
    """Compare your compliance score against anonymized industry benchmarks."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        total = session.query(ControlResult).limit(500_000).count()
        compliant = (
            session.query(ControlResult)
            .filter(ControlResult.status == "compliant")
            .limit(500_000)
            .count()
        )

    org_score = _score_pct(compliant, total)
    bench = _INDUSTRY_BENCHMARKS[industry]
    delta = round(org_score - bench, 1)
    delta_style = "green" if delta >= 0 else "red"

    # STUB-026: Clearly label benchmarks as simulated
    table = Table(title="Peer Benchmark Comparison (SIMULATED)")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row(
        "Your Score", f"[{_score_style(org_score)}]{org_score}%[/{_score_style(org_score)}]"
    )
    table.add_row(f"Industry Avg ({escape(industry)})", f"{bench}%")
    table.add_row("Delta", f"[{delta_style}]{'+' if delta >= 0 else ''}{delta}%[/{delta_style}]")
    table.add_row("Total Controls Assessed", str(total))
    table.add_row("Compliant Controls", str(compliant))

    table.add_section()
    table.add_row("[dim]All Benchmarks (simulated)[/dim]", "")
    for ind, avg in sorted(_INDUSTRY_BENCHMARKS.items()):
        marker = " <-- you" if ind == industry else ""
        table.add_row(f"  {escape(ind)}", f"{avg}%{marker}")

    table.add_section()
    table.add_row(
        "[dim italic]Note[/dim italic]",
        "[dim italic]Benchmarks are simulated from static industry averages, "
        "not sourced from real peer data.[/dim italic]",
    )

    data = [
        {
            "org_score": org_score,
            "industry": industry,
            "industry_avg": bench,
            "delta": delta,
            "total_assessed": total,
            "compliant": compliant,
            "benchmarks": _INDUSTRY_BENCHMARKS,
            "simulated": True,
        }
    ]
    _format_output(data, fmt, table)


# ---------------------------------------------------------------------------
# CPV-4: cato-dashboard (ATO health per system)
# ---------------------------------------------------------------------------


@compliance_views.command("cato-dashboard")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def cato_dashboard(fmt: str) -> None:
    """Real-time ATO health dashboard per system profile."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import PostureSnapshot, SystemProfile

    init_db()
    with get_session() as session:
        profiles = (
            session.query(SystemProfile).filter(SystemProfile.is_active.is_(True)).limit(1000).all()
        )
        if not profiles:
            console.print("[dim]No system profiles found.[/dim]")
            return

        profile_data = []
        for p in profiles:
            snapshots = (
                session.query(PostureSnapshot)
                .filter(PostureSnapshot.system_profile_id == p.id)
                .order_by(PostureSnapshot.snapshot_date.desc())
                .limit(500)
                .all()
            )
            total = len(snapshots)
            compliant_count = sum(1 for s in snapshots if s.status == "compliant")
            score = _score_pct(compliant_count, total)
            auth_status = p.authorization_status or "not_authorized"
            auth_expiry = ensure_aware(p.authorization_expiry) if p.authorization_expiry else None
            days_to_expiry = None
            if auth_expiry:
                days_to_expiry = (auth_expiry - _utcnow()).days

            profile_data.append(
                {
                    "name": p.name,
                    "acronym": p.acronym or "",
                    "auth_status": auth_status,
                    "score": score,
                    "total_controls": total,
                    "days_to_expiry": days_to_expiry,
                    "deployment_model": p.deployment_model or "unknown",
                }
            )

    table = Table(title="cATO Health Dashboard")
    table.add_column("System", style="bold")
    table.add_column("Acronym")
    table.add_column("Auth Status")
    table.add_column("Score %", justify="right")
    table.add_column("Controls", justify="right")
    table.add_column("Days to Expiry", justify="right")
    table.add_column("Deployment")

    for pd in sorted(profile_data, key=lambda x: x["score"]):
        auth_style = "green" if pd["auth_status"] == "authorized" else "yellow"
        expiry_str = str(pd["days_to_expiry"]) if pd["days_to_expiry"] is not None else "N/A"
        expiry_style = ""
        if pd["days_to_expiry"] is not None and pd["days_to_expiry"] < 90:
            expiry_style = "red"
        table.add_row(
            escape(pd["name"]),
            escape(pd["acronym"]),
            f"[{auth_style}]{escape(pd['auth_status'])}[/{auth_style}]",
            f"[{_score_style(pd['score'])}]{pd['score']}%[/{_score_style(pd['score'])}]",
            str(pd["total_controls"]),
            f"[{expiry_style}]{expiry_str}[/{expiry_style}]" if expiry_style else expiry_str,
            escape(pd["deployment_model"]),
        )

    _format_output(profile_data, fmt, table)


# ---------------------------------------------------------------------------
# CPV-5: pareto (top failure control families)
# ---------------------------------------------------------------------------


@compliance_views.command("pareto")
@click.option("--top", default=20, help="Number of top families to show.")
@click.option("--framework", default=None, help="Filter to a specific framework.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def pareto(top: int, framework: str | None, fmt: str) -> None:
    """Pareto analysis: top control families causing the most failures."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        query = session.query(
            ControlResult.framework,
            ControlResult.control_id,
        ).filter(ControlResult.status == "non_compliant")
        if framework:
            query = query.filter(ControlResult.framework == framework)
        rows = query.limit(500_000).all()

    if not rows:
        console.print("[dim]No non-compliant control results found.[/dim]")
        return

    # Group by control family (prefix before the dot or dash)
    family_counts: Counter[tuple[str, str]] = Counter()
    for fw, ctrl_id in rows:
        # Extract family: "AC-2" -> "AC", "CC6.1" -> "CC6", "A.9.2.1" -> "A.9"
        parts = ctrl_id.split("-", 1)
        if len(parts) > 1:
            family = parts[0]
        else:
            dot_parts = ctrl_id.split(".", 2)
            family = ".".join(dot_parts[:2]) if len(dot_parts) > 2 else dot_parts[0]
        family_counts[(fw, family)] += 1

    total_failures = sum(family_counts.values())
    sorted_families = family_counts.most_common(top)

    table = Table(title=f"Top {top} Failure Families (Pareto)")
    table.add_column("Rank", justify="right")
    table.add_column("Framework")
    table.add_column("Family", style="bold")
    table.add_column("Failures", justify="right", style="red")
    table.add_column("% of Total", justify="right")
    table.add_column("Cumulative %", justify="right")

    data: list[dict] = []
    cumulative = 0.0
    for rank, ((fw, family), count) in enumerate(sorted_families, 1):
        pct = round(count / total_failures * 100, 1)
        cumulative += pct
        table.add_row(
            str(rank),
            escape(fw),
            escape(family),
            str(count),
            f"{pct}%",
            f"{round(cumulative, 1)}%",
        )
        data.append(
            {
                "rank": rank,
                "framework": fw,
                "family": family,
                "failures": count,
                "pct": pct,
                "cumulative_pct": round(cumulative, 1),
            }
        )

    _format_output(data, fmt, table)


# ---------------------------------------------------------------------------
# CPV-6: finding-diff
# ---------------------------------------------------------------------------


@compliance_views.command("finding-diff")
@click.option("--resource-id", required=True, help="Resource identifier to diff.")
@click.option("--source", default=None, help="Filter to a specific source.")
@click.option("--limit", "max_rows", default=100, help="Max findings to compare.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def finding_diff(resource_id: str, source: str | None, max_rows: int, fmt: str) -> None:
    """Show what changed between consecutive scans for a resource."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        query = (
            session.query(Finding)
            .filter(Finding.resource_id == resource_id)
            .order_by(Finding.observed_at.asc())
        )
        if source:
            query = query.filter(Finding.source == source)
        findings = query.limit(max_rows).all()

    if not findings:
        console.print(f"[dim]No findings for resource {escape(resource_id)}.[/dim]")
        return

    # Group findings by connector_run (via raw_event)
    run_groups: dict[str, list] = defaultdict(list)
    for f in findings:
        run_id = f.raw_event_id  # proxy for scan grouping
        run_groups[run_id].append(f)

    if len(run_groups) < 2:
        console.print("[dim]Only one scan found -- need at least two to diff.[/dim]")
        # Show the single scan's findings
        table = Table(title=f"Findings for {escape(resource_id)} (single scan)")
        table.add_column("ID", style="dim")
        table.add_column("Title")
        table.add_column("Severity")
        table.add_column("Observed At")
        for f in findings:
            obs = ensure_aware(f.observed_at) if f.observed_at else None
            table.add_row(
                f.id[:8],
                escape(f.title or ""),
                f.severity,
                str(obs) if obs else "N/A",
            )
        console.print(table)
        return

    # Compare last two scan groups
    run_ids = sorted(
        run_groups.keys(),
        key=lambda rid: min(
            ensure_aware(f.observed_at) if f.observed_at else _utcnow() for f in run_groups[rid]
        ),
    )
    prev_run = run_ids[-2]
    curr_run = run_ids[-1]

    prev_titles = {f.title for f in run_groups[prev_run]}
    curr_titles = {f.title for f in run_groups[curr_run]}

    added = curr_titles - prev_titles
    removed = prev_titles - curr_titles
    unchanged = prev_titles & curr_titles

    table = Table(title=f"Finding Diff for {escape(resource_id)}")
    table.add_column("Status", style="bold")
    table.add_column("Finding")
    table.add_column("Severity")

    data: list[dict] = []

    for f in run_groups[curr_run]:
        if f.title in added:
            table.add_row("[green]+ ADDED[/green]", escape(f.title or ""), f.severity)
            data.append({"status": "added", "title": f.title, "severity": f.severity})

    for f in run_groups[prev_run]:
        if f.title in removed:
            table.add_row("[red]- REMOVED[/red]", escape(f.title or ""), f.severity)
            data.append({"status": "removed", "title": f.title, "severity": f.severity})

    for title in sorted(unchanged):
        table.add_row("[dim]= UNCHANGED[/dim]", escape(title), "")
        data.append({"status": "unchanged", "title": title, "severity": ""})

    summary = f"  Added: {len(added)}  |  Removed: {len(removed)}  |  Unchanged: {len(unchanged)}"
    _format_output(data, fmt, table)
    if fmt == "table":
        console.print(summary)


# ---------------------------------------------------------------------------
# CPV-7: ai-confidence
# ---------------------------------------------------------------------------


@compliance_views.command("ai-confidence")
@click.option("--buckets", default=10, help="Number of histogram buckets.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def ai_confidence(buckets: int, fmt: str) -> None:
    """AI confidence distribution across control results."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        rows = (
            session.query(ControlResult.ai_confidence)
            .filter(ControlResult.ai_confidence.isnot(None))
            .limit(500_000)
            .all()
        )

    if not rows:
        console.print("[dim]No AI-assessed control results found.[/dim]")
        return

    values = [r[0] for r in rows if r[0] is not None]
    if not values:
        console.print("[dim]No AI confidence values available.[/dim]")
        return

    bucket_size = 1.0 / buckets
    histogram: dict[int, int] = defaultdict(int)
    for v in values:
        idx = min(int(v / bucket_size), buckets - 1)
        histogram[idx] += 1

    avg_conf = sum(values) / len(values)
    median_conf = sorted(values)[len(values) // 2]

    table = Table(title="AI Confidence Distribution")
    table.add_column("Range", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Bar")
    table.add_column("% of Total", justify="right")

    max_count = max(histogram.values()) if histogram else 1
    data: list[dict] = []
    for i in range(buckets):
        lo = round(i * bucket_size, 2)
        hi = round((i + 1) * bucket_size, 2)
        count = histogram.get(i, 0)
        pct = round(count / len(values) * 100, 1)
        bar_len = int(count / max_count * 30) if max_count > 0 else 0
        bar_char = "#" * bar_len
        style = "green" if lo >= 0.7 else ("yellow" if lo >= 0.4 else "red")
        table.add_row(
            f"{lo:.2f}-{hi:.2f}",
            str(count),
            f"[{style}]{bar_char}[/{style}]",
            f"{pct}%",
        )
        data.append({"range_lo": lo, "range_hi": hi, "count": count, "pct": pct})

    _format_output(data, fmt, table)
    if fmt == "table":
        console.print(
            f"\n  Total AI assessments: {len(values)}  |  "
            f"Mean: {avg_conf:.3f}  |  Median: {median_conf:.3f}"
        )


# ---------------------------------------------------------------------------
# CPV-8: platform-health
# ---------------------------------------------------------------------------


@compliance_views.command("platform-health")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def platform_health(fmt: str) -> None:
    """Platform health: connector sync status, error rates, job stats."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, PipelineRun

    init_db()
    now = _utcnow()
    with get_session() as session:
        # Recent connector runs (last 24h)
        cutoff = now - timedelta(hours=24)
        recent_runs = (
            session.query(ConnectorRun)
            .filter(ConnectorRun.started_at >= cutoff)
            .limit(10_000)
            .all()
        )

        total_runs = len(recent_runs)
        success_runs = sum(1 for r in recent_runs if r.status == "success")
        error_runs = sum(1 for r in recent_runs if r.status == "error")
        running_runs = sum(1 for r in recent_runs if r.status == "running")
        total_errors = sum(r.error_count or 0 for r in recent_runs)

        # Last connector run time
        last_run = session.query(ConnectorRun).order_by(ConnectorRun.started_at.desc()).first()
        last_run_at = (
            ensure_aware(last_run.started_at) if last_run and last_run.started_at else None
        )

        # Pipeline runs (last 7 days)
        week_cutoff = now - timedelta(days=7)
        pipeline_runs = (
            session.query(PipelineRun)
            .filter(PipelineRun.started_at >= week_cutoff)
            .limit(1_000)
            .all()
        )
        pipeline_completed = sum(1 for r in pipeline_runs if r.status == "completed")
        pipeline_failed = sum(1 for r in pipeline_runs if r.status == "failed")

    table = Table(title="Platform Health (Last 24h)")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    health_data = {
        "connector_runs_24h": total_runs,
        "connector_success": success_runs,
        "connector_errors": error_runs,
        "connector_running": running_runs,
        "total_error_count": total_errors,
        "last_connector_run": str(last_run_at) if last_run_at else "never",
        "pipeline_runs_7d": len(pipeline_runs),
        "pipeline_completed": pipeline_completed,
        "pipeline_failed": pipeline_failed,
    }

    error_style = "red" if error_runs > 0 else "green"
    table.add_row("Connector Runs (24h)", str(total_runs))
    table.add_row("  Successful", f"[green]{success_runs}[/green]")
    table.add_row("  Errors", f"[{error_style}]{error_runs}[/{error_style}]")
    table.add_row("  Running", str(running_runs))
    table.add_row("  Total Error Count", str(total_errors))
    if last_run_at:
        age_min = int((now - last_run_at).total_seconds() / 60)
        table.add_row("Last Connector Run", f"{age_min} min ago")
    else:
        table.add_row("Last Connector Run", "[dim]never[/dim]")
    table.add_section()
    table.add_row("Pipeline Runs (7d)", str(len(pipeline_runs)))
    table.add_row("  Completed", f"[green]{pipeline_completed}[/green]")
    pipe_err_style = "red" if pipeline_failed > 0 else "green"
    table.add_row("  Failed", f"[{pipe_err_style}]{pipeline_failed}[/{pipe_err_style}]")

    _format_output([health_data], fmt, table)


# ---------------------------------------------------------------------------
# CPV-9: usage-stats
# ---------------------------------------------------------------------------


@compliance_views.command("usage-stats")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def usage_stats(fmt: str) -> None:
    """Platform usage statistics: users, keys, audit entries, findings, controls."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        APIKey,
        AuditEntry,
        ControlResult,
        Finding,
        PipelineRun,
        User,
    )

    init_db()
    with get_session() as session:
        user_count = session.query(User).limit(100_000).count()
        api_key_count = session.query(APIKey).limit(100_000).count()
        audit_count = session.query(AuditEntry).limit(500_000).count()
        pipeline_count = session.query(PipelineRun).limit(100_000).count()
        finding_count = session.query(Finding).limit(500_000).count()
        control_count = session.query(ControlResult).limit(500_000).count()

    table = Table(title="Platform Usage Statistics")
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")

    stats = {
        "users": user_count,
        "api_keys": api_key_count,
        "audit_entries": audit_count,
        "pipeline_runs": pipeline_count,
        "findings": finding_count,
        "control_results": control_count,
    }

    table.add_row("Users", f"{user_count:,}")
    table.add_row("API Keys", f"{api_key_count:,}")
    table.add_row("Audit Trail Entries", f"{audit_count:,}")
    table.add_row("Pipeline Runs", f"{pipeline_count:,}")
    table.add_row("Findings", f"{finding_count:,}")
    table.add_row("Control Results", f"{control_count:,}")

    _format_output([stats], fmt, table)


# ---------------------------------------------------------------------------
# CPV-10: forecast
# ---------------------------------------------------------------------------


@compliance_views.command("forecast")
@click.option("--framework", default=None, help="Framework to forecast.")
@click.option(
    "--target-score", default=90.0, type=float, help="Target compliance score (default 90%)."
)
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def forecast_cmd(framework: str | None, target_score: float, fmt: str) -> None:
    """Project when remediation velocity achieves target compliance score."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Issue

    init_db()
    now = _utcnow()
    with get_session() as session:
        # Current compliance score
        cr_query = session.query(ControlResult)
        if framework:
            cr_query = cr_query.filter(ControlResult.framework == framework)
        total = cr_query.limit(500_000).count()
        compliant = cr_query.filter(ControlResult.status == "compliant").limit(500_000).count()
        non_compliant = (
            cr_query.filter(ControlResult.status == "non_compliant").limit(500_000).count()
        )

        # Remediation velocity: issues closed in last 90 days
        lookback = now - timedelta(days=90)
        closed_issues = (
            session.query(Issue)
            .filter(
                Issue.status.in_(["closed", "verified", "remediated"]),
                Issue.closed_at >= lookback,
            )
            .limit(100_000)
            .all()
        )

    current_score = _score_pct(compliant, total)

    if current_score >= target_score:
        console.print(
            f"[green]Already at target! Current score: {current_score}% "
            f"(target: {target_score}%)[/green]"
        )
        return

    # Calculate remediation rate (issues closed per day over 90 days)
    closed_count = len(closed_issues)
    daily_rate = closed_count / 90.0 if closed_count > 0 else 0.0

    if daily_rate == 0:
        console.print(
            "[yellow]No closed issues in last 90 days -- cannot project velocity.[/yellow]"
        )
        console.print(f"  Current score: {current_score}% | Target: {target_score}%")
        console.print(f"  Non-compliant controls: {non_compliant:,}")
        return

    # How many more controls need to become compliant
    needed_compliant = math.ceil(target_score / 100.0 * total) - compliant
    if needed_compliant <= 0:
        needed_compliant = 1

    days_to_target = math.ceil(needed_compliant / daily_rate)
    if days_to_target > 3650:
        console.print("[yellow]At current velocity, target is >10 years away.[/yellow]")
        return
    projected_date = now + timedelta(days=days_to_target)

    table = Table(title="Compliance Forecast")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    fw_label = framework or "all frameworks"
    table.add_row("Framework", escape(fw_label))
    table.add_row(
        "Current Score",
        f"[{_score_style(current_score)}]{current_score}%[/{_score_style(current_score)}]",
    )
    table.add_row("Target Score", f"{target_score}%")
    table.add_row("Total Controls", f"{total:,}")
    table.add_row("Currently Compliant", f"{compliant:,}")
    table.add_row("Non-Compliant", f"[red]{non_compliant:,}[/red]")
    table.add_row("Controls Needed", f"{needed_compliant:,}")
    table.add_section()
    table.add_row("Remediation Rate", f"{daily_rate:.1f} issues/day")
    table.add_row("Issues Closed (90d)", str(closed_count))
    table.add_row("Projected Days to Target", str(days_to_target))
    table.add_row("Projected Date", projected_date.strftime("%Y-%m-%d"))

    data = [
        {
            "framework": fw_label,
            "current_score": current_score,
            "target_score": target_score,
            "total_controls": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "controls_needed": needed_compliant,
            "daily_remediation_rate": round(daily_rate, 2),
            "issues_closed_90d": closed_count,
            "projected_days": days_to_target,
            "projected_date": projected_date.strftime("%Y-%m-%d"),
        }
    ]
    _format_output(data, fmt, table)


# ---------------------------------------------------------------------------
# CPV-11: multi-cloud
# ---------------------------------------------------------------------------


@compliance_views.command("multi-cloud")
@click.option("--framework", default=None, help="Filter to a specific framework.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def multi_cloud(framework: str | None, fmt: str) -> None:
    """Unified compliance posture across all sources (cloud, SaaS, on-prem)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding

    init_db()
    with get_session() as session:
        query = session.query(
            Finding.provider,
            ControlResult.status,
        ).join(Finding, ControlResult.finding_id == Finding.id)
        if framework:
            query = query.filter(ControlResult.framework == framework)
        rows = query.limit(500_000).all()

    if not rows:
        console.print("[dim]No control results found.[/dim]")
        return

    agg: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "compliant": 0, "non_compliant": 0}
    )
    for provider, status in rows:
        cloud = _cloud_bucket(provider)
        agg[cloud]["total"] += 1
        if status == "compliant":
            agg[cloud]["compliant"] += 1
        elif status == "non_compliant":
            agg[cloud]["non_compliant"] += 1

    table = Table(title="Multi-Source Compliance Posture")
    table.add_column("Source", style="bold")
    table.add_column("Total", justify="right")
    table.add_column("Compliant", justify="right", style="green")
    table.add_column("Non-Compliant", justify="right", style="red")
    table.add_column("Score %", justify="right")

    data: list[dict] = []
    for cloud, counts in sorted(agg.items()):
        score = _score_pct(counts["compliant"], counts["total"])
        table.add_row(
            escape(cloud),
            str(counts["total"]),
            str(counts["compliant"]),
            str(counts["non_compliant"]),
            f"[{_score_style(score)}]{score}%[/{_score_style(score)}]",
        )
        data.append({"source": cloud, **counts, "score_pct": score})

    _format_output(data, fmt, table)


# ---------------------------------------------------------------------------
# CPV-12: common-providers
# ---------------------------------------------------------------------------


@compliance_views.command("common-providers")
@click.option("--top", default=20, help="Number of top providers to show.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def common_providers(top: int, fmt: str) -> None:
    """Identify evidence sources providing coverage across the most frameworks."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding

    init_db()
    with get_session() as session:
        rows = (
            session.query(Finding.source, Finding.provider, ControlResult.framework)
            .join(Finding, ControlResult.finding_id == Finding.id)
            .distinct()
            .limit(100_000)
            .all()
        )

    if not rows:
        console.print("[dim]No control result evidence found.[/dim]")
        return

    # Map (source, provider) -> set of frameworks
    provider_frameworks: dict[tuple[str, str], set[str]] = defaultdict(set)
    for source, provider, fw in rows:
        provider_frameworks[(source, provider)].add(fw)

    sorted_providers = sorted(
        provider_frameworks.items(),
        key=lambda x: len(x[1]),
        reverse=True,
    )[:top]

    table = Table(title=f"Top {top} Evidence Providers by Framework Coverage")
    table.add_column("Rank", justify="right")
    table.add_column("Source", style="bold")
    table.add_column("Provider")
    table.add_column("Frameworks", justify="right")
    table.add_column("Framework List")

    data: list[dict] = []
    for rank, ((source, provider), frameworks) in enumerate(sorted_providers, 1):
        fw_list = ", ".join(sorted(frameworks))
        table.add_row(
            str(rank),
            escape(source),
            escape(provider),
            str(len(frameworks)),
            escape(fw_list),
        )
        data.append(
            {
                "rank": rank,
                "source": source,
                "provider": provider,
                "framework_count": len(frameworks),
                "frameworks": sorted(frameworks),
            }
        )

    _format_output(data, fmt, table)
