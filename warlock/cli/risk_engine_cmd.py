"""Risk quantification engine commands: risk-engine group with quantify, simulate,
aggregate, trend, heatmap, top-risks, exposure, and nested register/appetite/treatment
sub-groups.

Uses RiskAnalysis, Finding, ControlResult, and AuditEntry models. Risk register,
appetite, and treatment records are stored as AuditEntry rows with
entity_type in {"risk_register", "risk_appetite", "risk_treatment"}.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import _error, _get_actor, cli, console

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_style(severity: str) -> str:
    return {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "dim",
    }.get(severity.lower(), "")


def _status_style(status: str) -> str:
    return {
        "active": "cyan",
        "mitigated": "green",
        "accepted": "magenta",
        "open": "yellow",
        "closed": "dim",
        "transferred": "blue",
    }.get(status.lower(), "")


def _fmt_dollars(value: float | None) -> str:
    if value is None:
        return "\u2014"
    return f"${value:,.0f}"


def _store_record(
    session,
    entity_type: str,
    action: str,
    record_id: str,
    payload: dict,
    actor: str,
) -> None:
    """Persist a risk register / appetite / treatment record as an AuditEntry."""
    import hashlib

    from warlock.db.models import AuditEntry

    blob = json.dumps(payload, sort_keys=True, default=str).encode()
    evidence_sha256 = hashlib.sha256(blob).hexdigest()

    last = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
    prev_hash = last.entry_hash if last else "genesis"
    sequence = (last.sequence + 1) if last else 1

    chain_blob = f"{prev_hash}{sequence}{action}{entity_type}{record_id}{actor}".encode()
    entry_hash = hashlib.sha256(chain_blob).hexdigest()

    entry = AuditEntry(
        id=str(uuid.uuid4()),
        sequence=sequence,
        previous_hash=prev_hash,
        entry_hash=entry_hash,
        action=action,
        entity_type=entity_type,
        entity_id=record_id,
        actor=actor,
        evidence_sha256=evidence_sha256,
        extra=payload,
    )
    session.add(entry)
    session.commit()


def _load_records(session, entity_type: str) -> list[dict]:
    """Load risk records stored as AuditEntry rows for a given entity_type."""
    from warlock.db.models import AuditEntry

    rows = (
        session.query(AuditEntry)
        .filter(AuditEntry.entity_type == entity_type)
        .order_by(AuditEntry.created_at)
        .all()
    )
    # Group by entity_id, keep last write per record_id
    records: dict[str, dict] = {}
    for row in rows:
        rid = row.entity_id
        extra = row.extra or {}
        extra["_id"] = rid
        extra["_created_at"] = row.created_at
        if row.action == "deleted":
            records.pop(rid, None)
        else:
            records[rid] = extra
    return list(records.values())


# ---------------------------------------------------------------------------
# risk-engine group
# ---------------------------------------------------------------------------


@cli.group("risk-engine", invoke_without_command=True)
@click.pass_context
def risk_engine(ctx: click.Context) -> None:
    """Risk quantification engine: FAIR analysis, Monte Carlo, register, appetite, treatment."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# Quantification commands
# ---------------------------------------------------------------------------


@risk_engine.command("quantify")
@click.argument("finding_id")
@click.option(
    "--method",
    type=click.Choice(["fair", "qualitative"]),
    default="fair",
    show_default=True,
    help="Quantification method",
)
def quantify(finding_id: str, method: str) -> None:
    """Estimate risk in dollar terms for a single finding.

    FINDING_ID may be a full UUID or a prefix (first 8 chars).
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding

    init_db()
    with get_session() as session:
        finding = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not finding:
            _error(f"Finding not found: {finding_id}")

        # Pull the latest control result for context
        result = (
            session.query(ControlResult)
            .filter(ControlResult.finding_id == finding.id)
            .order_by(ControlResult.assessed_at.desc())
            .first()
        )

        severity = finding.severity.lower()
        # FAIR-style dollar estimates by severity tier
        fair_estimates: dict[str, tuple[float, float, float]] = {
            "critical": (850_000.0, 2_500_000.0, 8_000_000.0),
            "high": (150_000.0, 500_000.0, 1_500_000.0),
            "medium": (25_000.0, 80_000.0, 250_000.0),
            "low": (2_000.0, 10_000.0, 40_000.0),
            "info": (0.0, 1_000.0, 5_000.0),
        }
        qualitative_scores: dict[str, str] = {
            "critical": "Extreme (9-10)",
            "high": "High (7-8)",
            "medium": "Moderate (4-6)",
            "low": "Low (1-3)",
            "info": "Negligible (0-1)",
        }

        console.print(f"\n[bold]Risk Quantification \u2014 {finding.id[:8]}[/bold]")
        console.print(f"  Title:    {escape(finding.title[:70] if finding.title else '')}")
        console.print(f"  Severity: [{_severity_style(severity)}]{severity}[/]")
        console.print(f"  Source:   {finding.source} / {finding.provider}")
        console.print(f"  Method:   {method.upper()}")

        if method == "fair":
            low_ale, mean_ale, high_ale = fair_estimates.get(severity, (0.0, 0.0, 0.0))
            console.print("\n  [bold]FAIR Annualized Loss Expectancy[/bold]")
            console.print(f"  Low (10th pct):   {_fmt_dollars(low_ale)}")
            console.print(f"  Mean ALE:         [bold]{_fmt_dollars(mean_ale)}[/bold]")
            console.print(f"  High (90th pct):  {_fmt_dollars(high_ale)}")
        else:
            score = qualitative_scores.get(severity, "Unknown")
            console.print("\n  [bold]Qualitative Risk Score[/bold]")
            console.print(f"  Score: {score}")

        if result:
            status_label = result.status
            console.print(
                f"\n  Latest control: {result.framework} / {result.control_id} \u2014 {status_label}"
            )


@risk_engine.command("quantify-bulk")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high"]),
    default=None,
    help="Filter by severity tier",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    show_default=True,
    help="Output format",
)
def quantify_bulk(framework: str | None, severity: str | None, output_format: str) -> None:
    """Batch FAIR risk quantification across findings portfolio."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding

    init_db()
    fair_estimates: dict[str, tuple[float, float, float]] = {
        "critical": (850_000.0, 2_500_000.0, 8_000_000.0),
        "high": (150_000.0, 500_000.0, 1_500_000.0),
        "medium": (25_000.0, 80_000.0, 250_000.0),
        "low": (2_000.0, 10_000.0, 40_000.0),
        "info": (0.0, 1_000.0, 5_000.0),
    }

    with get_session() as session:
        q = session.query(Finding)
        if severity:
            q = q.filter(Finding.severity == severity)

        if framework:
            # Filter findings that have at least one control result in the given framework
            subq = (
                session.query(ControlResult.finding_id)
                .filter(ControlResult.framework == framework)
                .subquery()
            )
            q = q.filter(Finding.id.in_(subq))

        findings = q.order_by(Finding.severity, Finding.observed_at.desc()).limit(500).all()

    if not findings:
        console.print("[dim]No findings found for the given filters.[/dim]")
        return

    rows_data = []
    for f in findings:
        sev = f.severity.lower()
        low_ale, mean_ale, high_ale = fair_estimates.get(sev, (0.0, 0.0, 0.0))
        rows_data.append(
            {
                "id": f.id[:8],
                "title": f.title[:60],
                "severity": sev,
                "source": f.source,
                "low_ale": low_ale,
                "mean_ale": mean_ale,
                "high_ale": high_ale,
            }
        )

    if output_format in ("json", "csv"):
        if output_format == "csv":
            from warlock.cli.output import render_csv

            render_csv(rows_data, keys=list(rows_data[0].keys()) if rows_data else [])
        else:
            console.print_json(json.dumps(rows_data, default=str))
        return

    table = Table(title=f"Bulk Risk Quantification ({len(rows_data)} findings)")
    table.add_column("ID", max_width=8, style="dim")
    table.add_column("Severity")
    table.add_column("Source", style="dim")
    table.add_column("Low ALE", justify="right")
    table.add_column("Mean ALE", justify="right")
    table.add_column("High ALE", justify="right")
    table.add_column("Title", max_width=45)

    total_mean = 0.0
    for r in rows_data:
        total_mean += r["mean_ale"]
        table.add_row(
            r["id"],
            f"[{_severity_style(r['severity'])}]{r['severity']}[/]",
            r["source"],
            _fmt_dollars(r["low_ale"]),
            _fmt_dollars(r["mean_ale"]),
            _fmt_dollars(r["high_ale"]),
            r["title"],
        )

    console.print(table)
    console.print(f"\n[bold]Total Portfolio Mean ALE:[/bold] {_fmt_dollars(total_mean)}")


@risk_engine.command("simulate")
@click.option("--iterations", "-n", default=10000, show_default=True, help="Monte Carlo iterations")
@click.option(
    "--confidence",
    default=95,
    show_default=True,
    help="Confidence interval percentile (e.g. 95 for 95th pct VaR)",
)
def simulate(iterations: int, confidence: int) -> None:
    """Run Monte Carlo simulation across the full risk portfolio."""
    from warlock.assessors.risk_engine import RiskEngine
    from warlock.db.engine import get_session, init_db

    init_db()
    engine = RiskEngine(default_iterations=iterations)

    console.print(f"[dim]Running Monte Carlo with {iterations:,} iterations...[/dim]")

    with get_session() as session:
        # Discover all active frameworks from ControlResult
        from warlock.db.models import ControlResult

        frameworks = [r[0] for r in session.query(ControlResult.framework).distinct().all()]

        if not frameworks:
            console.print("[dim]No control results found. Run 'warlock collect' first.[/dim]")
            return

        all_scenarios: list[dict] = []
        total_mean_ale = 0.0

        for fw in sorted(frameworks):
            result = engine.analyze_framework_risk(session, fw, iterations=iterations)
            portfolio = result.get("portfolio", {})
            scenarios = result.get("scenarios", [])
            fw_mean = portfolio.get("total_mean_ale", 0.0)
            total_mean_ale += fw_mean
            for s in scenarios:
                s["framework"] = fw
                all_scenarios.append(s)

    if not all_scenarios:
        console.print("[dim]No risk scenarios found.[/dim]")
        return

    table = Table(title=f"Monte Carlo Portfolio Simulation ({iterations:,} iterations)")
    table.add_column("Framework", style="cyan")
    table.add_column("Scenario")
    table.add_column("Mean ALE", justify="right")
    table.add_column(f"VaR {confidence}%", justify="right")
    table.add_column("Control Eff.", justify="right")

    for s in sorted(all_scenarios, key=lambda x: x.get("mean_ale", 0), reverse=True)[:50]:
        # VaR key may be var_95 or var_99 — fall back gracefully
        var_key = f"var_{confidence}"
        var_val = s.get(var_key) or s.get("var_95") or 0.0
        table.add_row(
            s.get("framework", ""),
            s["name"],
            _fmt_dollars(s.get("mean_ale")),
            _fmt_dollars(var_val),
            f"{s.get('control_effectiveness', 0):.0%}",
        )

    console.print(table)
    console.print(f"\n[bold]Portfolio Total Mean ALE:[/bold] {_fmt_dollars(total_mean_ale)}")
    console.print(f"[bold]Frameworks modeled:[/bold]       {len(frameworks)}")
    console.print(f"[bold]Total scenarios:[/bold]          {len(all_scenarios)}")


@risk_engine.command("aggregate")
@click.option(
    "--by",
    "group_by",
    type=click.Choice(["framework", "source", "severity"]),
    default="framework",
    show_default=True,
    help="Aggregation dimension",
)
def aggregate(group_by: str) -> None:
    """Aggregate risk exposure across the portfolio by a chosen dimension."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding

    fair_estimates: dict[str, float] = {
        "critical": 2_500_000.0,
        "high": 500_000.0,
        "medium": 80_000.0,
        "low": 10_000.0,
        "info": 1_000.0,
    }

    init_db()
    with get_session() as session:
        findings = session.query(Finding).all()
        results = session.query(ControlResult).all()
        result_map: dict[str, list[ControlResult]] = {}
        for r in results:
            result_map.setdefault(r.finding_id, []).append(r)

    if not findings:
        console.print("[dim]No findings found.[/dim]")
        return

    buckets: dict[str, dict] = {}
    for f in findings:
        ale = fair_estimates.get(f.severity.lower(), 0.0)
        if group_by == "framework":
            keys = list({r.framework for r in result_map.get(f.id, [])}) or ["unmapped"]
        elif group_by == "source":
            keys = [f.source]
        else:
            keys = [f.severity.lower()]

        for key in keys:
            if key not in buckets:
                buckets[key] = {"count": 0, "total_ale": 0.0}
            buckets[key]["count"] += 1
            buckets[key]["total_ale"] += ale

    table = Table(title=f"Risk Exposure Aggregated by {group_by.capitalize()}")
    table.add_column(group_by.capitalize(), style="cyan")
    table.add_column("Findings", justify="right")
    table.add_column("Total Mean ALE", justify="right")

    for key in sorted(buckets, key=lambda k: buckets[k]["total_ale"], reverse=True):
        b = buckets[key]
        table.add_row(key, str(b["count"]), _fmt_dollars(b["total_ale"]))

    console.print(table)


@risk_engine.command("trend")
@click.option("--days", "-d", default=30, show_default=True, help="Lookback window in days")
def trend(days: int) -> None:
    """Show risk trend over time (findings per day for the past N days)."""
    from datetime import timedelta

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    fair_estimates: dict[str, float] = {
        "critical": 2_500_000.0,
        "high": 500_000.0,
        "medium": 80_000.0,
        "low": 10_000.0,
        "info": 1_000.0,
    }

    with get_session() as session:
        findings = (
            session.query(Finding)
            .filter(Finding.observed_at >= cutoff)
            .order_by(Finding.observed_at)
            .all()
        )

    if not findings:
        console.print(f"[dim]No findings in the past {days} days.[/dim]")
        return

    # Group by date
    by_date: dict[str, dict] = {}
    for f in findings:
        day = f.observed_at.date().isoformat()
        if day not in by_date:
            by_date[day] = {"count": 0, "ale": 0.0, "critical": 0, "high": 0}
        by_date[day]["count"] += 1
        by_date[day]["ale"] += fair_estimates.get(f.severity.lower(), 0.0)
        if f.severity.lower() == "critical":
            by_date[day]["critical"] += 1
        if f.severity.lower() == "high":
            by_date[day]["high"] += 1

    table = Table(title=f"Risk Trend \u2014 Last {days} Days")
    table.add_column("Date", style="cyan")
    table.add_column("Findings", justify="right")
    table.add_column("Critical", justify="right")
    table.add_column("High", justify="right")
    table.add_column("Daily ALE", justify="right")

    for day in sorted(by_date):
        b = by_date[day]
        crit_fmt = f"[red bold]{b['critical']}[/]" if b["critical"] else "0"
        high_fmt = f"[red]{b['high']}[/]" if b["high"] else "0"
        table.add_row(day, str(b["count"]), crit_fmt, high_fmt, _fmt_dollars(b["ale"]))

    console.print(table)


@risk_engine.command("heatmap")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def heatmap(framework: str | None) -> None:
    """Display risk heatmap by likelihood x impact (5x5 grid)."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        records = _load_records(session, "risk_register")

    if framework:
        records = [r for r in records if r.get("framework") == framework]

    if not records:
        console.print(
            "[dim]No risk register entries found. Use 'warlock risk-engine register add'.[/dim]"
        )
        return

    # Build 5x5 grid
    grid: dict[tuple[int, int], int] = {}
    for r in records:
        lh = min(max(int(r.get("likelihood", 3)), 1), 5)
        im = min(max(int(r.get("impact", 3)), 1), 5)
        grid[(lh, im)] = grid.get((lh, im), 0) + 1

    table = Table(title="Risk Heatmap (Likelihood x Impact)")
    table.add_column("Likelihood \\ Impact", style="bold")
    for i in range(1, 6):
        table.add_column(f"Impact {i}", justify="center")

    for lh in range(5, 0, -1):
        row_cells: list[str] = [f"Likelihood {lh}"]
        for im in range(1, 6):
            count = grid.get((lh, im), 0)
            score = lh * im
            if score >= 20:
                color = "red bold"
            elif score >= 12:
                color = "red"
            elif score >= 6:
                color = "yellow"
            else:
                color = "green"
            cell = f"[{color}]{count if count else '.'}[/]"
            row_cells.append(cell)
        table.add_row(*row_cells)

    console.print(table)
    console.print("[dim]Score = Likelihood x Impact. Red=High, Yellow=Medium, Green=Low[/dim]")


@risk_engine.command("top-risks")
@click.option("--limit", "-n", default=10, show_default=True, help="Number of top risks to show")
def top_risks(limit: int) -> None:
    """Show the highest quantified risks from the register."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        records = _load_records(session, "risk_register")

    if not records:
        console.print("[dim]No risk register entries found.[/dim]")
        return

    scored = []
    for r in records:
        lh = int(r.get("likelihood", 3))
        im = int(r.get("impact", 3))
        scored.append((lh * im, r))

    scored.sort(key=lambda x: x[0], reverse=True)

    table = Table(title=f"Top {limit} Risks")
    table.add_column("Score", justify="right", style="bold")
    table.add_column("ID", max_width=8, style="dim")
    table.add_column("Title", max_width=50)
    table.add_column("Category", style="cyan")
    table.add_column("Likelihood", justify="right")
    table.add_column("Impact", justify="right")
    table.add_column("Status")
    table.add_column("Owner", style="dim")

    for score, r in scored[:limit]:
        status = r.get("status", "active")
        table.add_row(
            str(score),
            r.get("_id", "")[:8],
            r.get("title", "")[:50],
            r.get("category", ""),
            str(r.get("likelihood", "")),
            str(r.get("impact", "")),
            f"[{_status_style(status)}]{status}[/]",
            r.get("owner", ""),
        )

    console.print(table)


@risk_engine.command("exposure")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def exposure(framework: str | None) -> None:
    """Show total risk exposure by framework from live control results."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    fair_map: dict[str, float] = {
        "critical": 2_500_000.0,
        "high": 500_000.0,
        "medium": 80_000.0,
        "low": 10_000.0,
        "info": 1_000.0,
    }

    init_db()
    with get_session() as session:
        q = session.query(ControlResult).filter(ControlResult.status == "non_compliant")
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.all()

    if not results:
        console.print("[dim]No non-compliant control results found.[/dim]")
        return

    buckets: dict[str, dict] = {}
    for r in results:
        fw = r.framework
        if fw not in buckets:
            buckets[fw] = {"total": 0, "ale": 0.0}
        buckets[fw]["total"] += 1
        buckets[fw]["ale"] += fair_map.get(r.severity.lower(), 0.0)

    table = Table(title="Risk Exposure by Framework (Non-Compliant Controls)")
    table.add_column("Framework", style="cyan")
    table.add_column("Non-Compliant", justify="right")
    table.add_column("Estimated ALE", justify="right")

    grand_total_ale = 0.0
    for fw in sorted(buckets, key=lambda k: buckets[k]["ale"], reverse=True):
        b = buckets[fw]
        grand_total_ale += b["ale"]
        table.add_row(fw, str(b["total"]), _fmt_dollars(b["ale"]))

    console.print(table)
    console.print(f"\n[bold]Grand Total ALE:[/bold] {_fmt_dollars(grand_total_ale)}")


# ---------------------------------------------------------------------------
# register sub-group
# ---------------------------------------------------------------------------


@risk_engine.group("register", invoke_without_command=True)
@click.pass_context
def register(ctx: click.Context) -> None:
    """Risk register management: list, add, show, update."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@register.command("list")
@click.option(
    "--status",
    "-s",
    type=click.Choice(["active", "mitigated", "accepted"]),
    default=None,
    help="Filter by status",
)
def register_list(status: str | None) -> None:
    """List risk register entries."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        records = _load_records(session, "risk_register")

    if status:
        records = [r for r in records if r.get("status") == status]

    if not records:
        console.print("[dim]No risk register entries found.[/dim]")
        return

    table = Table(title=f"Risk Register ({len(records)} entries)")
    table.add_column("ID", max_width=8, style="dim")
    table.add_column("Title", max_width=45)
    table.add_column("Category", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Likelihood", justify="right")
    table.add_column("Impact", justify="right")
    table.add_column("Status")
    table.add_column("Owner", style="dim")

    for r in sorted(
        records, key=lambda x: int(x.get("likelihood", 3)) * int(x.get("impact", 3)), reverse=True
    ):
        lh = int(r.get("likelihood", 0))
        im = int(r.get("impact", 0))
        score = lh * im
        st = r.get("status", "active")
        table.add_row(
            r.get("_id", "")[:8],
            r.get("title", "")[:45],
            r.get("category", ""),
            str(score),
            str(lh),
            str(im),
            f"[{_status_style(st)}]{st}[/]",
            r.get("owner", ""),
        )

    console.print(table)


@register.command("add")
@click.option("--title", required=True, help="Risk title")
@click.option(
    "--category", required=True, help="Risk category (e.g. operational, compliance, cyber)"
)
@click.option("--likelihood", type=click.IntRange(1, 5), required=True, help="Likelihood score 1-5")
@click.option("--impact", type=click.IntRange(1, 5), required=True, help="Impact score 1-5")
@click.option("--owner", default="unassigned", show_default=True, help="Risk owner (email or name)")
@click.option("--framework", "-f", default=None, help="Associated framework (optional)")
def register_add(
    title: str,
    category: str,
    likelihood: int,
    impact: int,
    owner: str,
    framework: str | None,
) -> None:
    """Add a new entry to the risk register."""
    from warlock.db.engine import get_session, init_db

    init_db()
    actor = _get_actor()
    record_id = str(uuid.uuid4())

    payload: dict = {
        "title": title,
        "category": category,
        "likelihood": likelihood,
        "impact": impact,
        "owner": owner,
        "status": "active",
        "created_by": actor,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if framework:
        payload["framework"] = framework

    with get_session() as session:
        _store_record(session, "risk_register", "created", record_id, payload, actor)

    score = likelihood * impact
    console.print(
        f"[green]Risk registered: {record_id[:8]} \u2014 '{title}' "
        f"(score {score}, owner {owner})[/green]"
    )


@register.command("show")
@click.argument("risk_id")
def register_show(risk_id: str) -> None:
    """Show details for a single risk register entry (RISK_ID prefix or full UUID)."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        records = _load_records(session, "risk_register")

    matches = [r for r in records if r.get("_id", "").startswith(risk_id)]
    if not matches:
        _error(f"Risk not found: {risk_id}")
    r = matches[0]

    from rich.panel import Panel

    lh = int(r.get("likelihood", 0))
    im = int(r.get("impact", 0))
    score = lh * im
    st = r.get("status", "active")
    console.print(
        Panel(
            f"[bold]{r.get('title', '')}[/bold]\n\n"
            f"ID: {r.get('_id', '')[:8]}  |  Category: {r.get('category', '')}  |  "
            f"Framework: {r.get('framework', '\u2014')}\n"
            f"Status: [{_status_style(st)}]{st}[/]  |  Owner: {r.get('owner', '\u2014')}\n"
            f"Likelihood: {lh}/5  |  Impact: {im}/5  |  Score: {score}/25\n"
            f"Created: {r.get('created_at', '\u2014')}",
            title="[bold cyan]Risk Register Entry[/bold cyan]",
            border_style="cyan",
        )
    )


@register.command("update")
@click.argument("risk_id")
@click.option(
    "--status", "-s", type=click.Choice(["active", "mitigated", "accepted"]), default=None
)
@click.option("--likelihood", type=click.IntRange(1, 5), default=None)
@click.option("--impact", type=click.IntRange(1, 5), default=None)
@click.option("--owner", default=None)
def register_update(
    risk_id: str,
    status: str | None,
    likelihood: int | None,
    impact: int | None,
    owner: str | None,
) -> None:
    """Update an existing risk register entry (RISK_ID prefix or full UUID)."""
    from warlock.db.engine import get_session, init_db

    init_db()
    actor = _get_actor()

    with get_session() as session:
        records = _load_records(session, "risk_register")
        matches = [r for r in records if r.get("_id", "").startswith(risk_id)]
        if not matches:
            _error(f"Risk not found: {risk_id}")

        r = matches[0]
        record_id = r["_id"]

        if status:
            r["status"] = status
        if likelihood is not None:
            r["likelihood"] = likelihood
        if impact is not None:
            r["impact"] = impact
        if owner:
            r["owner"] = owner
        r["updated_by"] = actor
        r["updated_at"] = datetime.now(timezone.utc).isoformat()

        _store_record(session, "risk_register", "updated", record_id, r, actor)

    console.print(f"[green]Risk {record_id[:8]} updated.[/green]")


# ---------------------------------------------------------------------------
# appetite sub-group
# ---------------------------------------------------------------------------


@risk_engine.group("appetite", invoke_without_command=True)
@click.pass_context
def appetite(ctx: click.Context) -> None:
    """Risk appetite management: list, set, check."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@appetite.command("list")
def appetite_list() -> None:
    """Show risk appetite thresholds by category."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        records = _load_records(session, "risk_appetite")

    if not records:
        console.print(
            "[dim]No risk appetite thresholds configured. Use 'warlock risk-engine appetite set'.[/dim]"
        )
        return

    table = Table(title="Risk Appetite Thresholds")
    table.add_column("Category", style="cyan")
    table.add_column("Threshold", justify="right")
    table.add_column("Unit")
    table.add_column("Set By", style="dim")
    table.add_column("Set At", style="dim")

    for r in sorted(records, key=lambda x: x.get("category", "")):
        table.add_row(
            r.get("category", ""),
            str(r.get("threshold", "")),
            r.get("unit", "score"),
            r.get("set_by", ""),
            str(r.get("set_at", ""))[:19],
        )

    console.print(table)


@appetite.command("set")
@click.option("--category", required=True, help="Risk category (e.g. operational, cyber)")
@click.option("--threshold", required=True, type=float, help="Appetite threshold value")
@click.option(
    "--unit",
    type=click.Choice(["dollars", "score"]),
    default="score",
    show_default=True,
    help="Threshold unit",
)
def appetite_set(category: str, threshold: float, unit: str) -> None:
    """Set a risk appetite threshold for a category."""
    from warlock.db.engine import get_session, init_db

    init_db()
    actor = _get_actor()

    with get_session() as session:
        # Use category as the stable record_id so upsert semantics apply
        record_id = f"appetite_{category}"
        payload = {
            "category": category,
            "threshold": threshold,
            "unit": unit,
            "set_by": actor,
            "set_at": datetime.now(timezone.utc).isoformat(),
        }
        _store_record(session, "risk_appetite", "set", record_id, payload, actor)

    console.print(f"[green]Risk appetite set: {category} \u2264 {threshold} {unit}[/green]")


@appetite.command("check")
def appetite_check() -> None:
    """Compare current risk exposure against appetite thresholds."""
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        thresholds = _load_records(session, "risk_appetite")
        register_entries = _load_records(session, "risk_register")

    if not thresholds:
        console.print(
            "[dim]No appetite thresholds set. Use 'warlock risk-engine appetite set'.[/dim]"
        )
        return

    # FAIR-style ALE estimates by risk score bracket for dollar/FAIR_ALE comparisons
    _score_to_ale: dict[int, float] = {
        25: 2_500_000.0,
        20: 1_500_000.0,
        15: 500_000.0,
        12: 250_000.0,
        10: 80_000.0,
        6: 40_000.0,
        3: 10_000.0,
        1: 1_000.0,
    }

    def _estimate_ale(score: int) -> float:
        """Map a likelihood*impact score to an estimated ALE dollar value."""
        for threshold_score, ale in sorted(_score_to_ale.items(), reverse=True):
            if score >= threshold_score:
                return ale
        return 0.0

    # Calculate current score-based exposure per category
    cat_scores: dict[str, list[int]] = {}
    for r in register_entries:
        cat = r.get("category", "other")
        score = int(r.get("likelihood", 3)) * int(r.get("impact", 3))
        cat_scores.setdefault(cat, []).append(score)

    table = Table(title="Risk Appetite Check")
    table.add_column("Category", style="cyan")
    table.add_column("Threshold", justify="right")
    table.add_column("Unit")
    table.add_column("Current Exposure", justify="right")
    table.add_column("Status")

    for t in sorted(thresholds, key=lambda x: x.get("category", "")):
        cat = t.get("category", "")
        limit = float(t.get("threshold", 0))
        unit = t.get("unit", "score")
        scores = cat_scores.get(cat, [])
        if unit.lower() in ("fair_ale", "dollar", "dollars", "usd"):
            # Compare estimated ALE values, not raw scores
            ale_values = [_estimate_ale(s) for s in scores]
            current = max(ale_values) if ale_values else 0.0
        else:
            current = max(scores) if scores else 0.0
        within = current <= limit
        status_label = (
            "[green]Within appetite[/green]" if within else "[red bold]EXCEEDS appetite[/red bold]"
        )
        table.add_row(
            cat,
            str(limit),
            unit,
            str(current),
            status_label,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# treatment sub-group
# ---------------------------------------------------------------------------


@risk_engine.group("treatment", invoke_without_command=True)
@click.pass_context
def treatment(ctx: click.Context) -> None:
    """Risk treatment plan management: list, add, update."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@treatment.command("list")
@click.argument("risk_id", required=False, default=None)
def treatment_list(risk_id: str | None) -> None:
    """Show treatment plans for a given risk (RISK_ID prefix or full UUID).

    When RISK_ID is omitted, shows all treatment plans.
    """
    from warlock.db.engine import get_session, init_db

    init_db()
    with get_session() as session:
        records = _load_records(session, "risk_treatment")

    if risk_id is not None:
        treatments = [r for r in records if r.get("risk_id", "").startswith(risk_id)]
    else:
        treatments = records

    if not treatments:
        label = f"risk {risk_id}" if risk_id else "any risk"
        console.print(f"[dim]No treatment plans for {label}.[/dim]")
        return

    title = f"Treatment Plans for Risk {risk_id[:8]}" if risk_id else "All Treatment Plans"
    table = Table(title=title)
    table.add_column("ID", max_width=8, style="dim")
    if risk_id is None:
        table.add_column("Risk ID", max_width=8, style="dim")
    table.add_column("Type", style="cyan")
    table.add_column("Description", max_width=50)
    table.add_column("Owner", style="dim")
    table.add_column("Deadline")
    table.add_column("Status")

    for t in treatments:
        cells = [t.get("_id", "")[:8]]
        if risk_id is None:
            cells.append(t.get("risk_id", "")[:8])
        cells.extend(
            [
                t.get("treatment_type", ""),
                t.get("description", "")[:50],
                t.get("owner", ""),
                t.get("deadline", "\u2014"),
                t.get("status", "planned"),
            ]
        )
        table.add_row(*cells)

    console.print(table)


@treatment.command("add")
@click.argument("risk_id")
@click.option(
    "--type",
    "treatment_type",
    type=click.Choice(["mitigate", "transfer", "accept", "avoid"]),
    required=True,
    help="Treatment type",
)
@click.option("--description", required=True, help="Treatment description")
@click.option("--owner", default="unassigned", show_default=True, help="Treatment owner")
@click.option("--deadline", default=None, help="Target completion date (YYYY-MM-DD)")
def treatment_add(
    risk_id: str,
    treatment_type: str,
    description: str,
    owner: str,
    deadline: str | None,
) -> None:
    """Add a treatment plan to a risk register entry (RISK_ID prefix or full UUID)."""
    from warlock.db.engine import get_session, init_db

    init_db()
    actor = _get_actor()

    # Resolve full risk_id from register
    with get_session() as session:
        register_entries = _load_records(session, "risk_register")
        matches = [r for r in register_entries if r.get("_id", "").startswith(risk_id)]
        if not matches:
            _error(f"Risk not found: {risk_id}. Use 'warlock risk-engine register list'.")

        full_risk_id = matches[0]["_id"]
        treatment_id = str(uuid.uuid4())
        payload: dict = {
            "risk_id": full_risk_id,
            "treatment_type": treatment_type,
            "description": description,
            "owner": owner,
            "status": "planned",
            "created_by": actor,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        if deadline:
            payload["deadline"] = deadline

        _store_record(session, "risk_treatment", "created", treatment_id, payload, actor)

    console.print(
        f"[green]Treatment {treatment_id[:8]} added to risk {full_risk_id[:8]} "
        f"(type: {treatment_type}, owner: {owner})[/green]"
    )


@treatment.command("update")
@click.argument("risk_id")
@click.argument("treatment_id")
@click.option("--status", required=True, help="New status (e.g. planned, in_progress, completed)")
def treatment_update(risk_id: str, treatment_id: str, status: str) -> None:
    """Update the status of a treatment plan (prefix or full UUIDs)."""
    from warlock.db.engine import get_session, init_db

    init_db()
    actor = _get_actor()

    with get_session() as session:
        records = _load_records(session, "risk_treatment")
        matches = [
            r
            for r in records
            if r.get("_id", "").startswith(treatment_id)
            and r.get("risk_id", "").startswith(risk_id)
        ]
        if not matches:
            _error(f"Treatment {treatment_id} not found for risk {risk_id}.")

        t = matches[0]
        full_id = t["_id"]
        t["status"] = status
        t["updated_by"] = actor
        t["updated_at"] = datetime.now(timezone.utc).isoformat()

        _store_record(session, "risk_treatment", "updated", full_id, t, actor)

    console.print(f"[green]Treatment {full_id[:8]} status updated to '{status}'.[/green]")


# ---------------------------------------------------------------------------
# scenario — FAIR Monte Carlo simulation with custom parameters
# ---------------------------------------------------------------------------


@risk_engine.command("scenario")
@click.option("--description", "-d", required=True, help="Threat scenario description")
@click.option("--asset-value", type=float, required=True, help="Asset value in dollars")
@click.option(
    "--threat-frequency",
    type=float,
    required=True,
    help="Expected annual threat event frequency",
)
@click.option("--control-effectiveness", type=float, default=0.5, help="Control effectiveness 0-1")
@click.option("--iterations", type=int, default=10000, help="Monte Carlo iterations")
def risk_scenario(
    description: str,
    asset_value: float,
    threat_frequency: float,
    control_effectiveness: float,
    iterations: int,
) -> None:
    """Run a custom FAIR Monte Carlo scenario with specified parameters.

    Example: warlock risk-engine scenario -d "Ransomware attack" \\
             --asset-value 5000000 --threat-frequency 3 --control-effectiveness 0.7
    """
    from warlock.assessors.risk_engine import (
        RiskEngine,
        ThreatScenario,
    )

    scenario = ThreatScenario(
        name="custom_scenario",
        description=description,
        frequency_min=max(threat_frequency * 0.3, 0.1),
        frequency_mode=threat_frequency,
        frequency_max=threat_frequency * 3.0,
        impact_min=asset_value * 0.05,
        impact_mode=asset_value * 0.2,
        impact_max=asset_value * 0.8,
        control_effectiveness=control_effectiveness,
    )

    engine = RiskEngine()
    result = engine.simulate_scenario(scenario, iterations=iterations)

    from rich.panel import Panel

    lines = [
        f"[bold]Scenario:[/bold]  {escape(description)}",
        f"[bold]Asset Value:[/bold] {_fmt_dollars(asset_value)}",
        f"[bold]Threat Frequency:[/bold] {threat_frequency:.1f} events/year",
        f"[bold]Control Effectiveness:[/bold] {control_effectiveness:.0%}",
        f"[bold]Iterations:[/bold] {iterations:,}",
        "",
        "[bold]FAIR Results[/bold]",
        f"  Mean ALE:     [bold]{_fmt_dollars(result.mean_ale)}[/bold]",
        f"  Median ALE:   {_fmt_dollars(result.median_ale)}",
        f"  VaR 90th:     {_fmt_dollars(result.var_90)}",
        f"  VaR 95th:     {_fmt_dollars(result.var_95)}",
        f"  VaR 99th:     {_fmt_dollars(result.var_99)}",
        f"  Min:          {_fmt_dollars(result.min_ale)}",
        f"  Max:          {_fmt_dollars(result.max_ale)}",
        f"  Std Dev:      {_fmt_dollars(result.std_dev)}",
    ]
    console.print(Panel("\n".join(lines), title="FAIR Risk Quantification", border_style="cyan"))
