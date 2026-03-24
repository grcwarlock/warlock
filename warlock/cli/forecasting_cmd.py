"""Compliance forecasting CLI commands.

Provides Monte Carlo simulation-based compliance score projections
using historical remediation rates and statistical modeling.
"""

from __future__ import annotations

import json as _json
import math
import random
from collections import defaultdict
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


def _compute_remediation_stats(
    closed_dates: list[datetime],
    lookback_days: int = 180,
) -> tuple[float, float]:
    """Compute mean and standard deviation of daily remediation rate.

    Returns (mean_daily_rate, std_daily_rate) over weekly windows.
    """
    if not closed_dates:
        return 0.0, 0.0

    now = _utcnow()
    cutoff = now - timedelta(days=lookback_days)

    # Count closures per week
    weekly_counts: dict[int, int] = defaultdict(int)
    for dt in closed_dates:
        dt_aware = ensure_aware(dt) if dt else None
        if dt_aware and dt_aware >= cutoff:
            week_offset = (now - dt_aware).days // 7
            weekly_counts[week_offset] += 1

    total_weeks = max(lookback_days // 7, 1)
    weekly_rates = [weekly_counts.get(w, 0) for w in range(total_weeks)]

    if not weekly_rates:
        return 0.0, 0.0

    mean_weekly = sum(weekly_rates) / len(weekly_rates)
    variance = sum((r - mean_weekly) ** 2 for r in weekly_rates) / max(len(weekly_rates) - 1, 1)
    std_weekly = math.sqrt(variance)

    # Convert to daily
    mean_daily = mean_weekly / 7.0
    std_daily = std_weekly / 7.0

    return mean_daily, std_daily


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@cli.group("forecast", invoke_without_command=True)
@click.pass_context
def forecast(ctx: click.Context) -> None:
    """Compliance forecasting and Monte Carlo projections."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# compliance-forecast (Monte Carlo)
# ---------------------------------------------------------------------------


@forecast.command("compliance-forecast")
@click.option("--framework", default=None, help="Framework to forecast (default: all).")
@click.option("--months", default=12, type=int, help="Projection horizon in months (default: 12).")
@click.option(
    "--simulations",
    default=1000,
    type=int,
    help="Number of Monte Carlo simulations (default: 1000).",
)
@click.option(
    "--target-score", default=90.0, type=float, help="Target compliance score (default: 90%)."
)
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def compliance_forecast(
    framework: str | None,
    months: int,
    simulations: int,
    target_score: float,
    fmt: str,
) -> None:
    """Monte Carlo projection of compliance score over time.

    Uses historical remediation rates (issue close dates) to simulate
    future compliance trajectories. Shows projected score per month with
    confidence intervals (P10, P50, P90).
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Issue

    init_db()
    now = _utcnow()

    with get_session() as session:
        # Current compliance state
        cr_query = session.query(ControlResult)
        if framework:
            cr_query = cr_query.filter(ControlResult.framework == framework)

        total = cr_query.limit(500_000).count()
        compliant = cr_query.filter(ControlResult.status == "compliant").limit(500_000).count()
        non_compliant = (
            cr_query.filter(ControlResult.status == "non_compliant").limit(500_000).count()
        )

        # Historical remediation data (last 180 days)
        lookback = now - timedelta(days=180)
        closed_issues = (
            session.query(Issue.closed_at)
            .filter(
                Issue.status.in_(["closed", "verified", "remediated"]),
                Issue.closed_at >= lookback,
            )
            .limit(100_000)
            .all()
        )

    if total == 0:
        console.print("[dim]No control results found.[/dim]")
        return

    current_score = _score_pct(compliant, total)
    closed_dates = [r[0] for r in closed_issues if r[0] is not None]
    mean_rate, std_rate = _compute_remediation_stats(closed_dates)

    if mean_rate == 0:
        console.print(
            "[yellow]No closed issues in last 180 days -- using minimal baseline rate.[/yellow]"
        )
        # Assume at least 0.1 per day as a minimal baseline for projection
        mean_rate = 0.1
        std_rate = 0.05

    # Cap simulations to a reasonable range
    simulations = min(max(simulations, 100), 50_000)

    # Run Monte Carlo simulations
    # For each month, simulate how many controls get remediated
    monthly_scores: list[list[float]] = [[] for _ in range(months)]
    days_per_month = 30

    for _ in range(simulations):
        sim_compliant = compliant
        for month_idx in range(months):
            # Sample daily rate from normal distribution, floor at 0
            daily = max(random.gauss(mean_rate, std_rate), 0.0)
            remediated = int(daily * days_per_month)
            sim_compliant = min(sim_compliant + remediated, total)
            score = sim_compliant / total * 100.0
            monthly_scores[month_idx].append(score)

    # Compute percentiles for each month
    table = Table(title="Compliance Forecast (Monte Carlo)")
    table.add_column("Month", justify="right")
    table.add_column("Date")
    table.add_column("P10", justify="right")
    table.add_column("P50 (Median)", justify="right", style="bold")
    table.add_column("P90", justify="right")
    table.add_column("Target Met?", justify="center")

    data: list[dict] = []
    target_month: int | None = None

    for month_idx in range(months):
        scores = sorted(monthly_scores[month_idx])
        p10_idx = max(0, int(len(scores) * 0.10) - 1)
        p50_idx = max(0, int(len(scores) * 0.50) - 1)
        p90_idx = max(0, int(len(scores) * 0.90) - 1)

        p10 = round(scores[p10_idx], 1)
        p50 = round(scores[p50_idx], 1)
        p90 = round(scores[p90_idx], 1)

        month_date = now + timedelta(days=(month_idx + 1) * days_per_month)
        date_str = month_date.strftime("%Y-%m")

        met = p50 >= target_score
        if met and target_month is None:
            target_month = month_idx + 1
        met_str = "[green]YES[/green]" if met else "[dim]no[/dim]"

        table.add_row(
            str(month_idx + 1),
            date_str,
            f"[{_score_style(p10)}]{p10}%[/{_score_style(p10)}]",
            f"[{_score_style(p50)}]{p50}%[/{_score_style(p50)}]",
            f"[{_score_style(p90)}]{p90}%[/{_score_style(p90)}]",
            met_str,
        )
        data.append(
            {
                "month": month_idx + 1,
                "date": date_str,
                "p10": p10,
                "p50": p50,
                "p90": p90,
                "target_met_p50": met,
            }
        )

    _format_output(data, fmt, table)

    if fmt == "table":
        console.print()
        fw_label = framework or "all frameworks"
        console.print(f"  Framework:            {escape(fw_label)}")
        console.print(
            f"  Current score:        [{_score_style(current_score)}]"
            f"{current_score}%[/{_score_style(current_score)}]"
        )
        console.print(f"  Target score:         {target_score}%")
        console.print(f"  Remediation rate:     {mean_rate:.2f} +/- {std_rate:.2f} issues/day")
        console.print(f"  Simulations:          {simulations:,}")
        console.print(f"  Non-compliant:        {non_compliant:,}")
        if target_month is not None:
            target_date = (now + timedelta(days=target_month * days_per_month)).strftime("%Y-%m")
            console.print(
                f"  [green]Projected to reach {target_score}% by month {target_month} "
                f"({target_date})[/green]"
            )
        else:
            console.print(
                f"  [yellow]Target {target_score}% not projected to be reached "
                f"within {months} months at current rate[/yellow]"
            )
