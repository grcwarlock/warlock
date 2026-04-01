"""CLI commands for control testing schedule and execution.

Group: warlock control-tests
Commands:
  schedule          -- view test schedule per control family
  schedule-set      -- set cadence for a control
  execute           -- record a test result
  due               -- controls due for testing
  history           -- test history for a control
  report            -- framework-level test report
  gaps              -- controls never tested or past-due
"""

from __future__ import annotations

import click
from rich.table import Table

from warlock.cli import _error, _get_actor, cli, console
from warlock.utils import ensure_aware


@cli.group("control-tests", invoke_without_command=True)
@click.pass_context
def control_tests(ctx: click.Context) -> None:
    """Schedule, execute, and track control test results."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------


@control_tests.command("list")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--limit", "-n", default=50, help="Max results")
@click.option(
    "--format", "output_format", default="table", type=click.Choice(["table", "json", "csv"])
)
def control_tests_list(framework: str | None, limit: int, output_format: str) -> None:
    """List recent control test results."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(ControlResult).order_by(ControlResult.assessed_at.desc())
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.limit(limit).all()

        data = [
            {
                "id": r.id[:8],
                "framework": r.framework,
                "control_id": r.control_id,
                "status": r.status,
                "assessor": r.assessor or "",
                "assessed_at": str(r.assessed_at)[:19] if r.assessed_at else "",
                "examined_by": r.examined_by or "",
            }
            for r in rows
        ]

    if not data:
        console.print("[dim]No control test results found.[/dim]")
        return

    if output_format in ("json", "csv"):
        if output_format == "csv":
            from warlock.cli.output import render_csv

            render_csv(data, keys=list(data[0].keys()) if data else [])
        else:
            import json

            console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Control Test Results ({len(data)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Framework", style="cyan")
    table.add_column("Control", style="cyan")
    table.add_column("Status")
    table.add_column("Assessor", max_width=25)
    table.add_column("Assessed At")
    table.add_column("Examined By", max_width=20)

    for r in data:
        status_style = {
            "compliant": "green",
            "non_compliant": "red",
            "partial": "yellow",
            "not_assessed": "dim",
        }.get(r["status"], "")
        st_text = f"[{status_style}]{r['status']}[/{status_style}]" if status_style else r["status"]
        table.add_row(
            r["id"],
            r["framework"],
            r["control_id"],
            st_text,
            r["assessor"][:25] if r["assessor"] else "\u2014",
            r["assessed_at"],
            r["examined_by"][:20] or "\u2014",
        )

    console.print(table)


@control_tests.command("import")
@click.option(
    "--file", "filepath", required=True, type=click.Path(exists=True), help="Input file path"
)
@click.option(
    "--format", "fmt", default="json", type=click.Choice(["json", "csv"]), help="File format"
)
@click.option("--dry-run", is_flag=True, default=False, help="Preview without importing")
def control_tests_import(filepath: str, fmt: str, dry_run: bool) -> None:
    """Import control test results from a JSON or CSV file.

    Expected JSON structure: {"results": [{"control_id": "...", "framework": "...", "result": "pass|fail|partial", ...}]}
    Expected CSV columns: control_id, framework, result, evidence (optional), tester (optional)
    """
    import csv
    import json

    from rich.table import Table as RTable

    records: list[dict] = []
    if fmt == "json":
        try:
            with open(filepath) as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            _error(f"Invalid JSON in {filepath}: {exc}")
            return
        records = data.get("results", data) if isinstance(data, dict) else data
    else:
        with open(filepath, newline="") as fh:
            reader = csv.DictReader(fh)
            records = list(reader)

    if not records:
        console.print("[dim]No records found in file.[/dim]")
        return

    console.print(f"[bold]{len(records)}[/bold] test result(s) found in {filepath}.")

    table = RTable(title="Control Test Import Preview")
    table.add_column("Control ID", style="cyan")
    table.add_column("Framework")
    table.add_column("Result")
    table.add_column("Tester", style="dim")

    for r in records[:20]:
        table.add_row(
            r.get("control_id", "?"),
            r.get("framework", "?"),
            r.get("result", "?"),
            r.get("tester", "")[:30],
        )
    if len(records) > 20:
        console.print(f"[dim]... and {len(records) - 20} more[/dim]")
    console.print(table)

    if dry_run:
        console.print(
            f"\n[dim](dry-run) Would import {len(records)} test result(s). "
            f"Pass without --dry-run to execute.[/dim]"
        )
        return

    from datetime import datetime, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    status_map = {"pass": "compliant", "fail": "non_compliant", "partial": "partial"}
    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)
    imported = 0
    skipped = 0

    with get_session() as session:
        for r in records:
            control_id = r.get("control_id", "").strip()
            framework = r.get("framework", "").strip()
            result = r.get("result", "").strip().lower()
            if not control_id or not framework or result not in status_map:
                skipped += 1
                continue

            cr = (
                session.query(ControlResult)
                .filter(
                    ControlResult.control_id == control_id,
                    ControlResult.framework == framework,
                )
                .order_by(ControlResult.assessed_at.desc())
                .first()
            )
            if not cr:
                skipped += 1
                continue

            cr.status = status_map[result]
            cr.examined_at = now
            cr.examined_by = r.get("tester", actor)
            evidence = r.get("evidence", "")
            if evidence:
                existing = cr.remediation_summary or ""
                cr.remediation_summary = (
                    f"{existing}\n[Import {now.date()}] Evidence: {evidence}".strip()
                )
            imported += 1
        session.commit()

    console.print(f"[green]Imported {imported} test result(s), skipped {skipped}.[/green]")


# ---------------------------------------------------------------------------
# schedule
# ---------------------------------------------------------------------------


@control_tests.command("schedule")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--format", "output_format", default="table", type=click.Choice(["table", "json", "csv"])
)
def schedule_view(framework: str | None, output_format: str) -> None:
    """View control test schedule grouped by control family."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(
            ControlResult.framework,
            ControlResult.control_id,
            ControlResult.assessor,
            ControlResult.assessed_at,
        )
        if framework:
            q = q.filter(ControlResult.framework == framework)
        # One latest result per (framework, control_id)
        rows = q.order_by(ControlResult.assessed_at.desc()).all()

    # Deduplicate to latest per control
    seen: dict[tuple[str, str], dict] = {}
    for fw, ctrl, assessor, assessed_at in rows:
        key = (fw, ctrl)
        if key not in seen:
            family = ctrl.split("-")[0] if "-" in ctrl else ctrl[:2]
            seen[key] = {
                "framework": fw,
                "control_id": ctrl,
                "control_family": family,
                "assessor": assessor or "",
                "last_assessed": str(assessed_at)[:10] if assessed_at else "\u2014",
            }

    data = sorted(
        seen.values(), key=lambda r: (r["framework"], r["control_family"], r["control_id"])
    )

    if not data:
        console.print("[dim]No control results found.[/dim]")
        return

    if output_format in ("json", "csv"):
        if output_format == "csv":
            from warlock.cli.output import render_csv

            render_csv(data, keys=list(data[0].keys()) if data else [])
        else:
            import json

            console.print(json.dumps(data, indent=2))
        return

    table = Table(title="Control Test Schedule")
    table.add_column("Framework", style="cyan")
    table.add_column("Family")
    table.add_column("Control")
    table.add_column("Assessor", max_width=30)
    table.add_column("Last Assessed")

    for r in data:
        table.add_row(
            r["framework"],
            r["control_family"],
            r["control_id"],
            r["assessor"][:30],
            r["last_assessed"],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# schedule-set
# ---------------------------------------------------------------------------


@control_tests.command("schedule-set")
@click.argument("control_id")
@click.option(
    "--cadence",
    required=True,
    type=click.Choice(["quarterly", "semi-annual", "annual"]),
    help="Testing cadence",
)
@click.option("--framework", "-f", default=None, help="Scope to a specific framework")
def schedule_set(control_id: str, cadence: str, framework: str | None) -> None:
    """Set the testing cadence for a specific control.

    This updates the monitoring_frequency on all matching ControlMapping rows.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping

    init_db()
    with get_session() as session:
        q = session.query(ControlMapping).filter(ControlMapping.control_id == control_id)
        if framework:
            q = q.filter(ControlMapping.framework == framework)
        mappings = q.all()

        if not mappings:
            _error(
                f"No control mappings found for control '{control_id}'"
                + (f" in framework '{framework}'" if framework else "")
                + ". Run 'warlock control-tests schedule' to see available controls."
            )

        for m in mappings:
            m.monitoring_frequency = cadence
        count = len(mappings)

    console.print(
        f"[green]Updated cadence to '{cadence}'[/green] for {count} mapping(s) "
        f"of control [cyan]{control_id}[/cyan]"
        + (f" in framework [cyan]{framework}[/cyan]" if framework else "")
        + "."
    )


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------


@control_tests.command("execute")
@click.argument("control_id")
@click.option(
    "--result",
    required=True,
    type=click.Choice(["pass", "fail", "partial"]),
    help="Test outcome",
)
@click.option("--evidence", "-e", default="", help="Evidence description or reference")
@click.option("--tester", default=None, help="Tester actor identity")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
def execute_test(
    control_id: str,
    result: str,
    evidence: str,
    tester: str | None,
    framework: str | None,
) -> None:
    """Record a manual control test result.

    Updates the examined_at / examined_by fields on the latest ControlResult
    for the given control.  For a full re-assessment, run 'warlock collect'.
    """
    from datetime import datetime, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    actor = tester or _get_actor()
    now = datetime.now(timezone.utc)

    init_db()
    with get_session() as session:
        q = (
            session.query(ControlResult)
            .filter(ControlResult.control_id == control_id)
            .order_by(ControlResult.assessed_at.desc())
        )
        if framework:
            q = q.filter(ControlResult.framework == framework)
        cr = q.first()

        if not cr:
            _error(
                f"No ControlResult found for control '{control_id}'"
                + (f" in framework '{framework}'" if framework else "")
                + "."
            )

        cr.examined_at = now
        cr.examined_by = actor

        # Map result to status
        status_map = {"pass": "compliant", "fail": "non_compliant", "partial": "partial"}
        cr.status = status_map[result]

        if evidence:
            # Append evidence reference to remediation summary
            existing = cr.remediation_summary or ""
            cr.remediation_summary = f"{existing}\n[Test {now.date()}] Evidence: {evidence}".strip()

        cr_id = cr.id
        cr_framework = cr.framework

    icon = {
        "pass": "[green]PASS[/green]",
        "fail": "[red]FAIL[/red]",
        "partial": "[yellow]PARTIAL[/yellow]",
    }[result]
    console.print(
        f"{icon} Control [cyan]{control_id}[/cyan] "
        f"(framework: {cr_framework}, result id: {cr_id[:8]}) "
        f"examined by [cyan]{actor}[/cyan] at {str(now)[:19]}."
    )
    if evidence:
        console.print(f"  Evidence: {evidence}")


# ---------------------------------------------------------------------------
# due
# ---------------------------------------------------------------------------


@control_tests.command("due")
@click.option("--days", "-d", default=30, help="Controls due within N days (default: 30)")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--format", "output_format", default="table", type=click.Choice(["table", "json", "csv"])
)
def due_controls(days: int, framework: str | None, output_format: str) -> None:
    """List controls due for testing within the next N days.

    Uses monitoring_frequency from ControlMapping and last assessed_at from
    ControlResult to compute the next due date.
    """
    from datetime import datetime, timedelta, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, ControlResult

    cutoff = datetime.now(timezone.utc) + timedelta(days=days)
    init_db()

    frequency_days = {
        "daily": 1,
        "weekly": 7,
        "monthly": 30,
        "quarterly": 90,
        "semi-annual": 180,
        "annual": 365,
    }

    with get_session() as session:
        # Get latest assessed_at per (framework, control_id)
        q = session.query(
            ControlResult.framework, ControlResult.control_id, ControlResult.assessed_at
        )
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.order_by(ControlResult.assessed_at.desc()).all()

        last_assessed: dict[tuple[str, str], datetime | None] = {}
        for fw, ctrl, assessed_at in results:
            key = (fw, ctrl)
            if key not in last_assessed:
                last_assessed[key] = assessed_at

        # Get mappings with frequency set
        mq = session.query(ControlMapping).filter(ControlMapping.monitoring_frequency.isnot(None))
        if framework:
            mq = mq.filter(ControlMapping.framework == framework)
        mappings = mq.all()

        due_rows = []
        for m in mappings:
            freq_days = frequency_days.get(m.monitoring_frequency or "", 365)
            la = last_assessed.get((m.framework, m.control_id))
            if la is None:
                # Never assessed — always due
                next_due_str = "never tested"
                due_rows.append(
                    {
                        "framework": m.framework,
                        "control_id": m.control_id,
                        "cadence": m.monitoring_frequency,
                        "last_assessed": "\u2014",
                        "next_due": next_due_str,
                    }
                )
            else:
                next_due = ensure_aware(la) + timedelta(days=freq_days)
                if next_due <= cutoff:
                    due_rows.append(
                        {
                            "framework": m.framework,
                            "control_id": m.control_id,
                            "cadence": m.monitoring_frequency,
                            "last_assessed": str(la)[:10],
                            "next_due": str(next_due)[:10],
                        }
                    )

    # Deduplicate by (framework, control_id)
    seen_keys: set[tuple[str, str]] = set()
    deduped = []
    for r in due_rows:
        key = (r["framework"], r["control_id"])
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(r)

    if not deduped:
        console.print(f"[green]No controls due within {days} days.[/green]")
        return

    if output_format in ("json", "csv"):
        if output_format == "csv":
            from warlock.cli.output import render_csv

            render_csv(deduped, keys=list(deduped[0].keys()) if deduped else [])
        else:
            import json

            console.print(json.dumps(deduped, indent=2))
        return

    table = Table(title=f"Controls Due Within {days} Days ({len(deduped)})")
    table.add_column("Framework", style="cyan")
    table.add_column("Control")
    table.add_column("Cadence")
    table.add_column("Last Assessed")
    table.add_column("Next Due")

    for r in deduped:
        due_style = "red" if r["next_due"] == "never tested" else "yellow"
        table.add_row(
            r["framework"],
            r["control_id"],
            r["cadence"] or "\u2014",
            r["last_assessed"],
            f"[{due_style}]{r['next_due']}[/]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------


@control_tests.command("history")
@click.argument("control_id", required=False, default=None)
@click.option("--last", "-n", default=20, help="Show last N results (default: 20)")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--format", "output_format", default="table", type=click.Choice(["table", "json", "csv"])
)
def control_history(
    control_id: str | None, last: int, framework: str | None, output_format: str
) -> None:
    """Show test history for a control.

    When CONTROL_ID is omitted, shows recent test history across all controls.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(ControlResult).order_by(ControlResult.assessed_at.desc())
        if control_id is not None:
            q = q.filter(ControlResult.control_id == control_id)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.limit(last).all()

        data = [
            {
                "id": r.id,
                "framework": r.framework,
                "control_id": r.control_id,
                "status": r.status,
                "severity": r.severity,
                "assessor": r.assessor,
                "assertion_passed": r.assertion_passed,
                "ai_confidence": r.ai_confidence,
                "examined_by": r.examined_by or "",
                "examined_at": str(r.examined_at)[:19] if r.examined_at else "",
                "assessed_at": str(r.assessed_at)[:19] if r.assessed_at else "",
            }
            for r in rows
        ]

    if not data:
        label = f"control '{control_id}'" if control_id else "any control"
        console.print(f"[dim]No test history found for {label}.[/dim]")
        return

    if output_format in ("json", "csv"):
        if output_format == "csv":
            from warlock.cli.output import render_csv

            render_csv(data, keys=list(data[0].keys()) if data else [])
        else:
            import json

            console.print(json.dumps(data, indent=2))
        return

    title = (
        f"Test History: {control_id} (last {last})"
        if control_id
        else f"Recent Test History (last {last})"
    )
    table = Table(title=title)
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Framework", style="cyan")
    table.add_column("Control", style="cyan")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Assessor", max_width=25)
    table.add_column("Examined By", max_width=20)
    table.add_column("Assessed At")

    for r in data:
        status_style = {
            "compliant": "green",
            "non_compliant": "red",
            "partial": "yellow",
            "not_assessed": "dim",
        }.get(r["status"], "")
        table.add_row(
            r["id"][:8],
            r["framework"],
            r["control_id"],
            f"[{status_style}]{r['status']}[/]",
            r["severity"],
            r["assessor"][:25] if r["assessor"] else "\u2014",
            r["examined_by"][:20] or "\u2014",
            r["assessed_at"],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@control_tests.command("report")
@click.option("--framework", "-f", default=None, help="Scope to framework")
@click.option(
    "--format", "output_format", default="table", type=click.Choice(["table", "json", "md"])
)
def tests_report(framework: str | None, output_format: str) -> None:
    """Generate a control testing report by framework."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(
            ControlResult.framework,
            ControlResult.status,
        )
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.all()

    # Aggregate by framework
    fw_counts: dict[str, dict[str, int]] = {}
    for fw, status in rows:
        if fw not in fw_counts:
            fw_counts[fw] = {}
        fw_counts[fw][status] = fw_counts[fw].get(status, 0) + 1

    if not fw_counts:
        console.print("[dim]No control results found.[/dim]")
        return

    if output_format == "json":
        import json

        console.print(json.dumps(fw_counts, indent=2))
        return

    if output_format == "md":
        console.print("# Control Test Report\n")
        for fw, counts in sorted(fw_counts.items()):
            total = sum(counts.values())
            compliant = counts.get("compliant", 0)
            pct = f"{compliant / total * 100:.1f}%" if total else "N/A"
            console.print(f"## {fw}")
            console.print(f"- Total: {total}")
            console.print(f"- Compliant: {compliant} ({pct})")
            for s, c in sorted(counts.items()):
                if s != "compliant":
                    console.print(f"- {s}: {c}")
            console.print()
        return

    table = Table(title="Control Test Report")
    table.add_column("Framework", style="cyan")
    table.add_column("Total", justify="right")
    table.add_column("Compliant", justify="right", style="green")
    table.add_column("Non-Compliant", justify="right", style="red")
    table.add_column("Partial", justify="right", style="yellow")
    table.add_column("Other", justify="right")
    table.add_column("Pass Rate", justify="right")

    for fw, counts in sorted(fw_counts.items()):
        total = sum(counts.values())
        compliant = counts.get("compliant", 0)
        non_compliant = counts.get("non_compliant", 0)
        partial = counts.get("partial", 0)
        other = total - compliant - non_compliant - partial
        pct = f"{compliant / total * 100:.1f}%" if total else "N/A"
        table.add_row(
            fw,
            str(total),
            str(compliant),
            str(non_compliant),
            str(partial),
            str(other),
            pct,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# gaps
# ---------------------------------------------------------------------------


@control_tests.command("gaps")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--format", "output_format", default="table", type=click.Choice(["table", "json", "csv"])
)
def gaps(framework: str | None, output_format: str) -> None:
    """List controls that have never been tested or are past-due.

    'Past-due' means the last assessment is older than the monitoring_frequency
    set on the control mapping.  'Never tested' means no ControlResult exists.
    'No manual test' means automated assessments exist but no auditor has
    examined the control (examined_at is NULL for all results).
    Controls with no frequency set are excluded from past-due detection.
    """
    from datetime import datetime, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, ControlResult

    init_db()
    frequency_days = {
        "daily": 1,
        "weekly": 7,
        "monthly": 30,
        "quarterly": 90,
        "semi-annual": 180,
        "annual": 365,
    }
    now = datetime.now(timezone.utc)

    with get_session() as session:
        q = session.query(ControlMapping)
        if framework:
            q = q.filter(ControlMapping.framework == framework)
        mappings = q.all()

        # Latest assessed_at and examined_at per (framework, control_id)
        rq = session.query(
            ControlResult.framework,
            ControlResult.control_id,
            ControlResult.assessed_at,
            ControlResult.examined_at,
        )
        if framework:
            rq = rq.filter(ControlResult.framework == framework)
        result_rows = rq.order_by(ControlResult.assessed_at.desc()).all()

        last_assessed: dict[tuple[str, str], datetime | None] = {}
        last_examined: dict[tuple[str, str], datetime | None] = {}
        for fw, ctrl, assessed_at, examined_at in result_rows:
            key = (fw, ctrl)
            if key not in last_assessed:
                last_assessed[key] = assessed_at
            # Track latest examined_at across all results for this control
            if examined_at is not None:
                prev = last_examined.get(key)
                if prev is None or ensure_aware(examined_at) > ensure_aware(prev):
                    last_examined[key] = examined_at

    gap_rows = []
    seen_keys: set[tuple[str, str]] = set()

    for m in mappings:
        key = (m.framework, m.control_id)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        la = last_assessed.get(key)
        le = last_examined.get(key)
        if la is None:
            gap_rows.append(
                {
                    "framework": m.framework,
                    "control_id": m.control_id,
                    "cadence": m.monitoring_frequency or "\u2014",
                    "last_assessed": "\u2014",
                    "gap_type": "never_tested",
                    "overdue_days": "",
                }
            )
        else:
            # Check for past-due automated assessment
            if m.monitoring_frequency:
                freq_days = frequency_days.get(m.monitoring_frequency, 365)
                overdue_by = (now - ensure_aware(la)).days - freq_days
                if overdue_by > 0:
                    gap_rows.append(
                        {
                            "framework": m.framework,
                            "control_id": m.control_id,
                            "cadence": m.monitoring_frequency,
                            "last_assessed": str(la)[:10],
                            "gap_type": "past_due",
                            "overdue_days": str(overdue_by),
                        }
                    )
            # Flag controls with automated assessment but no manual examination
            if le is None:
                gap_rows.append(
                    {
                        "framework": m.framework,
                        "control_id": m.control_id,
                        "cadence": m.monitoring_frequency or "\u2014",
                        "last_assessed": str(la)[:10],
                        "gap_type": "no_manual_test",
                        "overdue_days": "",
                    }
                )

    if not gap_rows:
        console.print(
            "[green]No gaps found. All controls have been tested "
            "(both automated and manual examination).[/green]"
        )
        return

    if output_format in ("json", "csv"):
        if output_format == "csv":
            from warlock.cli.output import render_csv

            render_csv(gap_rows, keys=list(gap_rows[0].keys()) if gap_rows else [])
        else:
            import json

            console.print(json.dumps(gap_rows, indent=2))
        return

    table = Table(title=f"Control Testing Gaps ({len(gap_rows)})")
    table.add_column("Framework", style="cyan")
    table.add_column("Control")
    table.add_column("Cadence")
    table.add_column("Last Assessed")
    table.add_column("Gap Type")
    table.add_column("Overdue Days", justify="right")

    for r in gap_rows:
        gap_style = {"never_tested": "red", "past_due": "yellow", "no_manual_test": "magenta"}.get(
            r["gap_type"], "dim"
        )
        table.add_row(
            r["framework"],
            r["control_id"],
            r["cadence"],
            r["last_assessed"],
            f"[{gap_style}]{r['gap_type']}[/]",
            r["overdue_days"],
        )

    console.print(table)
