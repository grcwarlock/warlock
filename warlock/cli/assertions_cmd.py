"""Assertion engine commands.

Inspect, run, and debug the deterministic assertion library that
powers Tier-1 compliance checking.
"""

from __future__ import annotations

import json
from collections import defaultdict

import click
from rich.table import Table

from warlock.cli import cli, console, _error


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("assertions", invoke_without_command=True)
@click.pass_context
def assertions(ctx: click.Context) -> None:
    """Inspect and run the compliance assertion engine."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(assertions_list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_engine():
    """Return the singleton AssertionEngine with all assertions loaded."""
    # Import assertions module to ensure all @engine.assertion decorators run
    import warlock.assessors.assertions  # noqa: F401

    from warlock.assessors.engine import engine

    return engine


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@assertions.command("list")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def assertions_list(fmt: str) -> None:
    """List all registered assertion functions."""
    eng = _get_engine()
    names = sorted(eng._assertions.keys())

    if not names:
        console.print("[dim]No assertions registered.[/dim]")
        return

    if fmt == "json":
        data = []
        for name in names:
            fn = eng._assertions[name]
            data.append(
                {
                    "name": name,
                    "docstring": (fn.__doc__ or "").strip().split("\n")[0],
                }
            )
        console.print(json.dumps(data, indent=2))
        return

    # Build control bindings index per assertion
    bindings: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for (fw, ctrl), assertion_list in eng._control_assertions.items():
        for a in assertion_list:
            bindings[a].append((fw, ctrl))

    table = Table(title=f"Assertions ({len(names)})")
    table.add_column("Name", style="cyan")
    table.add_column("Control Bindings", justify="right")
    table.add_column("Description", max_width=60)

    for name in names:
        fn = eng._assertions[name]
        doc = (fn.__doc__ or "").strip().split("\n")[0]
        table.add_row(name, str(len(bindings.get(name, []))), doc)

    console.print(table)


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@assertions.command("show")
@click.argument("name")
def assertions_show(name: str) -> None:
    """Show details for a specific assertion."""
    eng = _get_engine()
    fn = eng._assertions.get(name)
    if fn is None:
        _error(f"Assertion '{name}' not found. Use 'warlock assertions list'.")

    from rich.panel import Panel

    bindings: list[tuple[str, str]] = [
        (fw, ctrl) for (fw, ctrl), alist in eng._control_assertions.items() if name in alist
    ]
    remediation = eng._remediation.get(name, {})

    doc = (fn.__doc__ or "").strip()
    body = f"[bold]{name}[/bold]\n\n"
    body += f"[dim]{doc}[/dim]\n\n" if doc else ""
    body += f"Control bindings: {len(bindings)}\n"
    if bindings:
        body += "  " + ", ".join(f"{fw}:{ctrl}" for fw, ctrl in sorted(bindings)[:8])
        if len(bindings) > 8:
            body += f" ... (+{len(bindings) - 8} more)"
        body += "\n"
    if remediation:
        body += f"\nRemediation: {remediation.get('summary', '\u2014')}"

    console.print(Panel(body, title="[bold cyan]Assertion[/bold cyan]", border_style="cyan"))


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


@assertions.command("run")
@click.argument("name")
@click.option(
    "--detail",
    default="{}",
    help="JSON string for finding detail dict",
)
@click.option(
    "--raw-data",
    default="{}",
    help="JSON string for raw event data dict",
)
def assertions_run(name: str, detail: str, raw_data: str) -> None:
    """Run a single assertion with provided data dicts.

    \b
    Example:
        warlock assertions run mfa_enabled --detail '{"mfa_active": false, "password_enabled": true}'
    """
    eng = _get_engine()
    if name not in eng._assertions:
        _error(f"Assertion '{name}' not found.")

    try:
        detail_dict = json.loads(detail)
    except json.JSONDecodeError as exc:
        _error(f"--detail is invalid JSON: {exc}")

    try:
        raw_dict = json.loads(raw_data)
    except json.JSONDecodeError as exc:
        _error(f"--raw-data is invalid JSON: {exc}")

    passed, reasons = eng.evaluate(name, detail_dict, raw_dict)

    if passed:
        console.print(f"[green]PASS[/green] Assertion '{name}' passed.")
    else:
        console.print(f"[red]FAIL[/red] Assertion '{name}' failed.")
        for reason in reasons:
            console.print(f"  [dim]- {reason}[/dim]")


# ---------------------------------------------------------------------------
# run-all
# ---------------------------------------------------------------------------


@assertions.command("run-all")
@click.option(
    "--detail",
    default="{}",
    help="JSON string for finding detail (applied to all assertions)",
)
def assertions_run_all(detail: str) -> None:
    """Run all assertions against a shared detail dict.

    Useful for testing how a given finding detail would fare against every
    assertion in the registry.
    """
    eng = _get_engine()
    try:
        detail_dict = json.loads(detail)
    except json.JSONDecodeError as exc:
        _error(f"--detail is invalid JSON: {exc}")

    names = sorted(eng._assertions.keys())
    if not names:
        console.print("[dim]No assertions registered.[/dim]")
        return

    table = Table(title=f"Run All Assertions ({len(names)})")
    table.add_column("Assertion", style="cyan")
    table.add_column("Result")
    table.add_column("Reason", max_width=60)

    for name in names:
        passed, reasons = eng.evaluate(name, detail_dict, {})
        result_str = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
        reason_str = reasons[0][:60] if reasons else ""
        table.add_row(name, result_str, reason_str)

    console.print(table)


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------


@assertions.command("test")
@click.argument("name")
def assertions_test(name: str) -> None:
    """Smoke-test an assertion with safe default inputs."""
    eng = _get_engine()
    if name not in eng._assertions:
        _error(f"Assertion '{name}' not found.")

    # Call with empty dicts — should not raise, may return False
    try:
        passed, reasons = eng.evaluate(name, {}, {})
        console.print(
            f"[green]Assertion '{name}' is callable without errors.[/green] "
            f"Result: {'pass' if passed else 'fail'}"
        )
    except Exception as exc:
        console.print(f"[red]Assertion '{name}' raised an exception: {exc}[/red]")


# ---------------------------------------------------------------------------
# bindings
# ---------------------------------------------------------------------------


@assertions.command("bindings")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--limit", "-n", default=100, help="Max bindings to show")
def assertions_bindings(framework: str | None, limit: int) -> None:
    """List all control-to-assertion bindings."""
    eng = _get_engine()
    items = list(eng._control_assertions.items())

    if framework:
        items = [((fw, ctrl), alist) for (fw, ctrl), alist in items if fw == framework]

    if not items:
        console.print("[dim]No bindings found.[/dim]")
        return

    table = Table(title=f"Control Bindings ({len(items)})")
    table.add_column("Framework", style="cyan")
    table.add_column("Control ID")
    table.add_column("Assertions", max_width=80)

    for (fw, ctrl), alist in sorted(items)[:limit]:
        table.add_row(fw, ctrl, ", ".join(alist))

    if len(items) > limit:
        console.print(f"[dim]... showing {limit} of {len(items)} bindings[/dim]")

    console.print(table)


# ---------------------------------------------------------------------------
# bindings-for
# ---------------------------------------------------------------------------


@assertions.command("bindings-for")
@click.argument("assertion_name")
def assertions_bindings_for(assertion_name: str) -> None:
    """List all controls bound to a specific assertion."""
    eng = _get_engine()
    if assertion_name not in eng._assertions:
        _error(f"Assertion '{assertion_name}' not found.")

    bound = [
        (fw, ctrl)
        for (fw, ctrl), alist in eng._control_assertions.items()
        if assertion_name in alist
    ]

    if not bound:
        console.print(f"[dim]No controls bound to assertion '{assertion_name}'.[/dim]")
        return

    table = Table(title=f"Controls bound to '{assertion_name}' ({len(bound)})")
    table.add_column("Framework", style="cyan")
    table.add_column("Control ID")

    for fw, ctrl in sorted(bound):
        table.add_row(fw, ctrl)

    console.print(table)


# ---------------------------------------------------------------------------
# coverage
# ---------------------------------------------------------------------------


@assertions.command("coverage")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def assertions_coverage(framework: str | None) -> None:
    """Show which controls have assertion coverage vs. none."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    _get_engine()  # ensure all assertions are registered
    init_db()

    with get_session() as session:
        q = session.query(
            ControlResult.framework,
            ControlResult.control_id,
            ControlResult.assertion_name,
        ).distinct()
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.all()

    if not rows:
        console.print("[dim]No control results found.[/dim]")
        return

    covered = sum(1 for r in rows if r.assertion_name)
    uncovered = sum(1 for r in rows if not r.assertion_name)
    pct = covered / len(rows) * 100 if rows else 0

    console.print("\n[bold]Assertion Coverage[/bold]")
    console.print(f"  Total controls evaluated:  {len(rows)}")
    console.print(f"  [green]With assertion:[/green]            {covered}")
    console.print(f"  [yellow]Without assertion:[/yellow]         {uncovered}")
    console.print(f"  Coverage:                  {pct:.1f}%\n")

    # Show uncovered controls
    uncovered_rows = [r for r in rows if not r.assertion_name]
    if uncovered_rows:
        table = Table(title=f"Controls Without Assertions ({len(uncovered_rows)})")
        table.add_column("Framework", style="cyan")
        table.add_column("Control ID")

        for r in sorted(uncovered_rows, key=lambda x: (x.framework, x.control_id))[:20]:
            table.add_row(r.framework, r.control_id)
        if len(uncovered_rows) > 20:
            console.print(f"  [dim]... and {len(uncovered_rows) - 20} more[/dim]")
        console.print(table)


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


@assertions.command("stats")
def assertions_stats() -> None:
    """Show aggregate assertion pass/fail statistics from DB results."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        rows = (
            session.query(
                ControlResult.assertion_name,
                ControlResult.assertion_passed,
            )
            .filter(ControlResult.assertion_name.isnot(None))
            .all()
        )

    if not rows:
        console.print("[dim]No assertion results in database.[/dim]")
        return

    by_name: dict[str, dict] = defaultdict(lambda: {"passed": 0, "failed": 0, "total": 0})
    for r in rows:
        name = r.assertion_name or "unknown"
        by_name[name]["total"] += 1
        if r.assertion_passed:
            by_name[name]["passed"] += 1
        else:
            by_name[name]["failed"] += 1

    table = Table(title="Assertion Statistics")
    table.add_column("Assertion", style="cyan")
    table.add_column("Total", justify="right")
    table.add_column("Passed", justify="right")
    table.add_column("Failed", justify="right")
    table.add_column("Pass Rate", justify="right")

    for name in sorted(by_name):
        d = by_name[name]
        rate = d["passed"] / d["total"] * 100 if d["total"] else 0
        rate_style = "green" if rate >= 80 else ("yellow" if rate >= 50 else "red")
        table.add_row(
            name,
            str(d["total"]),
            f"[green]{d['passed']}[/green]",
            f"[red]{d['failed']}[/red]" if d["failed"] else "0",
            f"[{rate_style}]{rate:.0f}%[/{rate_style}]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------


@assertions.command("history")
@click.argument("assertion_name")
@click.option("--limit", "-n", default=20, help="Max results")
def assertions_history(assertion_name: str, limit: int) -> None:
    """Show recent DB results for a specific assertion."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        rows = (
            session.query(ControlResult)
            .filter(ControlResult.assertion_name == assertion_name)
            .order_by(ControlResult.assessed_at.desc())
            .limit(limit)
            .all()
        )

    if not rows:
        _error(f"No results found for assertion '{assertion_name}'.")

    table = Table(title=f"History: {assertion_name}")
    table.add_column("Result ID", style="dim", max_width=8)
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Passed")
    table.add_column("Status")
    table.add_column("Assessed At")

    for r in rows:
        passed_str = "[green]yes[/green]" if r.assertion_passed else "[red]no[/red]"
        status_style = "green" if r.status == "compliant" else "red"
        table.add_row(
            r.id[:8],
            r.framework,
            r.control_id,
            passed_str,
            f"[{status_style}]{r.status}[/{status_style}]",
            str(r.assessed_at)[:19] if r.assessed_at else "\u2014",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# failures
# ---------------------------------------------------------------------------


@assertions.command("failures")
@click.option("--assertion", "-a", default=None, help="Filter by assertion name")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--limit", "-n", default=25, help="Max results")
def assertions_failures(assertion: str | None, framework: str | None, limit: int) -> None:
    """List recent assertion failures with failure reasons."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = (
            session.query(ControlResult)
            .filter(
                ControlResult.assertion_name.isnot(None),
                ControlResult.assertion_passed == False,  # noqa: E712
            )
            .order_by(ControlResult.assessed_at.desc())
        )
        if assertion:
            q = q.filter(ControlResult.assertion_name == assertion)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.limit(limit).all()

    if not rows:
        console.print("[green]No assertion failures found.[/green]")
        return

    table = Table(title=f"Assertion Failures ({len(rows)})")
    table.add_column("Assertion", style="cyan")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("First Failure Reason", max_width=60)
    table.add_column("Assessed At")

    for r in rows:
        findings = r.assertion_findings or []
        first_reason = findings[0] if findings else "\u2014"
        table.add_row(
            r.assertion_name or "\u2014",
            r.framework,
            r.control_id,
            str(first_reason)[:60],
            str(r.assessed_at)[:19] if r.assessed_at else "\u2014",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------


@assertions.command("explain")
@click.argument("assertion_name")
def assertions_explain(assertion_name: str) -> None:
    """Explain an assertion: docstring, bindings, remediation, and recent results."""
    eng = _get_engine()
    fn = eng._assertions.get(assertion_name)
    if fn is None:
        _error(f"Assertion '{assertion_name}' not found.")

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()

    # Full docstring
    doc = (fn.__doc__ or "No documentation.").strip()
    console.print(f"\n[bold cyan]{assertion_name}[/bold cyan]")
    console.print(f"[dim]{doc}[/dim]\n")

    # Bindings
    bound = sorted(
        (fw, ctrl)
        for (fw, ctrl), alist in eng._control_assertions.items()
        if assertion_name in alist
    )
    console.print(f"[bold]Control bindings ({len(bound)}):[/bold]")
    for fw, ctrl in bound[:10]:
        console.print(f"  [cyan]{fw}[/cyan] / {ctrl}")
    if len(bound) > 10:
        console.print(f"  [dim]... and {len(bound) - 10} more[/dim]")

    # Remediation
    remediation = eng._remediation.get(assertion_name)
    if remediation:
        console.print("\n[bold]Remediation:[/bold]")
        console.print(f"  {remediation.get('summary', '\u2014')}")
        for step in (remediation.get("steps") or [])[:3]:
            console.print(f"  - {step}")

    # Recent results
    with get_session() as session:
        rows = (
            session.query(ControlResult)
            .filter(ControlResult.assertion_name == assertion_name)
            .order_by(ControlResult.assessed_at.desc())
            .limit(10)
            .all()
        )

    if rows:
        passed = sum(1 for r in rows if r.assertion_passed)
        failed = len(rows) - passed
        console.print(
            f"\n[bold]Recent results (last {len(rows)}):[/bold] "
            f"[green]{passed} passed[/green], [red]{failed} failed[/red]"
        )
