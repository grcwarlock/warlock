"""CLI commands for OPA policy management.

NOTE: This module registers the "policies" group (plural).
The existing policy_cmd.py registers "policy" (singular). No collision.

Groups:
  warlock policies list         -- list all OPA policy files
  warlock policies show         -- show a single policy file
  warlock policies evaluate     -- evaluate a policy against input
  warlock policies test         -- run OPA tests for a policy
  warlock policies test-all     -- run all OPA tests
  warlock policies coverage     -- show which controls have OPA coverage
  warlock policies stats        -- aggregate statistics
  warlock policies check        -- syntax-check all Rego files
  warlock policies diff         -- compare policies for two frameworks
  warlock policies search       -- search policy content
  warlock policies unused       -- show frameworks with no OPA coverage
  warlock policies export       -- export policy file
  warlock policies lifecycle ... -- lifecycle sub-group
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
from typing import Any

import click
from rich.table import Table
from rich.syntax import Syntax

from warlock.cli import cli, console, _error

_POLICIES_DIR = pathlib.Path(__file__).resolve().parent.parent.parent / "policies"


def _get_registry():
    """Return a PolicyRegistry instance (lazy import)."""
    from warlock.assessors.policy_registry import get_policy_registry

    return get_policy_registry()


def _opa_available() -> bool:
    """Return True if the `opa` binary is on PATH."""
    try:
        result = subprocess.run(
            ["opa", "version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Top-level group
# ---------------------------------------------------------------------------


@cli.group("policies")
def policies_grp() -> None:
    """Inspect and manage OPA/Rego compliance policies."""
    pass


# ---------------------------------------------------------------------------
# policies list
# ---------------------------------------------------------------------------


@policies_grp.command("list")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--limit", "-n", default=100, help="Max results")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def policies_list(framework: str | None, limit: int, fmt: str) -> None:
    """List all OPA policy files."""
    registry = _get_registry()
    policy_map = registry.policy_map  # {package_path: (framework, control_id)}

    rows: list[dict[str, Any]] = []
    for pkg, (fw, ctrl_id) in sorted(policy_map.items()):
        if framework and fw != framework:
            continue
        # Find the actual file path
        rego_candidates = list(_POLICIES_DIR.rglob("*.rego"))
        file_path = ""
        for f in rego_candidates:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                if f"package {pkg}" in content:
                    file_path = str(f.relative_to(_POLICIES_DIR))
                    break
            except Exception:
                continue
        rows.append(
            {
                "framework": fw,
                "control_id": ctrl_id,
                "package": pkg,
                "file": file_path,
            }
        )

    rows = rows[:limit]

    if fmt == "json":
        console.print_json(json.dumps(rows))
        return

    if not rows:
        console.print("[dim]No OPA policies found.[/dim]")
        return

    table = Table(title=f"OPA Policies ({len(rows)})")
    table.add_column("Framework", style="cyan")
    table.add_column("Control ID")
    table.add_column("Package Path", style="dim")
    table.add_column("File", style="dim")

    for row in rows:
        table.add_row(row["framework"], row["control_id"], row["package"], row["file"])

    console.print(table)


# ---------------------------------------------------------------------------
# policies show
# ---------------------------------------------------------------------------


@policies_grp.command("show")
@click.argument("policy_ref")
@click.option("--raw", is_flag=True, help="Print raw Rego without syntax highlighting")
def policies_show(policy_ref: str, raw: bool) -> None:
    """Show the content of a policy file.

    POLICY_REF can be a file path relative to the policies/ directory,
    a framework name (shows all policies for that framework),
    or a control ID.
    """
    registry = _get_registry()

    # Try as (framework, control_id) lookup
    for pkg, (fw, ctrl_id) in registry.policy_map.items():
        if ctrl_id == policy_ref or fw == policy_ref:
            # Find the file
            for rego_file in _POLICIES_DIR.rglob("*.rego"):
                if rego_file.stem.endswith("_test"):
                    continue
                try:
                    content = rego_file.read_text(encoding="utf-8")
                except Exception:
                    continue
                if f"package {pkg}" in content:
                    console.print(f"\n[bold]{rego_file.relative_to(_POLICIES_DIR)}[/bold]")
                    if raw:
                        console.print(content)
                    else:
                        console.print(Syntax(content, "rego", theme="monokai"))
                    if fw != policy_ref:
                        # Only show first match when looking up by control_id
                        return
            if fw != policy_ref:
                return
            return

    # Try as a direct file path
    candidates = [
        _POLICIES_DIR / policy_ref,
        _POLICIES_DIR / f"{policy_ref}.rego",
    ]
    for candidate in candidates:
        if candidate.exists():
            content = candidate.read_text(encoding="utf-8")
            console.print(f"\n[bold]{candidate.relative_to(_POLICIES_DIR)}[/bold]")
            if raw:
                console.print(content)
            else:
                console.print(Syntax(content, "rego", theme="monokai"))
            return

    _error(
        f"Policy '{policy_ref}' not found. Use 'warlock policies list' to see available policies."
    )


# ---------------------------------------------------------------------------
# policies evaluate
# ---------------------------------------------------------------------------


@policies_grp.command("evaluate")
@click.argument("policy_ref")
@click.option(
    "--input",
    "input_json",
    default=None,
    help="JSON input to evaluate against (or '-' to read from stdin)",
)
@click.option("--query", default="data", help="OPA query to evaluate")
def policies_evaluate(policy_ref: str, input_json: str | None, query: str) -> None:
    """Evaluate an OPA policy against a JSON input.

    Requires `opa` binary on PATH.

    \b
    Examples:
        warlock policies evaluate nist-800-53/ac/ac2_mfa.rego --input '{"mfa_enabled": false}'
        warlock policies evaluate ac2_mfa --query data.warlock.nist_800_53.ac2.allow
    """
    if not _opa_available():
        _error(
            "OPA binary not found. Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa"
        )

    # Resolve file
    rego_path: pathlib.Path | None = None
    for candidate in [
        _POLICIES_DIR / policy_ref,
        _POLICIES_DIR / f"{policy_ref}.rego",
    ]:
        if candidate.exists():
            rego_path = candidate
            break

    if rego_path is None:
        # Try by scanning policy_map
        registry = _get_registry()
        for pkg, (fw, ctrl_id) in registry.policy_map.items():
            if ctrl_id == policy_ref or pkg.endswith(policy_ref):
                for rego_file in _POLICIES_DIR.rglob("*.rego"):
                    try:
                        content = rego_file.read_text(encoding="utf-8")
                        if f"package {pkg}" in content:
                            rego_path = rego_file
                            break
                    except Exception:
                        continue
                if rego_path:
                    break

    if rego_path is None:
        _error(f"Policy file not found for '{policy_ref}'.")

    # Build OPA command
    cmd = ["opa", "eval", "--data", str(rego_path), query]

    if input_json:
        if input_json == "-":
            input_data = sys.stdin.read()
        else:
            input_data = input_json
        cmd += ["--input", "/dev/stdin"]
        result = subprocess.run(cmd, input=input_data.encode(), capture_output=True, timeout=30)
    else:
        result = subprocess.run(cmd, capture_output=True, timeout=30)

    if result.returncode != 0:
        console.print(f"[red]OPA evaluation failed:[/red]\n{result.stderr.decode()}")
        return

    try:
        out = json.loads(result.stdout)
        console.print_json(json.dumps(out, indent=2))
    except json.JSONDecodeError:
        console.print(result.stdout.decode())


# ---------------------------------------------------------------------------
# policies test
# ---------------------------------------------------------------------------


@policies_grp.command("test")
@click.argument("framework")
@click.option("--verbose", "-v", is_flag=True, help="Verbose OPA test output")
def policies_test(framework: str, verbose: bool) -> None:
    """Run OPA tests for a specific framework.

    Requires `opa` binary on PATH.
    """
    if not _opa_available():
        _error(
            "OPA binary not found. Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa"
        )

    # Find framework directory under policies/
    fw_dir = _POLICIES_DIR / framework
    if not fw_dir.is_dir():
        # Try with dash normalization
        fw_norm = framework.replace("_", "-")
        fw_dir = _POLICIES_DIR / fw_norm
        if not fw_dir.is_dir():
            _error(
                f"Policy directory not found for framework '{framework}'. "
                f"Checked: {_POLICIES_DIR / framework}"
            )

    cmd = ["opa", "test", str(fw_dir)]
    if verbose:
        cmd.append("-v")

    console.print(f"[cyan]Running OPA tests for {framework}...[/cyan]")
    result = subprocess.run(cmd, capture_output=False, timeout=120)

    if result.returncode == 0:
        console.print("[green]All tests passed.[/green]")
    else:
        console.print("[red]Some tests failed.[/red]")
        raise SystemExit(result.returncode)


# ---------------------------------------------------------------------------
# policies test-all
# ---------------------------------------------------------------------------


@policies_grp.command("test-all")
@click.option("--verbose", "-v", is_flag=True, help="Verbose OPA test output")
def policies_test_all(verbose: bool) -> None:
    """Run all OPA tests across all policy directories.

    Requires `opa` binary on PATH.
    """
    if not _opa_available():
        _error(
            "OPA binary not found. Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa"
        )

    cmd = ["opa", "test", str(_POLICIES_DIR)]
    if verbose:
        cmd.append("-v")

    console.print("[cyan]Running all OPA tests...[/cyan]")
    result = subprocess.run(cmd, capture_output=False, timeout=300)

    if result.returncode == 0:
        console.print("[green]All OPA tests passed.[/green]")
    else:
        console.print("[red]Some OPA tests failed.[/red]")
        raise SystemExit(result.returncode)


# ---------------------------------------------------------------------------
# policies coverage
# ---------------------------------------------------------------------------


@policies_grp.command("coverage")
@click.option("--framework", "-f", default=None, help="Filter to a specific framework")
def policies_coverage(framework: str | None) -> None:
    """Show which controls have OPA policy coverage."""
    registry = _get_registry()
    policy_map = registry.policy_map

    # Group by framework
    by_fw: dict[str, set[str]] = {}
    for pkg, (fw, ctrl_id) in policy_map.items():
        if framework and fw != framework:
            continue
        by_fw.setdefault(fw, set()).add(ctrl_id)

    if not by_fw:
        console.print("[dim]No OPA policy coverage found.[/dim]")
        return

    table = Table(title="OPA Policy Coverage")
    table.add_column("Framework", style="cyan")
    table.add_column("Controls with OPA", justify="right")

    for fw, ctrl_ids in sorted(by_fw.items()):
        table.add_row(fw, str(len(ctrl_ids)))

    console.print(table)
    console.print(
        f"\n[dim]Total policies: {len(policy_map)} across {len(by_fw)} framework(s)[/dim]"
    )


# ---------------------------------------------------------------------------
# policies stats
# ---------------------------------------------------------------------------


@policies_grp.command("stats")
def policies_stats() -> None:
    """Aggregate OPA policy statistics."""
    registry = _get_registry()
    policy_map = registry.policy_map

    by_fw: dict[str, int] = {}
    for pkg, (fw, ctrl_id) in policy_map.items():
        by_fw[fw] = by_fw.get(fw, 0) + 1

    # Count rego files
    total_rego = sum(1 for f in _POLICIES_DIR.rglob("*.rego") if not f.stem.endswith("_test"))
    total_tests = sum(1 for f in _POLICIES_DIR.rglob("*_test.rego"))

    console.print("\n[bold]OPA Policy Statistics[/bold]")
    console.print(f"  Total Rego files:  {total_rego}")
    console.print(f"  Total test files:  {total_tests}")
    console.print(f"  Mapped policies:   {len(policy_map)}")
    console.print(f"  Frameworks:        {len(by_fw)}")

    table = Table(title="Policies by Framework")
    table.add_column("Framework", style="cyan")
    table.add_column("Policy Count", justify="right")

    for fw, cnt in sorted(by_fw.items(), key=lambda x: -x[1]):
        table.add_row(fw, str(cnt))

    console.print(table)


# ---------------------------------------------------------------------------
# policies check
# ---------------------------------------------------------------------------


@policies_grp.command("check")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework directory")
def policies_check(framework: str | None) -> None:
    """Syntax-check all Rego files.

    Requires `opa` binary on PATH.
    """
    if not _opa_available():
        _error(
            "OPA binary not found. Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa"
        )

    target_dir = _POLICIES_DIR
    if framework:
        fw_dir = _POLICIES_DIR / framework
        if not fw_dir.is_dir():
            fw_dir = _POLICIES_DIR / framework.replace("_", "-")
        if fw_dir.is_dir():
            target_dir = fw_dir
        else:
            _error(f"Framework directory not found: {framework}")

    cmd = ["opa", "check", str(target_dir)]
    console.print(f"[cyan]Checking Rego syntax in {target_dir}...[/cyan]")
    result = subprocess.run(cmd, capture_output=True, timeout=120)

    if result.returncode == 0:
        console.print("[green]All Rego files pass syntax check.[/green]")
    else:
        console.print(f"[red]Syntax errors found:[/red]\n{result.stderr.decode()}")
        raise SystemExit(result.returncode)


# ---------------------------------------------------------------------------
# policies diff
# ---------------------------------------------------------------------------


@policies_grp.command("diff")
@click.argument("framework_a")
@click.argument("framework_b")
def policies_diff(framework_a: str, framework_b: str) -> None:
    """Compare OPA policy coverage between two frameworks."""
    registry = _get_registry()

    ctrls_a = {ctrl_id for fw, ctrl_id in registry.policy_map.values() if fw == framework_a}
    ctrls_b = {ctrl_id for fw, ctrl_id in registry.policy_map.values() if fw == framework_b}

    shared = ctrls_a & ctrls_b
    only_a = ctrls_a - ctrls_b
    only_b = ctrls_b - ctrls_a

    console.print(f"\n[bold]Policy Coverage Diff: {framework_a} vs {framework_b}[/bold]")
    console.print(f"  {framework_a}: {len(ctrls_a)} policies")
    console.print(f"  {framework_b}: {len(ctrls_b)} policies")
    console.print(f"  Shared control IDs: {len(shared)}")
    console.print(f"  Only in {framework_a}: {len(only_a)}")
    console.print(f"  Only in {framework_b}: {len(only_b)}")

    if only_a:
        console.print(f"\n[bold]Only in {framework_a}:[/bold]")
        for c in sorted(only_a)[:20]:
            console.print(f"  {c}")
        if len(only_a) > 20:
            console.print(f"  [dim]... and {len(only_a) - 20} more[/dim]")

    if only_b:
        console.print(f"\n[bold]Only in {framework_b}:[/bold]")
        for c in sorted(only_b)[:20]:
            console.print(f"  {c}")
        if len(only_b) > 20:
            console.print(f"  [dim]... and {len(only_b) - 20} more[/dim]")


# ---------------------------------------------------------------------------
# policies search
# ---------------------------------------------------------------------------


@policies_grp.command("search")
@click.argument("pattern")
@click.option("--framework", "-f", default=None, help="Limit to a framework directory")
@click.option("--limit", "-n", default=20, help="Max results")
def policies_search(pattern: str, framework: str | None, limit: int) -> None:
    """Search policy file content for a pattern."""
    target_dir = _POLICIES_DIR
    if framework:
        fw_dir = _POLICIES_DIR / framework
        if not fw_dir.is_dir():
            fw_dir = _POLICIES_DIR / framework.replace("_", "-")
        if fw_dir.is_dir():
            target_dir = fw_dir

    pattern_lower = pattern.lower()
    matches: list[dict[str, Any]] = []

    for rego_file in sorted(target_dir.rglob("*.rego")):
        try:
            content = rego_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if pattern_lower in content.lower():
            # Find the first matching line
            for lineno, line in enumerate(content.splitlines(), 1):
                if pattern_lower in line.lower():
                    matches.append(
                        {
                            "file": str(rego_file.relative_to(_POLICIES_DIR)),
                            "line": lineno,
                            "text": line.strip(),
                        }
                    )
                    break
        if len(matches) >= limit:
            break

    if not matches:
        console.print(f"[dim]No matches for '{pattern}'.[/dim]")
        return

    table = Table(title=f"Search results for '{pattern}' ({len(matches)})")
    table.add_column("File", style="cyan")
    table.add_column("Line", justify="right", style="dim")
    table.add_column("Content")

    for m in matches:
        table.add_row(m["file"], str(m["line"]), m["text"][:100])

    console.print(table)


# ---------------------------------------------------------------------------
# policies unused
# ---------------------------------------------------------------------------


@policies_grp.command("unused")
def policies_unused() -> None:
    """Show frameworks that have no OPA policy coverage."""
    fw_dir = pathlib.Path(__file__).resolve().parent.parent / "frameworks"
    registry = _get_registry()
    covered_fws = set(registry.list_frameworks())

    all_fws: set[str] = set()
    for yaml_file in fw_dir.glob("*.yaml"):
        if yaml_file.stem.startswith("crosswalk") or yaml_file.stem in ("diff",):
            continue
        try:
            import yaml as _yaml

            data = _yaml.safe_load(yaml_file.read_text()) or {}
            fw_id = data.get("framework_id", yaml_file.stem)
            all_fws.add(fw_id)
        except Exception:
            pass

    uncovered = all_fws - covered_fws

    if not uncovered:
        console.print("[green]All frameworks have OPA policy coverage.[/green]")
        return

    console.print(f"\n[yellow]Frameworks with no OPA policies ({len(uncovered)}):[/yellow]")
    table = Table()
    table.add_column("Framework ID", style="yellow")
    for fw in sorted(uncovered):
        table.add_row(fw)
    console.print(table)


# ---------------------------------------------------------------------------
# policies export
# ---------------------------------------------------------------------------


@policies_grp.command("export")
@click.argument("policy_ref")
@click.option("--output", "-o", default=None, help="Output file path (default: stdout)")
def policies_export(policy_ref: str, output: str | None) -> None:
    """Export a policy Rego file to a destination."""
    # Resolve by framework or control_id
    registry = _get_registry()
    rego_path: pathlib.Path | None = None

    for pkg, (fw, ctrl_id) in registry.policy_map.items():
        if ctrl_id == policy_ref or fw == policy_ref or pkg.endswith(policy_ref):
            for rego_file in _POLICIES_DIR.rglob("*.rego"):
                try:
                    content = rego_file.read_text(encoding="utf-8")
                    if f"package {pkg}" in content:
                        rego_path = rego_file
                        break
                except Exception:
                    continue
            if rego_path:
                break

    # Fall back to direct path
    if rego_path is None:
        for candidate in [_POLICIES_DIR / policy_ref, _POLICIES_DIR / f"{policy_ref}.rego"]:
            if candidate.exists():
                rego_path = candidate
                break

    if rego_path is None:
        _error(f"Policy '{policy_ref}' not found.")

    content = rego_path.read_text(encoding="utf-8")
    if output:
        pathlib.Path(output).write_text(content)
        console.print(f"[green]Exported to {output}[/green]")
    else:
        console.print(content)


# ---------------------------------------------------------------------------
# Sub-group: lifecycle
# ---------------------------------------------------------------------------


@policies_grp.group("lifecycle")
def lifecycle_grp() -> None:
    """Manage Policy DB records (push via 'warlock policy set')."""
    pass


@lifecycle_grp.command("list")
@click.option("--policy-type", "-t", default=None, help="Filter by policy type")
@click.option("--enabled/--disabled", default=None, help="Filter by enabled status")
@click.option("--limit", "-n", default=50, help="Max results")
def lifecycle_list(policy_type: str | None, enabled: bool | None, limit: int) -> None:
    """List active Policy DB records."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Policy

    init_db()
    with get_session() as session:
        q = session.query(Policy)
        if policy_type:
            q = q.filter(Policy.policy_type == policy_type)
        if enabled is not None:
            q = q.filter(Policy.enabled == enabled)
        q = q.order_by(Policy.created_at.desc()).limit(limit)
        rows = q.all()

    if not rows:
        console.print("[dim]No policies found.[/dim]")
        return

    table = Table(title=f"Policies ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Type", style="cyan")
    table.add_column("Priority", justify="right")
    table.add_column("Enabled")
    table.add_column("Created By", style="dim")
    table.add_column("Created At", style="dim")

    for p in rows:
        enabled_str = "[green]yes[/green]" if p.enabled else "[red]no[/red]"
        created = p.created_at.strftime("%Y-%m-%d") if p.created_at else "\u2014"
        table.add_row(
            p.id[:8],
            p.policy_type,
            str(p.priority),
            enabled_str,
            p.created_by or "",
            created,
        )

    console.print(table)


@lifecycle_grp.command("review-due")
@click.option("--days", type=int, default=30, help="Show policies expiring within N days")
def lifecycle_review_due(days: int) -> None:
    """List policies that are expiring or due for review."""
    from datetime import datetime, timedelta, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Policy

    init_db()
    cutoff = datetime.now(timezone.utc) + timedelta(days=days)

    with get_session() as session:
        rows = (
            session.query(Policy)
            .filter(Policy.enabled == True, Policy.expires_at <= cutoff)  # noqa: E712
            .order_by(Policy.expires_at.asc())
            .all()
        )

    if not rows:
        console.print(f"[green]No policies expiring within {days} days.[/green]")
        return

    table = Table(title=f"Policies Expiring Within {days} Days")
    table.add_column("ID", max_width=8)
    table.add_column("Type", style="cyan")
    table.add_column("Expires At", style="yellow")
    table.add_column("Description")

    for p in rows:
        expires = p.expires_at.strftime("%Y-%m-%d") if p.expires_at else "\u2014"
        table.add_row(p.id[:8], p.policy_type, expires, (p.description or "")[:60])

    console.print(table)


@lifecycle_grp.command("acknowledge")
@click.argument("policy_id")
@click.option("--actor", default=None, envvar="WLK_CLI_ACTOR", help="Actor identity")
@click.option("--reason", default="", help="Acknowledgment reason")
def lifecycle_acknowledge(policy_id: str, actor: str | None, reason: str) -> None:
    """Record acknowledgment of a policy (extends review timestamp in history)."""
    from datetime import datetime, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Policy, PolicyHistory

    actor = actor or "cli@warlock"
    init_db()

    with get_session() as session:
        policy = session.query(Policy).filter(Policy.id.startswith(policy_id)).first()
        if not policy:
            _error(f"Policy '{policy_id}' not found.")

        # Record acknowledgment in history
        history = PolicyHistory(
            policy_id=policy.id,
            action="acknowledged",
            old_rules=policy.rules,
            new_rules=policy.rules,
            actor=actor,
            timestamp=datetime.now(timezone.utc),
        )
        session.add(history)
        session.commit()
        console.print(
            f"[green]Policy {policy.id[:8]} ({policy.policy_type}) acknowledged by {actor}.[/green]"
        )
        if reason:
            console.print(f"  Reason: {reason}")
