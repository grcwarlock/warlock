"""Terraform IaC management commands: modules (list, show), validate, plan, drift,
compliance.

Works with the terraform/ directory (12 modules across AWS, Azure, GCP).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import click
from rich.table import Table

from warlock.cli import cli, console, _error

# Terraform root, relative to the repo root (two levels up from this file)
_TF_ROOT = Path(__file__).resolve().parent.parent.parent / "terraform"
_TF_MODULES_ROOT = _TF_ROOT / "modules"

# Cloud providers and their sub-module directories
_CLOUD_PROVIDERS = ["aws", "azure", "gcp"]


def _find_modules() -> list[dict]:
    """Discover all Terraform modules under terraform/modules/.

    Returns:
        List of dicts with keys: cloud, name, path, has_main, has_variables, has_outputs.
    """
    modules: list[dict] = []
    if not _TF_MODULES_ROOT.exists():
        return modules

    for provider in _CLOUD_PROVIDERS:
        provider_dir = _TF_MODULES_ROOT / provider
        if not provider_dir.exists():
            continue
        for module_dir in sorted(provider_dir.iterdir()):
            if not module_dir.is_dir():
                continue
            modules.append(
                {
                    "cloud": provider,
                    "name": module_dir.name,
                    "path": module_dir,
                    "has_main": (module_dir / "main.tf").exists(),
                    "has_variables": (module_dir / "variables.tf").exists(),
                    "has_outputs": (module_dir / "outputs.tf").exists(),
                }
            )
    return modules


def _run_tf(args: list[str], cwd: Path, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a terraform command.

    Args:
        args: terraform sub-command arguments.
        cwd: Working directory for the terraform command.
        capture: If True, capture stdout/stderr; otherwise stream to terminal.

    Returns:
        CompletedProcess result.
    """
    cmd = ["terraform"] + args
    if capture:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)
    else:
        return subprocess.run(cmd, cwd=cwd, timeout=300)


def _terraform_available() -> bool:
    """Check if the terraform binary is available on PATH."""
    import shutil

    return shutil.which("terraform") is not None


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("terraform")
def terraform_group() -> None:
    """Terraform IaC management: module browsing, validation, drift detection, compliance."""


# ---------------------------------------------------------------------------
# modules sub-group
# ---------------------------------------------------------------------------


@terraform_group.group("modules")
def modules_group() -> None:
    """Browse Terraform modules."""


@modules_group.command("list")
@click.option(
    "--cloud",
    "-c",
    default=None,
    type=click.Choice(["aws", "azure", "gcp"]),
    help="Filter by cloud provider",
)
def modules_list(cloud: str | None) -> None:
    """List available Terraform modules."""
    if not _TF_MODULES_ROOT.exists():
        _error(f"Terraform modules directory not found: {_TF_MODULES_ROOT}")

    all_modules = _find_modules()
    if cloud:
        all_modules = [m for m in all_modules if m["cloud"] == cloud]

    if not all_modules:
        console.print("[dim]No Terraform modules found.[/dim]")
        return

    table = Table(title=f"Terraform Modules ({len(all_modules)})")
    table.add_column("Cloud", style="cyan")
    table.add_column("Module Name")
    table.add_column("main.tf", justify="center")
    table.add_column("variables.tf", justify="center")
    table.add_column("outputs.tf", justify="center")
    table.add_column("Path", style="dim")

    for m in all_modules:
        _y = "[green]Y[/green]"
        _n = "[dim].[/dim]"
        table.add_row(
            m["cloud"],
            m["name"],
            _y if m["has_main"] else _n,
            _y if m["has_variables"] else _n,
            _y if m["has_outputs"] else _n,
            str(m["path"].relative_to(_TF_ROOT)),
        )

    console.print(table)


@modules_group.command("show")
@click.argument("module")
@click.option("--cloud", "-c", default=None, help="Cloud provider (aws, azure, gcp)")
def modules_show(module: str, cloud: str | None) -> None:
    """Show details for a specific Terraform module.

    MODULE: Module name (e.g. iam-baseline, compliant-vpc)
    """
    all_modules = _find_modules()
    candidates = [m for m in all_modules if m["name"] == module]
    if cloud:
        candidates = [m for m in candidates if m["cloud"] == cloud]

    if not candidates:
        _error(f"Module '{module}' not found. Use 'warlock terraform modules list' to browse.")

    mod = candidates[0]
    if len(candidates) > 1:
        console.print(
            f"[yellow]Multiple modules named '{module}' found. Showing first ({mod['cloud']}).[/yellow]"
        )

    console.print(f"\n[bold cyan]{mod['cloud'].upper()} / {mod['name']}[/bold cyan]")
    console.print(f"[dim]Path:[/dim] {mod['path']}\n")

    for tf_file in sorted(mod["path"].glob("*.tf")):
        content = tf_file.read_text(encoding="utf-8")
        lines = content.splitlines()
        console.print(f"[bold]{tf_file.name}[/bold] ({len(lines)} lines)")

        # Show first 20 meaningful lines (skip blank/comment lines)
        shown = 0
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                console.print(f"  [dim]{line}[/dim]")
                shown += 1
                if shown >= 20:
                    remaining = (
                        len([ln for ln in lines if ln.strip() and not ln.strip().startswith("#")])
                        - 20
                    )
                    if remaining > 0:
                        console.print(f"  [dim]... ({remaining} more lines)[/dim]")
                    break
        console.print()


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


@terraform_group.command("validate")
@click.option(
    "--cloud",
    "-c",
    default=None,
    type=click.Choice(["aws", "azure", "gcp"]),
    help="Validate only modules for this cloud provider",
)
@click.option("--module", "-m", default=None, help="Validate only this module name")
def terraform_validate(cloud: str | None, module: str | None) -> None:
    """Run terraform validate on all modules (or a specific module)."""
    if not _terraform_available():
        _error(
            "terraform not found on PATH. Install from https://developer.hashicorp.com/terraform"
        )

    all_modules = _find_modules()
    if cloud:
        all_modules = [m for m in all_modules if m["cloud"] == cloud]
    if module:
        all_modules = [m for m in all_modules if m["name"] == module]

    if not all_modules:
        _error("No modules match the given filters.")

    results: list[dict] = []
    for mod in all_modules:
        # terraform init -backend=false -input=false (quiet)
        init_result = _run_tf(
            ["-chdir=" + str(mod["path"]), "init", "-backend=false", "-input=false"], cwd=_TF_ROOT
        )
        if init_result.returncode != 0:
            results.append(
                {"mod": mod, "ok": False, "msg": "init failed: " + init_result.stderr[:200]}
            )
            continue

        val_result = _run_tf(["-chdir=" + str(mod["path"]), "validate", "-no-color"], cwd=_TF_ROOT)
        ok = val_result.returncode == 0
        msg = (val_result.stdout + val_result.stderr).strip()[:200] if not ok else "OK"
        results.append({"mod": mod, "ok": ok, "msg": msg})

    table = Table(title="Terraform Validate Results")
    table.add_column("Cloud", style="cyan")
    table.add_column("Module")
    table.add_column("Result")
    table.add_column("Message", max_width=50)

    for r in results:
        ok_str = "[green]PASS[/green]" if r["ok"] else "[red]FAIL[/red]"
        table.add_row(r["mod"]["cloud"], r["mod"]["name"], ok_str, r["msg"])

    console.print(table)
    failed = [r for r in results if not r["ok"]]
    if failed:
        console.print(f"\n[red]{len(failed)} module(s) failed validation.[/red]")
        raise SystemExit(1)
    else:
        console.print(f"[green]All {len(results)} module(s) validated successfully.[/green]")


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------


@terraform_group.command("plan")
@click.argument("module")
@click.option("--cloud", "-c", default=None, help="Cloud provider (aws, azure, gcp)")
@click.option("--var-file", default=None, help="Path to a .tfvars file")
def terraform_plan(module: str, cloud: str | None, var_file: str | None) -> None:
    """Run terraform plan for a specific module (dry-run, no apply).

    MODULE: Module name (e.g. iam-baseline).

    Note: terraform plan requires valid credentials for the target cloud.
    Use --var-file to provide variable overrides.
    """
    if not _terraform_available():
        _error("terraform not found on PATH.")

    all_modules = _find_modules()
    candidates = [m for m in all_modules if m["name"] == module]
    if cloud:
        candidates = [m for m in candidates if m["cloud"] == cloud]

    if not candidates:
        _error(f"Module '{module}' not found.")

    mod = candidates[0]
    console.print(f"[cyan]Planning {mod['cloud']}/{mod['name']}...[/cyan]")

    # init
    init_res = _run_tf(
        ["-chdir=" + str(mod["path"]), "init", "-backend=false", "-input=false"],
        cwd=_TF_ROOT,
    )
    if init_res.returncode != 0:
        _error(f"terraform init failed:\n{init_res.stderr}")

    plan_args = ["-chdir=" + str(mod["path"]), "plan", "-input=false", "-no-color"]
    if var_file:
        plan_args.append(f"-var-file={var_file}")

    # Stream plan output to terminal
    plan_res = _run_tf(plan_args, cwd=_TF_ROOT, capture=False)
    if plan_res.returncode not in (0, 2):  # 0=no changes, 2=changes present
        raise SystemExit(plan_res.returncode)


# ---------------------------------------------------------------------------
# drift
# ---------------------------------------------------------------------------


@terraform_group.command("drift")
@click.option(
    "--cloud",
    "-c",
    default=None,
    type=click.Choice(["aws", "azure", "gcp"]),
    help="Check drift only for this cloud",
)
def terraform_drift(cloud: str | None) -> None:
    """Check for configuration drift by running terraform plan -detailed-exitcode.

    Exit code 0: no drift. Exit code 2: drift detected. Requires cloud credentials.
    """
    if not _terraform_available():
        _error("terraform not found on PATH.")

    all_modules = _find_modules()
    if cloud:
        all_modules = [m for m in all_modules if m["cloud"] == cloud]

    if not all_modules:
        _error("No modules to check.")

    console.print(f"[cyan]Checking drift for {len(all_modules)} module(s)...[/cyan]\n")

    drifted: list[str] = []
    errors: list[str] = []

    for mod in all_modules:
        _run_tf(
            ["-chdir=" + str(mod["path"]), "init", "-backend=false", "-input=false"],
            cwd=_TF_ROOT,
        )
        plan_res = _run_tf(
            [
                "-chdir=" + str(mod["path"]),
                "plan",
                "-detailed-exitcode",
                "-input=false",
                "-no-color",
            ],
            cwd=_TF_ROOT,
        )
        label = f"{mod['cloud']}/{mod['name']}"
        if plan_res.returncode == 0:
            console.print(f"  [green]No drift:[/green] {label}")
        elif plan_res.returncode == 2:
            console.print(f"  [yellow]DRIFT DETECTED:[/yellow] {label}")
            drifted.append(label)
        else:
            console.print(f"  [red]Error:[/red] {label} (check credentials)")
            errors.append(label)

    console.print()
    if drifted:
        console.print(f"[yellow]{len(drifted)} module(s) have drift.[/yellow]")
    if errors:
        console.print(
            f"[red]{len(errors)} module(s) had errors (likely missing credentials).[/red]"
        )
    if not drifted and not errors:
        console.print(f"[green]No drift detected in {len(all_modules)} module(s).[/green]")


# ---------------------------------------------------------------------------
# compliance
# ---------------------------------------------------------------------------


@terraform_group.command("compliance")
@click.option(
    "--cloud",
    "-c",
    default=None,
    type=click.Choice(["aws", "azure", "gcp"]),
    help="Check only this cloud provider's modules",
)
@click.option(
    "--framework", "-f", default=None, help="Framework to check compliance for (informational)"
)
def terraform_compliance(cloud: str | None, framework: str | None) -> None:
    """Show Terraform module compliance coverage by framework.

    This command maps Terraform modules to the compliance frameworks they
    support and shows structural compliance (module presence, variable
    completeness, output definitions).
    """
    # Framework-to-module mapping (which modules satisfy which frameworks)
    _FRAMEWORK_MODULE_MAP: dict[str, list[str]] = {
        "nist_800_53": [
            "iam-baseline",
            "secure-account-baseline",
            "cloudtrail-org",
            "config-rules",
            "guardduty-org",
            "kms-baseline",
            "key-vault-baseline",
            "secure-subscription-baseline",
            "secure-project-baseline",
        ],
        "fedramp": [
            "iam-baseline",
            "cloudtrail-org",
            "config-rules",
            "guardduty-org",
            "kms-baseline",
            "compliant-vpc",
        ],
        "hipaa": [
            "iam-baseline",
            "kms-baseline",
            "cloudtrail-org",
            "key-vault-baseline",
            "secure-project-baseline",
        ],
        "pci_dss": [
            "compliant-vpc",
            "iam-baseline",
            "kms-baseline",
            "config-rules",
            "cloudtrail-org",
        ],
        "soc2": [
            "iam-baseline",
            "cloudtrail-org",
            "config-rules",
            "secure-account-baseline",
        ],
        "iso_27001": [
            "iam-baseline",
            "kms-baseline",
            "secure-account-baseline",
            "key-vault-baseline",
            "secure-project-baseline",
        ],
    }

    all_modules = _find_modules()
    module_names = {m["name"] for m in all_modules}

    if cloud:
        cloud_modules = {m["name"] for m in all_modules if m["cloud"] == cloud}
    else:
        cloud_modules = module_names

    frameworks_to_check = (
        {framework: _FRAMEWORK_MODULE_MAP.get(framework, [])}
        if framework and framework in _FRAMEWORK_MODULE_MAP
        else _FRAMEWORK_MODULE_MAP
    )

    table = Table(title="Terraform Compliance Coverage")
    table.add_column("Framework", style="cyan")
    table.add_column("Required Modules", justify="right")
    table.add_column("Present", justify="right")
    table.add_column("Missing", justify="right")
    table.add_column("Coverage %", justify="right")
    table.add_column("Missing Modules", max_width=45)

    for fw, required_modules in sorted(frameworks_to_check.items()):
        if cloud:
            # Filter to only modules relevant to this cloud provider
            relevant = [m for m in required_modules if m in cloud_modules or m in module_names]
        else:
            relevant = required_modules

        present = [m for m in relevant if m in module_names]
        missing = [m for m in relevant if m not in module_names]
        total = len(relevant)
        coverage = (len(present) / total * 100) if total > 0 else 0.0
        cov_style = "green" if coverage >= 80 else ("yellow" if coverage >= 60 else "red")
        missing_str = ", ".join(missing[:3])
        if len(missing) > 3:
            missing_str += f" (+{len(missing) - 3})"

        table.add_row(
            fw,
            str(total),
            str(len(present)),
            str(len(missing)),
            f"[{cov_style}]{coverage:.0f}%[/{cov_style}]",
            missing_str or "[green]none[/green]",
        )

    console.print(table)
    console.print(
        f"\n[dim]Based on {len(all_modules)} modules in {_TF_MODULES_ROOT.relative_to(_TF_ROOT.parent)}[/dim]"
    )
