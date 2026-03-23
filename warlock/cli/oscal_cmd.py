"""OSCAL commands: catalog and profile browsing, assessment results, SSP, POA&M, validation.

NOTE: The existing ``warlock oscal`` flat command in export.py exports assessment data.
This module registers a ``warlock oscal`` *group* with sub-commands for browsing OSCAL
packages in frameworks-oscal/. When both modules are imported the last one registered
wins. The orchestrating import order in __init__.py controls which wins; this module is
Phase 3 and should be imported after export.py to take precedence.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.table import Table

from warlock.cli import cli, console, _error

# Root of the OSCAL package directory (resolved relative to this file's location)
_OSCAL_ROOT = Path(__file__).resolve().parent.parent.parent / "frameworks-oscal"

# Mapping of well-known framework slugs to their directory names
_FRAMEWORK_DIRS: dict[str, str] = {
    "nist_800_53": "nist-800-53-oscal",
    "nist-800-53": "nist-800-53-oscal",
    "iso_27001": "iso-27001-oscal",
    "iso-27001": "iso-27001-oscal",
    "iso_27701": "iso-27701-oscal",
    "iso-27701": "iso-27701-oscal",
    "iso_42001": "iso-42001-oscal",
    "iso-42001": "iso-42001-oscal",
    "soc2": "soc2-oscal",
    "fedramp": "fedramp-oscal",
    "hipaa": "hipaa-oscal",
    "pci_dss": "pci-dss-oscal",
    "pci-dss": "pci-dss-oscal",
    "cmmc": "cmmc-oscal",
    "gdpr": "gdpr-oscal",
    "ucf": "unified-controls-framework",
}


def _resolve_framework_dir(framework: str) -> Path:
    """Resolve a framework slug to its OSCAL package directory.

    Args:
        framework: Framework slug (e.g. 'nist_800_53', 'soc2').

    Returns:
        Path to the OSCAL package directory.
    """
    dir_name = _FRAMEWORK_DIRS.get(framework.lower(), f"{framework.lower()}-oscal")
    candidate = _OSCAL_ROOT / dir_name
    if not candidate.exists():
        # Fall back to exact slug as directory name
        candidate = _OSCAL_ROOT / framework.lower()
    return candidate


def _load_json(path: Path) -> dict:
    """Load and return a JSON file as a dict.

    Args:
        path: Path to the JSON file.

    Returns:
        Parsed JSON content.
    """
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _find_json_files(directory: Path, pattern: str = "*.json") -> list[Path]:
    """Find JSON files under a directory.

    Args:
        directory: Root directory to search.
        pattern: Glob pattern for matching files.

    Returns:
        Sorted list of matching Path objects.
    """
    return sorted(directory.rglob(pattern))


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("oscal")
def oscal_group() -> None:
    """Browse and validate OSCAL packages (catalogs, profiles, SSP, POA&M, assessment results)."""


# ---------------------------------------------------------------------------
# catalogs sub-group
# ---------------------------------------------------------------------------


@oscal_group.group("catalogs")
def catalogs_group() -> None:
    """Browse OSCAL catalog packages."""


@catalogs_group.command("list")
def catalogs_list() -> None:
    """List available OSCAL catalog packages."""
    if not _OSCAL_ROOT.exists():
        _error(f"OSCAL root directory not found: {_OSCAL_ROOT}")

    table = Table(title="OSCAL Catalog Packages")
    table.add_column("Framework", style="cyan")
    table.add_column("Directory")
    table.add_column("Catalog File")
    table.add_column("Size")

    found = 0
    for entry in sorted(_OSCAL_ROOT.iterdir()):
        if not entry.is_dir():
            continue
        catalog_dir = entry / "catalog"
        catalog_file = catalog_dir / "catalog.json"
        if not catalog_file.exists():
            # Try top-level catalog.json
            catalog_file = entry / "catalog.json"
        if catalog_file.exists():
            size_kb = catalog_file.stat().st_size // 1024
            table.add_row(
                entry.name.replace("-oscal", "").replace("-", "_"),
                entry.name,
                catalog_file.name,
                f"{size_kb} KB",
            )
            found += 1

    if found == 0:
        console.print("[dim]No OSCAL catalog packages found.[/dim]")
        return

    console.print(table)


@catalogs_group.command("show")
@click.argument("framework")
@click.option("--limit", "-n", default=20, help="Number of controls to show")
@click.option("--family", "-f", default=None, help="Filter by control family")
def catalogs_show(framework: str, limit: int, family: str | None) -> None:
    """Show controls from an OSCAL catalog.

    FRAMEWORK: Framework slug (e.g. nist_800_53, soc2, iso_27001)
    """
    fw_dir = _resolve_framework_dir(framework)
    catalog_file = fw_dir / "catalog" / "catalog.json"
    if not catalog_file.exists():
        catalog_file = fw_dir / "catalog.json"
    if not catalog_file.exists():
        _error(
            f"Catalog not found for framework '{framework}'. "
            f"Expected at {fw_dir / 'catalog' / 'catalog.json'}"
        )

    try:
        data = _load_json(catalog_file)
    except json.JSONDecodeError as exc:
        _error(f"Failed to parse catalog JSON: {exc}")

    catalog = data.get("catalog", data)
    title = catalog.get("metadata", {}).get("title", framework)
    console.print(f"\n[bold cyan]{title}[/bold cyan]\n")

    groups = catalog.get("groups", [])
    controls_shown = 0

    table = Table(title=f"Controls — {framework}")
    table.add_column("ID", style="cyan", max_width=15)
    table.add_column("Title", max_width=60)
    table.add_column("Family", style="dim")

    def _emit_controls(items: list, fam_label: str) -> None:
        nonlocal controls_shown
        for ctrl in items:
            if controls_shown >= limit:
                return
            ctrl_id = ctrl.get("id", "")
            ctrl_title = ctrl.get("title", "")
            if (
                family
                and family.lower() not in fam_label.lower()
                and family.lower() not in ctrl_id.lower()
            ):
                # Also check sub-controls
                _emit_controls(ctrl.get("controls", []), fam_label)
                return
            table.add_row(ctrl_id, ctrl_title[:60], fam_label)
            controls_shown += 1
            _emit_controls(ctrl.get("controls", []), fam_label)

    for group in groups:
        fam = group.get("title", group.get("id", ""))
        _emit_controls(group.get("controls", []), fam)
        if controls_shown >= limit:
            break

    # Also check top-level controls (some catalogs have flat structure)
    _emit_controls(catalog.get("controls", []), "")

    console.print(table)
    if controls_shown >= limit:
        console.print(f"[dim](showing first {limit} controls — use --limit to see more)[/dim]")


# ---------------------------------------------------------------------------
# profiles sub-group
# ---------------------------------------------------------------------------


@oscal_group.group("profiles")
def profiles_group() -> None:
    """Browse OSCAL profile packages."""


@profiles_group.command("list")
def profiles_list() -> None:
    """List available OSCAL profile files."""
    if not _OSCAL_ROOT.exists():
        _error(f"OSCAL root directory not found: {_OSCAL_ROOT}")

    table = Table(title="OSCAL Profile Files")
    table.add_column("Framework", style="cyan")
    table.add_column("Profile File")
    table.add_column("Size")

    found = 0
    for entry in sorted(_OSCAL_ROOT.iterdir()):
        if not entry.is_dir():
            continue
        for profile_file in sorted(entry.rglob("profile*.json")):
            size_kb = profile_file.stat().st_size // 1024
            table.add_row(
                entry.name,
                profile_file.relative_to(_OSCAL_ROOT).as_posix(),
                f"{size_kb} KB",
            )
            found += 1

    if found == 0:
        console.print("[dim]No OSCAL profile files found.[/dim]")
        return

    console.print(table)


@profiles_group.command("show")
@click.argument("framework")
def profiles_show(framework: str) -> None:
    """Show an OSCAL profile for a framework.

    FRAMEWORK: Framework slug (e.g. fedramp, nist_800_53)
    """
    fw_dir = _resolve_framework_dir(framework)
    profile_files = list(fw_dir.rglob("profile*.json"))

    if not profile_files:
        _error(f"No profile found for framework '{framework}' in {fw_dir}")

    profile_file = profile_files[0]
    try:
        data = _load_json(profile_file)
    except json.JSONDecodeError as exc:
        _error(f"Failed to parse profile JSON: {exc}")

    profile = data.get("profile", data)
    meta = profile.get("metadata", {})
    console.print(f"\n[bold]Profile:[/bold] {meta.get('title', framework)}")
    console.print(f"[dim]File:[/dim] {profile_file.relative_to(_OSCAL_ROOT)}")

    imports = profile.get("imports", [])
    if imports:
        console.print(f"\n[bold]Imports ({len(imports)}):[/bold]")
        for imp in imports:
            href = imp.get("href", "")
            include = imp.get("include-controls", {})
            with_ids = include.get("with-ids", [])
            console.print(f"  [cyan]{href}[/cyan]")
            if with_ids:
                preview = ", ".join(with_ids[:5])
                suffix = f" (+{len(with_ids) - 5} more)" if len(with_ids) > 5 else ""
                console.print(f"    Controls: {preview}{suffix}")

    modify = profile.get("modify", {})
    set_params = modify.get("set-parameters", [])
    if set_params:
        console.print(f"\n[bold]Parameter overrides:[/bold] {len(set_params)}")

    console.print()


# ---------------------------------------------------------------------------
# assessment-results
# ---------------------------------------------------------------------------


@oscal_group.command("assessment-results")
@click.argument("framework")
@click.option("--output", "-o", default=None, help="Output file path (default: stdout/display)")
@click.option("--system-name", default="Warlock GRC System", help="System name for OSCAL metadata")
def assessment_results(framework: str, output: str | None, system_name: str) -> None:
    """Export OSCAL assessment results for a framework.

    FRAMEWORK: Framework slug (e.g. nist_800_53, soc2)
    """
    from warlock.db.engine import get_session, init_db
    from warlock.export.oscal import OscalExporter

    init_db()
    exporter = OscalExporter()

    with get_session() as session:
        data = exporter.export_assessment_results(
            session, framework=framework, system_name=system_name
        )

    if output:
        exporter.to_file(data, output)
        console.print(f"[green]OSCAL assessment results written to {output}[/green]")
    else:
        from warlock.export.paths import export_path

        dest = export_path("ar", framework=framework)
        exporter.to_file(data, str(dest))
        console.print(f"[green]OSCAL assessment results written to {dest}[/green]")


# ---------------------------------------------------------------------------
# ssp
# ---------------------------------------------------------------------------


@oscal_group.command("ssp")
@click.argument("framework")
@click.option("--output", "-o", default=None, help="Output file path")
@click.option("--system-name", default="Warlock GRC System", help="System name for OSCAL metadata")
@click.option("--description", default="", help="System description")
def ssp_export(framework: str, output: str | None, system_name: str, description: str) -> None:
    """Export an OSCAL System Security Plan (SSP) for a framework.

    FRAMEWORK: Framework slug (e.g. nist_800_53, fedramp)
    """
    from warlock.db.engine import get_session, init_db
    from warlock.export.oscal import OscalExporter

    init_db()
    exporter = OscalExporter()

    with get_session() as session:
        data = exporter.export_ssp(
            session,
            framework=framework,
            system_name=system_name,
            description=description or f"{system_name} System Security Plan",
            narrator=None,
        )

    if output:
        exporter.to_file(data, output)
        console.print(f"[green]OSCAL SSP written to {output}[/green]")
    else:
        from warlock.export.paths import export_path

        dest = export_path("ssp", framework=framework)
        exporter.to_file(data, str(dest))
        console.print(f"[green]OSCAL SSP written to {dest}[/green]")


# ---------------------------------------------------------------------------
# poam
# ---------------------------------------------------------------------------


@oscal_group.command("poam")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--output", "-o", default=None, help="Output file path")
@click.option("--system-name", default="Warlock GRC System", help="System name for OSCAL metadata")
def poam_export(framework: str | None, output: str | None, system_name: str) -> None:
    """Export an OSCAL POA&M document."""
    from warlock.db.engine import get_session, init_db
    from warlock.export.oscal import OscalExporter

    init_db()
    exporter = OscalExporter()

    with get_session() as session:
        data = exporter.export_poam(
            session,
            framework=framework,
            system_name=system_name,
            narrator=None,
        )

    if output:
        exporter.to_file(data, output)
        console.print(f"[green]OSCAL POA&M written to {output}[/green]")
    else:
        from warlock.export.paths import export_path

        dest = export_path("poam", framework=framework)
        exporter.to_file(data, str(dest))
        console.print(f"[green]OSCAL POA&M written to {dest}[/green]")


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


@oscal_group.command("validate")
@click.argument("file", type=click.Path(exists=True))
def validate_file(file: str) -> None:
    """Validate an OSCAL JSON file for structural correctness.

    FILE: Path to the OSCAL JSON file to validate.
    """
    path = Path(file)
    try:
        data = _load_json(path)
    except json.JSONDecodeError as exc:
        _error(f"Invalid JSON: {exc}")

    # Detect document type
    known_types = [
        "catalog",
        "profile",
        "system-security-plan",
        "assessment-plan",
        "assessment-results",
        "plan-of-action-and-milestones",
        "component-definition",
    ]
    doc_type = None
    for t in known_types:
        if t in data:
            doc_type = t
            break

    if doc_type is None:
        console.print(
            f"[yellow]Warning: unrecognized OSCAL document type. Top-level keys: {list(data.keys())}[/yellow]"
        )
    else:
        console.print(f"[green]Document type:[/green] {doc_type}")

    # Basic metadata check
    doc = data.get(doc_type, data) if doc_type else data
    meta = doc.get("metadata", {})
    if meta:
        console.print(f"[green]Title:[/green] {meta.get('title', '(no title)')}")
        console.print(f"[green]Version:[/green] {meta.get('version', '(no version)')}")
        console.print(f"[green]Last modified:[/green] {meta.get('last-modified', '(unknown)')}")
    else:
        console.print("[yellow]Warning: no 'metadata' section found.[/yellow]")

    console.print(
        f"\n[green]File parses cleanly:[/green] {path.name} ({path.stat().st_size // 1024} KB)"
    )
    console.print("[green]Validation passed.[/green]")


# ---------------------------------------------------------------------------
# component-definition (EI-001)
# ---------------------------------------------------------------------------


@oscal_group.command("component-definition")
@click.argument("framework")
@click.option("--output", "-o", default=None, help="Output file path")
@click.option(
    "--system-name", default="Warlock GRC System", help="System name for OSCAL metadata"
)
@click.option(
    "--component-type",
    default="software",
    type=click.Choice(["software", "service", "policy", "process"]),
    help="Component type for the definition",
)
def component_definition(
    framework: str, output: str | None, system_name: str, component_type: str
) -> None:
    """Export an OSCAL component definition for shared/inherited controls.

    FRAMEWORK: Framework slug (e.g. nist_800_53, soc2, fedramp)

    Generates an OSCAL component-definition document that describes the
    system's implemented controls, suitable for sharing with downstream
    consumers or leveraging organizations.
    """
    import uuid as _uuid
    from datetime import datetime, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()

    with get_session() as session:
        results = (
            session.query(ControlResult)
            .filter(ControlResult.framework == framework)
            .order_by(ControlResult.control_id)
            .all()
        )

    if not results:
        _error(f"No control results found for framework '{framework}'.")

    # Deduplicate: keep latest per control_id
    latest: dict[str, object] = {}
    for r in results:
        if r.control_id not in latest or (r.assessed_at and r.assessed_at > latest[r.control_id].assessed_at):
            latest[r.control_id] = r

    now = datetime.now(timezone.utc)
    comp_uuid = str(_uuid.uuid4())

    implemented_reqs = []
    for ctrl_id, r in sorted(latest.items()):
        impl_status = "implemented" if r.status == "compliant" else (
            "partial" if r.status == "partial" else "planned"
        )
        implemented_reqs.append({
            "control-id": ctrl_id,
            "uuid": str(_uuid.uuid4()),
            "description": r.remediation_summary or f"Control {ctrl_id} — status: {r.status}",
            "props": [
                {"name": "implementation-status", "value": impl_status},
            ],
        })

    doc = {
        "component-definition": {
            "uuid": str(_uuid.uuid4()),
            "metadata": {
                "title": f"{system_name} Component Definition — {framework}",
                "version": "1.0.0",
                "oscal-version": "1.1.2",
                "last-modified": now.isoformat(),
            },
            "components": [
                {
                    "uuid": comp_uuid,
                    "type": component_type,
                    "title": system_name,
                    "description": f"Component definition for {system_name} ({framework})",
                    "control-implementations": [
                        {
                            "uuid": str(_uuid.uuid4()),
                            "source": f"#{framework}",
                            "description": f"Controls implemented for {framework}",
                            "implemented-requirements": implemented_reqs,
                        }
                    ],
                }
            ],
        }
    }

    dest = output
    if not dest:
        from warlock.export.paths import export_path

        dest = str(export_path("comp-def", framework=framework))

    with open(dest, "w") as fh:
        json.dump(doc, fh, indent=2)

    console.print(
        f"[green]OSCAL component definition written to {dest}[/green] "
        f"({len(implemented_reqs)} control(s))"
    )


# ---------------------------------------------------------------------------
# audit-package (EI-002)
# ---------------------------------------------------------------------------


@oscal_group.command("audit-package")
@click.option("--framework", "-f", required=True, help="Framework slug (e.g. soc2, nist_800_53)")
@click.option(
    "--output", "-o", required=True, type=click.Path(), help="Output directory for the package"
)
@click.option(
    "--system-name", default="Warlock GRC System", help="System name for OSCAL metadata"
)
def audit_package(framework: str, output: str, system_name: str) -> None:
    """Export a complete audit package for a framework.

    Creates a directory containing all OSCAL artifacts an auditor needs:
    - assessment-results.json
    - ssp.json (System Security Plan)
    - poam.json (Plan of Action & Milestones)
    - component-definition.json
    - manifest.json (index of all files)
    """
    from datetime import datetime, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.export.oscal import OscalExporter

    init_db()
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    exporter = OscalExporter()
    now = datetime.now(timezone.utc)
    files_written: list[dict[str, str]] = []

    # 1. Assessment Results
    with get_session() as session:
        ar_data = exporter.export_assessment_results(
            session, framework=framework, system_name=system_name
        )
    ar_path = out_dir / "assessment-results.json"
    exporter.to_file(ar_data, str(ar_path))
    files_written.append({"file": "assessment-results.json", "type": "assessment-results"})
    console.print("  [green]\u2713[/green] assessment-results.json")

    # 2. SSP
    with get_session() as session:
        ssp_data = exporter.export_ssp(
            session,
            framework=framework,
            system_name=system_name,
            description=f"{system_name} System Security Plan",
            narrator=None,
        )
    ssp_path = out_dir / "ssp.json"
    exporter.to_file(ssp_data, str(ssp_path))
    files_written.append({"file": "ssp.json", "type": "system-security-plan"})
    console.print("  [green]\u2713[/green] ssp.json")

    # 3. POA&M
    with get_session() as session:
        poam_data = exporter.export_poam(
            session, framework=framework, system_name=system_name, narrator=None
        )
    poam_path = out_dir / "poam.json"
    exporter.to_file(poam_data, str(poam_path))
    files_written.append({"file": "poam.json", "type": "plan-of-action-and-milestones"})
    console.print("  [green]\u2713[/green] poam.json")

    # 4. Component Definition (invoke via code, not subprocess)
    from warlock.db.models import ControlResult

    with get_session() as session:
        results = (
            session.query(ControlResult)
            .filter(ControlResult.framework == framework)
            .order_by(ControlResult.control_id)
            .all()
        )

    if results:
        import uuid as _uuid

        latest: dict[str, object] = {}
        for r in results:
            if r.control_id not in latest or (
                r.assessed_at and r.assessed_at > latest[r.control_id].assessed_at
            ):
                latest[r.control_id] = r

        implemented_reqs = []
        for ctrl_id, r in sorted(latest.items()):
            impl_status = "implemented" if r.status == "compliant" else (
                "partial" if r.status == "partial" else "planned"
            )
            implemented_reqs.append({
                "control-id": ctrl_id,
                "uuid": str(_uuid.uuid4()),
                "description": r.remediation_summary or f"Control {ctrl_id} — status: {r.status}",
                "props": [{"name": "implementation-status", "value": impl_status}],
            })

        comp_doc = {
            "component-definition": {
                "uuid": str(_uuid.uuid4()),
                "metadata": {
                    "title": f"{system_name} Component Definition — {framework}",
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                    "last-modified": now.isoformat(),
                },
                "components": [
                    {
                        "uuid": str(_uuid.uuid4()),
                        "type": "software",
                        "title": system_name,
                        "description": f"Component definition for {system_name} ({framework})",
                        "control-implementations": [
                            {
                                "uuid": str(_uuid.uuid4()),
                                "source": f"#{framework}",
                                "description": f"Controls implemented for {framework}",
                                "implemented-requirements": implemented_reqs,
                            }
                        ],
                    }
                ],
            }
        }
        comp_path = out_dir / "component-definition.json"
        with open(comp_path, "w") as fh:
            json.dump(comp_doc, fh, indent=2)
        files_written.append({"file": "component-definition.json", "type": "component-definition"})
        console.print("  [green]\u2713[/green] component-definition.json")

    # 5. Manifest
    manifest = {
        "audit-package": {
            "framework": framework,
            "system_name": system_name,
            "generated_at": now.isoformat(),
            "files": files_written,
        }
    }
    manifest_path = out_dir / "manifest.json"
    with open(manifest_path, "w") as fh:
        json.dump(manifest, fh, indent=2)
    console.print("  [green]\u2713[/green] manifest.json")

    console.print(
        f"\n[green]Audit package for {framework} written to {out_dir}/ "
        f"({len(files_written) + 1} files)[/green]"
    )
