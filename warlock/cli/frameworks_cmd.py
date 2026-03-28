"""CLI commands for framework exploration and management.

Groups:
  warlock frameworks list          -- list all loaded frameworks
  warlock frameworks show          -- show framework details
  warlock frameworks controls      -- list controls for a framework
  warlock frameworks compare       -- compare two frameworks
  warlock frameworks crosswalk     -- show crosswalk mappings
  warlock frameworks coverage      -- show control coverage from DB
  warlock frameworks gaps          -- show controls with no findings
  warlock frameworks heatmap       -- compliance heatmap by family
  warlock frameworks stats         -- aggregate statistics
  warlock frameworks export        -- export framework definition
  warlock frameworks event-types   -- list event types for a framework
  warlock frameworks connectors    -- list connectors for a framework
  warlock frameworks calendar      -- show monitoring frequency calendar
  warlock frameworks inheritance   -- show inheritance report
  warlock frameworks baselines ... -- baseline management sub-group
  warlock frameworks inherited ... -- inherited controls sub-group
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import click
import yaml
from rich.table import Table

from warlock.cli import cli, console, _error

_FRAMEWORKS_DIR = pathlib.Path(__file__).resolve().parent.parent / "frameworks"
_REFERENCE_DIR = _FRAMEWORKS_DIR / "reference"

_FRAMEWORK_DISPLAY_NAMES: dict[str, str] = {
    "nist_800_53": "NIST 800-53",
    "iso_27001": "ISO 27001",
    "iso_27701": "ISO 27701",
    "iso_42001": "ISO 42001",
    "soc2": "SOC 2",
    "ucf": "UCF",
    "fedramp": "FedRAMP",
    "hipaa": "HIPAA",
    "cmmc_l2": "CMMC L2",
    "gdpr": "GDPR",
    "pci_dss": "PCI DSS v4.0",
    "nist_csf": "NIST CSF 2.0",
    "eu_ai_act": "EU AI Act",
    "sec_cyber": "SEC Cyber",
}


def _load_framework_yaml(framework_id: str) -> dict[str, Any]:
    """Load a single framework YAML by framework_id (e.g. 'nist_800_53')."""
    yaml_path = _FRAMEWORKS_DIR / f"{framework_id}.yaml"
    if not yaml_path.exists():
        _error(f"Framework YAML not found: {yaml_path}")
    with open(yaml_path) as fh:
        data = yaml.safe_load(fh) or {}
    return data


def _iter_all_frameworks() -> list[dict[str, Any]]:
    """Return parsed data for all non-crosswalk framework YAMLs."""
    results: list[dict[str, Any]] = []
    for yaml_file in sorted(_FRAMEWORKS_DIR.glob("*.yaml")):
        if yaml_file.stem.startswith("crosswalk") or yaml_file.stem in (
            "diff",
            "soc2_points_of_focus",
        ):
            continue
        try:
            data = yaml.safe_load(yaml_file.read_text()) or {}
        except Exception:
            continue
        data.setdefault("_file", yaml_file.stem)
        results.append(data)
    return results


def _count_controls(data: dict[str, Any]) -> int:
    """Count total controls across all families in a framework YAML."""
    families = data.get("control_families", {})
    return sum(len(v.get("controls", {})) for v in families.values())


def _collect_controls(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Flatten all controls from a framework YAML into {control_id: control_data}."""
    result: dict[str, dict[str, Any]] = {}
    for _family_id, family in data.get("control_families", {}).items():
        for ctrl_id, ctrl_data in (family.get("controls") or {}).items():
            result[ctrl_id] = ctrl_data or {}
    return result


def _collect_event_types(controls: dict[str, dict[str, Any]]) -> set[str]:
    """Gather all event_types across all checks in a set of controls."""
    event_types: set[str] = set()
    for ctrl_data in controls.values():
        for check in ctrl_data.get("checks", []):
            event_types.update(check.get("event_types", []))
    return event_types


# ---------------------------------------------------------------------------
# Top-level group
# ---------------------------------------------------------------------------


@cli.group("frameworks", invoke_without_command=True)
@click.pass_context
def frameworks_grp(ctx: click.Context) -> None:
    """Explore compliance frameworks, controls, and crosswalks."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# frameworks list
# ---------------------------------------------------------------------------


@frameworks_grp.command("list")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def frameworks_list(fmt: str) -> None:
    """List all available compliance frameworks."""
    all_fw = _iter_all_frameworks()

    if fmt == "json":
        out = []
        for d in all_fw:
            fw_id = d.get("framework_id", d.get("_file", "unknown"))
            out.append(
                {
                    "framework_id": fw_id,
                    "display_name": _FRAMEWORK_DISPLAY_NAMES.get(fw_id, fw_id),
                    "families": len(d.get("control_families", {})),
                    "controls": _count_controls(d),
                }
            )
        console.print_json(json.dumps(out))
        return

    table = Table(title=f"Compliance Frameworks ({len(all_fw)})")
    table.add_column("Framework ID", style="cyan")
    table.add_column("Display Name")
    table.add_column("Families", justify="right")
    table.add_column("Controls", justify="right")

    for d in all_fw:
        fw_id = d.get("framework_id", d.get("_file", "?"))
        families = d.get("control_families", {})
        ctrl_count = _count_controls(d)
        table.add_row(
            fw_id,
            _FRAMEWORK_DISPLAY_NAMES.get(fw_id, fw_id),
            str(len(families)),
            str(ctrl_count),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# frameworks show
# ---------------------------------------------------------------------------


@frameworks_grp.command("show")
@click.argument("framework_id")
def frameworks_show(framework_id: str) -> None:
    """Show details for a specific framework."""
    data = _load_framework_yaml(framework_id)
    fw_id = data.get("framework_id", framework_id)
    families = data.get("control_families", {})
    ctrl_count = _count_controls(data)
    controls = _collect_controls(data)
    event_types = _collect_event_types(controls)

    console.print(f"\n[bold cyan]{_FRAMEWORK_DISPLAY_NAMES.get(fw_id, fw_id)}[/bold cyan]")
    console.print(f"  Framework ID:  {fw_id}")
    console.print(f"  Families:      {len(families)}")
    console.print(f"  Controls:      {ctrl_count}")
    console.print(f"  Event types:   {len(event_types)}")

    console.print("\n[bold]Control Families:[/bold]")
    table = Table()
    table.add_column("Family ID", style="cyan")
    table.add_column("Controls", justify="right")
    for family_id, family_data in sorted(families.items()):
        ctrl_cnt = len(family_data.get("controls", {}))
        table.add_row(family_id, str(ctrl_cnt))
    console.print(table)


# ---------------------------------------------------------------------------
# frameworks controls
# ---------------------------------------------------------------------------


@frameworks_grp.command("controls")
@click.argument("framework_id")
@click.option("--family", "-f", default=None, help="Filter by family ID")
@click.option("--limit", "-n", default=100, help="Max results")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def frameworks_controls(framework_id: str, family: str | None, limit: int, fmt: str) -> None:
    """List controls for a framework."""
    data = _load_framework_yaml(framework_id)
    families = data.get("control_families", {})

    rows: list[tuple[str, str, int, int]] = []
    for fam_id, fam_data in sorted(families.items()):
        if family and fam_id != family:
            continue
        for ctrl_id, ctrl_data in sorted((fam_data.get("controls") or {}).items()):
            checks = ctrl_data.get("checks", []) if ctrl_data else []
            event_types = set()
            for chk in checks:
                event_types.update(chk.get("event_types", []))
            rows.append((fam_id, ctrl_id, len(checks), len(event_types)))

    rows = rows[:limit]

    if fmt == "json":
        out = [
            {"family": r[0], "control_id": r[1], "checks": r[2], "event_types": r[3]} for r in rows
        ]
        console.print_json(json.dumps(out))
        return

    fw_label = _FRAMEWORK_DISPLAY_NAMES.get(framework_id, framework_id)
    table = Table(title=f"{fw_label} Controls ({len(rows)})")
    table.add_column("Family", style="dim")
    table.add_column("Control ID", style="cyan")
    table.add_column("Checks", justify="right")
    table.add_column("Event Types", justify="right")

    for fam_id, ctrl_id, checks, evts in rows:
        table.add_row(fam_id, ctrl_id, str(checks), str(evts))

    console.print(table)


# ---------------------------------------------------------------------------
# frameworks compare
# ---------------------------------------------------------------------------


def _load_crosswalk_mappings(fw_a: str, fw_b: str) -> list[dict[str, Any]]:
    """Load crosswalk mappings between two frameworks from all crosswalk YAML files."""
    crosswalk_files = list(_FRAMEWORKS_DIR.glob("crosswalk*.yaml"))
    mappings: list[dict[str, Any]] = []
    for cw_file in crosswalk_files:
        try:
            data = yaml.safe_load(cw_file.read_text()) or {}
        except Exception:
            continue
        entries = data.get("crosswalks", data.get("mappings", []))
        if not isinstance(entries, list):
            continue
        for entry in entries:
            src_fw = entry.get("source_framework", "")
            tgt_fw = entry.get("target_framework", "")
            src_ctrl = entry.get("source_control_id", "") or entry.get("source_control", "")
            tgt_ctrl = entry.get("target_control_id", "") or entry.get("target_control", "")
            # Match in either direction
            if (src_fw == fw_a and tgt_fw == fw_b) or (src_fw == fw_b and tgt_fw == fw_a):
                mappings.append(
                    {
                        "source_framework": src_fw,
                        "source_control": src_ctrl,
                        "target_framework": tgt_fw,
                        "target_control": tgt_ctrl,
                        "confidence": entry.get("confidence", 0.0),
                    }
                )
    return mappings


@frameworks_grp.command("compare")
@click.argument("framework_a")
@click.argument("framework_b")
def frameworks_compare(framework_a: str, framework_b: str) -> None:
    """Compare two frameworks: shared families, control overlap, crosswalk mappings."""
    data_a = _load_framework_yaml(framework_a)
    data_b = _load_framework_yaml(framework_b)

    ctrls_a = set(_collect_controls(data_a).keys())
    ctrls_b = set(_collect_controls(data_b).keys())
    shared = ctrls_a & ctrls_b
    only_a = ctrls_a - ctrls_b
    only_b = ctrls_b - ctrls_a

    label_a = _FRAMEWORK_DISPLAY_NAMES.get(framework_a, framework_a)
    label_b = _FRAMEWORK_DISPLAY_NAMES.get(framework_b, framework_b)

    console.print(f"\n[bold]Comparing {label_a} vs {label_b}[/bold]")
    console.print(f"  {label_a} controls:  {len(ctrls_a)}")
    console.print(f"  {label_b} controls:  {len(ctrls_b)}")
    console.print(f"  Shared (exact ID):   {len(shared)}")
    console.print(f"  Only in {label_a}:   {len(only_a)}")
    console.print(f"  Only in {label_b}:   {len(only_b)}")

    fams_a = set(data_a.get("control_families", {}).keys())
    fams_b = set(data_b.get("control_families", {}).keys())
    shared_fams = fams_a & fams_b
    if shared_fams:
        console.print(f"\n[bold]Shared families ({len(shared_fams)}):[/bold]")
        for f in sorted(shared_fams):
            console.print(f"  {f}")

    if shared:
        console.print("\n[bold]Shared control IDs (sample, up to 20):[/bold]")
        for c in sorted(shared)[:20]:
            console.print(f"  {c}")

    # Crosswalk-based shared controls
    crosswalk_mappings = _load_crosswalk_mappings(framework_a, framework_b)
    if crosswalk_mappings:
        # Collect unique pairs of mapped controls
        mapped_pairs: list[tuple[str, str]] = []
        mapped_a: set[str] = set()
        mapped_b: set[str] = set()
        for m in crosswalk_mappings:
            if m["source_framework"] == framework_a:
                ctrl_a, ctrl_b = m["source_control"], m["target_control"]
            else:
                ctrl_a, ctrl_b = m["target_control"], m["source_control"]
            if ctrl_a in ctrls_a and ctrl_b in ctrls_b:
                mapped_pairs.append((ctrl_a, ctrl_b))
                mapped_a.add(ctrl_a)
                mapped_b.add(ctrl_b)

        console.print(
            f"\n[bold]Crosswalk mappings ({len(mapped_pairs)} links, "
            f"{len(mapped_a)} {label_a} controls \u2192 {len(mapped_b)} {label_b} controls):[/bold]"
        )
        table = Table()
        table.add_column(f"{label_a} Control", style="cyan")
        table.add_column(f"{label_b} Control", style="cyan")
        for a_ctrl, b_ctrl in sorted(mapped_pairs)[:30]:
            table.add_row(a_ctrl, b_ctrl)
        if len(mapped_pairs) > 30:
            console.print(f"[dim]... and {len(mapped_pairs) - 30} more mappings[/dim]")
        console.print(table)
    else:
        console.print("\n[dim]No crosswalk mappings found between these frameworks.[/dim]")


# ---------------------------------------------------------------------------
# frameworks crosswalk
# ---------------------------------------------------------------------------


@frameworks_grp.command("crosswalk")
@click.argument("source_framework")
@click.option("--target", "-t", default=None, help="Target framework to filter to")
@click.option("--limit", "-n", default=50, help="Max results")
def frameworks_crosswalk(source_framework: str, target: str | None, limit: int) -> None:
    """Show crosswalk mappings from a source framework."""
    crosswalk_files = list(_FRAMEWORKS_DIR.glob("crosswalk*.yaml"))
    if not crosswalk_files:
        console.print("[dim]No crosswalk files found in frameworks directory.[/dim]")
        return

    rows: list[dict[str, Any]] = []
    for cw_file in crosswalk_files:
        try:
            data = yaml.safe_load(cw_file.read_text()) or {}
        except Exception:
            continue
        mappings = data.get("crosswalks", data.get("mappings", []))
        if not isinstance(mappings, list):
            continue
        for mapping in mappings:
            src_fw = mapping.get("source_framework", "")
            tgt_fw = mapping.get("target_framework", "")
            if src_fw != source_framework and tgt_fw != source_framework:
                continue
            if target and tgt_fw != target and src_fw != target:
                continue
            rows.append(mapping)

    rows = rows[:limit]
    if not rows:
        console.print(f"[dim]No crosswalk entries found for '{source_framework}'.[/dim]")
        return

    table = Table(title=f"Crosswalk: {source_framework} ({len(rows)} mappings)")
    table.add_column("Source FW", style="cyan")
    table.add_column("Source Ctrl")
    table.add_column("Target FW", style="cyan")
    table.add_column("Target Ctrl")
    table.add_column("Method", style="dim")

    for m in rows:
        table.add_row(
            m.get("source_framework", ""),
            m.get("source_control_id", "") or m.get("source_control", ""),
            m.get("target_framework", ""),
            m.get("target_control_id", "") or m.get("target_control", ""),
            m.get("mapping_method", "") or m.get("method", ""),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# frameworks coverage
# ---------------------------------------------------------------------------


@frameworks_grp.command("coverage")
@click.argument("framework_id")
@click.option("--limit", "-n", default=50, help="Max results")
def frameworks_coverage(framework_id: str, limit: int) -> None:
    """Show control coverage: which controls have findings in the DB."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    data = _load_framework_yaml(framework_id)
    all_controls = set(_collect_controls(data).keys())

    with get_session() as session:
        covered = (
            session.query(ControlResult.control_id)
            .filter(ControlResult.framework == framework_id)
            .distinct()
            .all()
        )

    covered_ids = {r[0] for r in covered}
    uncovered = all_controls - covered_ids

    label = _FRAMEWORK_DISPLAY_NAMES.get(framework_id, framework_id)
    pct = (len(covered_ids) / len(all_controls) * 100) if all_controls else 0.0
    console.print(f"\n[bold]{label} Coverage[/bold]")
    console.print(f"  Total controls:   {len(all_controls)}")
    console.print(f"  Covered (has DB results): {len(covered_ids)}  ({pct:.1f}%)")
    console.print(f"  Uncovered:        {len(uncovered)}")

    if uncovered:
        console.print(f"\n[bold]Uncovered controls (sample, up to {limit}):[/bold]")
        table = Table()
        table.add_column("Control ID", style="yellow")
        for ctrl_id in sorted(uncovered)[:limit]:
            table.add_row(ctrl_id)
        console.print(table)


# ---------------------------------------------------------------------------
# frameworks gaps
# ---------------------------------------------------------------------------


@frameworks_grp.command("gaps")
@click.argument("framework_id")
@click.option("--limit", "-n", default=50, help="Max results")
def frameworks_gaps(framework_id: str, limit: int) -> None:
    """Show controls with no compliant findings (gaps)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    data = _load_framework_yaml(framework_id)
    all_controls = set(_collect_controls(data).keys())

    with get_session() as session:
        compliant = (
            session.query(ControlResult.control_id)
            .filter(
                ControlResult.framework == framework_id,
                ControlResult.status == "compliant",
            )
            .distinct()
            .all()
        )

    compliant_ids = {r[0] for r in compliant}
    gaps = sorted(all_controls - compliant_ids)[:limit]

    label = _FRAMEWORK_DISPLAY_NAMES.get(framework_id, framework_id)
    console.print(f"\n[bold]{label} Compliance Gaps ({len(gaps)} shown)[/bold]")

    if not gaps:
        console.print(
            "[green]No gaps found — all controls have at least one compliant result.[/green]"
        )
        return

    table = Table()
    table.add_column("Control ID", style="red")
    for ctrl_id in gaps:
        table.add_row(ctrl_id)
    console.print(table)


# ---------------------------------------------------------------------------
# frameworks heatmap
# ---------------------------------------------------------------------------


@frameworks_grp.command("heatmap")
@click.argument("framework_id")
def frameworks_heatmap(framework_id: str) -> None:
    """Compliance heatmap by control family."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    data = _load_framework_yaml(framework_id)
    families = data.get("control_families", {})

    with get_session() as session:
        results = (
            session.query(
                ControlResult.control_id,
                ControlResult.status,
            )
            .filter(ControlResult.framework == framework_id)
            .all()
        )

    # Group DB results by control_id -> most recent status
    ctrl_status: dict[str, str] = {}
    for ctrl_id, status in results:
        ctrl_status[ctrl_id] = status

    label = _FRAMEWORK_DISPLAY_NAMES.get(framework_id, framework_id)
    table = Table(title=f"{label} Compliance Heatmap")
    table.add_column("Family", style="cyan")
    table.add_column("Controls", justify="right")
    table.add_column("Compliant", justify="right", style="green")
    table.add_column("Non-compliant", justify="right", style="red")
    table.add_column("Partial", justify="right", style="yellow")
    table.add_column("Not assessed", justify="right", style="dim")
    table.add_column("Score", justify="right")

    for fam_id, fam_data in sorted(families.items()):
        ctrl_ids = list((fam_data.get("controls") or {}).keys())
        total = len(ctrl_ids)
        compliant = sum(1 for c in ctrl_ids if ctrl_status.get(c) == "compliant")
        non_compliant = sum(1 for c in ctrl_ids if ctrl_status.get(c) == "non_compliant")
        partial = sum(1 for c in ctrl_ids if ctrl_status.get(c) == "partial")
        not_assessed = total - compliant - non_compliant - partial
        score = (compliant / total * 100) if total else 0.0
        table.add_row(
            fam_id,
            str(total),
            str(compliant),
            str(non_compliant),
            str(partial),
            str(not_assessed),
            f"{score:.0f}%",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# frameworks stats
# ---------------------------------------------------------------------------


@frameworks_grp.command("stats")
def frameworks_stats() -> None:
    """Aggregate statistics across all frameworks."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    all_fw = _iter_all_frameworks()

    with get_session() as session:
        counts = session.query(ControlResult.framework, ControlResult.status).all()

    db_stats: dict[str, dict[str, int]] = {}
    for fw_id, status in counts:
        db_stats.setdefault(fw_id, {})
        db_stats[fw_id][status] = db_stats[fw_id].get(status, 0) + 1

    table = Table(title="Framework Statistics")
    table.add_column("Framework ID", style="cyan")
    table.add_column("Controls", justify="right")
    table.add_column("DB Results", justify="right")
    table.add_column("Compliant", justify="right", style="green")
    table.add_column("Non-compliant", justify="right", style="red")

    for d in all_fw:
        fw_id = d.get("framework_id", d.get("_file", "?"))
        ctrl_count = _count_controls(d)
        fw_db = db_stats.get(fw_id, {})
        total_results = sum(fw_db.values())
        compliant = fw_db.get("compliant", 0)
        non_compliant = fw_db.get("non_compliant", 0)
        table.add_row(
            fw_id,
            str(ctrl_count),
            str(total_results),
            str(compliant),
            str(non_compliant),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# frameworks export
# ---------------------------------------------------------------------------


@frameworks_grp.command("export")
@click.argument("framework_id")
@click.option(
    "--format", "fmt", type=click.Choice(["json", "yaml"]), default="json", help="Output format"
)
@click.option("--output", "-o", default=None, help="Output file path (default: stdout)")
def frameworks_export(framework_id: str, fmt: str, output: str | None) -> None:
    """Export a framework definition to JSON or YAML."""
    data = _load_framework_yaml(framework_id)
    # Remove internal _file key
    data.pop("_file", None)

    if fmt == "json":
        text = json.dumps(data, indent=2, default=str)
    else:
        text = yaml.dump(data, default_flow_style=False, allow_unicode=True)

    if output:
        pathlib.Path(output).write_text(text)
        console.print(f"[green]Exported {framework_id} to {output}[/green]")
    else:
        console.print(text)


# ---------------------------------------------------------------------------
# frameworks event-types
# ---------------------------------------------------------------------------


@frameworks_grp.command("event-types")
@click.argument("framework_id")
@click.option("--limit", "-n", default=100, help="Max results")
def frameworks_event_types(framework_id: str, limit: int) -> None:
    """List all event types referenced by a framework's controls."""
    data = _load_framework_yaml(framework_id)
    controls = _collect_controls(data)
    event_types = sorted(_collect_event_types(controls))[:limit]

    label = _FRAMEWORK_DISPLAY_NAMES.get(framework_id, framework_id)
    if not event_types:
        console.print(f"[dim]No event types found for {label}.[/dim]")
        return

    table = Table(title=f"{label} Event Types ({len(event_types)})")
    table.add_column("Event Type", style="cyan")
    for et in event_types:
        table.add_row(et)
    console.print(table)


# ---------------------------------------------------------------------------
# frameworks connectors
# ---------------------------------------------------------------------------


@frameworks_grp.command("connectors")
@click.argument("framework_id", required=False, default=None)
def frameworks_connectors(framework_id: str | None) -> None:
    """List connectors that feed data relevant to a framework.

    When FRAMEWORK_ID is omitted, shows connectors for all frameworks.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import RawEvent

    init_db()

    fw_ids = [framework_id] if framework_id else list(_FRAMEWORK_DISPLAY_NAMES.keys())

    for fw_id in fw_ids:
        data = _load_framework_yaml(fw_id)
        controls = _collect_controls(data)
        event_types = _collect_event_types(controls)

        with get_session() as session:
            rows = (
                session.query(RawEvent.provider, RawEvent.source_type, RawEvent.source)
                .filter(RawEvent.event_type.in_(event_types))
                .distinct()
                .all()
            )

        label = _FRAMEWORK_DISPLAY_NAMES.get(fw_id, fw_id)
        if not rows:
            console.print(f"[dim]No connector data found for {label} event types.[/dim]")
            continue

        table = Table(title=f"Connectors contributing to {label}")
        table.add_column("Provider", style="cyan")
        table.add_column("Source Type")
        table.add_column("Source")

        for provider, source_type, source in sorted(rows):
            table.add_row(provider, source_type, source)

        console.print(table)


# ---------------------------------------------------------------------------
# frameworks calendar
# ---------------------------------------------------------------------------


@frameworks_grp.command("calendar")
@click.argument("framework_id", required=False, default=None)
def frameworks_calendar(framework_id: str | None) -> None:
    """Show monitoring frequency calendar for a framework's controls.

    When FRAMEWORK_ID is omitted, shows calendars for all frameworks.
    """
    fw_ids = [framework_id] if framework_id else list(_FRAMEWORK_DISPLAY_NAMES.keys())

    for fw_id in fw_ids:
        data = _load_framework_yaml(fw_id)
        controls = _collect_controls(data)

        freq_map: dict[str, list[str]] = {}
        for ctrl_id, ctrl_data in controls.items():
            freq = "not_specified"
            if ctrl_data:
                for check in ctrl_data.get("checks", []):
                    if check.get("monitoring_frequency"):
                        freq = check["monitoring_frequency"]
                        break
            freq_map.setdefault(freq, []).append(ctrl_id)

        label = _FRAMEWORK_DISPLAY_NAMES.get(fw_id, fw_id)
        table = Table(title=f"{label} Monitoring Calendar")
        table.add_column("Frequency", style="cyan")
        table.add_column("Controls", justify="right")
        table.add_column("Sample Controls", style="dim")

        order = ["daily", "weekly", "monthly", "quarterly", "annual", "not_specified"]
        for freq in order:
            if freq not in freq_map:
                continue
            ctrls = freq_map[freq]
            sample = ", ".join(sorted(ctrls)[:5])
            if len(ctrls) > 5:
                sample += f" (+{len(ctrls) - 5} more)"
            table.add_row(freq, str(len(ctrls)), sample)

        console.print(table)


# ---------------------------------------------------------------------------
# frameworks inheritance (report)
# ---------------------------------------------------------------------------


@frameworks_grp.command("inheritance")
@click.argument("framework_id")
@click.option(
    "--provider",
    default=None,
    help="Filter by cloud provider (aws, azure, gcp)",
)
def frameworks_inheritance(framework_id: str, provider: str | None) -> None:
    """Show control inheritance report from inherited_controls.yaml."""
    inherited_path = _REFERENCE_DIR / "inherited_controls.yaml"
    if not inherited_path.exists():
        _error(f"inherited_controls.yaml not found at {inherited_path}")

    with open(inherited_path) as fh:
        idata = yaml.safe_load(fh) or {}

    data = _load_framework_yaml(framework_id)
    all_controls = set(_collect_controls(data).keys())

    table = Table(title=f"Control Inheritance Report — {framework_id}")
    table.add_column("Provider", style="cyan")
    table.add_column("Type")
    table.add_column("Controls", justify="right")
    table.add_column("Sample", style="dim")

    # The YAML may have a top-level grouping key (e.g. "cloud_inherited") or
    # provider keys directly.  Detect and flatten one level if needed.
    providers: dict = {}
    for key, val in idata.items():
        if isinstance(val, dict) and all(isinstance(v, dict) for v in val.values()):
            # Nested: top-level grouping → provider dicts
            providers.update(val)
        else:
            # Flat: key is already a provider name
            providers[key] = val

    for prov, prov_data in sorted(providers.items()):
        if provider and prov != provider:
            continue
        for inherit_type, ctrl_list in (prov_data or {}).items():
            if not isinstance(ctrl_list, list):
                continue
            relevant = [c for c in ctrl_list if c in all_controls]
            if not relevant:
                continue
            sample = ", ".join(relevant[:5])
            if len(relevant) > 5:
                sample += f" (+{len(relevant) - 5})"
            table.add_row(prov, inherit_type, str(len(relevant)), sample)

    console.print(table)


# ---------------------------------------------------------------------------
# Sub-group: baselines
# ---------------------------------------------------------------------------


@frameworks_grp.group("baselines", invoke_without_command=True)
@click.pass_context
def baselines_grp(ctx: click.Context) -> None:
    """Manage NIST control baselines (Low / Moderate / High)."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@baselines_grp.command("list")
def baselines_list() -> None:
    """List available baselines."""
    baselines_path = _REFERENCE_DIR / "baselines.yaml"
    if not baselines_path.exists():
        _error(f"baselines.yaml not found at {baselines_path}")

    with open(baselines_path) as fh:
        data = yaml.safe_load(fh) or {}

    table = Table(title="Available Baselines")
    table.add_column("Framework", style="cyan")
    table.add_column("Level")
    table.add_column("Description")
    table.add_column("Controls", justify="right")

    for fw_id, levels in sorted(data.items()):
        if not isinstance(levels, dict):
            continue
        for level, level_data in sorted(levels.items()):
            desc = level_data.get("description", "") if isinstance(level_data, dict) else ""
            ctrls = level_data.get("controls", []) if isinstance(level_data, dict) else []
            table.add_row(fw_id, level, desc[:60], str(len(ctrls)))

    console.print(table)


@baselines_grp.command("show")
@click.argument("framework_id")
@click.argument("level")
@click.option("--limit", "-n", default=100, help="Max controls to display")
def baselines_show(framework_id: str, level: str, limit: int) -> None:
    """Show controls in a baseline (e.g. nist_800_53 low)."""
    baselines_path = _REFERENCE_DIR / "baselines.yaml"
    if not baselines_path.exists():
        _error(f"baselines.yaml not found at {baselines_path}")

    with open(baselines_path) as fh:
        data = yaml.safe_load(fh) or {}

    fw_data = data.get(framework_id)
    if not fw_data:
        _error(f"Framework '{framework_id}' not found in baselines.yaml")

    level_data = fw_data.get(level)
    if not level_data:
        available = ", ".join(fw_data.keys())
        _error(f"Level '{level}' not found for {framework_id}. Available: {available}")

    desc = level_data.get("description", "")
    controls = level_data.get("controls", [])

    console.print(f"\n[bold cyan]{framework_id} — {level.title()} Baseline[/bold cyan]")
    if desc:
        console.print(f"  {desc}")
    console.print(f"  Controls: {len(controls)}")

    table = Table()
    table.add_column("Control ID", style="cyan")
    for ctrl_id in sorted(controls)[:limit]:
        table.add_row(ctrl_id)

    if len(controls) > limit:
        console.print(f"[dim](Showing {limit} of {len(controls)})[/dim]")

    console.print(table)


@baselines_grp.command("apply")
@click.argument("framework_id")
@click.argument("level")
@click.option(
    "--dry-run", is_flag=True, help="Show controls that would be scoped without making changes"
)
def baselines_apply(framework_id: str, level: str, dry_run: bool) -> None:
    """Apply a baseline: show controls that fall within the baseline scope."""
    baselines_path = _REFERENCE_DIR / "baselines.yaml"
    if not baselines_path.exists():
        _error(f"baselines.yaml not found at {baselines_path}")

    with open(baselines_path) as fh:
        data = yaml.safe_load(fh) or {}

    fw_data = data.get(framework_id)
    if not fw_data:
        _error(f"Framework '{framework_id}' not found in baselines.yaml")

    level_data = fw_data.get(level)
    if not level_data:
        available = ", ".join(fw_data.keys())
        _error(f"Level '{level}' not found. Available: {available}")

    controls = level_data.get("controls", [])

    if dry_run:
        console.print(
            f"[yellow](dry-run)[/yellow] Baseline {framework_id}/{level} — "
            f"{len(controls)} controls in scope:"
        )
        for ctrl in sorted(controls):
            console.print(f"  {ctrl}")
    else:
        console.print(
            f"[green]Baseline {framework_id}/{level} has {len(controls)} controls.[/green]"
        )
        console.print(
            "[dim]Tip: use 'warlock frameworks controls --family <ID>' to explore controls "
            "or pipe this list to 'warlock audit engagement create --in-scope'.[/dim]"
        )


# ---------------------------------------------------------------------------
# Sub-group: inherited
# ---------------------------------------------------------------------------


@frameworks_grp.group("inherited", invoke_without_command=True)
@click.pass_context
def inherited_grp(ctx: click.Context) -> None:
    """View inherited controls from cloud providers."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@inherited_grp.command("list")
@click.option("--provider", default=None, help="Filter by provider (aws, azure, gcp)")
def inherited_list(provider: str | None) -> None:
    """List all inherited control sets."""
    inherited_path = _REFERENCE_DIR / "inherited_controls.yaml"
    if not inherited_path.exists():
        _error(f"inherited_controls.yaml not found at {inherited_path}")

    with open(inherited_path) as fh:
        data = yaml.safe_load(fh) or {}

    table = Table(title="Inherited Control Sets")
    table.add_column("Provider", style="cyan")
    table.add_column("Inheritance Type")
    table.add_column("Controls", justify="right")

    for prov, prov_data in sorted(data.items()):
        if provider and prov != provider:
            continue
        for inherit_type, ctrl_list in (prov_data or {}).items():
            if isinstance(ctrl_list, list):
                table.add_row(prov, inherit_type, str(len(ctrl_list)))

    console.print(table)


@inherited_grp.command("show")
@click.argument("provider")
@click.argument("inherit_type")
@click.option("--limit", "-n", default=100, help="Max controls")
def inherited_show(provider: str, inherit_type: str, limit: int) -> None:
    """Show controls for a specific provider and inheritance type."""
    inherited_path = _REFERENCE_DIR / "inherited_controls.yaml"
    if not inherited_path.exists():
        _error(f"inherited_controls.yaml not found at {inherited_path}")

    with open(inherited_path) as fh:
        data = yaml.safe_load(fh) or {}

    prov_data = data.get(provider)
    if not prov_data:
        _error(f"Provider '{provider}' not found. Available: {', '.join(data.keys())}")

    ctrl_list = prov_data.get(inherit_type)
    if ctrl_list is None:
        available = ", ".join(prov_data.keys())
        _error(f"Inheritance type '{inherit_type}' not found. Available: {available}")

    console.print(
        f"\n[bold cyan]{provider} — {inherit_type}[/bold cyan] ({len(ctrl_list)} controls)"
    )
    table = Table()
    table.add_column("Control ID", style="cyan")
    for ctrl_id in sorted(ctrl_list)[:limit]:
        table.add_row(ctrl_id)
    if len(ctrl_list) > limit:
        console.print(f"[dim](Showing {limit} of {len(ctrl_list)})[/dim]")
    console.print(table)


# ---------------------------------------------------------------------------
# frameworks import
# ---------------------------------------------------------------------------


@frameworks_grp.command("import")
@click.option(
    "--file", "filepath", required=True, type=click.Path(exists=True), help="Path to framework YAML"
)
@click.option("--validate/--no-validate", default=True, help="Validate structure before importing")
def frameworks_import(filepath: str, validate: bool) -> None:
    """Import a custom framework YAML into the frameworks directory.

    Validates the YAML structure (v2 dict-based format with control_families)
    and copies it into the warlock/frameworks/ directory.
    """
    import shutil

    src = pathlib.Path(filepath)

    # Load and optionally validate
    try:
        with open(src) as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        _error(f"Invalid YAML: {exc}")

    fw_id = data.get("framework_id")
    if not fw_id:
        _error("Framework YAML must have a 'framework_id' key at the top level.")

    if validate:
        families = data.get("control_families", {})
        if not isinstance(families, dict):
            _error(
                "Framework YAML must have 'control_families' as a dict (v2 format). "
                "Got: " + type(families).__name__
            )
        if not families:
            _error("Framework YAML has no control families defined.")

        total_controls = 0
        for fam_id, fam_data in families.items():
            if not isinstance(fam_data, dict):
                _error(f"Family '{fam_id}' must be a dict, got {type(fam_data).__name__}")
            controls = fam_data.get("controls", {})
            if not isinstance(controls, dict):
                _error(f"Family '{fam_id}' controls must be a dict, got {type(controls).__name__}")
            total_controls += len(controls)

        console.print(f"[green]Validation passed:[/green] {fw_id}")
        console.print(f"  Families: {len(families)}")
        console.print(f"  Controls: {total_controls}")

    dest = _FRAMEWORKS_DIR / f"{fw_id}.yaml"
    if dest.exists():
        console.print(
            f"[yellow]Warning: overwriting existing framework YAML at {dest.name}[/yellow]"
        )

    shutil.copy2(src, dest)
    console.print(f"[green]Framework '{fw_id}' imported to {dest}[/green]")


# ---------------------------------------------------------------------------
# frameworks import-custom (FWK-4)
# ---------------------------------------------------------------------------


@frameworks_grp.command("import-custom")
@click.option(
    "--file",
    "filepath",
    required=True,
    type=click.Path(exists=True),
    help="Path to custom framework YAML",
)
def frameworks_import_custom(filepath: str) -> None:
    """Import and validate a custom framework definition from YAML.

    Validates the YAML has the required v2 dict-based structure
    (framework_id, control_families with nested controls dict)
    and copies it into the warlock/frameworks/ directory.
    """
    import shutil

    src = pathlib.Path(filepath)

    try:
        with open(src) as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        _error(f"Invalid YAML: {exc}")

    fw_id = data.get("framework_id")
    if not fw_id:
        _error("Custom framework YAML must have a 'framework_id' key at the top level.")

    if not isinstance(fw_id, str) or not fw_id.strip():
        _error("'framework_id' must be a non-empty string.")

    families = data.get("control_families", {})
    if not isinstance(families, dict):
        _error(
            "Framework YAML must have 'control_families' as a dict (v2 format). "
            "Got: " + type(families).__name__
        )
    if not families:
        _error("Framework YAML has no control families defined.")

    # Validate each family structure
    total_controls = 0
    for fam_id, fam_data in families.items():
        if not isinstance(fam_data, dict):
            _error(f"Family '{fam_id}' must be a dict, got {type(fam_data).__name__}")
        controls = fam_data.get("controls", {})
        if not isinstance(controls, dict):
            _error(f"Family '{fam_id}' controls must be a dict, got {type(controls).__name__}")
        total_controls += len(controls)

    if total_controls == 0:
        _error("Framework has control families but no controls defined in any family.")

    console.print(f"[green]Validation passed:[/green] {fw_id}")
    console.print(f"  Families: {len(families)}")
    console.print(f"  Controls: {total_controls}")

    # Check for event_types in controls (optional but useful)
    controls_all = _collect_controls(data)
    event_types = _collect_event_types(controls_all)
    if event_types:
        console.print(f"  Event types: {len(event_types)}")
    else:
        console.print(
            "  [dim]No event_types defined (controls will not match pipeline events)[/dim]"
        )

    dest = _FRAMEWORKS_DIR / f"{fw_id}.yaml"
    if dest.exists():
        console.print(
            f"[yellow]Warning: overwriting existing framework YAML at {dest.name}[/yellow]"
        )

    shutil.copy2(src, dest)
    console.print(f"[green]Custom framework '{fw_id}' imported to {dest}[/green]")


# ---------------------------------------------------------------------------
# frameworks tailor (FWK-2: Baseline tailoring)
# ---------------------------------------------------------------------------


@frameworks_grp.command("tailor")
@click.option("--framework", "-f", required=True, help="Source framework ID (e.g. nist_800_53)")
@click.option(
    "--system-id", "-s", required=True, help="System identifier for the tailored baseline"
)
@click.option(
    "--add-controls",
    default=None,
    help="Comma-separated control IDs to add to the baseline",
)
@click.option(
    "--remove-controls",
    default=None,
    help="Comma-separated control IDs to remove from the baseline",
)
@click.option(
    "--output",
    "-o",
    default=None,
    type=click.Path(),
    help="Output file path (default: frameworks/<framework>_tailored_<system-id>.yaml)",
)
def frameworks_tailor(
    framework: str,
    system_id: str,
    add_controls: str | None,
    remove_controls: str | None,
    output: str | None,
) -> None:
    """Create a tailored baseline for a specific system from an existing framework.

    Starts with the full framework control set, then applies additions
    and removals to produce a system-specific baseline YAML.
    """
    from rich.markup import escape as esc

    data = _load_framework_yaml(framework)
    all_controls = _collect_controls(data)
    base_ids = set(all_controls.keys())

    adds: set[str] = set()
    removes: set[str] = set()

    if add_controls:
        adds = {c.strip() for c in add_controls.split(",") if c.strip()}
    if remove_controls:
        removes = {c.strip() for c in remove_controls.split(",") if c.strip()}

    # Validate that removals exist in the base
    unknown_removes = removes - base_ids
    if unknown_removes:
        console.print(
            f"[yellow]Warning: these controls are not in {framework} "
            f"and cannot be removed: {', '.join(sorted(unknown_removes))}[/yellow]"
        )
        removes -= unknown_removes

    tailored_ids = (base_ids - removes) | adds
    removed_count = len(base_ids & removes)
    added_count = len(adds - base_ids)

    # Build tailored YAML structure
    tailored_families: dict[str, Any] = {}
    families = data.get("control_families", {})
    for fam_id, fam_data in families.items():
        fam_controls = fam_data.get("controls", {})
        kept = {cid: cdata for cid, cdata in fam_controls.items() if cid in tailored_ids}
        if kept:
            tailored_families[fam_id] = {
                **{k: v for k, v in fam_data.items() if k != "controls"},
                "controls": kept,
            }

    # Add controls that don't belong to any existing family
    added_without_family = adds - base_ids
    if added_without_family:
        custom_controls = {
            cid: {"title": f"Custom addition: {cid}"} for cid in sorted(added_without_family)
        }
        tailored_families.setdefault("custom_additions", {"controls": {}})
        tailored_families["custom_additions"]["controls"].update(custom_controls)

    tailored_data = {
        "framework_id": f"{framework}_tailored_{system_id}",
        "source_framework": framework,
        "system_id": system_id,
        "tailoring": {
            "added": sorted(adds),
            "removed": sorted(removes),
        },
        "control_families": tailored_families,
    }

    total_controls = sum(len(f.get("controls", {})) for f in tailored_families.values())

    # Write output
    out_path = output or str(_FRAMEWORKS_DIR / f"{framework}_tailored_{system_id}.yaml")
    with open(out_path, "w") as fh:
        yaml.dump(tailored_data, fh, default_flow_style=False, sort_keys=False)

    label = _FRAMEWORK_DISPLAY_NAMES.get(framework, framework)
    console.print("\n[bold cyan]Tailored Baseline Created[/bold cyan]")
    console.print(f"  Source framework: {label}")
    console.print(f"  System ID:        {esc(system_id)}")
    console.print(f"  Base controls:    {len(base_ids)}")
    console.print(f"  Added:            {added_count}")
    console.print(f"  Removed:          {removed_count}")
    console.print(f"  Final controls:   {total_controls}")
    console.print(f"  Output:           {out_path}")


# ---------------------------------------------------------------------------
# frameworks gap-analysis (FWK-6)
# ---------------------------------------------------------------------------


@frameworks_grp.command("gap-analysis")
@click.argument("framework_id")
@click.option("--limit", "-n", default=100, help="Max results")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def frameworks_gap_analysis(framework_id: str, limit: int, fmt: str) -> None:
    """Comprehensive gap analysis: controls with no assertions, no evidence, or no test coverage.

    Shows a table with each control and its gap status across three dimensions:
    assertions (has a deterministic check), evidence (has findings), and
    test results (has been assessed).
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    data = _load_framework_yaml(framework_id)
    all_controls = _collect_controls(data)

    with get_session() as session:
        # Controls with any assessment result
        assessed_rows = (
            session.query(ControlResult.control_id, ControlResult.assertion_name)
            .filter(ControlResult.framework == framework_id)
            .all()
        )

        # Controls with findings (evidence)
        evidence_rows = (
            session.query(ControlResult.control_id)
            .filter(
                ControlResult.framework == framework_id,
                ControlResult.finding_id.isnot(None),
            )
            .distinct()
            .all()
        )

    # Build sets
    has_assertion: set[str] = set()
    has_test: set[str] = set()
    for ctrl_id, assertion_name in assessed_rows:
        has_test.add(ctrl_id)
        if assertion_name:
            has_assertion.add(ctrl_id)

    has_evidence = {r[0] for r in evidence_rows}

    # Build gap rows
    rows: list[dict] = []
    for ctrl_id in sorted(all_controls.keys()):
        a = ctrl_id in has_assertion
        e = ctrl_id in has_evidence
        t = ctrl_id in has_test

        gaps: list[str] = []
        if not a:
            gaps.append("no_assertion")
        if not e:
            gaps.append("no_evidence")
        if not t:
            gaps.append("no_test")

        if gaps:
            rows.append(
                {
                    "control_id": ctrl_id,
                    "has_assertion": a,
                    "has_evidence": e,
                    "has_test": t,
                    "gap_type": ", ".join(gaps),
                }
            )

    rows = rows[:limit]
    total_controls = len(all_controls)
    gap_count = len(rows)

    if fmt == "json":
        out = {
            "framework": framework_id,
            "total_controls": total_controls,
            "gap_count": gap_count,
            "gaps": rows,
        }
        console.print_json(json.dumps(out, indent=2))
        return

    label = _FRAMEWORK_DISPLAY_NAMES.get(framework_id, framework_id)
    console.print(f"\n[bold]{label} Gap Analysis[/bold]")
    console.print(f"  Total controls: {total_controls}")
    console.print(f"  Controls with gaps: {gap_count}")
    pct_covered = ((total_controls - gap_count) / total_controls * 100) if total_controls else 0
    console.print(f"  Full coverage: {pct_covered:.1f}%")

    if not rows:
        console.print(
            "\n[green]No gaps found -- all controls have assertions, evidence, and tests.[/green]"
        )
        return

    table = Table(title=f"{label} Control Gaps ({len(rows)} shown)")
    table.add_column("Control ID", style="cyan")
    table.add_column("Assertion", justify="center")
    table.add_column("Evidence", justify="center")
    table.add_column("Test", justify="center")
    table.add_column("Gap Type", style="yellow")

    for r in rows:
        table.add_row(
            r["control_id"],
            "[green]yes[/green]" if r["has_assertion"] else "[red]no[/red]",
            "[green]yes[/green]" if r["has_evidence"] else "[red]no[/red]",
            "[green]yes[/green]" if r["has_test"] else "[red]no[/red]",
            r["gap_type"],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# frameworks coverage-gaps  (GAP-031)
# ---------------------------------------------------------------------------


@frameworks_grp.command("coverage-gaps")
@click.option(
    "--framework",
    "-f",
    default=None,
    help="Filter to a single framework_id (e.g. nist_800_53). Omit for all.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format.",
)
def coverage_gaps(framework: str | None, fmt: str) -> None:
    """Show controls with no automated checks defined.

    Reads framework YAMLs and reports which controls have empty or missing
    ``checks`` arrays.  Useful for identifying where automated coverage
    needs to be added.
    """
    from rich.markup import escape

    if framework:
        frameworks_to_check = [_load_framework_yaml(framework)]
        frameworks_to_check[0].setdefault("_file", framework)
    else:
        frameworks_to_check = _iter_all_frameworks()

    summary_rows: list[dict[str, Any]] = []

    for fw_data in frameworks_to_check:
        fw_id = fw_data.get("framework_id", fw_data.get("_file", "unknown"))
        controls = _collect_controls(fw_data)
        total = len(controls)

        with_checks = 0
        without_checks = 0
        missing_ids: list[str] = []

        for ctrl_id, ctrl_data in sorted(controls.items()):
            checks = ctrl_data.get("checks") or []
            if checks:
                with_checks += 1
            else:
                without_checks += 1
                missing_ids.append(ctrl_id)

        pct = (with_checks / total * 100) if total else 0.0
        summary_rows.append(
            {
                "framework_id": fw_id,
                "display_name": _FRAMEWORK_DISPLAY_NAMES.get(fw_id, fw_id),
                "total_controls": total,
                "with_checks": with_checks,
                "without_checks": without_checks,
                "coverage_pct": round(pct, 1),
                "missing_control_ids": missing_ids,
            }
        )

    if fmt == "json":
        console.print_json(json.dumps(summary_rows, indent=2))
        return

    # Summary table
    table = Table(title="Framework Check Coverage")
    table.add_column("Framework", style="cyan")
    table.add_column("Total", justify="right")
    table.add_column("With Checks", justify="right", style="green")
    table.add_column("Without Checks", justify="right", style="red")
    table.add_column("Coverage %", justify="right")

    total_all = 0
    total_with = 0
    total_without = 0

    for row in summary_rows:
        total_all += row["total_controls"]
        total_with += row["with_checks"]
        total_without += row["without_checks"]

        pct_str = f"{row['coverage_pct']:.1f}%"
        if row["coverage_pct"] >= 80:
            pct_str = f"[green]{pct_str}[/green]"
        elif row["coverage_pct"] >= 50:
            pct_str = f"[yellow]{pct_str}[/yellow]"
        else:
            pct_str = f"[red]{pct_str}[/red]"

        table.add_row(
            escape(row["display_name"]),
            str(row["total_controls"]),
            str(row["with_checks"]),
            str(row["without_checks"]),
            pct_str,
        )

    # Footer totals
    overall_pct = (total_with / total_all * 100) if total_all else 0.0
    table.add_section()
    table.add_row(
        "[bold]TOTAL[/bold]",
        str(total_all),
        str(total_with),
        str(total_without),
        f"[bold]{overall_pct:.1f}%[/bold]",
    )

    console.print(table)

    # Detail: show controls without checks for each framework (if single fw)
    if framework and summary_rows:
        row = summary_rows[0]
        if row["missing_control_ids"]:
            detail = Table(title=f"Controls Without Checks -- {escape(row['display_name'])}")
            detail.add_column("#", justify="right", style="dim")
            detail.add_column("Control ID", style="yellow")
            for i, ctrl_id in enumerate(row["missing_control_ids"], 1):
                detail.add_row(str(i), escape(ctrl_id))
            console.print(detail)
        else:
            console.print(
                f"\n[green]All controls in {escape(row['display_name'])} "
                f"have checks defined.[/green]"
            )
