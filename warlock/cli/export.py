"""Export commands: oscal, framework-diff, architecture."""

from __future__ import annotations

import click

from warlock.cli import _error, cli, console


@cli.command()
@click.option(
    "-f", "--framework", default=None, help="Filter by framework (e.g. nist_800_53, iso_27001)"
)
@click.option(
    "-s", "--system-name", default="Warlock GRC System", help="System name for OSCAL metadata"
)
@click.option("-o", "--output", default=None, help="Output file path (default: stdout)")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["ar", "ssp", "poam"]),
    default="ar",
    help="OSCAL document type",
)
@click.option("--description", default="", help="System description (for SSP)")
@click.option(
    "--ai/--no-ai",
    "use_ai",
    default=None,
    help="Use AI to generate framework-aware narratives (SSP/POA&M)",
)
def oscal(framework, system_name, output, fmt, description, use_ai):
    """Export assessment data in OSCAL JSON format.

    Use --ai with SSP or POA&M to generate rich, framework-aware narratives.
    The AI adapts its language to match the framework: NIST SSP language,
    ISO SoA language, SOC 2 report language, etc.

    Requires WLK_AI_PROVIDER and WLK_AI_API_KEY to be set.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.export.oscal import OscalExporter

    init_db()
    exporter = OscalExporter()

    # Set up AI narrator if requested
    narrator = None
    if use_ai and fmt in ("ssp", "poam"):
        from warlock.assessors.ai_narrator import create_narrator

        narrator = create_narrator()
        if narrator is None:
            console.print(
                "[yellow]Warning: --ai requested but WLK_AI_PROVIDER / WLK_AI_API_KEY not configured. Falling back to deterministic output.[/yellow]"
            )
        else:
            console.print(f"[cyan]AI narrator active: {narrator.provider}/{narrator.model}[/cyan]")

    with get_session() as session:
        if fmt == "ar":
            data = exporter.export_assessment_results(
                session, framework=framework, system_name=system_name
            )
        elif fmt == "ssp":
            if not framework:
                raise click.UsageError("SSP export requires --framework (-f)")
            data = exporter.export_ssp(
                session,
                framework=framework,
                system_name=system_name,
                description=description or f"{system_name} System Security Plan",
                narrator=narrator,
            )
        elif fmt == "poam":
            data = exporter.export_poam(
                session,
                framework=framework,
                system_name=system_name,
                narrator=narrator,
            )

    if output:
        exporter.to_file(data, output)
        console.print(f"[green]OSCAL {fmt.upper()} written to {output}[/green]")
    else:
        from warlock.export.paths import export_path

        dest = export_path(fmt, framework=framework)
        exporter.to_file(data, str(dest))
        console.print(f"[green]OSCAL {fmt.upper()} written to {dest}[/green]")


@cli.command("framework-diff")
@click.option(
    "--old",
    "old_path",
    required=True,
    help="Old framework YAML: framework ID (e.g. nist_800_53) or file path",
)
@click.option(
    "--new",
    "new_path",
    required=True,
    help="New framework YAML: framework ID (e.g. nist_800_53) or file path",
)
def framework_diff_cmd(old_path: str, new_path: str) -> None:
    """Compare two framework versions and show control changes.

    Accepts framework IDs (e.g. nist_800_53, soc2) which resolve to
    warlock/frameworks/<id>.yaml, or explicit file paths.
    """
    import pathlib

    from warlock.frameworks.diff import FrameworkDiff

    frameworks_dir = pathlib.Path(__file__).resolve().parent.parent / "frameworks"

    def _resolve(val: str) -> str:
        """Resolve a framework ID or file path to an actual path."""
        p = pathlib.Path(val)
        if p.exists():
            return str(p)
        # Try as framework ID
        candidate = frameworks_dir / f"{val}.yaml"
        if candidate.exists():
            return str(candidate)
        _error(
            f"Cannot resolve '{val}': not a file path and no framework YAML found at {candidate}"
        )

    differ = FrameworkDiff()
    result = differ.diff(_resolve(old_path), _resolve(new_path))

    console.print("\n[bold]Framework Diff[/bold]")
    console.print(f"  Added:     [green]{len(result.added_controls)}[/green]")
    console.print(f"  Removed:   [red]{len(result.removed_controls)}[/red]")
    console.print(f"  Modified:  [yellow]{len(result.modified_controls)}[/yellow]")
    console.print(f"  Unchanged: [dim]{len(result.unchanged_controls)}[/dim]")

    if result.added_controls:
        console.print("\n[green]Added:[/green]")
        for c in sorted(result.added_controls)[:20]:
            console.print(f"  + {c}")
    if result.removed_controls:
        console.print("\n[red]Removed:[/red]")
        for c in sorted(result.removed_controls)[:20]:
            console.print(f"  - {c}")
    if result.modified_controls:
        console.print("\n[yellow]Modified:[/yellow]")
        for c in sorted(result.modified_controls)[:20]:
            console.print(f"  ~ {c}")


@cli.command("architecture")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["terminal", "svg", "png"]),
    default="terminal",
    help="Output format",
)
@click.option("--output", "-o", default=None, help="Output file path (for svg/png)")
def architecture_diagram(fmt: str, output: str | None) -> None:
    """Render a live architecture diagram from the seeded database."""
    import os
    import shutil
    import subprocess
    import tempfile

    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        POAM,
        AuditEngagement,
        CompensatingControl,
        ComplianceDrift,
        ConnectorRun,
        ControlInheritance,
        ControlResult,
        DataSilo,
        Finding,
        Issue,
        LegalHold,
        Personnel,
        PostureSnapshot,
        RawEvent,
        RiskAcceptance,
        SystemDependency,
        SystemProfile,
    )

    init_db()
    with get_session() as s:
        systems = s.query(SystemProfile).all()
        connector_count = s.query(ConnectorRun).count()
        raw_count = s.query(RawEvent).count()
        finding_count = s.query(Finding).count()
        result_count = s.query(ControlResult).count()
        personnel_count = s.query(Personnel).count()
        issue_count = s.query(Issue).count()
        poam_count = s.query(POAM).count()
        cc_count = s.query(CompensatingControl).count()
        ra_count = s.query(RiskAcceptance).count()
        drift_count = s.query(ComplianceDrift).count()
        snapshot_count = s.query(PostureSnapshot).count()
        silo_count = s.query(DataSilo).count()
        hold_count = s.query(LegalHold).count()
        engagement_count = s.query(AuditEngagement).count()
        dep_count = s.query(SystemDependency).count()
        inheritance_count = s.query(ControlInheritance).count()

        fw_counts = dict(
            s.query(ControlResult.framework, func.count(ControlResult.id))
            .group_by(ControlResult.framework)
            .all()
        )
        source_counts = dict(
            s.query(Finding.source, func.count(Finding.id)).group_by(Finding.source).all()
        )
        status_counts = dict(
            s.query(ControlResult.status, func.count(ControlResult.id))
            .group_by(ControlResult.status)
            .all()
        )

        # System dependencies for the diagram
        deps = s.query(SystemDependency).all()

    # --- Terminal mode: Rich tree ---
    if fmt == "terminal":
        from rich.panel import Panel
        from rich.tree import Tree

        tree = Tree("[bold cyan]Warlock GRC Platform[/bold cyan]")

        pipeline = tree.add("[bold green]Pipeline[/bold green]")
        stage1 = pipeline.add(
            f"[yellow]Stage 1:[/yellow] Connectors \u2014 {connector_count} runs \u2192 {raw_count} raw events"
        )
        for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1])[:10]:
            stage1.add(f"{src}: {cnt} findings")
        if len(source_counts) > 10:
            stage1.add(f"[dim]... and {len(source_counts) - 10} more sources[/dim]")
        pipeline.add(f"[yellow]Stage 2:[/yellow] Normalizers \u2014 {finding_count} findings")
        pipeline.add(
            f"[yellow]Stage 3:[/yellow] Control Mapper \u2014 {result_count:,} control results"
        )
        stage4 = pipeline.add(
            f"[yellow]Stage 4:[/yellow] Assessor \u2014 {status_counts.get('compliant', 0):,} compliant, {status_counts.get('non_compliant', 0):,} non-compliant, {status_counts.get('not_assessed', 0):,} not assessed"
        )
        stage4.add("Tier 1: 25 deterministic assertions")
        stage4.add("Tier 2: AI reasoning (optional)")
        stage4.add("Tier 3: OPA policy evaluation (616 policies)")

        frameworks_node = tree.add(f"[bold green]Frameworks[/bold green] ({len(fw_counts)} active)")
        for fw, cnt in sorted(fw_counts.items(), key=lambda x: -x[1]):
            bar = "\u2588" * min(cnt * 40 // max(fw_counts.values()), 40)
            frameworks_node.add(f"{fw:15s} {cnt:>6,} results  [green]{bar}[/green]")

        sys_tree = tree.add(f"[bold green]Systems[/bold green] ({len(systems)} profiles)")
        for sp in systems:
            style = {"authorized": "green", "in_process": "yellow", "not_authorized": "red"}.get(
                sp.authorization_status or "", "white"
            )
            node = sys_tree.add(
                f"[bold]{sp.acronym}[/bold] \u2014 {sp.name} ([{style}]{sp.authorization_status}[/{style}], {sp.overall_impact} impact)"
            )
            if sp.frameworks:
                node.add(f"Frameworks: {', '.join(sp.frameworks)}")
            if sp.connector_scope:
                node.add(f"Connectors: {', '.join(sp.connector_scope)}")

        gov = tree.add("[bold green]Governance[/bold green]")
        gov.add(
            f"Issues: {issue_count}  |  POA&Ms: {poam_count}  |  Compensating: {cc_count}  |  Risk Acceptances: {ra_count}"
        )
        gov.add(f"Inheritances: {inheritance_count}  |  Dependencies: {dep_count}")

        intel = tree.add("[bold green]Intelligence[/bold green]")
        intel.add(f"Drifts: {drift_count}  |  Snapshots: {snapshot_count}")

        assets = tree.add("[bold green]Assets & People[/bold green]")
        assets.add(
            f"Personnel: {personnel_count}  |  Data Silos: {silo_count}  |  Engagements: {engagement_count}  |  Legal Holds: {hold_count}"
        )

        console.print()
        console.print(
            Panel(tree, title="[bold]Live Architecture[/bold]", border_style="cyan", expand=False)
        )
        console.print()
        return

    # --- SVG/PNG mode: d2 diagram ---
    if not shutil.which("d2"):
        _error("d2 not installed. Install with: brew install d2")

    # Build d2 source from live data
    sorted(source_counts.items(), key=lambda x: -x[1])[:15]
    source_groups = {
        "Cloud": [
            "aws",
            "azure",
            "gcp",
            "oci",
            "ibm_cloud",
            "alibaba",
            "digitalocean",
            "huawei",
            "ovh",
            "cloudflare",
        ],
        "Identity": ["okta", "entra_id", "cyberark", "sailpoint", "vault"],
        "Endpoint": ["crowdstrike", "defender", "sentinelone", "intune"],
        "SIEM": ["sentinel", "splunk", "elastic"],
        "Scanners": ["tenable", "qualys", "wiz", "prisma"],
        "Other": [
            "servicenow",
            "workday",
            "knowbe4",
            "confluence",
            "onetrust",
            "snyk",
            "github",
            "proofpoint",
            "purview",
            "veeam",
            "verkada",
            "mlflow",
            "securityscorecard",
            "kubernetes",
        ],
    }

    d2 = []
    d2.append("direction: right")
    d2.append("")

    # Connectors container
    d2.append("connectors: Connectors (40 sources) {")
    d2.append('  style.fill: "#1a1a2e"')
    d2.append('  style.font-color: "#e0e0e0"')
    for group_name, members in source_groups.items():
        active = [m for m in members if m in source_counts]
        if active:
            d2.append(f"  {group_name.lower()}: {group_name} ({len(active)}) {{")
            d2.append('    style.fill: "#16213e"')
            for src in active:
                cnt = source_counts[src]
                d2.append(f"    {src}: {src} ({cnt})")
            d2.append("  }")
    d2.append("}")
    d2.append("")

    # Pipeline
    d2.append("pipeline: Pipeline {")
    d2.append('  style.fill: "#0f3460"')
    d2.append('  style.font-color: "#e0e0e0"')
    d2.append(f"  normalize: Normalize\\n{finding_count} findings")
    d2.append(f"  map: Map Controls\\n{result_count:,} results")
    d2.append("  assess: Assess {")
    d2.append("    tier1: Tier 1 Assertions (25)")
    d2.append("    tier2: Tier 2 AI Reasoning")
    d2.append("    tier3: Tier 3 OPA (616 policies)")
    d2.append("    tier1 -> tier2: fallback")
    d2.append("    tier2 -> tier3: fallback")
    d2.append("  }")
    d2.append("  normalize -> map -> assess")
    d2.append("}")
    d2.append("")

    # Frameworks
    d2.append("frameworks: Frameworks (10) {")
    d2.append('  style.fill: "#533483"')
    d2.append('  style.font-color: "#e0e0e0"')
    for fw, cnt in sorted(fw_counts.items(), key=lambda x: -x[1]):
        d2.append(f"  {fw}: {fw.upper().replace('_', ' ')}\\n{cnt:,} results")
    d2.append("}")
    d2.append("")

    # Systems
    d2.append("systems: Authorization Boundaries {")
    d2.append('  style.fill: "#1a1a2e"')
    d2.append('  style.font-color: "#e0e0e0"')
    for sp in systems:
        fws = ", ".join(sp.frameworks or [])
        conns = ", ".join(sp.connector_scope or [])
        d2.append(
            f"  {sp.acronym}: {sp.acronym} \u2014 {sp.name}\\n{sp.authorization_status} | {sp.overall_impact} impact\\nFrameworks: {fws}\\nConnectors: {conns}"
        )
    d2.append("}")
    d2.append("")

    # Governance
    d2.append("governance: Governance {")
    d2.append('  style.fill: "#e94560"')
    d2.append('  style.font-color: "#ffffff"')
    d2.append(f"  issues: Issues ({issue_count})")
    d2.append(f"  poams: POA&Ms ({poam_count})")
    d2.append(f"  compensating: Compensating ({cc_count})")
    d2.append(f"  risk_accept: Risk Accepted ({ra_count})")
    d2.append("}")
    d2.append("")

    # Intelligence
    d2.append("intelligence: Intelligence {")
    d2.append('  style.fill: "#0f3460"')
    d2.append('  style.font-color: "#e0e0e0"')
    d2.append(f"  drift: Compliance Drift ({drift_count})")
    d2.append(f"  posture: Posture Trends ({snapshot_count} snapshots)")
    d2.append("}")
    d2.append("")

    # Assets
    d2.append("assets: Assets & People {")
    d2.append('  style.fill: "#16213e"')
    d2.append('  style.font-color: "#e0e0e0"')
    d2.append(f"  personnel: Personnel ({personnel_count})")
    d2.append(f"  silos: Data Silos ({silo_count})")
    d2.append(f"  engagements: Audit Engagements ({engagement_count})")
    d2.append(f"  holds: Legal Holds ({hold_count})")
    d2.append("}")
    d2.append("")

    # Connections
    d2.append("# Data flow")
    d2.append("connectors -> pipeline.normalize: raw events")
    d2.append("pipeline.assess -> frameworks: map to controls")
    d2.append("pipeline.assess -> systems: scope by boundary")
    d2.append("pipeline.assess -> governance: non-compliant \u2192 issues")
    d2.append("pipeline.assess -> intelligence: track over time")
    d2.append("systems -> assets: personnel & data")
    d2.append("")

    # System dependencies
    for dep in deps:
        consumer = next((sp.acronym for sp in systems if sp.id == dep.consumer_system_id), None)
        provider = next((sp.acronym for sp in systems if sp.id == dep.provider_system_id), None)
        if consumer and provider:
            d2.append(f"systems.{consumer} -> systems.{provider}: {dep.dependency_type}")

    d2_source = "\n".join(d2)

    # Write and render
    out_path = output or f"exports/architecture.{fmt}"
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".d2", delete=False) as f:
        f.write(d2_source)
        d2_file = f.name

    try:
        cmd = ["d2", "--theme", "200", d2_file, out_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            console.print(f"[green]Architecture diagram written to {out_path}[/green]")
            # Try to open it
            if fmt == "svg" or fmt == "png":
                subprocess.run(["open", out_path], capture_output=True)
        else:
            console.print(f"[red]d2 error: {result.stderr}[/red]")
            # Fall back to writing the d2 source
            d2_out = out_path.rsplit(".", 1)[0] + ".d2"
            with open(d2_out, "w") as f:
                f.write(d2_source)
            console.print(
                f"[yellow]d2 source written to {d2_out} \u2014 render manually with: d2 {d2_out} output.svg[/yellow]"
            )
    finally:
        os.unlink(d2_file)
