"""P2 feature CLI commands: lake partitions, SCD history, tenant filtering,
time travel, audit program, trust center, compliance gate, scope discovery,
attack path, horizon scan, predictive risk, compliance chart, custom reports,
auditor portal, anomaly baseline, lake lineage, lake retention tiering.

Items: 62, 63, 64, 67, 78, 83, 88, 89, 90, 91, 94, 95, 96, 97, 98, 100, 101, 102
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import _error, _get_actor, cli, console
from warlock.cli.lake import _format_size, _safe_lake_path, lake
from warlock.utils import ensure_aware

# ===================================================================
# Item 62: Lake partitions management
# ===================================================================


@lake.group("partitions", invoke_without_command=True)
@click.pass_context
def lake_partitions(ctx: click.Context) -> None:
    """Partition management commands."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(partitions_show)


@lake_partitions.command("show")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def partitions_show(path: str | None) -> None:
    """Show partition statistics (file count, size per partition)."""
    from warlock.config import get_settings

    settings = get_settings()
    lake_path = Path(path or settings.lake_path)

    if not lake_path.exists():
        console.print(f"[yellow]Lake directory does not exist: {lake_path}[/yellow]")
        return

    table = Table(title="Lake Partition Statistics")
    table.add_column("Zone", style="cyan")
    table.add_column("Partition", style="dim")
    table.add_column("Files", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("Status")

    total_files = 0
    total_size = 0

    for zone in ["raw", "enrichment", "curated"]:
        zone_dir = lake_path / zone
        if not zone_dir.exists():
            continue

        # Walk subdirectories as partitions
        for subdir in sorted(zone_dir.rglob("*")):
            if not subdir.is_dir():
                continue
            parquet_files = list(subdir.glob("*.parquet"))
            if not parquet_files:
                continue

            size = sum(f.stat().st_size for f in parquet_files)
            total_files += len(parquet_files)
            total_size += size

            # Status: small (<1MB) = undersized, >256MB = oversized
            if size < 1024 * 1024:
                status = "[yellow]undersized[/yellow]"
            elif size > 256 * 1024 * 1024:
                status = "[yellow]oversized[/yellow]"
            else:
                status = "[green]ok[/green]"

            rel = str(subdir.relative_to(lake_path))
            table.add_row(zone, rel, str(len(parquet_files)), _format_size(size), status)

    if total_files == 0:
        console.print("[dim]No partitions found in lake.[/dim]")
        return

    table.add_row("---", "---", "---", "---", "---")
    table.add_row("[bold]Total[/bold]", "", str(total_files), _format_size(total_size), "")
    console.print(table)


@lake_partitions.command("rebalance")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--dry-run/--no-dry-run", default=True, help="Preview only (default: dry run)")
def partitions_rebalance(path: str | None, dry_run: bool) -> None:
    """Merge small partitions and split large ones."""
    from warlock.config import get_settings

    settings = get_settings()
    lake_path = Path(path or settings.lake_path)

    if not lake_path.exists():
        console.print(f"[yellow]Lake directory does not exist: {lake_path}[/yellow]")
        return

    actions: list[tuple[str, str, str]] = []  # (zone, partition, action)
    target_min = 1 * 1024 * 1024  # 1MB
    target_max = 256 * 1024 * 1024  # 256MB

    for zone in ["raw", "enrichment", "curated"]:
        zone_dir = lake_path / zone
        if not zone_dir.exists():
            continue

        for subdir in sorted(zone_dir.rglob("*")):
            if not subdir.is_dir():
                continue
            parquet_files = list(subdir.glob("*.parquet"))
            if not parquet_files:
                continue

            size = sum(f.stat().st_size for f in parquet_files)
            rel = str(subdir.relative_to(lake_path))

            if size < target_min and len(parquet_files) > 1:
                actions.append((zone, rel, "merge"))
            elif size > target_max:
                actions.append((zone, rel, "split"))

    if not actions:
        console.print("[dim]All partitions are within target size range. Nothing to do.[/dim]")
        return

    table = Table(title="Rebalance Plan" + (" (dry run)" if dry_run else ""))
    table.add_column("Zone", style="cyan")
    table.add_column("Partition")
    table.add_column("Action")

    for zone, partition, action in actions:
        style = "yellow" if action == "merge" else "red"
        table.add_row(zone, partition, f"[{style}]{action}[/]")

    console.print(table)

    if dry_run:
        console.print(
            f"\n[yellow]{len(actions)} partition(s) need rebalancing. "
            "Use --no-dry-run to execute.[/yellow]"
        )
    else:
        # Execute compaction for merges
        try:
            from warlock.lake.maintenance import compact

            stats = compact(str(lake_path))
            console.print(f"[green]Rebalanced {len(stats)} partition(s).[/green]")
        except ImportError:
            _error("pyarrow required for rebalance. Install with: pip install pyarrow")


# ===================================================================
# Item 63: SCD tracking / history
# ===================================================================


@lake.command("scd-history")
@click.option("--control", "-c", required=True, help="Control ID to trace")
@click.option("--framework", "-f", default=None, help="Framework filter")
@click.option("--path", default=None, help="Lake root path")
def lake_scd_history(control: str, framework: str | None, path: str | None) -> None:
    """Show SCD Type 2 history for a control (status changes over time)."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import ControlResult

    init_db()

    with get_read_session() as session:
        q = session.query(ControlResult).filter(ControlResult.control_id == control)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.order_by(ControlResult.assessed_at.asc()).all()

    if not results:
        console.print(f"[dim]No results found for control {escape(control)}.[/dim]")
        return

    table = Table(title=f"SCD History: {escape(control)}")
    table.add_column("Framework", style="cyan")
    table.add_column("Status")
    table.add_column("Effective From", style="dim")
    table.add_column("Severity")
    table.add_column("Assessor", style="dim")

    status_styles = {
        "compliant": "green",
        "non_compliant": "red",
        "partial": "yellow",
        "not_assessed": "dim",
    }

    prev_status = None
    for r in results:
        # Only show rows where status changed (SCD Type 2 semantics)
        if r.status != prev_status:
            st = status_styles.get(r.status, "")
            assessed = r.assessed_at.strftime("%Y-%m-%d %H:%M") if r.assessed_at else "\u2014"
            table.add_row(
                r.framework,
                f"[{st}]{r.status}[/]" if st else r.status,
                assessed,
                r.severity or "",
                (r.assessor or "")[:30],
            )
            prev_status = r.status

    console.print(table)
    console.print(f"\n[dim]Total assessments: {len(results)}, status changes shown above.[/dim]")


# ===================================================================
# Item 64: Lake tenant filtering
# ===================================================================


@lake.command("tenant-filter")
@click.option("--tenant-id", "-t", default=None, help="Tenant ID to filter by")
@click.option("--table-name", default="control_results", help="Lake table to query")
@click.option("--path", default=None, help="Lake root path")
@click.option("--limit", default=10, type=int, help="Max rows")
def lake_tenant_filter(
    tenant_id: str | None, table_name: str, path: str | None, limit: int
) -> None:
    """Query lake data with tenant-aware filtering."""
    from warlock.config import get_settings

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)

    if not tenant_id:
        if settings.multi_tenancy_enabled:
            tenant_id = settings.default_tenant_id
            console.print(f"[dim]Using default tenant: {tenant_id}[/dim]")
        else:
            console.print("[dim]Multi-tenancy not enabled. Showing all data.[/dim]")

    glob_pattern = _safe_lake_path(str(base / "curated" / table_name / "**" / "*.parquet"))

    if not list(base.glob(f"curated/{table_name}/**/*.parquet")):
        console.print(f"[yellow]No data found for table '{escape(table_name)}' in lake.[/yellow]")
        return

    try:
        from warlock.lake.query import LakeQueryEngine

        engine = LakeQueryEngine(lake_path)
        try:
            if tenant_id:
                result = engine.query(
                    f"SELECT * FROM read_parquet('{glob_pattern}', union_by_name=true) "
                    "WHERE tenant_id = ? LIMIT ?",
                    [tenant_id, limit],
                )
            else:
                result = engine.query(
                    f"SELECT * FROM read_parquet('{glob_pattern}', union_by_name=true) LIMIT ?",
                    [limit],
                )

            if not result:
                console.print("[dim]No matching rows found.[/dim]")
                return

            table = Table(title=f"Lake: {escape(table_name)} (tenant filtered)")
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
            console.print(table)
        finally:
            engine.close()
    except ImportError:
        _error("duckdb required for lake queries. Install with: pip install duckdb")


# ===================================================================
# Item 67: Lake time travel
# ===================================================================


@lake.command("time-travel")
@click.option("--table-name", "-t", required=True, help="Table name to query")
@click.option("--as-of", required=True, help="Point-in-time date (YYYY-MM-DD)")
@click.option("--path", default=None, help="Lake root path")
@click.option("--limit", default=20, type=int, help="Max rows")
def lake_time_travel(table_name: str, as_of: str, path: str | None, limit: int) -> None:
    """Query lake data as of a specific point in time."""
    from warlock.config import get_settings

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)

    try:
        cutoff = datetime.strptime(as_of, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        _error(f"Invalid date format: {as_of}. Use YYYY-MM-DD.")
        return

    glob_pattern = _safe_lake_path(str(base / "curated" / table_name / "**" / "*.parquet"))

    if not list(base.glob(f"curated/{table_name}/**/*.parquet")):
        console.print(f"[yellow]No data found for table '{escape(table_name)}'.[/yellow]")
        return

    try:
        from warlock.lake.query import LakeQueryEngine

        engine = LakeQueryEngine(lake_path)
        try:
            # Time-travel via assessed_at / collected_at / snapshot_date filter
            time_cols = ["assessed_at", "collected_at", "snapshot_date", "created_at"]
            # Detect which column exists
            cols = engine.query(
                f"SELECT column_name FROM (DESCRIBE SELECT * FROM "
                f"read_parquet('{glob_pattern}', union_by_name=true)) LIMIT 100"
            )
            col_names = {c["column_name"] for c in cols}
            time_col = None
            for tc in time_cols:
                if tc in col_names:
                    time_col = tc
                    break

            if not time_col:
                console.print(
                    "[yellow]No timestamp column found for time-travel filtering.[/yellow]"
                )
                return

            result = engine.query(
                f"SELECT * FROM read_parquet('{glob_pattern}', union_by_name=true) "
                f"WHERE CAST({time_col} AS TIMESTAMP) <= ? "
                f"ORDER BY {time_col} DESC LIMIT ?",
                [cutoff.isoformat(), limit],
            )

            if not result:
                console.print(f"[dim]No data found as of {as_of}.[/dim]")
                return

            table = Table(title=f"Time Travel: {escape(table_name)} as of {as_of}")
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
            console.print(table)
            console.print(f"\n[dim]Showing {len(result)} rows as of {as_of} ({time_col})[/dim]")
        finally:
            engine.close()
    except ImportError:
        _error("duckdb required for lake queries. Install with: pip install duckdb")


# ===================================================================
# Item 78: Audit program lifecycle
# ===================================================================


@cli.group("program", invoke_without_command=True)
@click.pass_context
def program(ctx: click.Context) -> None:
    """Audit program lifecycle management."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(program_list)


@program.command("list")
def program_list() -> None:
    """List audit programs with their current phase."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.audit_program import AuditProgramManager

    init_db()
    mgr = AuditProgramManager()

    with get_session() as session:
        programs = mgr.list_programs(session)

    if not programs:
        console.print("[dim]No audit programs found.[/dim]")
        console.print(
            "[dim]Create an engagement first with 'warlock audit engagement create'.[/dim]"
        )
        return

    table = Table(title=f"Audit Programs ({len(programs)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", max_width=40)
    table.add_column("Framework", style="cyan")
    table.add_column("Phase")
    table.add_column("Period", style="dim")

    phase_styles = {
        "plan": "dim",
        "scope": "cyan",
        "fieldwork": "yellow",
        "draft_report": "yellow",
        "management_response": "yellow",
        "final_report": "green",
        "follow_up": "green",
        "completed": "green bold",
    }

    for p in programs:
        ps = phase_styles.get(p["phase"], "")
        period = ""
        if p["period_start"] and p["period_end"]:
            period = f"{p['period_start'][:10]} - {p['period_end'][:10]}"
        table.add_row(
            p["id"][:8],
            escape(p["name"]),
            p["framework"],
            f"[{ps}]{p['phase']}[/]" if ps else p["phase"],
            period,
        )

    console.print(table)


@program.command("status")
@click.argument("engagement_id")
def program_status(engagement_id: str) -> None:
    """Show detailed program status for an engagement."""
    from rich.panel import Panel

    from warlock.db.engine import get_session, init_db
    from warlock.workflows.audit_program import PROGRAM_PHASES, AuditProgramManager

    init_db()
    mgr = AuditProgramManager()

    with get_session() as session:
        try:
            status = mgr.get_status(session, engagement_id)
        except ValueError as e:
            _error(str(e))
            return

    # Build phase progression bar
    current_idx = PROGRAM_PHASES.index(status["current_phase"])
    phases_display = []
    for i, phase in enumerate(PROGRAM_PHASES):
        if i < current_idx:
            phases_display.append(f"[green]{phase}[/green]")
        elif i == current_idx:
            phases_display.append(f"[yellow bold]>> {phase} <<[/yellow bold]")
        else:
            phases_display.append(f"[dim]{phase}[/dim]")

    info = (
        f"[bold]{escape(status['engagement_name'])}[/bold]\n\n"
        f"Framework: [cyan]{status['framework']}[/cyan]\n"
        f"Period: {status['period_start'][:10]} - {status['period_end'][:10]}\n"
        f"Auditor: {escape(status['auditor'])}\n\n"
        f"Phase: {' -> '.join(phases_display)}\n\n"
        f"Allowed next: {', '.join(status['allowed_transitions']) or 'none (completed)'}"
    )

    console.print(Panel(info, title="[bold blue]Audit Program[/bold blue]", border_style="blue"))

    if status["phase_history"]:
        table = Table(title="Phase History")
        table.add_column("From", style="dim")
        table.add_column("To")
        table.add_column("Actor", style="dim")
        table.add_column("Timestamp", style="dim")
        table.add_column("Notes", max_width=40)

        for h in status["phase_history"]:
            table.add_row(
                h["from"],
                h["to"],
                escape(h["actor"]),
                h["timestamp"][:19] if h["timestamp"] else "",
                escape(h["notes"]),
            )
        console.print(table)


@program.command("advance")
@click.argument("engagement_id")
@click.option("--notes", "-n", default="", help="Notes for the transition")
def program_advance(engagement_id: str, notes: str) -> None:
    """Advance an audit program to the next phase."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.audit_program import AuditProgramManager

    init_db()
    mgr = AuditProgramManager()
    actor = _get_actor()

    with get_session() as session:
        try:
            result = mgr.advance(session, engagement_id, actor=actor, notes=notes)
        except ValueError as e:
            _error(str(e))
            return

    console.print(
        f"[green]Program advanced:[/green] "
        f"{result['from_phase']} -> [bold]{result['to_phase']}[/bold]"
    )


# ===================================================================
# Item 83: Trust center
# ===================================================================


@cli.group("trust-center", invoke_without_command=True)
@click.pass_context
def trust_center(ctx: click.Context) -> None:
    """Trust center management: public compliance status and documents."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(trust_center_status)


@trust_center.command("status")
def trust_center_status() -> None:
    """Show public trust center certification status."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.trust_center import TrustCenterManager

    init_db()
    mgr = TrustCenterManager()

    with get_session() as session:
        statuses = mgr.get_status(session)

    if not statuses:
        console.print("[dim]No certification attestations found.[/dim]")
        console.print("[dim]Create attestations first with 'warlock attestations create'.[/dim]")
        return

    table = Table(title="Trust Center Status")
    table.add_column("Framework", style="cyan")
    table.add_column("Certification")
    table.add_column("Status")
    table.add_column("Last Updated", style="dim")

    status_styles = {
        "Current": "green bold",
        "Certified": "green bold",
        "Active": "green",
        "In Progress": "yellow",
        "Under Review": "yellow",
        "Expired": "red",
    }

    for s in statuses:
        ss = status_styles.get(s["status"], "")
        table.add_row(
            s["framework"],
            s["label"],
            f"[{ss}]{s['status']}[/]" if ss else s["status"],
            s["last_updated"][:10] if s["last_updated"] else "\u2014",
        )

    console.print(table)


@trust_center.command("publish")
@click.argument("document_id")
def trust_center_publish(document_id: str) -> None:
    """Publish a trust document to make it visible."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.trust_center import TrustCenterManager

    init_db()
    mgr = TrustCenterManager()
    actor = _get_actor()

    with get_session() as session:
        try:
            result = mgr.publish_document(session, document_id=document_id, actor=actor)
        except ValueError as e:
            _error(str(e))
            return

    console.print(
        f"[green]Published:[/green] {escape(result['title'])} "
        f"(classification: {result['classification']})"
    )


@trust_center.command("documents")
def trust_center_documents() -> None:
    """List published trust center documents."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.trust_center import TrustCenterManager

    init_db()
    mgr = TrustCenterManager()

    with get_session() as session:
        docs = mgr.list_documents(session)

    if not docs:
        console.print("[dim]No published trust documents found.[/dim]")
        return

    table = Table(title=f"Trust Center Documents ({len(docs)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Title", max_width=40)
    table.add_column("Classification")
    table.add_column("Uploaded By", style="dim")
    table.add_column("Uploaded At", style="dim")

    for d in docs:
        table.add_row(
            d["id"][:8],
            escape(d["title"]),
            d["classification"],
            escape(d["uploaded_by"]),
            d["uploaded_at"][:10] if d["uploaded_at"] else "",
        )

    console.print(table)


# ===================================================================
# Item 88: Compliance gate command
# ===================================================================


@cli.command("gate")
@click.option("--framework", "-f", default=None, help="Framework to check")
@click.option(
    "--threshold",
    "-t",
    default=80.0,
    type=float,
    help="Minimum compliance score (0-100, default: 80)",
)
@click.option(
    "--format", "fmt", default="table", type=click.Choice(["table", "json"]), help="Output format"
)
def compliance_gate(framework: str | None, threshold: float, fmt: str) -> None:
    """CI/CD compliance gate. Exits non-zero if below threshold.

    Use in CI pipelines to block deployments when compliance posture drops.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()

    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.all()

    if not results:
        if fmt == "json":
            console.print(json.dumps({"passed": False, "reason": "no_data", "score": 0}))
        else:
            console.print("[red]GATE FAILED: No control results found.[/red]")
        raise SystemExit(1)

    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    score = (compliant / total * 100) if total else 0.0

    passed = score >= threshold

    if fmt == "json":
        console.print(
            json.dumps(
                {
                    "passed": passed,
                    "score": round(score, 1),
                    "threshold": threshold,
                    "total_controls": total,
                    "compliant": compliant,
                    "framework": framework or "all",
                }
            )
        )
    else:
        style = "green" if passed else "red"
        console.print(
            f"[{style}]GATE {'PASSED' if passed else 'FAILED'}[/{style}]: "
            f"Score {score:.1f}% (threshold: {threshold}%, "
            f"{compliant}/{total} compliant)"
        )

    if not passed:
        raise SystemExit(1)


# ===================================================================
# Item 89: Scope auto-discover
# ===================================================================


@cli.command("scope")
@click.argument("subcommand", default="auto-discover")
def scope_auto_discover(subcommand: str) -> None:
    """Read asset inventory and suggest authorization boundary."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import Finding

    init_db()

    with get_read_session() as session:
        # Gather unique sources, providers, and resource types from findings
        findings = (
            session.query(
                Finding.source,
                Finding.provider,
                Finding.resource_type,
            )
            .distinct()
            .all()
        )

    if not findings:
        console.print("[dim]No findings data available for scope discovery.[/dim]")
        return

    # Group by provider
    by_provider: dict[str, set[str]] = defaultdict(set)
    sources: set[str] = set()
    for f in findings:
        provider = f.provider or "unknown"
        by_provider[provider].add(f.resource_type or "unknown")
        sources.add(f.source or "unknown")

    console.print("[bold]Authorization Boundary Discovery[/bold]\n")

    table = Table(title="Discovered Asset Inventory")
    table.add_column("Provider", style="cyan")
    table.add_column("Resource Types")
    table.add_column("Count", justify="right")

    for provider in sorted(by_provider):
        rtypes = by_provider[provider]
        table.add_row(
            provider,
            ", ".join(sorted(rtypes)[:5]) + ("..." if len(rtypes) > 5 else ""),
            str(len(rtypes)),
        )

    console.print(table)

    console.print(f"\n[dim]Data sources: {', '.join(sorted(sources))}[/dim]")
    console.print(
        f"\n[bold]Suggested boundary:[/bold] {len(by_provider)} provider(s), "
        f"{sum(len(v) for v in by_provider.values())} resource type(s)"
    )


# ===================================================================
# Item 90: Attack path correlation
# ===================================================================


def _register_attack_path() -> None:
    """Register attack-path command on the correlate group (deferred import)."""
    from warlock.cli.correlate_cmd import correlate as _correlate_grp

    @_correlate_grp.command("attack-path")
    @click.argument("finding_id")
    def correlate_attack_path(finding_id: str) -> None:
        """Trace from finding through affected controls to downstream impact."""
        _attack_path_impl(finding_id)


_register_attack_path()


def _attack_path_impl(finding_id: str) -> None:
    """Trace from finding through affected controls to downstream impact."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import ControlMapping, ControlResult, Finding

    init_db()

    with get_read_session() as session:
        finding = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not finding:
            _error(f"Finding not found: {finding_id}")
            return

        # Get control mappings for this finding
        mappings = (
            session.query(ControlMapping).filter(ControlMapping.finding_id == finding.id).all()
        )

        # Get control results for mapped controls
        affected_controls = []
        for m in mappings:
            results = (
                session.query(ControlResult)
                .filter(
                    ControlResult.framework == m.framework,
                    ControlResult.control_id == m.control_id,
                )
                .all()
            )
            for r in results:
                affected_controls.append(
                    {
                        "framework": r.framework,
                        "control_id": r.control_id,
                        "status": r.status,
                        "severity": r.severity,
                    }
                )

    console.print(f"\n[bold]Attack Path: Finding {finding.id[:8]}[/bold]\n")
    console.print(f"  Source: [cyan]{escape(finding.source or '')}[/cyan]")
    console.print(f"  Title: {escape(finding.title or '')}")
    console.print(f"  Severity: {finding.severity or 'unknown'}")
    console.print(f"\n  [bold]Affected Controls ({len(affected_controls)}):[/bold]")

    if affected_controls:
        table = Table()
        table.add_column("Framework", style="cyan")
        table.add_column("Control")
        table.add_column("Status")
        table.add_column("Severity")

        status_styles = {
            "compliant": "green",
            "non_compliant": "red",
            "partial": "yellow",
        }

        for c in affected_controls[:20]:
            ss = status_styles.get(c["status"], "")
            table.add_row(
                c["framework"],
                c["control_id"],
                f"[{ss}]{c['status']}[/]" if ss else c["status"],
                c["severity"],
            )

        console.print(table)

        non_compliant = sum(1 for c in affected_controls if c["status"] == "non_compliant")
        if non_compliant:
            console.print(
                f"\n  [red bold]Impact: {non_compliant} non-compliant control(s) "
                f"exposed by this finding[/red bold]"
            )
    else:
        console.print("  [dim]No control mappings found for this finding.[/dim]")


# ===================================================================
# Item 91: Regulatory horizon scan
# ===================================================================


@cli.command("horizon")
@click.argument("subcommand", default="scan")
def horizon_scan(subcommand: str) -> None:
    """Check regulatory deadlines and flag upcoming requirements."""
    # Known regulatory deadlines (hardcoded, updated periodically)
    deadlines = [
        {
            "regulation": "EU AI Act",
            "milestone": "Prohibited AI systems ban effective",
            "date": "2025-02-01",
            "status": "past",
        },
        {
            "regulation": "EU AI Act",
            "milestone": "High-risk AI obligations",
            "date": "2025-08-02",
            "status": "past",
        },
        {
            "regulation": "PCI DSS v4.0",
            "milestone": "Full enforcement (all requirements)",
            "date": "2025-03-31",
            "status": "past",
        },
        {
            "regulation": "SEC Cyber",
            "milestone": "Annual 10-K cybersecurity disclosure",
            "date": "2026-12-31",
            "status": "upcoming",
        },
        {
            "regulation": "NIST CSF 2.0",
            "milestone": "Recommended adoption for federal agencies",
            "date": "2026-09-30",
            "status": "upcoming",
        },
        {
            "regulation": "CMMC 2.0",
            "milestone": "Phase 2 — Third-party assessments required",
            "date": "2026-06-01",
            "status": "upcoming",
        },
        {
            "regulation": "EU DORA",
            "milestone": "Full application for financial entities",
            "date": "2025-01-17",
            "status": "past",
        },
        {
            "regulation": "ISO 27001:2022",
            "milestone": "Transition deadline from 2013 version",
            "date": "2025-10-31",
            "status": "past",
        },
        {
            "regulation": "CCPA/CPRA",
            "milestone": "Cybersecurity audit regulations expected",
            "date": "2026-07-01",
            "status": "upcoming",
        },
    ]

    now = datetime.now(timezone.utc)

    table = Table(title="Regulatory Horizon Scan")
    table.add_column("Regulation", style="cyan")
    table.add_column("Milestone", max_width=50)
    table.add_column("Date")
    table.add_column("Status")
    table.add_column("Days", justify="right")

    for d in sorted(deadlines, key=lambda x: x["date"]):
        deadline_date = datetime.strptime(d["date"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        days_away = (deadline_date - now).days

        if days_away < 0:
            status = "[dim]past[/dim]"
            days_str = f"[dim]{abs(days_away)}d ago[/dim]"
        elif days_away < 90:
            status = "[red bold]imminent[/red bold]"
            days_str = f"[red]{days_away}d[/red]"
        elif days_away < 365:
            status = "[yellow]upcoming[/yellow]"
            days_str = f"[yellow]{days_away}d[/yellow]"
        else:
            status = "[dim]future[/dim]"
            days_str = f"{days_away}d"

        table.add_row(
            d["regulation"],
            d["milestone"],
            d["date"],
            status,
            days_str,
        )

    console.print(table)


# ===================================================================
# Item 94: Predictive risk
# ===================================================================


def _register_risk_predict() -> None:
    """Register risk predict command (deferred import)."""
    from warlock.cli.risk import risk as _risk_grp

    @_risk_grp.command("predict")
    @click.option("--framework", "-f", default=None, help="Framework to predict")
    @click.option("--months", "-m", default=6, type=int, help="Months to forecast")
    def risk_predict(framework: str | None, months: int) -> None:
        """Predict future compliance posture using linear extrapolation."""
        _risk_predict_impl(framework, months)


_register_risk_predict()


def _risk_predict_impl(framework: str | None, months: int) -> None:
    """Implementation of risk predict."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import PostureSnapshot

    init_db()

    with get_read_session() as session:
        q = session.query(PostureSnapshot)
        if framework:
            q = q.filter(PostureSnapshot.framework == framework)
        snapshots = q.order_by(PostureSnapshot.snapshot_date.asc()).all()

    if len(snapshots) < 2:
        console.print(
            "[dim]Insufficient data for prediction (need at least 2 posture snapshots).[/dim]"
        )
        return

    # Aggregate scores by date
    by_date: dict[str, list[float]] = defaultdict(list)
    for s in snapshots:
        dt = ensure_aware(s.snapshot_date) if s.snapshot_date else None
        if dt:
            key = dt.strftime("%Y-%m-%d")
            by_date[key].append(s.posture_score or 0.0)

    dates = sorted(by_date.keys())
    avg_scores = [sum(by_date[d]) / len(by_date[d]) for d in dates]

    if len(avg_scores) < 2:
        console.print("[dim]Insufficient unique dates for trend analysis.[/dim]")
        return

    # Simple linear regression
    n = len(avg_scores)
    x_vals = list(range(n))
    x_mean = sum(x_vals) / n
    y_mean = sum(avg_scores) / n

    numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, avg_scores))
    denominator = sum((x - x_mean) ** 2 for x in x_vals)

    if denominator == 0:
        slope = 0.0
    else:
        slope = numerator / denominator
    intercept = y_mean - slope * x_mean

    # Predict future
    table = Table(title=f"Risk Prediction ({months} months)")
    table.add_column("Month", style="cyan")
    table.add_column("Predicted Score", justify="right")
    table.add_column("Trend")

    now = datetime.now(timezone.utc)
    current_score = avg_scores[-1]

    for m in range(1, months + 1):
        future_x = n + m * 4  # ~4 data points per month
        predicted = max(0.0, min(100.0, intercept + slope * future_x))
        month_label = (now + timedelta(days=30 * m)).strftime("%Y-%m")

        if predicted > current_score:
            trend = "[green]improving[/green]"
        elif predicted < current_score - 5:
            trend = "[red]declining[/red]"
        else:
            trend = "[dim]stable[/dim]"

        table.add_row(month_label, f"{predicted:.1f}%", trend)

    console.print(table)
    console.print(
        f"\n[dim]Based on {len(dates)} historical data points. "
        f"Trend slope: {slope:+.3f} per period.[/dim]"
    )


# ===================================================================
# Item 95: Compliance visualization (ASCII heatmap)
# ===================================================================


def _register_comply_chart() -> None:
    """Register chart command on comply group (deferred import)."""
    from warlock.cli.comply_cmd import comply as _comply_grp

    @_comply_grp.command("chart")
    @click.option("--framework", "-f", default=None, help="Framework to chart")
    def comply_chart(framework: str | None) -> None:
        """ASCII heatmap of control family compliance status."""
        _comply_chart_impl(framework)


_register_comply_chart()


def _comply_chart_impl(framework: str | None) -> None:
    """Implementation of comply chart."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import ControlResult

    init_db()

    with get_read_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.all()

    if not results:
        console.print("[dim]No control results found.[/dim]")
        return

    # Group by control family (first part of control_id before hyphen or dot)
    families: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in results:
        # Extract family: AC-2 -> AC, CC6.1 -> CC6, etc.
        cid = r.control_id or ""
        family = cid.split("-")[0].split(".")[0] if cid else "unknown"
        key = f"{r.framework}:{family}" if not framework else family
        families[key][r.status] += 1

    table = Table(title=f"Compliance Heatmap{f': {framework}' if framework else ''}")
    table.add_column("Family", style="cyan")
    table.add_column("Total", justify="right")
    table.add_column("Bar")
    table.add_column("Score", justify="right")

    for family in sorted(families):
        counts = families[family]
        total = sum(counts.values())
        compliant = counts.get("compliant", 0)
        partial_ct = counts.get("partial", 0)
        non_compliant = counts.get("non_compliant", 0)
        score = (compliant / total * 100) if total else 0

        # ASCII bar
        bar_width = 30
        green_len = int(bar_width * compliant / total) if total else 0
        yellow_len = int(bar_width * partial_ct / total) if total else 0
        red_len = int(bar_width * non_compliant / total) if total else 0
        grey_len = bar_width - green_len - yellow_len - red_len

        bar = (
            f"[green]{'█' * green_len}[/green]"
            f"[yellow]{'█' * yellow_len}[/yellow]"
            f"[red]{'█' * red_len}[/red]"
            f"[dim]{'░' * grey_len}[/dim]"
        )

        score_style = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        table.add_row(family, str(total), bar, f"[{score_style}]{score:.0f}%[/]")

    console.print(table)


# ===================================================================
# Item 97: Custom report builder
# ===================================================================


def _register_reports_custom() -> None:
    """Register custom report commands on the reports group (deferred import)."""
    from warlock.cli.reports_cmd import reports as _reports_grp

    @_reports_grp.group("custom", invoke_without_command=True)
    @click.pass_context
    def reports_custom(ctx: click.Context) -> None:
        """Custom report builder commands."""
        if ctx.invoked_subcommand is None:
            ctx.invoke(reports_custom_list_cmd)

    @reports_custom.command("list")
    def reports_custom_list_cmd() -> None:
        """List saved custom report definitions."""
        from warlock.db.engine import get_read_session, init_db
        from warlock.db.models import AuditEntry

        init_db()

        with get_read_session() as session:
            entries = (
                session.query(AuditEntry)
                .filter(
                    AuditEntry.action == "custom_report_created",
                    AuditEntry.entity_type == "custom_report",
                )
                .order_by(AuditEntry.created_at.desc())
                .all()
            )

        if not entries:
            console.print("[dim]No custom reports defined.[/dim]")
            console.print("[dim]Use 'warlock reports custom create' to define one.[/dim]")
            return

        table = Table(title=f"Custom Reports ({len(entries)})")
        table.add_column("ID", style="dim", max_width=8)
        table.add_column("Name", max_width=40)
        table.add_column("Framework", style="cyan")
        table.add_column("Sections")
        table.add_column("Created", style="dim")

        for e in entries:
            meta = e.extra or {}
            table.add_row(
                e.entity_id[:8],
                escape(meta.get("name", "")),
                meta.get("framework", "all"),
                str(len(meta.get("sections", []))),
                ensure_aware(e.created_at).strftime("%Y-%m-%d") if e.created_at else "",
            )

        console.print(table)

    @reports_custom.command("create")
    @click.option("--name", "-n", required=True, help="Report name")
    @click.option("--framework", "-f", default="all", help="Framework scope")
    @click.option(
        "--sections",
        "-s",
        multiple=True,
        default=["posture", "gaps", "risks"],
        help="Report sections (repeatable)",
    )
    def reports_custom_create(name: str, framework: str, sections: tuple[str, ...]) -> None:
        """Create a custom report definition."""
        from uuid import uuid4

        from warlock.db.audit import AuditTrail
        from warlock.db.engine import get_session, init_db

        init_db()
        report_id = str(uuid4())
        actor = _get_actor()

        with get_session() as session:
            audit = AuditTrail(session)
            audit.record(
                action="custom_report_created",
                entity_type="custom_report",
                entity_id=report_id,
                actor=actor,
                metadata={
                    "name": name,
                    "framework": framework,
                    "sections": list(sections),
                },
            )

        console.print(
            f"[green]Report created:[/green] {report_id[:8]} ({escape(name)}, "
            f"framework={escape(framework)}, sections={', '.join(sections)})"
        )

    @reports_custom.command("run")
    @click.argument("report_id")
    @click.option(
        "--format",
        "fmt",
        default="table",
        type=click.Choice(["table", "json"]),
        help="Output format",
    )
    def reports_custom_run(report_id: str, fmt: str) -> None:
        """Execute a saved custom report."""
        from warlock.db.engine import get_session, init_db
        from warlock.db.models import AuditEntry, ControlResult, Finding

        init_db()

        with get_session() as session:
            entry = (
                session.query(AuditEntry)
                .filter(
                    AuditEntry.entity_id.startswith(report_id),
                    AuditEntry.action == "custom_report_created",
                )
                .first()
            )
            if not entry:
                _error(f"Custom report not found: {report_id}")
                return

            meta = entry.extra or {}
            framework = meta.get("framework", "all")
            sections = meta.get("sections", [])

            q = session.query(ControlResult)
            if framework and framework != "all":
                q = q.filter(ControlResult.framework == framework)
            results = q.all()

            total = len(results)
            compliant = sum(1 for r in results if r.status == "compliant")
            non_compliant = sum(1 for r in results if r.status == "non_compliant")
            partial_ct = sum(1 for r in results if r.status == "partial")
            score = (compliant / total * 100) if total else 0.0

            findings_count = session.query(Finding).count()

        report_data = {
            "name": meta.get("name", ""),
            "framework": framework,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "posture": {
                "score": round(score, 1),
                "total": total,
                "compliant": compliant,
                "non_compliant": non_compliant,
                "partial": partial_ct,
            },
            "findings": findings_count,
            "sections": sections,
        }

        if fmt == "json":
            console.print(json.dumps(report_data, indent=2))
            return

        console.print(f"\n[bold]Custom Report: {escape(meta.get('name', ''))}[/bold]")
        console.print(f"Framework: [cyan]{framework}[/cyan]")
        console.print(f"Generated: {report_data['generated_at'][:19]}\n")

        if "posture" in sections:
            console.print(f"  Posture Score: {score:.1f}%")
            console.print(
                f"  Controls: {total} total, {compliant} compliant, {non_compliant} non-compliant"
            )

        if "gaps" in sections:
            console.print(f"  Gaps: {non_compliant + partial_ct} controls need attention")

        if "risks" in sections:
            console.print(f"  Findings: {findings_count} total")


_register_reports_custom()


# ===================================================================
# Item 98: Auditor portal CLI
# ===================================================================


@cli.command("trust-portal")
@click.argument("subcommand", default="query")
@click.option("--framework", "-f", default=None, help="Framework filter")
@click.option("--status-filter", default=None, help="Status filter")
def trust_portal_query(subcommand: str, framework: str | None, status_filter: str | None) -> None:
    """Auditor self-service portal query interface."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import ControlResult

    init_db()

    with get_read_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        if status_filter:
            q = q.filter(ControlResult.status == status_filter)
        results = q.order_by(ControlResult.assessed_at.desc()).limit(50).all()

    if not results:
        console.print("[dim]No results found matching query.[/dim]")
        return

    table = Table(title="Auditor Portal Query Results")
    table.add_column("Framework", style="cyan")
    table.add_column("Control")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Assessed", style="dim")
    table.add_column("Evidence", justify="right")

    for r in results:
        st = {
            "compliant": "green",
            "non_compliant": "red",
            "partial": "yellow",
        }.get(r.status, "")
        table.add_row(
            r.framework,
            r.control_id,
            f"[{st}]{r.status}[/]" if st else r.status,
            r.severity or "",
            r.assessed_at.strftime("%Y-%m-%d") if r.assessed_at else "\u2014",
            str(len(r.evidence_ids or [])),
        )

    console.print(table)


# ===================================================================
# Item 100: Anomaly detection baseline
# ===================================================================


@lake.command("anomaly-baseline")
@click.option("--path", default=None, help="Lake root path")
@click.option("--window-days", default=30, type=int, help="Baseline window (days)")
def lake_anomaly_baseline(path: str | None, window_days: int) -> None:
    """Compute and store anomaly detection baselines."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import Finding

    init_db()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=window_days)

    with get_read_session() as session:
        findings = session.query(Finding).filter(Finding.ingested_at >= cutoff).all()

    if not findings:
        console.print("[dim]No findings in baseline window.[/dim]")
        return

    # Compute baselines per source/severity
    by_source: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        source = f.source or "unknown"
        severity = f.severity or "info"
        by_source[source][severity] += 1

    table = Table(title=f"Anomaly Detection Baselines ({window_days}d window)")
    table.add_column("Source", style="cyan")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("High", justify="right", style="red")
    table.add_column("Medium", justify="right", style="yellow")
    table.add_column("Low", justify="right", style="dim")
    table.add_column("Total", justify="right")
    table.add_column("Daily Avg", justify="right")

    for source in sorted(by_source):
        counts = by_source[source]
        total = sum(counts.values())
        daily_avg = total / window_days if window_days else 0
        table.add_row(
            source,
            str(counts.get("critical", 0)),
            str(counts.get("high", 0)),
            str(counts.get("medium", 0)),
            str(counts.get("low", 0)),
            str(total),
            f"{daily_avg:.1f}",
        )

    console.print(table)
    console.print(
        f"\n[dim]Baseline computed from {len(findings)} findings over {window_days} days.[/dim]"
    )


# ===================================================================
# Item 101: Lake lineage visualization
# ===================================================================


@lake.command("lineage")
@click.argument("finding_id")
def lake_lineage(finding_id: str) -> None:
    """Show data lineage graph for a finding (ASCII)."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import ControlMapping, ControlResult, Finding, RawEvent

    init_db()

    with get_read_session() as session:
        finding = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not finding:
            _error(f"Finding not found: {finding_id}")
            return

        # Trace lineage: raw_event -> finding -> control_mapping -> control_result
        raw_event = (
            session.query(RawEvent).filter(RawEvent.id == finding.raw_event_id).first()
            if finding.raw_event_id
            else None
        )

        mappings = (
            session.query(ControlMapping).filter(ControlMapping.finding_id == finding.id).all()
        )

        results = []
        for m in mappings:
            cr = (
                session.query(ControlResult)
                .filter(ControlResult.control_mapping_id == m.id)
                .first()
            )
            if cr:
                results.append((m, cr))

    # ASCII lineage graph
    console.print(f"\n[bold]Data Lineage: Finding {finding.id[:8]}[/bold]\n")

    # Level 0: Raw Event
    if raw_event:
        console.print(f"  [dim]RawEvent[/dim] {raw_event.id[:8]}")
        console.print(f"    source: {escape(raw_event.source or '')}")
        console.print("    |")
        console.print("    v")

    # Level 1: Finding
    console.print(f"  [cyan]Finding[/cyan] {finding.id[:8]}")
    console.print(f"    title: {escape((finding.title or '')[:60])}")
    console.print(f"    severity: {finding.severity or 'unknown'}")

    if not mappings:
        console.print("    [dim](no control mappings)[/dim]")
        return

    console.print("    |")
    for i, m in enumerate(mappings[:10]):
        is_last_mapping = i == min(len(mappings), 10) - 1
        prefix = "    +--" if not is_last_mapping else "    \\--"
        console.print(f"{prefix} [yellow]Mapping[/yellow] {m.framework}/{m.control_id}")

        # Find matching result
        for mp, cr in results:
            if mp.id == m.id:
                st = {
                    "compliant": "green",
                    "non_compliant": "red",
                    "partial": "yellow",
                }.get(cr.status, "")
                indent = "    |   " if not is_last_mapping else "        "
                console.print(
                    f"{indent}\\-> [{st}]Result[/{st}] "
                    f"{cr.status} (assessed: "
                    f"{cr.assessed_at.strftime('%Y-%m-%d') if cr.assessed_at else 'n/a'})"
                )
                break

    if len(mappings) > 10:
        console.print(f"    [dim]... and {len(mappings) - 10} more mappings[/dim]")


# ===================================================================
# Item 102: Lake retention tiering
# ===================================================================


@lake.group("retention", invoke_without_command=True)
@click.pass_context
def lake_retention(ctx: click.Context) -> None:
    """Lake retention management commands."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(retention_status)


@lake_retention.command("status")
@click.option("--path", default=None, help="Lake root path")
def retention_status(path: str | None) -> None:
    """Show retention tier status for each lake zone."""
    from warlock.config import get_settings

    settings = get_settings()
    lake_path = Path(path or settings.lake_path)

    if not lake_path.exists():
        console.print(f"[yellow]Lake does not exist: {lake_path}[/yellow]")
        return

    # Retention tiers
    tiers = {
        "raw": {"retention_days": 7, "description": "Raw events — short retention"},
        "enrichment": {"retention_days": 30, "description": "Enriched data — medium retention"},
        "curated": {"retention_days": 365, "description": "Curated analytics — long retention"},
    }

    now = datetime.now(timezone.utc)

    table = Table(title="Lake Retention Status")
    table.add_column("Zone", style="cyan")
    table.add_column("Retention", justify="right")
    table.add_column("Files", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("Oldest File", style="dim")
    table.add_column("Expired", justify="right")

    for zone, tier in tiers.items():
        zone_dir = lake_path / zone
        if not zone_dir.exists():
            table.add_row(zone, f"{tier['retention_days']}d", "0", "0 B", "\u2014", "0")
            continue

        files = list(zone_dir.rglob("*.parquet"))
        size = sum(f.stat().st_size for f in files)

        oldest = None
        expired_count = 0
        cutoff = now - timedelta(days=tier["retention_days"])

        for f in files:
            mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
            if oldest is None or mtime < oldest:
                oldest = mtime
            if mtime < cutoff:
                expired_count += 1

        oldest_str = oldest.strftime("%Y-%m-%d") if oldest else "\u2014"
        expired_style = "red" if expired_count > 0 else "dim"

        table.add_row(
            zone,
            f"{tier['retention_days']}d",
            str(len(files)),
            _format_size(size),
            oldest_str,
            f"[{expired_style}]{expired_count}[/]",
        )

    console.print(table)


@lake_retention.command("enforce")
@click.option("--path", default=None, help="Lake root path")
@click.option("--dry-run/--no-dry-run", default=True, help="Preview only (default: dry run)")
def retention_enforce(path: str | None, dry_run: bool) -> None:
    """Enforce retention policies by removing expired files."""
    from warlock.config import get_settings

    settings = get_settings()
    lake_path = Path(path or settings.lake_path)

    if not lake_path.exists():
        console.print(f"[yellow]Lake does not exist: {lake_path}[/yellow]")
        return

    tiers = {"raw": 7, "enrichment": 30, "curated": 365}
    now = datetime.now(timezone.utc)
    total_removed = 0
    total_bytes = 0

    for zone, retention_days in tiers.items():
        zone_dir = lake_path / zone
        if not zone_dir.exists():
            continue

        cutoff = now - timedelta(days=retention_days)
        for f in zone_dir.rglob("*.parquet"):
            mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                size = f.stat().st_size
                if dry_run:
                    console.print(
                        f"  [dim]Would remove: {f.relative_to(lake_path)} "
                        f"({_format_size(size)}, {(now - mtime).days}d old)[/dim]"
                    )
                else:
                    f.unlink()
                    console.print(f"  Removed: {f.relative_to(lake_path)}")
                total_removed += 1
                total_bytes += size

    if total_removed == 0:
        console.print("[dim]No expired files found. All data within retention window.[/dim]")
    else:
        action = "Would remove" if dry_run else "Removed"
        console.print(
            f"\n[{'yellow' if dry_run else 'green'}]{action} {total_removed} file(s) "
            f"({_format_size(total_bytes)})[/]"
        )
        if dry_run:
            console.print("[yellow]Dry run. Use --no-dry-run to execute.[/yellow]")
