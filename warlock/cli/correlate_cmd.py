"""Cross-domain correlation commands.

Traces relationships between findings, controls, incidents, evidence, and
audit entries across the Warlock pipeline. Every command is read-only.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import click
from rich.panel import Panel
from rich.table import Table

from warlock.cli import cli, console, _error


@cli.group("correlate")
def correlate() -> None:
    """Cross-domain correlation: trace findings, controls, evidence, and audit entries."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fmt_dt(dt: datetime | None) -> str:
    if dt is None:
        return "\u2014"
    return dt.strftime("%Y-%m-%d %H:%M")


def _severity_style(sev: str | None) -> str:
    return {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }.get(sev or "", "")


# ---------------------------------------------------------------------------
# finding-to-incident
# ---------------------------------------------------------------------------


@correlate.command("finding-to-incident")
@click.argument("finding_id")
def finding_to_incident(finding_id: str) -> None:
    """Show incidents (issues) linked to a finding."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, Issue

    init_db()
    with get_session() as session:
        finding = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not finding:
            _error(f"Finding not found: {finding_id}")

        issues = session.query(Issue).filter(Issue.finding_id == finding.id).all()

    if not issues:
        console.print(f"[dim]No incidents (issues) linked to finding {finding.id[:8]}.[/dim]")
        return

    table = Table(title=f"Incidents linked to finding {finding.id[:8]}")
    table.add_column("Issue ID", style="dim", max_width=8)
    table.add_column("Title", max_width=50)
    table.add_column("Status")
    table.add_column("Priority")
    table.add_column("Assigned To", style="dim")
    table.add_column("Created", style="dim")

    for i in issues:
        sty = _severity_style(i.priority)
        table.add_row(
            i.id[:8],
            (i.title or "")[:50],
            i.status,
            f"[{sty}]{i.priority}[/]",
            i.assigned_to or "\u2014",
            _fmt_dt(i.created_at),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# incident-to-findings
# ---------------------------------------------------------------------------


@correlate.command("incident-to-findings")
@click.argument("incident_id")
def incident_to_findings(incident_id: str) -> None:
    """Show all findings linked to an incident (issue)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, Issue

    init_db()
    with get_session() as session:
        issue = session.query(Issue).filter(Issue.id.startswith(incident_id)).first()
        if not issue:
            _error(f"Issue not found: {incident_id}")

        findings: list[Finding] = []
        if issue.finding_id:
            f = session.query(Finding).filter(Finding.id == issue.finding_id).first()
            if f:
                findings.append(f)

    if not findings:
        console.print(f"[dim]No findings linked to issue {issue.id[:8]}.[/dim]")
        return

    table = Table(title=f"Findings linked to issue {issue.id[:8]}")
    table.add_column("Finding ID", style="dim", max_width=8)
    table.add_column("Title", max_width=50)
    table.add_column("Source", style="cyan")
    table.add_column("Severity")
    table.add_column("Observed", style="dim")

    for f in findings:
        sty = _severity_style(f.severity)
        table.add_row(
            f.id[:8],
            (f.title or "")[:50],
            f.source,
            f"[{sty}]{f.severity}[/]",
            _fmt_dt(f.observed_at),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# finding-to-controls
# ---------------------------------------------------------------------------


@correlate.command("finding-to-controls")
@click.argument("finding_id")
def finding_to_controls(finding_id: str) -> None:
    """Show all controls mapped to a finding via ControlMapping."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, Finding

    init_db()
    with get_session() as session:
        finding = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not finding:
            _error(f"Finding not found: {finding_id}")

        mappings = (
            session.query(ControlMapping).filter(ControlMapping.finding_id == finding.id).all()
        )

    if not mappings:
        console.print(f"[dim]No control mappings for finding {finding.id[:8]}.[/dim]")
        return

    table = Table(title=f"Controls mapped to finding {finding.id[:8]}")
    table.add_column("Framework", style="cyan")
    table.add_column("Control ID", style="cyan")
    table.add_column("Family", style="dim")
    table.add_column("Method")
    table.add_column("Confidence", justify="right")

    for m in mappings:
        table.add_row(
            m.framework,
            m.control_id,
            m.control_family or "\u2014",
            m.mapping_method,
            f"{m.confidence:.2f}",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# control-to-findings
# ---------------------------------------------------------------------------


@correlate.command("control-to-findings")
@click.argument("control_id")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--limit", "-n", default=50, help="Max results")
def control_to_findings(control_id: str, framework: str | None, limit: int) -> None:
    """Show all findings mapped to a control."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, Finding

    init_db()
    with get_session() as session:
        q = session.query(ControlMapping).filter(ControlMapping.control_id == control_id)
        if framework:
            q = q.filter(ControlMapping.framework == framework)
        mappings = q.limit(limit).all()

        if not mappings:
            console.print(f"[dim]No findings mapped to control {control_id}.[/dim]")
            return

        finding_ids = list({m.finding_id for m in mappings})
        findings = session.query(Finding).filter(Finding.id.in_(finding_ids)).all()
        findings_by_id = {f.id: f for f in findings}

    table = Table(title=f"Findings mapped to control {control_id}")
    table.add_column("Finding ID", style="dim", max_width=8)
    table.add_column("Title", max_width=45)
    table.add_column("Source", style="cyan")
    table.add_column("Severity")
    table.add_column("Framework", style="dim")
    table.add_column("Method", style="dim")

    for m in mappings:
        f = findings_by_id.get(m.finding_id)
        if not f:
            continue
        sty = _severity_style(f.severity)
        table.add_row(
            f.id[:8],
            (f.title or "")[:45],
            f.source,
            f"[{sty}]{f.severity}[/]",
            m.framework,
            m.mapping_method,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# control-to-evidence
# ---------------------------------------------------------------------------


@correlate.command("control-to-evidence")
@click.argument("control_id")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--limit", "-n", default=50, help="Max results")
def control_to_evidence(control_id: str, framework: str | None, limit: int) -> None:
    """Show evidence (ControlResult evidence_ids) for a control."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(ControlResult).filter(ControlResult.control_id == control_id)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        results = q.order_by(ControlResult.assessed_at.desc()).limit(limit).all()

    if not results:
        console.print(f"[dim]No control results for control {control_id}.[/dim]")
        return

    table = Table(title=f"Evidence for control {control_id}")
    table.add_column("Result ID", style="dim", max_width=8)
    table.add_column("Framework", style="cyan")
    table.add_column("Status")
    table.add_column("Assessor", style="dim")
    table.add_column("Evidence IDs", max_width=40)
    table.add_column("Assessed", style="dim")

    for r in results:
        ev_ids = r.evidence_ids or []
        ev_str = ", ".join(str(e)[:8] for e in ev_ids[:3])
        if len(ev_ids) > 3:
            ev_str += f" (+{len(ev_ids) - 3})"
        status_style = {
            "compliant": "green",
            "non_compliant": "red",
            "partial": "yellow",
            "not_assessed": "dim",
            "risk_accepted": "magenta",
        }.get(r.status, "")
        table.add_row(
            r.id[:8],
            r.framework,
            f"[{status_style}]{r.status}[/]",
            (r.assessor or "")[:30],
            ev_str or "\u2014",
            _fmt_dt(r.assessed_at),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# trace
# ---------------------------------------------------------------------------


@correlate.command("trace")
@click.argument("finding_id")
def trace(finding_id: str) -> None:
    """Full trace: finding -> controls -> results -> evidence -> audit trail."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, ControlMapping, ControlResult, Finding, RawEvent

    init_db()
    with get_session() as session:
        finding = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not finding:
            _error(f"Finding not found: {finding_id}")

        raw = session.query(RawEvent).filter(RawEvent.id == finding.raw_event_id).first()
        mappings = (
            session.query(ControlMapping).filter(ControlMapping.finding_id == finding.id).all()
        )
        mapping_ids = [m.id for m in mappings]
        results = (
            session.query(ControlResult)
            .filter(ControlResult.control_mapping_id.in_(mapping_ids))
            .all()
            if mapping_ids
            else []
        )
        audit_entries = (
            session.query(AuditEntry)
            .filter(AuditEntry.entity_id == finding.id)
            .order_by(AuditEntry.sequence)
            .limit(10)
            .all()
        )

    # --- Finding header ---
    sev_sty = _severity_style(finding.severity)
    console.print(
        Panel(
            f"[bold]{finding.title}[/bold]\n"
            f"ID: {finding.id[:8]}  |  Source: {finding.source} / {finding.provider}\n"
            f"Severity: [{sev_sty}]{finding.severity}[/]  |  "
            f"Observed: {_fmt_dt(finding.observed_at)}\n"
            f"Resource: {finding.resource_id or finding.resource_type or '\u2014'}",
            title="[bold cyan]Finding[/bold cyan]",
            border_style="cyan",
        )
    )

    # --- Raw event ---
    if raw:
        console.print(
            f"[dim]Raw event:[/dim] {raw.id[:8]}  event_type={raw.event_type}  "
            f"ingested={_fmt_dt(raw.ingested_at)}"
        )

    # --- Control mappings ---
    if mappings:
        console.print(f"\n[bold]Control mappings ({len(mappings)}):[/bold]")
        for m in mappings:
            console.print(
                f"  [cyan]{m.framework}:{m.control_id}[/cyan]  "
                f"method={m.mapping_method}  confidence={m.confidence:.2f}"
            )

    # --- Control results ---
    if results:
        console.print(f"\n[bold]Control results ({len(results)}):[/bold]")
        for r in results:
            st_sty = {"compliant": "green", "non_compliant": "red", "partial": "yellow"}.get(
                r.status, ""
            )
            ev_count = len(r.evidence_ids or [])
            console.print(
                f"  [{st_sty}]{r.status}[/]  {r.framework}:{r.control_id}  "
                f"assessor={r.assessor}  evidence={ev_count} id(s)"
            )

    # --- Audit trail ---
    if audit_entries:
        console.print(f"\n[bold]Audit trail ({len(audit_entries)} entries):[/bold]")
        for ae in audit_entries:
            console.print(
                f"  seq={ae.sequence}  action=[cyan]{ae.action}[/cyan]  "
                f"actor={ae.actor}  {_fmt_dt(ae.created_at)}"
            )

    if not mappings and not results and not audit_entries:
        console.print("[dim]No downstream correlation data found for this finding.[/dim]")


# ---------------------------------------------------------------------------
# impact-analysis
# ---------------------------------------------------------------------------


@correlate.command("impact-analysis")
@click.argument("control_id")
@click.option("--framework", "-f", default=None, help="Framework filter")
def impact_analysis(control_id: str, framework: str | None) -> None:
    """Which findings, frameworks, and issues are affected if this control fails."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, ControlResult, Issue

    init_db()
    with get_session() as session:
        q = session.query(ControlMapping).filter(ControlMapping.control_id == control_id)
        if framework:
            q = q.filter(ControlMapping.framework == framework)
        mappings = q.all()

        finding_ids = list({m.finding_id for m in mappings})
        frameworks = list({m.framework for m in mappings})

        results = (
            session.query(ControlResult).filter(ControlResult.control_id == control_id).all()
        )
        non_compliant = [r for r in results if r.status == "non_compliant"]

        issues = session.query(Issue).filter(Issue.control_id == control_id).all()
        if framework:
            issues = [i for i in issues if i.framework == framework]

    console.print(
        Panel(
            f"Control: [bold cyan]{control_id}[/bold cyan]\n"
            f"Frameworks affected: {', '.join(frameworks) or '\u2014'}\n"
            f"Findings mapped:     [bold]{len(finding_ids)}[/bold]\n"
            f"Control results:     [bold]{len(results)}[/bold]  "
            f"([red]{len(non_compliant)} non-compliant[/red])\n"
            f"Open issues:         [bold]{len(issues)}[/bold]",
            title="[bold red]Impact Analysis[/bold red]",
            border_style="red",
        )
    )

    if issues:
        console.print("\n[bold]Open issues:[/bold]")
        for i in issues:
            sty = _severity_style(i.priority)
            console.print(
                f"  [dim]{i.id[:8]}[/dim]  [{sty}]{i.priority}[/]  "
                f"{(i.title or '')[:60]}  status={i.status}"
            )


# ---------------------------------------------------------------------------
# dependency-map
# ---------------------------------------------------------------------------


@correlate.command("dependency-map")
@click.option("--system", default=None, help="Filter by system profile ID or acronym")
def dependency_map(system: str | None) -> None:
    """Show cross-system dependency graph."""
    from warlock.cli import _resolve_system_id
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SystemDependency

    init_db()
    with get_session() as session:
        system_id = _resolve_system_id(session, system) if system else None
        q = session.query(SystemDependency)
        if system_id:
            q = q.filter(
                (SystemDependency.consumer_system_id == system_id)
                | (SystemDependency.provider_system_id == system_id)
            )
        rows = q.all()

    if not rows:
        console.print("[dim]No system dependencies found.[/dim]")
        return

    table = Table(title="System Dependency Map")
    table.add_column("Consumer", style="cyan", max_width=8)
    table.add_column("Provider", style="cyan", max_width=8)
    table.add_column("Type")
    table.add_column("Shared Controls", max_width=50)

    for d in rows:
        ctrls = (d.shared_controls or [])[:3]
        ctrl_str = ", ".join(ctrls)
        if len(d.shared_controls or []) > 3:
            ctrl_str += f" (+{len(d.shared_controls) - 3})"
        table.add_row(
            d.consumer_system_id[:8],
            d.provider_system_id[:8],
            d.dependency_type,
            ctrl_str or "\u2014",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# blast-radius
# ---------------------------------------------------------------------------


@correlate.command("blast-radius")
@click.argument("finding_id")
def blast_radius(finding_id: str) -> None:
    """How many controls, frameworks, and systems are affected by a finding."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, ControlResult, Finding

    init_db()
    with get_session() as session:
        finding = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not finding:
            _error(f"Finding not found: {finding_id}")

        mappings = (
            session.query(ControlMapping).filter(ControlMapping.finding_id == finding.id).all()
        )
        control_ids = list({m.control_id for m in mappings})
        frameworks = list({m.framework for m in mappings})

        results = (
            session.query(ControlResult)
            .filter(ControlResult.finding_id == finding.id)
            .all()
        )
        system_ids = list(
            {r.system_profile_id for r in results if r.system_profile_id}
        )

    sev_sty = _severity_style(finding.severity)
    console.print(
        Panel(
            f"Finding: [bold]{(finding.title or '')[:70]}[/bold]\n"
            f"ID: {finding.id[:8]}  Severity: [{sev_sty}]{finding.severity}[/]\n\n"
            f"Controls affected:  [bold]{len(control_ids)}[/bold]\n"
            f"Frameworks:         [bold]{len(frameworks)}[/bold]  "
            f"({', '.join(frameworks) or '\u2014'})\n"
            f"Systems affected:   [bold]{len(system_ids)}[/bold]\n"
            f"Control results:    [bold]{len(results)}[/bold]",
            title="[bold yellow]Blast Radius[/bold yellow]",
            border_style="yellow",
        )
    )

    if control_ids:
        console.print("\n[bold]Controls:[/bold]")
        for fw in frameworks:
            cids = [m.control_id for m in mappings if m.framework == fw]
            console.print(f"  [cyan]{fw}[/cyan]: {', '.join(sorted(cids)[:10])}")


# ---------------------------------------------------------------------------
# common-findings
# ---------------------------------------------------------------------------


@correlate.command("common-findings")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--min-frameworks", default=2, help="Minimum number of frameworks a finding maps to")
@click.option("--limit", "-n", default=50, help="Max results")
def common_findings(framework: str | None, min_frameworks: int, limit: int) -> None:
    """Findings that map to multiple frameworks."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, Finding
    from sqlalchemy import func

    init_db()
    with get_session() as session:
        # Count distinct frameworks per finding
        q = (
            session.query(
                ControlMapping.finding_id,
                func.count(func.distinct(ControlMapping.framework)).label("fw_count"),
            )
            .group_by(ControlMapping.finding_id)
            .having(func.count(func.distinct(ControlMapping.framework)) >= min_frameworks)
        )
        if framework:
            # Only include findings that have at least one mapping to the specified framework
            sub = (
                session.query(ControlMapping.finding_id)
                .filter(ControlMapping.framework == framework)
                .subquery()
            )
            q = q.filter(ControlMapping.finding_id.in_(sub))

        rows = q.order_by(func.count(func.distinct(ControlMapping.framework)).desc()).limit(limit).all()

        if not rows:
            console.print("[dim]No findings map to multiple frameworks.[/dim]")
            return

        finding_ids = [r.finding_id for r in rows]
        fw_counts = {r.finding_id: r.fw_count for r in rows}
        findings = session.query(Finding).filter(Finding.id.in_(finding_ids)).all()
        findings_by_id = {f.id: f for f in findings}

    table = Table(title=f"Findings spanning multiple frameworks (min {min_frameworks})")
    table.add_column("Finding ID", style="dim", max_width=8)
    table.add_column("Title", max_width=45)
    table.add_column("Source", style="cyan")
    table.add_column("Severity")
    table.add_column("Frameworks", justify="right")

    for row in rows:
        f = findings_by_id.get(row.finding_id)
        if not f:
            continue
        sty = _severity_style(f.severity)
        table.add_row(
            f.id[:8],
            (f.title or "")[:45],
            f.source,
            f"[{sty}]{f.severity}[/]",
            str(fw_counts[row.finding_id]),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# orphan-findings
# ---------------------------------------------------------------------------


@correlate.command("orphan-findings")
@click.option("--limit", "-n", default=50, help="Max results")
def orphan_findings(limit: int) -> None:
    """Findings with no control mapping."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, Finding

    init_db()
    with get_session() as session:
        mapped_sub = session.query(ControlMapping.finding_id).subquery()
        orphans = (
            session.query(Finding)
            .filter(~Finding.id.in_(session.query(mapped_sub)))
            .order_by(Finding.observed_at.desc())
            .limit(limit)
            .all()
        )

    if not orphans:
        console.print("[green]No orphan findings -- all findings have control mappings.[/green]")
        return

    table = Table(title=f"Orphan findings (no control mapping) -- {len(orphans)} shown")
    table.add_column("Finding ID", style="dim", max_width=8)
    table.add_column("Title", max_width=50)
    table.add_column("Source", style="cyan")
    table.add_column("Severity")
    table.add_column("Observed", style="dim")

    for f in orphans:
        sty = _severity_style(f.severity)
        table.add_row(
            f.id[:8],
            (f.title or "")[:50],
            f.source,
            f"[{sty}]{f.severity}[/]",
            _fmt_dt(f.observed_at),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# orphan-controls
# ---------------------------------------------------------------------------


@correlate.command("orphan-controls")
@click.option("--framework", "-f", default=None, help="Framework to check")
def orphan_controls(framework: str | None) -> None:
    """Controls with no findings or evidence (from ControlResult)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, ControlResult

    init_db()
    with get_session() as session:
        # Controls that appear in mappings
        q_mappings = session.query(
            ControlMapping.framework, ControlMapping.control_id
        ).distinct()
        if framework:
            q_mappings = q_mappings.filter(ControlMapping.framework == framework)
        mapped_controls: set[tuple[str, str]] = {(r.framework, r.control_id) for r in q_mappings.all()}

        # Controls that have results
        q_results = session.query(
            ControlResult.framework, ControlResult.control_id
        ).distinct()
        if framework:
            q_results = q_results.filter(ControlResult.framework == framework)
        assessed_controls: set[tuple[str, str]] = {(r.framework, r.control_id) for r in q_results.all()}

    controls_with_no_evidence = mapped_controls - assessed_controls
    controls_with_no_findings = assessed_controls - mapped_controls

    if not controls_with_no_evidence and not controls_with_no_findings:
        console.print("[green]No orphan controls found.[/green]")
        return

    if controls_with_no_evidence:
        table = Table(title="Controls with mappings but no assessment results")
        table.add_column("Framework", style="cyan")
        table.add_column("Control ID", style="cyan")
        for fw, cid in sorted(controls_with_no_evidence)[:50]:
            table.add_row(fw, cid)
        console.print(table)

    if controls_with_no_findings:
        table2 = Table(title="Controls with results but no finding mappings")
        table2.add_column("Framework", style="cyan")
        table2.add_column("Control ID", style="cyan")
        for fw, cid in sorted(controls_with_no_findings)[:50]:
            table2.add_row(fw, cid)
        console.print(table2)


# ---------------------------------------------------------------------------
# coverage-matrix
# ---------------------------------------------------------------------------


@correlate.command("coverage-matrix")
@click.option("--framework", "-f", required=True, help="Framework to analyze (e.g. nist_800_53)")
@click.option("--limit-controls", default=20, help="Max controls to show per row")
def coverage_matrix(framework: str, limit_controls: int) -> None:
    """Matrix of connectors x controls showing coverage for a framework."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, Finding

    init_db()
    with get_session() as session:
        # Collect (source, control_id) pairs
        rows = (
            session.query(Finding.source, ControlMapping.control_id)
            .join(ControlMapping, ControlMapping.finding_id == Finding.id)
            .filter(ControlMapping.framework == framework)
            .distinct()
            .all()
        )

    if not rows:
        console.print(f"[dim]No coverage data for framework {framework}.[/dim]")
        return

    # Build matrix
    sources: list[str] = sorted({r.source for r in rows})
    controls: list[str] = sorted({r.control_id for r in rows})[:limit_controls]
    covered: set[tuple[str, str]] = {(r.source, r.control_id) for r in rows}

    table = Table(title=f"Coverage matrix: {framework} (first {len(controls)} controls)")
    table.add_column("Source", style="cyan")
    for c in controls:
        table.add_column(c, max_width=8, justify="center")

    for src in sources[:30]:  # cap rows at 30
        row_cells = [
            "[green]Y[/green]" if (src, c) in covered else "[dim]-[/dim]" for c in controls
        ]
        table.add_row(src, *row_cells)

    console.print(table)
    if len(sources) > 30:
        console.print(f"[dim]... and {len(sources) - 30} more sources not shown[/dim]")


# ---------------------------------------------------------------------------
# gap-analysis
# ---------------------------------------------------------------------------


@correlate.command("gap-analysis")
@click.argument("framework")
def gap_analysis(framework: str) -> None:
    """Comprehensive gap analysis: missing connectors, unmapped controls, stale evidence, failed assertions."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, ControlResult, Finding

    STALE_HOURS = 24 * 7  # 7 days

    init_db()
    with get_session() as session:
        # Controls with mappings
        mapped = set(
            r.control_id
            for r in session.query(ControlMapping.control_id)
            .filter(ControlMapping.framework == framework)
            .distinct()
            .all()
        )

        # Controls with results
        assessed = set(
            r.control_id
            for r in session.query(ControlResult.control_id)
            .filter(ControlResult.framework == framework)
            .distinct()
            .all()
        )

        # Non-compliant results
        non_compliant = (
            session.query(ControlResult.control_id)
            .filter(ControlResult.framework == framework, ControlResult.status == "non_compliant")
            .distinct()
            .all()
        )
        non_compliant_ids = {r.control_id for r in non_compliant}

        # Stale evidence (no findings observed in last STALE_HOURS)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=STALE_HOURS)
        recent_mappings = set(
            r.control_id
            for r in (
                session.query(ControlMapping.control_id)
                .join(Finding, Finding.id == ControlMapping.finding_id)
                .filter(
                    ControlMapping.framework == framework,
                    Finding.observed_at >= cutoff,
                )
                .distinct()
                .all()
            )
        )
        stale_controls = mapped - recent_mappings

        # Sources active for this framework
        sources = set(
            r.source
            for r in (
                session.query(Finding.source)
                .join(ControlMapping, ControlMapping.finding_id == Finding.id)
                .filter(ControlMapping.framework == framework)
                .distinct()
                .all()
            )
        )

    console.print(
        Panel(
            f"Framework: [bold cyan]{framework}[/bold cyan]\n\n"
            f"Controls with mappings:   [bold]{len(mapped)}[/bold]\n"
            f"Controls assessed:        [bold]{len(assessed)}[/bold]\n"
            f"Controls unassessed:      [bold yellow]{len(mapped - assessed)}[/bold yellow]\n"
            f"Non-compliant controls:   [bold red]{len(non_compliant_ids)}[/bold red]\n"
            f"Stale evidence (>7d):     [bold yellow]{len(stale_controls)}[/bold yellow]\n"
            f"Active data sources:      [bold]{len(sources)}[/bold]",
            title="[bold]Gap Analysis[/bold]",
            border_style="blue",
        )
    )

    if mapped - assessed:
        console.print("\n[bold yellow]Unassessed controls:[/bold yellow]")
        for cid in sorted(mapped - assessed)[:20]:
            console.print(f"  [dim]{cid}[/dim]")
        if len(mapped - assessed) > 20:
            console.print(f"  [dim]... and {len(mapped - assessed) - 20} more[/dim]")

    if non_compliant_ids:
        console.print("\n[bold red]Non-compliant controls:[/bold red]")
        for cid in sorted(non_compliant_ids)[:20]:
            console.print(f"  [red]{cid}[/red]")
        if len(non_compliant_ids) > 20:
            console.print(f"  [dim]... and {len(non_compliant_ids) - 20} more[/dim]")

    if stale_controls:
        console.print("\n[bold yellow]Controls with stale evidence (>7 days):[/bold yellow]")
        for cid in sorted(stale_controls)[:20]:
            console.print(f"  [yellow]{cid}[/yellow]")
        if len(stale_controls) > 20:
            console.print(f"  [dim]... and {len(stale_controls) - 20} more[/dim]")


# ---------------------------------------------------------------------------
# timeline-correlation
# ---------------------------------------------------------------------------


@correlate.command("timeline-correlation")
@click.option("--days", default=7, help="Look-back window in days")
@click.option("--limit", "-n", default=100, help="Max events per type")
def timeline_correlation(days: int, limit: int) -> None:
    """Correlated timeline of findings, incidents, and change events."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ChangeEvent, Finding, Issue

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    init_db()
    with get_session() as session:
        findings = (
            session.query(Finding)
            .filter(Finding.observed_at >= cutoff)
            .order_by(Finding.observed_at.desc())
            .limit(limit)
            .all()
        )
        issues = (
            session.query(Issue)
            .filter(Issue.created_at >= cutoff)
            .order_by(Issue.created_at.desc())
            .limit(limit)
            .all()
        )
        changes = (
            session.query(ChangeEvent)
            .filter(ChangeEvent.occurred_at >= cutoff)
            .order_by(ChangeEvent.occurred_at.desc())
            .limit(limit)
            .all()
        )

    # Merge into a unified timeline
    events: list[tuple[datetime, str, str, str]] = []
    for f in findings:
        events.append((f.observed_at, "finding", f.severity, f"[{f.source}] {(f.title or '')[:60]}"))
    for i in issues:
        events.append((i.created_at, "issue", i.priority, f"[{i.status}] {(i.title or '')[:60]}"))
    for c in changes:
        events.append((c.occurred_at, "change", "info", f"[{c.source}] {(c.action or '')[:60]}"))

    events.sort(key=lambda x: x[0], reverse=True)

    if not events:
        console.print(f"[dim]No events in the last {days} days.[/dim]")
        return

    table = Table(title=f"Timeline correlation -- last {days} days ({len(events)} events)")
    table.add_column("Timestamp", style="dim")
    table.add_column("Type")
    table.add_column("Severity")
    table.add_column("Description", max_width=65)

    type_styles = {
        "finding": "cyan",
        "issue": "yellow",
        "change": "blue",
    }
    for ts, etype, sev, desc in events[:200]:
        tsty = type_styles.get(etype, "")
        ssty = _severity_style(sev)
        table.add_row(
            _fmt_dt(ts),
            f"[{tsty}]{etype}[/]",
            f"[{ssty}]{sev}[/]" if sev else "\u2014",
            desc,
        )

    console.print(table)
