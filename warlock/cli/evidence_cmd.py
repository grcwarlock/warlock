"""Evidence management commands.

Uses EvidenceRequest, AuditEntry, and ControlResult models.
Provides evidence lifecycle management, hash chain verification,
gap analysis, and auditor request workflows.
"""

from __future__ import annotations

import json as _json
from datetime import datetime, timedelta, timezone

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor
from warlock.utils import ensure_aware


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("evidence", invoke_without_command=True)
@click.pass_context
def evidence(ctx: click.Context) -> None:
    """Evidence collection, verification, and auditor request management."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@evidence.command("list")
@click.option("--control", "-c", default=None, help="Filter by control ID")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--fresh/--stale",
    default=None,
    help="Filter by freshness (--fresh: assessed in last 30 days, --stale: older than 30 days)",
)
@click.option(
    "--format", "fmt", default="table", type=click.Choice(["table", "json"]), help="Output format"
)
@click.option("--limit", "-n", default=50, help="Max results")
def evidence_list(
    control: str | None,
    framework: str | None,
    fresh: bool | None,
    fmt: str,
    limit: int,
) -> None:
    """List control results with evidence metadata."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    threshold = datetime.now(timezone.utc) - timedelta(days=30)

    with get_session() as session:
        q = session.query(ControlResult)
        if control:
            q = q.filter(ControlResult.control_id == control)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        if fresh is True:
            q = q.filter(ControlResult.assessed_at >= threshold)
        elif fresh is False:
            q = q.filter(ControlResult.assessed_at < threshold)
        rows = q.order_by(ControlResult.assessed_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No evidence records found.[/dim]")
        return

    if fmt == "json":
        out = [
            {
                "id": r.id,
                "framework": r.framework,
                "control_id": r.control_id,
                "status": r.status,
                "severity": r.severity,
                "assessor": r.assessor,
                "assessed_at": r.assessed_at.isoformat() if r.assessed_at else None,
                "evidence_ids": r.evidence_ids or [],
                "stale": ensure_aware(r.assessed_at) < threshold if r.assessed_at else True,
            }
            for r in rows
        ]
        console.print(_json.dumps(out, indent=2, default=str))
        return

    table = Table(title=f"Evidence Records ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Framework", style="cyan")
    table.add_column("Control", style="cyan")
    table.add_column("Status")
    table.add_column("Assessor", style="dim", max_width=30)
    table.add_column("Assessed At", style="dim")
    table.add_column("Evidence", justify="right")
    table.add_column("Freshness")

    for r in rows:
        status_style = {
            "compliant": "green",
            "non_compliant": "red",
            "partial": "yellow",
            "not_assessed": "dim",
        }.get(r.status, "")
        assessed = r.assessed_at.strftime("%Y-%m-%d") if r.assessed_at else "\u2014"
        ev_count = len(r.evidence_ids or [])
        is_stale = ensure_aware(r.assessed_at) < threshold if r.assessed_at else True
        freshness = "[dim]stale[/dim]" if is_stale else "[green]fresh[/green]"

        table.add_row(
            r.id[:8],
            r.framework,
            r.control_id,
            f"[{status_style}]{r.status}[/]",
            (r.assessor or "")[:30],
            assessed,
            str(ev_count),
            freshness,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@evidence.command("show")
@click.argument("result_id")
def evidence_show(result_id: str) -> None:
    """Show full detail for an evidence record (control result)."""
    from rich.panel import Panel

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    threshold = datetime.now(timezone.utc) - timedelta(days=30)

    with get_session() as session:
        result = session.query(ControlResult).filter(ControlResult.id.startswith(result_id)).first()
        if not result:
            _error(f"Evidence record not found: {result_id}")

        status_style = {
            "compliant": "green",
            "non_compliant": "red",
            "partial": "yellow",
            "not_assessed": "dim",
        }.get(result.status, "")
        is_stale = result.assessed_at < threshold if result.assessed_at else True
        freshness = "stale" if is_stale else "fresh"

        console.print()
        console.print(
            Panel(
                f"[bold]{result.framework} / {result.control_id}[/bold]\n\n"
                f"ID: {result.id}  |  Status: [{status_style}]{result.status}[/]  |  "
                f"Severity: {result.severity}\n"
                f"Assessor: {result.assessor}  |  "
                f"Assessed: {result.assessed_at}  |  Freshness: {freshness}",
                title="[bold blue]Evidence Record[/bold blue]",
                border_style="blue",
            )
        )

        if result.assertion_name:
            passed = "[green]PASS[/green]" if result.assertion_passed else "[red]FAIL[/red]"
            console.print(f"\n[bold]Assertion:[/bold] {result.assertion_name} — {passed}")
            if result.assertion_findings:
                console.print("[bold]Assertion findings:[/bold]")
                for f in result.assertion_findings:
                    console.print(f"  - {f}")

        if result.ai_assessment:
            console.print(f"\n[bold]AI Assessment:[/bold]\n{result.ai_assessment}")
            if result.ai_confidence is not None:
                console.print(f"  Confidence: {result.ai_confidence:.2f}  Model: {result.ai_model}")

        if result.remediation_summary:
            console.print(f"\n[bold]Remediation:[/bold]\n{result.remediation_summary}")
            if result.remediation_steps:
                for i, step in enumerate(result.remediation_steps, 1):
                    console.print(f"  {i}. {step}")

        ev_ids = result.evidence_ids or []
        console.print(f"\n[bold]Evidence IDs ({len(ev_ids)}):[/bold]")
        for eid in ev_ids[:10]:
            console.print(f"  {eid}")
        if len(ev_ids) > 10:
            console.print(f"  ... and {len(ev_ids) - 10} more")

        console.print()


# ---------------------------------------------------------------------------
# attach
# ---------------------------------------------------------------------------


@evidence.command("attach")
@click.argument("control_id")
@click.option("--file", "-f", "file_path", required=True, help="Path to evidence file")
@click.option("--description", "-d", required=True, help="Description of the evidence")
def evidence_attach(control_id: str, file_path: str, description: str) -> None:
    """Attach a file as evidence for a control result."""
    import hashlib
    import uuid
    from pathlib import Path

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, ControlResult

    path = Path(file_path)
    if not path.exists():
        _error(f"File not found: {file_path}")

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    # Compute file hash
    file_hash = hashlib.sha256(path.read_bytes()).hexdigest()

    with get_session() as session:
        result = (
            session.query(ControlResult)
            .filter(ControlResult.control_id == control_id)
            .order_by(ControlResult.assessed_at.desc())
            .first()
        )
        if not result:
            _error(
                f"No control result found for control '{control_id}'. "
                "Run 'warlock collect' to generate results first."
            )

        # Append evidence reference ID
        ev_ref = str(uuid.uuid4())
        ev_ids = list(result.evidence_ids or [])
        ev_ids.append(ev_ref)
        result.evidence_ids = ev_ids

        # Audit trail
        last = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        prev_hash = last.entry_hash if last else "genesis"
        seq = (last.sequence + 1) if last else 1
        payload = f"{seq}:{prev_hash}:evidence_attached:{result.id}:{actor}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()

        audit = AuditEntry(
            id=str(uuid.uuid4()),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="evidence_attached",
            entity_type="control_result",
            entity_id=result.id,
            actor=actor,
            evidence_sha256=file_hash,
            extra={
                "evidence_ref": ev_ref,
                "file": str(path.name),
                "description": description,
                "sha256": file_hash,
                "control_id": control_id,
                "framework": result.framework,
            },
            created_at=now,
        )
        session.add(audit)
        session.commit()

    console.print(
        f"[green]Evidence attached to control {control_id}[/green]\n"
        f"  File: {path.name}  SHA256: {file_hash[:16]}...  Ref: {ev_ref[:8]}"
    )


# ---------------------------------------------------------------------------
# package
# ---------------------------------------------------------------------------


@evidence.command("package")
@click.argument("framework")
@click.option("--output", "-o", default=".", help="Output directory for the package")
def evidence_package(framework: str, output: str) -> None:
    """Bundle all evidence for a framework into an auditor package."""
    import uuid
    from pathlib import Path

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    with get_session() as session:
        rows = (
            session.query(ControlResult)
            .filter(ControlResult.framework == framework)
            .order_by(ControlResult.control_id.asc())
            .all()
        )

    if not rows:
        _error(f"No control results found for framework '{framework}'.")

    package = {
        "framework": framework,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": _get_actor(),
        "package_id": str(uuid.uuid4()),
        "control_count": len(rows),
        "controls": [
            {
                "control_id": r.control_id,
                "status": r.status,
                "severity": r.severity,
                "assessor": r.assessor,
                "assessed_at": r.assessed_at.isoformat() if r.assessed_at else None,
                "evidence_ids": r.evidence_ids or [],
                "remediation_summary": r.remediation_summary,
                "assertion_name": r.assertion_name,
                "assertion_passed": r.assertion_passed,
            }
            for r in rows
        ],
    }

    out_file = (
        out_dir
        / f"evidence_package_{framework}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    )
    out_file.write_text(_json.dumps(package, indent=2, default=str))

    compliant = sum(1 for r in rows if r.status == "compliant")
    non_compliant = sum(1 for r in rows if r.status == "non_compliant")

    console.print(f"[green]Evidence package created:[/green] {out_file}")
    console.print(f"  Framework: {framework}")
    console.print(
        f"  Controls: {len(rows)} total, {compliant} compliant, {non_compliant} non-compliant"
    )


# ---------------------------------------------------------------------------
# chain
# ---------------------------------------------------------------------------


@evidence.command("chain")
@click.argument("result_id")
def evidence_chain(result_id: str) -> None:
    """Show the hash chain provenance for an evidence record."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, ControlResult

    init_db()
    with get_session() as session:
        result = session.query(ControlResult).filter(ControlResult.id.startswith(result_id)).first()
        if not result:
            _error(f"Evidence record not found: {result_id}")

        entries = (
            session.query(AuditEntry)
            .filter(AuditEntry.entity_id == result.id)
            .order_by(AuditEntry.sequence.asc())
            .all()
        )

    if not entries:
        console.print("[dim]No audit chain entries found for this record.[/dim]")
        return

    table = Table(title=f"Hash Chain: {result.id[:8]}")
    table.add_column("Seq", style="dim", justify="right")
    table.add_column("Action", style="cyan")
    table.add_column("Actor", style="dim")
    table.add_column("Prev Hash", style="dim", max_width=16)
    table.add_column("Entry Hash", style="dim", max_width=16)
    table.add_column("Timestamp", style="dim")

    for e in entries:
        ts = e.created_at.strftime("%Y-%m-%d %H:%M:%S") if e.created_at else "\u2014"
        table.add_row(
            str(e.sequence),
            e.action,
            e.actor,
            e.previous_hash[:16],
            e.entry_hash[:16],
            ts,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


@evidence.command("verify")
@click.argument("result_id")
def evidence_verify(result_id: str) -> None:
    """Verify the hash chain integrity for an evidence record."""
    import hashlib

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, ControlResult

    init_db()
    with get_session() as session:
        result = session.query(ControlResult).filter(ControlResult.id.startswith(result_id)).first()
        if not result:
            _error(f"Evidence record not found: {result_id}")

        entries = (
            session.query(AuditEntry)
            .filter(AuditEntry.entity_id == result.id)
            .order_by(AuditEntry.sequence.asc())
            .all()
        )

    if not entries:
        console.print("[yellow]No audit chain entries — cannot verify.[/yellow]")
        return

    console.print(f"Verifying hash chain for {result.id[:8]} ({len(entries)} entries)...")

    errors: list[str] = []
    prev_hash = "genesis"

    for e in entries:
        # Recompute expected hash
        payload = f"{e.sequence}:{prev_hash}:{e.action}:{e.entity_id}:{e.actor}"
        expected_hash = hashlib.sha256(payload.encode()).hexdigest()

        if e.previous_hash != prev_hash:
            errors.append(
                f"Seq {e.sequence}: previous_hash mismatch "
                f"(expected {prev_hash[:16]}, got {e.previous_hash[:16]})"
            )
        if e.entry_hash != expected_hash:
            errors.append(
                f"Seq {e.sequence}: entry_hash mismatch "
                f"(expected {expected_hash[:16]}, got {e.entry_hash[:16]})"
            )

        prev_hash = e.entry_hash

    if errors:
        console.print(f"[red]Chain integrity FAILED ({len(errors)} error(s)):[/red]")
        for err in errors:
            console.print(f"  [red]{err}[/red]")
    else:
        console.print(
            f"[green]Chain integrity VERIFIED[/green] — {len(entries)} entries, no tampering detected."
        )


# ---------------------------------------------------------------------------
# freshness
# ---------------------------------------------------------------------------


@evidence.command("freshness")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--threshold-days", "-t", default=30, help="Staleness threshold in days (default: 30)"
)
def evidence_freshness(framework: str | None, threshold_days: int) -> None:
    """Show evidence freshness report — which controls have stale or missing assessments."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    threshold = datetime.now(timezone.utc) - timedelta(days=threshold_days)

    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.order_by(ControlResult.assessed_at.asc()).all()

    if not rows:
        console.print("[dim]No evidence records found.[/dim]")
        return

    stale = [r for r in rows if not r.assessed_at or ensure_aware(r.assessed_at) < threshold]
    fresh = [r for r in rows if r.assessed_at and ensure_aware(r.assessed_at) >= threshold]

    console.print(
        f"[bold]Freshness Report[/bold] (threshold: {threshold_days} days)\n"
        f"  Total: {len(rows)}  |  Fresh: [green]{len(fresh)}[/green]  |  "
        f"Stale: [red]{len(stale)}[/red]"
    )

    if stale:
        table = Table(title=f"Stale Evidence ({len(stale)} controls)")
        table.add_column("Framework", style="cyan")
        table.add_column("Control", style="cyan")
        table.add_column("Last Assessed", style="dim")
        table.add_column("Days Ago", justify="right")
        table.add_column("Status")

        now = datetime.now(timezone.utc)
        for r in stale:
            if r.assessed_at:
                days_ago = (now - r.assessed_at).days
                last = r.assessed_at.strftime("%Y-%m-%d")
            else:
                days_ago = 9999
                last = "[dim]never[/dim]"
            status_style = {"compliant": "green", "non_compliant": "red"}.get(r.status, "")
            table.add_row(
                r.framework,
                r.control_id,
                last,
                str(days_ago),
                f"[{status_style}]{r.status}[/]",
            )

        console.print(table)


# ---------------------------------------------------------------------------
# gaps
# ---------------------------------------------------------------------------


@evidence.command("gaps")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def evidence_gaps(framework: str | None) -> None:
    """Show controls missing evidence (no evidence_ids attached)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.all()

    gaps = [r for r in rows if not r.evidence_ids]

    if not gaps:
        console.print("[green]No evidence gaps — all controls have evidence attached.[/green]")
        return

    table = Table(title=f"Evidence Gaps ({len(gaps)} controls)")
    table.add_column("Framework", style="cyan")
    table.add_column("Control", style="cyan")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Assessor", style="dim", max_width=30)

    for r in gaps:
        status_style = {
            "non_compliant": "red",
            "partial": "yellow",
            "compliant": "green",
        }.get(r.status, "")
        table.add_row(
            r.framework,
            r.control_id,
            f"[{status_style}]{r.status}[/]",
            r.severity,
            (r.assessor or "")[:30],
        )

    console.print(table)
    console.print(
        "\n[dim]Attach evidence with: warlock evidence attach <control_id> --file <path> --description '...'[/dim]"
    )


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


@evidence.command("export")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--format", "fmt", default="zip", type=click.Choice(["zip", "tar"]), help="Archive format"
)
def evidence_export(framework: str | None, fmt: str) -> None:
    """Export evidence records to a compressed archive."""
    import io
    import tarfile
    import zipfile

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.order_by(ControlResult.framework, ControlResult.control_id).all()

    if not rows:
        console.print("[dim]No evidence records found.[/dim]")
        return

    label = framework or "all"
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"evidence_export_{label}_{ts}.{fmt}"

    data = _json.dumps(
        [
            {
                "id": r.id,
                "framework": r.framework,
                "control_id": r.control_id,
                "status": r.status,
                "severity": r.severity,
                "assessor": r.assessor,
                "assessed_at": r.assessed_at.isoformat() if r.assessed_at else None,
                "evidence_ids": r.evidence_ids or [],
                "remediation_summary": r.remediation_summary,
            }
            for r in rows
        ],
        indent=2,
        default=str,
    ).encode()

    if fmt == "zip":
        with zipfile.ZipFile(filename, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("evidence.json", data)
    else:
        with tarfile.open(filename, "w:gz") as tf:
            info = tarfile.TarInfo(name="evidence.json")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

    console.print(f"[green]Evidence exported:[/green] {filename}  ({len(rows)} records)")


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


@evidence.command("stats")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def evidence_stats(framework: str | None) -> None:
    """Show evidence statistics by framework and status."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    threshold = datetime.now(timezone.utc) - timedelta(days=30)

    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.all()

    if not rows:
        console.print("[dim]No evidence records found.[/dim]")
        return

    # Group by framework
    by_fw: dict[str, list] = {}
    for r in rows:
        by_fw.setdefault(r.framework, []).append(r)

    table = Table(title="Evidence Statistics")
    table.add_column("Framework", style="cyan")
    table.add_column("Total", justify="right")
    table.add_column("Compliant", justify="right")
    table.add_column("Non-Compliant", justify="right")
    table.add_column("Partial", justify="right")
    table.add_column("Fresh", justify="right")
    table.add_column("With Evidence", justify="right")

    for fw, results in sorted(by_fw.items()):
        compliant = sum(1 for r in results if r.status == "compliant")
        non_compliant = sum(1 for r in results if r.status == "non_compliant")
        partial = sum(1 for r in results if r.status == "partial")
        fresh = sum(
            1 for r in results if r.assessed_at and ensure_aware(r.assessed_at) >= threshold
        )
        with_ev = sum(1 for r in results if r.evidence_ids)
        table.add_row(
            fw,
            str(len(results)),
            f"[green]{compliant}[/green]",
            f"[red]{non_compliant}[/red]",
            f"[yellow]{partial}[/yellow]",
            str(fresh),
            str(with_ev),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# timeline
# ---------------------------------------------------------------------------


@evidence.command("timeline")
@click.argument("control_id")
@click.option("--days", "-d", default=90, help="History window in days (default: 90)")
def evidence_timeline(control_id: str, days: int) -> None:
    """Show assessment history for a control over time."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    since = datetime.now(timezone.utc) - timedelta(days=days)

    with get_session() as session:
        rows = (
            session.query(ControlResult)
            .filter(
                ControlResult.control_id == control_id,
                ControlResult.assessed_at >= since,
            )
            .order_by(ControlResult.assessed_at.asc())
            .all()
        )

    if not rows:
        console.print(
            f"[dim]No assessments for control '{control_id}' in the last {days} days.[/dim]"
        )
        return

    table = Table(title=f"Timeline: {control_id} (last {days} days)")
    table.add_column("Assessed At", style="dim")
    table.add_column("Framework", style="cyan")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Assessor", style="dim", max_width=30)
    table.add_column("Evidence", justify="right")

    for r in rows:
        ts = r.assessed_at.strftime("%Y-%m-%d %H:%M") if r.assessed_at else "\u2014"
        status_style = {
            "compliant": "green",
            "non_compliant": "red",
            "partial": "yellow",
        }.get(r.status, "")
        ev_count = len(r.evidence_ids or [])
        table.add_row(
            ts,
            r.framework,
            f"[{status_style}]{r.status}[/]",
            r.severity,
            (r.assessor or "")[:30],
            str(ev_count),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Nested group: requests
# ---------------------------------------------------------------------------


@evidence.group("requests", invoke_without_command=True)
@click.pass_context
def evidence_requests(ctx: click.Context) -> None:
    """Manage auditor evidence requests."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# requests list
# ---------------------------------------------------------------------------


@evidence_requests.command("list")
@click.option(
    "--status",
    "-s",
    default=None,
    type=click.Choice(["requested", "in_progress", "fulfilled", "closed", "overdue"]),
    help="Filter by status",
)
@click.option("--limit", "-n", default=50, help="Max results")
def requests_list(status: str | None, limit: int) -> None:
    """List auditor evidence requests."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import EvidenceRequest

    init_db()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        q = session.query(EvidenceRequest)
        if status and status != "overdue":
            q = q.filter(EvidenceRequest.status == status)
        rows = q.order_by(EvidenceRequest.created_at.desc()).limit(limit).all()

    if status == "overdue":
        # EvidenceRequest has no due_date; use created_at + 14 days as SLA proxy
        rows = [r for r in rows if (now - r.created_at).days > 14 and r.status != "fulfilled"]

    if not rows:
        console.print("[dim]No evidence requests found.[/dim]")
        return

    table = Table(title=f"Evidence Requests ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Framework", style="cyan")
    table.add_column("Control", style="cyan")
    table.add_column("Description", max_width=40)
    table.add_column("Status")
    table.add_column("Fulfilled By", style="dim")
    table.add_column("Created", style="dim")

    for r in rows:
        st_style = {
            "requested": "yellow",
            "in_progress": "cyan",
            "fulfilled": "green",
            "closed": "dim",
        }.get(r.status, "")
        created = r.created_at.strftime("%Y-%m-%d") if r.created_at else "\u2014"
        table.add_row(
            r.id[:8],
            r.framework or "\u2014",
            r.control_id or "\u2014",
            escape((r.description or "")[:40]),
            f"[{st_style}]{r.status}[/]",
            r.fulfilled_by or "\u2014",
            created,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# requests create
# ---------------------------------------------------------------------------


@evidence_requests.command("create")
@click.option("--control", "-c", required=True, help="Control ID this request is for")
@click.option("--description", "-d", required=True, help="Evidence requested")
@click.option("--due-date", default=None, help="Due date YYYY-MM-DD")
def requests_create(control: str, description: str, due_date: str | None) -> None:
    """Create an auditor evidence request."""
    import uuid

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, ControlResult, EvidenceRequest

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    if due_date:
        try:
            datetime.strptime(due_date, "%Y-%m-%d")
        except ValueError:
            _error(f"Invalid --due-date: {due_date}. Use YYYY-MM-DD.")

    with get_session() as session:
        # Resolve framework from control result
        cr = (
            session.query(ControlResult)
            .filter(ControlResult.control_id == control)
            .order_by(ControlResult.assessed_at.desc())
            .first()
        )
        framework = cr.framework if cr else None

        # EvidenceRequest requires engagement_id and auditor_id — use sentinel UUIDs for CLI usage
        sentinel = "00000000-0000-0000-0000-000000000000"
        req = EvidenceRequest(
            id=str(uuid.uuid4()),
            engagement_id=sentinel,
            auditor_id=sentinel,
            framework=framework,
            control_id=control,
            description=description,
            status="requested",
            created_at=now,
            updated_at=now,
        )
        session.add(req)

        # Audit
        last = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        prev_hash = last.entry_hash if last else "genesis"
        seq = (last.sequence + 1) if last else 1
        import hashlib

        payload = f"{seq}:{prev_hash}:evidence_request_created:{req.id}:{actor}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()

        audit = AuditEntry(
            id=str(uuid.uuid4()),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="evidence_request_created",
            entity_type="evidence_request",
            entity_id=req.id,
            actor=actor,
            extra={"control_id": control, "framework": framework, "due_date": due_date},
            created_at=now,
        )
        session.add(audit)
        session.commit()

        console.print(
            f"[green]Evidence request created:[/green] [cyan]{req.id[:8]}[/cyan] "
            f"for control {control}"
        )
        if due_date:
            console.print(f"  Due: {due_date}")


# ---------------------------------------------------------------------------
# requests assign
# ---------------------------------------------------------------------------


@evidence_requests.command("assign")
@click.argument("request_id")
@click.option("--to", "assignee", required=True, help="User ID/email to assign to")
def requests_assign(request_id: str, assignee: str) -> None:
    """Assign an evidence request to a user."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import EvidenceRequest

    init_db()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        req = (
            session.query(EvidenceRequest).filter(EvidenceRequest.id.startswith(request_id)).first()
        )
        if not req:
            _error(f"Evidence request not found: {request_id}")

        req.status = "in_progress"
        req.fulfilled_by = assignee
        req.updated_at = now
        session.commit()

    console.print(
        f"[green]Request {request_id[:8]} assigned to {assignee} — status: in_progress[/green]"
    )


# ---------------------------------------------------------------------------
# requests fulfill
# ---------------------------------------------------------------------------


@evidence_requests.command("fulfill")
@click.argument("request_id")
@click.option("--file", "-f", "file_path", default=None, help="Path to fulfillment evidence file")
@click.option("--notes", "-n", default=None, help="Fulfillment notes")
def requests_fulfill(request_id: str, file_path: str | None, notes: str | None) -> None:
    """Mark an evidence request as fulfilled."""
    import hashlib
    import uuid
    from pathlib import Path

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, EvidenceRequest

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    file_hash: str | None = None
    if file_path:
        p = Path(file_path)
        if not p.exists():
            _error(f"File not found: {file_path}")
        file_hash = hashlib.sha256(p.read_bytes()).hexdigest()

    with get_session() as session:
        req = (
            session.query(EvidenceRequest).filter(EvidenceRequest.id.startswith(request_id)).first()
        )
        if not req:
            _error(f"Evidence request not found: {request_id}")

        req.status = "fulfilled"
        req.fulfilled_by = req.fulfilled_by or actor
        req.fulfilled_at = now
        req.fulfillment_notes = notes
        req.updated_at = now

        if file_hash:
            ev_ids = list(req.evidence_ids or [])
            ev_ids.append(str(uuid.uuid4()))
            req.evidence_ids = ev_ids

        # Audit
        last = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        prev_hash = last.entry_hash if last else "genesis"
        seq = (last.sequence + 1) if last else 1
        payload = f"{seq}:{prev_hash}:evidence_request_fulfilled:{req.id}:{actor}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()

        audit = AuditEntry(
            id=str(uuid.uuid4()),
            sequence=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action="evidence_request_fulfilled",
            entity_type="evidence_request",
            entity_id=req.id,
            actor=actor,
            evidence_sha256=file_hash,
            extra={
                "notes": notes,
                "file_sha256": file_hash,
                "file": file_path,
            },
            created_at=now,
        )
        session.add(audit)
        session.commit()

    console.print(f"[green]Evidence request {request_id[:8]} fulfilled.[/green]")
    if notes:
        console.print(f"  Notes: {notes}")
    if file_hash:
        console.print(f"  File SHA256: {file_hash[:16]}...")


# ---------------------------------------------------------------------------
# requests import
# ---------------------------------------------------------------------------


@evidence_requests.command("import")
@click.option("--file", "-f", "file_path", required=True, help="Path to CSV file with requests")
def requests_import(file_path: str) -> None:
    """Bulk import evidence requests from a CSV file.

    CSV columns: control_id, description, due_date (optional)
    """
    import csv
    import uuid
    from pathlib import Path

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, EvidenceRequest

    path = Path(file_path)
    if not path.exists():
        _error(f"File not found: {file_path}")

    init_db()
    now = datetime.now(timezone.utc)
    sentinel = "00000000-0000-0000-0000-000000000000"
    created_count = 0
    errors: list[str] = []

    with get_session() as session:
        with path.open(newline="") as fh:
            reader = csv.DictReader(fh)
            for row_num, row in enumerate(reader, start=2):
                control_id = (row.get("control_id") or "").strip()
                description = (row.get("description") or "").strip()
                if not control_id or not description:
                    errors.append(f"Row {row_num}: missing control_id or description")
                    continue

                cr = (
                    session.query(ControlResult)
                    .filter(ControlResult.control_id == control_id)
                    .order_by(ControlResult.assessed_at.desc())
                    .first()
                )
                framework = cr.framework if cr else None

                req = EvidenceRequest(
                    id=str(uuid.uuid4()),
                    engagement_id=sentinel,
                    auditor_id=sentinel,
                    framework=framework,
                    control_id=control_id,
                    description=description,
                    status="requested",
                    created_at=now,
                    updated_at=now,
                )
                session.add(req)
                created_count += 1

        session.commit()

    console.print(f"[green]Imported {created_count} evidence request(s).[/green]")
    if errors:
        console.print(f"[yellow]Skipped {len(errors)} row(s):[/yellow]")
        for err in errors:
            console.print(f"  [dim]{err}[/dim]")


# ---------------------------------------------------------------------------
# requests overdue
# ---------------------------------------------------------------------------


@evidence_requests.command("overdue")
def requests_overdue() -> None:
    """Show overdue evidence requests with SLA countdown."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import EvidenceRequest

    _SLA_DAYS = 14

    init_db()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=_SLA_DAYS)

    with get_session() as session:
        rows = (
            session.query(EvidenceRequest)
            .filter(
                EvidenceRequest.status.notin_(["fulfilled", "closed"]),
                EvidenceRequest.created_at <= cutoff,
            )
            .order_by(EvidenceRequest.created_at.asc())
            .all()
        )

    if not rows:
        console.print("[green]No overdue evidence requests.[/green]")
        return

    table = Table(title=f"Overdue Evidence Requests ({len(rows)}, SLA: {_SLA_DAYS} days)")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Framework", style="cyan")
    table.add_column("Control", style="cyan")
    table.add_column("Description", max_width=40)
    table.add_column("Status")
    table.add_column("Days Overdue", justify="right", style="red")

    for r in rows:
        days_overdue = (now - r.created_at).days - _SLA_DAYS
        st_style = {
            "requested": "yellow",
            "in_progress": "cyan",
        }.get(r.status, "")
        table.add_row(
            r.id[:8],
            r.framework or "\u2014",
            r.control_id or "\u2014",
            escape((r.description or "")[:40]),
            f"[{st_style}]{r.status}[/]",
            str(days_overdue),
        )

    console.print(table)
