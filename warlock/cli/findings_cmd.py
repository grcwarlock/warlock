"""Findings management commands.

Provides search, analysis, suppression, SLA tracking, aging, and
export operations on normalized findings from the pipeline.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import _error, _get_actor, _parse_ai_response, cli, console

# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("findings", invoke_without_command=True)
@click.option(
    "--ask",
    default=None,
    help="Ask AI a question about findings (e.g. 'What are the top risks?')",
)
@click.pass_context
def findings(ctx: click.Context, ask: str | None) -> None:
    """Query and manage normalized findings."""
    if ctx.invoked_subcommand is not None:
        return

    if ask is not None:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import ConversationContext

        svc = get_ai_service()
        if not svc.is_available():
            console.print(
                "[yellow]AI service not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY.[/yellow]"
            )
            return

        from warlock.db.engine import get_session, init_db
        from warlock.db.models import Finding

        init_db()
        with get_session() as session:
            rows = session.query(Finding).order_by(Finding.ingested_at.desc()).limit(50).all()

        finding_data = [
            {"title": r.title, "severity": r.severity, "provider": r.provider} for r in rows
        ]

        ai_ctx = ConversationContext(
            domain="findings",
            entity_type="finding",
            entity_data={"findings": finding_data, "count": len(rows)},
        )
        resp = svc.ask(ask, context=ai_ctx)
        console.print()
        _parse_ai_response(resp)
        return

    ctx.invoke(findings_list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_style(severity: str) -> str:
    return {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }.get(severity.lower(), "")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _interactive_findings_loop(rows: list) -> None:
    """Interactive browsing loop: select a finding by number to view details or act on it."""
    while True:
        console.print(
            "\n[bold]Interactive mode:[/bold] Enter a row number to view details, "
            "'s <num>' to suppress, 'a <num>' to annotate, or 'q' to quit."
        )
        try:
            raw = click.prompt("Action", default="q")
        except (EOFError, KeyboardInterrupt):
            break

        raw = raw.strip()
        if raw.lower() == "q":
            break

        parts = raw.split(maxsplit=1)
        action = parts[0].lower()

        if action.isdigit():
            idx = int(action) - 1
            if 0 <= idx < len(rows):
                r = rows[idx]
                console.print(
                    f"\n[bold cyan]{escape(r.title or '')}[/bold cyan]\n"
                    f"  ID:        {r.id}\n"
                    f"  Severity:  {r.severity}\n"
                    f"  Source:    {r.source}/{r.provider}\n"
                    f"  Resource:  {r.resource_type or '\u2014'} \u2014 {r.resource_id or '\u2014'}\n"
                    f"  Observed:  {r.observed_at}\n"
                    f"  Detail:    {json.dumps(r.detail or {}, default=str)[:200]}"
                )
            else:
                console.print(f"[red]Invalid row number. Enter 1-{len(rows)}.[/red]")
        elif action == "s" and len(parts) > 1 and parts[1].isdigit():
            idx = int(parts[1]) - 1
            if 0 <= idx < len(rows):
                reason = click.prompt("Suppression reason")
                from warlock.db.engine import get_session

                r = rows[idx]
                with get_session() as session:
                    from warlock.db.models import Finding

                    finding = session.query(Finding).filter(Finding.id == r.id).first()
                    if finding:
                        detail = dict(finding.detail or {})
                        detail["_suppressed"] = True
                        detail["_suppression_reason"] = reason
                        detail["_suppressed_at"] = _utcnow().isoformat()
                        detail["_suppressed_by"] = _get_actor()
                        finding.detail = detail
                        session.commit()
                        console.print(f"[yellow]Finding {r.id[:8]} suppressed.[/yellow]")
            else:
                console.print(f"[red]Invalid row number. Enter 1-{len(rows)}.[/red]")
        elif action == "a" and len(parts) > 1 and parts[1].isdigit():
            idx = int(parts[1]) - 1
            if 0 <= idx < len(rows):
                note = click.prompt("Annotation")
                from warlock.db.engine import get_session

                r = rows[idx]
                with get_session() as session:
                    from warlock.db.models import Finding

                    finding = session.query(Finding).filter(Finding.id == r.id).first()
                    if finding:
                        detail = dict(finding.detail or {})
                        annotations = list(detail.get("_annotations", []))
                        annotations.append(
                            {
                                "note": note,
                                "actor": _get_actor(),
                                "timestamp": _utcnow().isoformat(),
                            }
                        )
                        detail["_annotations"] = annotations
                        finding.detail = detail
                        session.commit()
                        console.print(f"[green]Annotation added to {r.id[:8]}.[/green]")
            else:
                console.print(f"[red]Invalid row number. Enter 1-{len(rows)}.[/red]")
        else:
            console.print("[dim]Unknown action. Use a number, 's <num>', 'a <num>', or 'q'.[/dim]")


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@findings.command("list")
@click.option("--severity", "-s", default=None, help="Filter by severity (critical, high, etc.)")
@click.option("--source", default=None, help="Filter by source (aws, crowdstrike, etc.)")
@click.option("--source-type", "-t", default=None, help="Filter by source type")
@click.option("--observation-type", "-o", default=None, help="Filter by observation type")
@click.option("--framework", "-f", default=None, help="Filter by mapped framework")
@click.option("--system", default=None, help="Filter by system profile ID or acronym")
@click.option("--suppressed/--no-suppressed", default=False, help="Include suppressed findings")
@click.option("--limit", "-n", default=50, help="Max results")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "csv"]), default=None)
@click.option("--export", "export_path", default=None, help="Export to file (json/csv)")
@click.option(
    "--interactive",
    "-i",
    is_flag=True,
    default=False,
    help="Interactive mode: browse and act on findings",
)
@click.pass_context
def findings_list(
    ctx: click.Context,
    severity: str | None,
    source: str | None,
    source_type: str | None,
    observation_type: str | None,
    framework: str | None,
    system: str | None,
    suppressed: bool,
    limit: int,
    fmt: str | None,
    export_path: str | None,
    interactive: bool,
) -> None:
    """List normalized findings."""
    from warlock.config import get_settings

    settings = get_settings()
    rows = None
    _lake_mode = False

    # Lake-first path (interactive mode needs ORM objects for mutations)
    if not interactive and settings.lake_reads_enabled("findings_list"):
        try:
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            lake_rows = readers.findings_list(
                severity=severity,
                source=source,
                source_type=source_type,
                observation_type=observation_type,
                limit=limit,
            )
            readers.close()
            if lake_rows:
                rows = lake_rows
                _lake_mode = True
        except Exception:
            pass  # Fall back to OLTP

    if rows is None:
        from warlock.db.engine import get_session, init_db
        from warlock.db.models import Finding

        init_db()
        with get_session() as session:
            q = session.query(Finding)
            if severity:
                q = q.filter(Finding.severity == severity)
            if source:
                q = q.filter(Finding.source == source)
            if source_type:
                q = q.filter(Finding.source_type == source_type)
            if observation_type:
                q = q.filter(Finding.observation_type == observation_type)
            if system:
                from warlock.cli import _resolve_system_id

                sid = _resolve_system_id(session, system)
                q = q.filter(Finding.system_profile_id == sid)
            q = q.order_by(Finding.observed_at.desc()).limit(limit)
            rows = q.all()

    if not rows:
        console.print("[dim]No findings found.[/dim]")
        return

    def _g(row, key, default=""):
        """Get attribute from ORM object or dict."""
        if isinstance(row, dict):
            return row.get(key, default)
        return getattr(row, key, default)

    # Resolve effective format (local --format > global --output-format > table)
    from warlock.cli.output import format_output, get_output_format

    effective_fmt = get_output_format(ctx, fmt)

    # Build uniform data dicts for all format paths
    data = [
        {
            "id": str(_g(r, "id", ""))[:8],
            "title": (_g(r, "title", "") or "")[:50],
            "severity": _g(r, "severity", ""),
            "observation_type": _g(r, "observation_type", ""),
            "source": _g(r, "source", ""),
            "provider": _g(r, "provider", ""),
            "resource_id": _g(r, "resource_id", ""),
            "observed_at": str(_g(r, "observed_at", ""))[:19] if _g(r, "observed_at") else "",
        }
        for r in rows
    ]

    _COLUMNS = [
        {"key": "id", "header": "ID", "style": "dim", "max_width": "8"},
        {"key": "severity", "header": "Severity"},
        {"key": "observation_type", "header": "Type"},
        {"key": "title", "header": "Title", "max_width": "50"},
        {"key": "source", "header": "Source"},
        {"key": "provider", "header": "Provider"},
        {"key": "observed_at", "header": "Observed At"},
    ]

    tag = " [lake]" if _lake_mode else ""
    format_output(
        data,
        _COLUMNS,
        fmt=effective_fmt,
        title=f"Findings ({len(rows)}){tag}",
        style_map={
            "severity": {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "dim",
                "info": "dim",
            },
        },
        export_path=export_path,
    )

    if interactive:
        _interactive_findings_loop(rows)


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@findings.command("show")
@click.argument("finding_id", required=False, default=None)
def findings_show(finding_id: str | None) -> None:
    """Show full detail for a finding.

    When FINDING_ID is omitted, shows the most recent finding.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        if finding_id is None:
            row = session.query(Finding).order_by(Finding.ingested_at.desc()).first()
            if row:
                console.print(
                    f"[dim]No FINDING_ID given; showing most recent: {row.id[:8]}[/dim]\n"
                )
        else:
            row = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
            if not row:
                # Try matching with LIKE %prefix% for cases where prefix doesn't
                # align to the start (e.g. UUID with/without dashes)
                row = session.query(Finding).filter(Finding.id.like(f"%{finding_id}%")).first()

    if not row:
        _error(f"Finding '{finding_id or 'N/A'}' not found.")

    from rich.panel import Panel

    body = (
        f"[bold]{escape(row.title or '')}[/bold]\n\n"
        f"ID:               {row.id}\n"
        f"Severity:         {row.severity}\n"
        f"Observation Type: {row.observation_type}\n"
        f"Source:           {row.source} / {row.provider}\n"
        f"Source Type:      {row.source_type}\n"
        f"Resource:         {row.resource_type or '\u2014'} — {row.resource_id or '\u2014'}\n"
        f"Account:          {row.account_id or '\u2014'}\n"
        f"Region:           {row.region or '\u2014'}\n"
        f"Confidence:       {row.confidence}\n"
        f"PII Detected:     {'yes' if row.pii_detected else 'no'}\n"
        f"Observed At:      {row.observed_at}\n"
        f"Ingested At:      {row.ingested_at}"
    )
    console.print(Panel(body, title="[bold cyan]Finding[/bold cyan]", border_style="cyan"))

    if row.detail:
        console.print("\n[bold]Detail:[/bold]")
        console.print(json.dumps(row.detail, indent=2, default=str)[:2000])


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


@findings.command("search")
@click.argument("query")
@click.option("--limit", "-n", default=50, help="Max results")
def findings_search(query: str, limit: int) -> None:
    """Full-text search findings by title."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        rows = (
            session.query(Finding)
            .filter(Finding.title.ilike(f"%{query}%"))
            .order_by(Finding.observed_at.desc())
            .limit(limit)
            .all()
        )

    if not rows:
        console.print(f"[dim]No findings matching '{query}'.[/dim]")
        return

    table = Table(title=f"Search results for '{query}' ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Severity")
    table.add_column("Title", max_width=60)
    table.add_column("Source")

    for r in rows:
        sty = _severity_style(r.severity)
        table.add_row(
            r.id[:8],
            f"[{sty}]{r.severity}[/{sty}]" if sty else r.severity,
            escape(r.title[:60] if r.title else ""),
            f"{r.source}/{r.provider}",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# timeline
# ---------------------------------------------------------------------------


@findings.command("timeline")
@click.option("--days", "-d", default=30, help="Number of days to show")
@click.option("--severity", "-s", default=None, help="Filter by severity")
def findings_timeline(days: int, severity: str | None) -> None:
    """Show daily finding counts over a time window."""
    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    since = _utcnow() - timedelta(days=days)

    with get_session() as session:
        q = session.query(
            func.date(Finding.observed_at).label("day"),
            func.count(Finding.id).label("cnt"),
        ).filter(Finding.observed_at >= since)
        if severity:
            q = q.filter(Finding.severity == severity)
        rows = q.group_by(func.date(Finding.observed_at)).order_by("day").all()

    if not rows:
        console.print(f"[dim]No findings in the last {days} days.[/dim]")
        return

    table = Table(title=f"Finding Timeline (last {days} days)")
    table.add_column("Date", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Bar")

    max_cnt = max(r.cnt for r in rows) if rows else 1
    for r in rows:
        bar_len = int(r.cnt / max_cnt * 30)
        table.add_row(str(r.day), str(r.cnt), "[cyan]" + "\u2588" * bar_len + "[/cyan]")

    console.print(table)


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


@findings.command("stats")
def findings_stats() -> None:
    """Aggregate finding statistics by severity, source type, and observation type."""
    from warlock.config import get_settings

    settings = get_settings()

    # Lake-first path
    if settings.lake_reads_enabled("findings_stats"):
        try:
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            stats = readers.findings_stats()
            readers.close()
            if stats["total"]:
                console.print(f"\n[bold]Total findings: {stats['total']}[/bold] [lake]\n")

                sev_table = Table(title="By Severity")
                sev_table.add_column("Severity", style="cyan")
                sev_table.add_column("Count", justify="right")
                for sev in ["critical", "high", "medium", "low", "info"]:
                    cnt = stats["by_severity"].get(sev, 0)
                    if cnt:
                        sty = _severity_style(sev)
                        sev_table.add_row(
                            f"[{sty}]{sev}[/{sty}]" if sty else sev,
                            str(cnt),
                        )
                console.print(sev_table)

                src_table = Table(title="By Source Type")
                src_table.add_column("Source Type", style="cyan")
                src_table.add_column("Count", justify="right")
                for st, cnt in sorted(
                    stats["by_source_type"].items(),
                    key=lambda x: x[1],
                    reverse=True,
                ):
                    src_table.add_row(st, str(cnt))
                console.print(src_table)

                obs_table = Table(title="By Observation Type")
                obs_table.add_column("Observation Type", style="cyan")
                obs_table.add_column("Count", justify="right")
                for ot, cnt in sorted(
                    stats["by_observation_type"].items(),
                    key=lambda x: x[1],
                    reverse=True,
                ):
                    obs_table.add_row(ot, str(cnt))
                console.print(obs_table)
                return
        except Exception:
            pass  # Fall back to OLTP

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        rows = session.query(
            Finding.severity,
            Finding.source_type,
            Finding.observation_type,
        ).all()

    if not rows:
        console.print("[dim]No findings found.[/dim]")
        return

    sev_counts: Counter[str] = Counter(r.severity for r in rows)
    type_counts: Counter[str] = Counter(r.source_type for r in rows)
    obs_counts: Counter[str] = Counter(r.observation_type for r in rows)

    console.print(f"\n[bold]Total findings: {len(rows)}[/bold]\n")

    sev_table = Table(title="By Severity")
    sev_table.add_column("Severity", style="cyan")
    sev_table.add_column("Count", justify="right")
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = sev_counts.get(sev, 0)
        if cnt:
            sty = _severity_style(sev)
            sev_table.add_row(f"[{sty}]{sev}[/{sty}]" if sty else sev, str(cnt))
    console.print(sev_table)

    src_table = Table(title="By Source Type")
    src_table.add_column("Source Type", style="cyan")
    src_table.add_column("Count", justify="right")
    for st, cnt in type_counts.most_common(15):
        src_table.add_row(st, str(cnt))
    console.print(src_table)

    obs_table = Table(title="By Observation Type")
    obs_table.add_column("Observation Type", style="cyan")
    obs_table.add_column("Count", justify="right")
    for ot, cnt in obs_counts.most_common(10):
        obs_table.add_row(ot, str(cnt))
    console.print(obs_table)


# ---------------------------------------------------------------------------
# suppress / unsuppress
# ---------------------------------------------------------------------------


@findings.command("suppress")
@click.argument("finding_id")
@click.option("--reason", "-r", required=True, help="Reason for suppression")
def findings_suppress(finding_id: str, reason: str) -> None:
    """Suppress a finding (sets pii_detected flag as suppression marker).

    Note: The Finding model does not have a dedicated suppressed column. This
    command sets pii_detected=True as a suppression proxy. For production
    usage, add a dedicated 'suppressed' boolean column and a suppression_reason
    text column to the Finding model.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        row = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not row:
            _error(f"Finding '{finding_id}' not found.")
        # Using detail dict to store suppression metadata since there is no
        # dedicated suppressed column on the current Finding model
        detail = dict(row.detail or {})
        detail["_suppressed"] = True
        detail["_suppression_reason"] = reason
        detail["_suppressed_at"] = _utcnow().isoformat()
        detail["_suppressed_by"] = _get_actor()
        row.detail = detail
        session.commit()
        console.print(f"[yellow]Finding {row.id[:8]} suppressed. Reason: {reason}[/yellow]")


@findings.command("unsuppress")
@click.argument("finding_id")
def findings_unsuppress(finding_id: str) -> None:
    """Remove suppression from a finding."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        row = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not row:
            _error(f"Finding '{finding_id}' not found.")
        detail = dict(row.detail or {})
        was_suppressed = detail.pop("_suppressed", False)
        detail.pop("_suppression_reason", None)
        detail.pop("_suppressed_at", None)
        detail.pop("_suppressed_by", None)
        row.detail = detail
        session.commit()
        if was_suppressed:
            console.print(f"[green]Suppression removed from finding {row.id[:8]}.[/green]")
        else:
            console.print(f"[dim]Finding {row.id[:8]} was not suppressed.[/dim]")


# ---------------------------------------------------------------------------
# annotate
# ---------------------------------------------------------------------------


@findings.command("annotate")
@click.argument("finding_id")
@click.option("--note", "-n", required=True, help="Annotation text")
def findings_annotate(finding_id: str, note: str) -> None:
    """Add an annotation note to a finding's detail dict."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        row = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not row:
            _error(f"Finding '{finding_id}' not found.")

        detail = dict(row.detail or {})
        annotations: list[dict] = list(detail.get("_annotations", []))
        annotations.append(
            {
                "note": note,
                "actor": _get_actor(),
                "timestamp": _utcnow().isoformat(),
            }
        )
        detail["_annotations"] = annotations
        row.detail = detail
        session.commit()
        console.print(f"[green]Annotation added to finding {row.id[:8]}.[/green]")


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


@findings.command("export")
@click.option("--output", "-o", default=None, help="Output file (default: stdout)")
@click.option("--severity", "-s", default=None, help="Filter by severity")
@click.option("--source", default=None, help="Filter by source")
@click.option("--limit", "-n", default=1000, help="Max findings to export")
@click.option("--format", "fmt", type=click.Choice(["json", "csv"]), default="json")
def findings_export(
    output: str | None,
    severity: str | None,
    source: str | None,
    limit: int,
    fmt: str,
) -> None:
    """Export findings to JSON or CSV."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        q = session.query(Finding).order_by(Finding.observed_at.desc())
        if severity:
            q = q.filter(Finding.severity == severity)
        if source:
            q = q.filter(Finding.source == source)
        rows = q.limit(limit).all()

    if fmt == "json":
        data = [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity,
                "observation_type": r.observation_type,
                "source": r.source,
                "source_type": r.source_type,
                "provider": r.provider,
                "resource_id": r.resource_id,
                "resource_type": r.resource_type,
                "account_id": r.account_id,
                "region": r.region,
                "confidence": r.confidence,
                "observed_at": str(r.observed_at),
                "ingested_at": str(r.ingested_at),
            }
            for r in rows
        ]
        payload = json.dumps(data, indent=2)
    else:
        # CSV
        import csv
        import io

        buf = io.StringIO()
        fields = [
            "id",
            "title",
            "severity",
            "observation_type",
            "source",
            "source_type",
            "provider",
            "resource_id",
            "observed_at",
        ]
        # SEC-C11: neutralize spreadsheet formula prefixes.
        from warlock.utils.csv_safety import neutralize_row

        writer = csv.DictWriter(buf, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            writer.writerow(
                neutralize_row(
                    {
                        "id": r.id,
                        "title": r.title,
                        "severity": r.severity,
                        "observation_type": r.observation_type,
                        "source": r.source,
                        "source_type": r.source_type,
                        "provider": r.provider,
                        "resource_id": r.resource_id or "",
                        "observed_at": str(r.observed_at),
                    }
                )
            )
        payload = buf.getvalue()

    if output:
        with open(output, "w") as fh:
            fh.write(payload)
        console.print(f"[green]Exported {len(rows)} findings to {output}[/green]")
    else:
        console.print(payload)


# ---------------------------------------------------------------------------
# deduplicate
# ---------------------------------------------------------------------------


@findings.command("deduplicate")
@click.option("--dry-run", is_flag=True, default=True, help="Show duplicates without removing")
def findings_deduplicate(dry_run: bool) -> None:
    """Identify findings with duplicate sha256 hashes."""
    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        dupes = (
            session.query(Finding.sha256, func.count(Finding.id).label("cnt"))
            .group_by(Finding.sha256)
            .having(func.count(Finding.id) > 1)
            .all()
        )

    if not dupes:
        console.print("[green]No duplicate findings detected.[/green]")
        return

    total_dupes = sum(r.cnt - 1 for r in dupes)
    console.print(
        f"[yellow]Found {len(dupes)} duplicate sha256 hash group(s), "
        f"{total_dupes} redundant record(s).[/yellow]"
    )

    table = Table(title="Duplicate Groups")
    table.add_column("SHA256 (prefix)", style="dim")
    table.add_column("Count", justify="right")

    for r in dupes[:20]:
        table.add_row(r.sha256[:16], str(r.cnt))

    console.print(table)

    if dry_run:
        console.print(
            "\n[dim]Dry run — pass --no-dry-run to remove duplicate records (keeps first per hash).[/dim]"
        )
    else:
        console.print(
            "[yellow]Deduplication write is not implemented in this command. "
            "Use the pipeline's dedup logic or a migration.[/yellow]"
        )


# ---------------------------------------------------------------------------
# trending
# ---------------------------------------------------------------------------


@findings.command("trending")
@click.option("--days", "-d", default=14, help="Look-back window in days")
@click.option("--top", "-n", default=10, help="Top N sources to show")
def findings_trending(days: int, top: int) -> None:
    """Show finding open/close rate trends by source over a time window."""
    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    since = _utcnow() - timedelta(days=days)

    with get_session() as session:
        rows = (
            session.query(
                Finding.source,
                Finding.provider,
                func.count(Finding.id).label("cnt"),
            )
            .filter(Finding.observed_at >= since)
            .group_by(Finding.source, Finding.provider)
            .order_by(func.count(Finding.id).desc())
            .limit(top)
            .all()
        )

    if not rows:
        console.print(f"[dim]No findings in the last {days} days.[/dim]")
        return

    table = Table(title=f"Trending Sources (last {days} days)")
    table.add_column("Source", style="cyan")
    table.add_column("Provider")
    table.add_column("New Findings", justify="right")

    for r in rows:
        table.add_row(r.source, r.provider, str(r.cnt))

    console.print(table)


# ---------------------------------------------------------------------------
# by-connector
# ---------------------------------------------------------------------------


@findings.command("by-connector")
@click.option("--limit", "-n", default=20, help="Max connectors to show")
def findings_by_connector(limit: int) -> None:
    """Group finding counts by connector (source + provider)."""
    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        rows = (
            session.query(
                Finding.source,
                Finding.provider,
                Finding.source_type,
                func.count(Finding.id).label("cnt"),
            )
            .group_by(Finding.source, Finding.provider, Finding.source_type)
            .order_by(func.count(Finding.id).desc())
            .limit(limit)
            .all()
        )

    if not rows:
        console.print("[dim]No findings found.[/dim]")
        return

    table = Table(title=f"Findings by Connector (top {limit})")
    table.add_column("Source", style="cyan")
    table.add_column("Provider")
    table.add_column("Source Type")
    table.add_column("Findings", justify="right")

    for r in rows:
        table.add_row(r.source, r.provider, r.source_type, str(r.cnt))

    console.print(table)


# ---------------------------------------------------------------------------
# by-control
# ---------------------------------------------------------------------------


@findings.command("by-control")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--limit", "-n", default=20, help="Max controls to show")
def findings_by_control(framework: str | None, limit: int) -> None:
    """Group finding counts by mapped control."""
    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping

    init_db()
    with get_session() as session:
        q = (
            session.query(
                ControlMapping.framework,
                ControlMapping.control_id,
                func.count(ControlMapping.finding_id).label("cnt"),
            )
            .group_by(ControlMapping.framework, ControlMapping.control_id)
            .order_by(func.count(ControlMapping.finding_id).desc())
        )
        if framework:
            q = q.filter(ControlMapping.framework == framework)
        rows = q.limit(limit).all()

    if not rows:
        console.print("[dim]No control mappings found.[/dim]")
        return

    table = Table(title=f"Findings by Control (top {limit})")
    table.add_column("Framework", style="cyan")
    table.add_column("Control ID")
    table.add_column("Findings", justify="right")

    for r in rows:
        table.add_row(r.framework, r.control_id, str(r.cnt))

    console.print(table)


# ---------------------------------------------------------------------------
# aging
# ---------------------------------------------------------------------------


@findings.command("aging")
@click.option("--severity", "-s", default=None, help="Filter by severity")
@click.option("--source-type", "-t", default=None, help="Filter by source type")
def findings_aging(severity: str | None, source_type: str | None) -> None:
    """Age analysis of findings (KRI metric).

    Shows how many findings are 0-7 days, 7-30 days, 30-90 days, and 90+ days old.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    now = _utcnow()

    with get_session() as session:
        q = session.query(Finding.id, Finding.observed_at, Finding.severity, Finding.title)
        if severity:
            q = q.filter(Finding.severity == severity)
        if source_type:
            q = q.filter(Finding.source_type == source_type)
        rows = q.all()

    if not rows:
        console.print("[dim]No findings found.[/dim]")
        return

    buckets: dict[str, list] = {
        "0-7 days": [],
        "8-30 days": [],
        "31-90 days": [],
        "91+ days": [],
    }

    for r in rows:
        if not r.observed_at:
            continue
        obs = r.observed_at
        if obs.tzinfo is None:
            obs = obs.replace(tzinfo=timezone.utc)
        age_days = (now - obs).days
        if age_days <= 7:
            buckets["0-7 days"].append(r)
        elif age_days <= 30:
            buckets["8-30 days"].append(r)
        elif age_days <= 90:
            buckets["31-90 days"].append(r)
        else:
            buckets["91+ days"].append(r)

    table = Table(title="Finding Age Distribution (KRI)")
    table.add_column("Age Bucket", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("% of Total", justify="right")

    total = len(rows)
    for bucket, items in buckets.items():
        cnt = len(items)
        pct = cnt / total * 100 if total else 0
        style = "green" if bucket == "0-7 days" else "yellow" if bucket == "8-30 days" else "red"
        table.add_row(
            f"[{style}]{bucket}[/{style}]",
            str(cnt),
            f"{pct:.1f}%",
        )

    console.print(table)

    # Show oldest findings
    oldest = sorted(
        [r for r in rows if r.observed_at],
        key=lambda r: r.observed_at,
    )[:5]
    if oldest:
        console.print("\n[bold]Oldest findings:[/bold]")
        for r in oldest:
            obs = r.observed_at
            if obs.tzinfo is None:
                obs = obs.replace(tzinfo=timezone.utc)
            age = (now - obs).days
            console.print(
                f"  [dim]{r.id[:8]}[/dim]  {age} days  {escape(r.title[:60] if r.title else '')}"
            )


# ---------------------------------------------------------------------------
# sla
# ---------------------------------------------------------------------------


@findings.command("sla")
@click.option(
    "--window",
    type=click.Choice(["30", "60", "90"]),
    default="30",
    help="SLA window in days",
)
@click.option("--severity", "-s", default=None, help="Filter by severity")
def findings_sla(window: str, severity: str | None) -> None:
    """Show findings by SLA compliance window (30/60/90-day).

    Findings within the SLA window are considered on-track. Findings older
    than the window are SLA breached.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    days = int(window)
    cutoff = _utcnow() - timedelta(days=days)

    with get_session() as session:
        q = session.query(Finding)
        if severity:
            q = q.filter(Finding.severity == severity)
        rows = q.all()

    if not rows:
        console.print("[dim]No findings found.[/dim]")
        return

    within_sla: list = []
    breached: list = []

    for r in rows:
        if not r.observed_at:
            continue
        obs = r.observed_at
        if obs.tzinfo is None:
            obs = obs.replace(tzinfo=timezone.utc)
        if obs >= cutoff:
            within_sla.append(r)
        else:
            breached.append(r)

    total = len(within_sla) + len(breached)
    pct_ok = len(within_sla) / total * 100 if total else 0

    console.print(f"\n[bold]SLA Compliance — {days}-Day Window[/bold]")
    console.print(f"  Total findings:      {total}")
    console.print(f"  [green]Within SLA:[/green]          {len(within_sla)} ({pct_ok:.1f}%)")
    console.print(f"  [red]SLA breached:[/red]        {len(breached)} ({100 - pct_ok:.1f}%)")

    # Severity breakdown for breached
    if breached:
        sev_counts: Counter[str] = Counter(r.severity for r in breached)
        console.print("\n[bold]Breached findings by severity:[/bold]")
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = sev_counts.get(sev, 0)
            if cnt:
                sty = _severity_style(sev)
                label = f"[{sty}]{sev}[/{sty}]" if sty else sev
                console.print(f"  {label}: {cnt}")


# ---------------------------------------------------------------------------
# create-issue
# ---------------------------------------------------------------------------


@findings.command("create-issue")
@click.argument("finding_id", required=False, default=None)
@click.option(
    "--priority", "-p", default="high", type=click.Choice(["critical", "high", "medium", "low"])
)
@click.option("--title", "-t", default=None, help="Issue title (defaults to finding title)")
def findings_create_issue(finding_id: str | None, priority: str, title: str | None) -> None:
    """Create an incident/issue from a finding.

    \b
    FINDING_ID: finding UUID or prefix (from 'warlock findings list').

    Links the new issue to the source finding via control_id and tags.
    """
    if finding_id is None:
        _error("Usage: warlock findings create-issue <FINDING_ID>")

    import uuid

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, Finding, Issue

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        finding = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not finding:
            _error(f"Finding not found: {finding_id}")

        issue_title = (
            title
            or f"[{finding.severity}] {finding.title or finding.observation_type or 'Finding'}"
        )

        mapping = (
            session.query(ControlMapping).filter(ControlMapping.finding_id == finding.id).first()
        )
        mapped_control_id = mapping.control_id if mapping else "UNKNOWN"

        issue = Issue(
            id=str(uuid.uuid4()),
            title=issue_title[:255],
            description=f"Auto-created from finding {finding.id[:8]}.\n\n"
            f"Provider: {finding.provider}\n"
            f"Source: {finding.source}\n"
            f"Resource: {finding.resource_id or '—'}",
            priority=priority,
            status="open",
            control_id=mapped_control_id,
            created_by=actor,
            created_at=now,
            updated_at=now,
        )
        session.add(issue)
        session.commit()

    console.print(
        f"[green]Issue created:[/green] [cyan]{issue.id[:8]}[/cyan] "
        f"— {escape(issue_title[:60])}\n"
        f"[dim]Linked to finding {finding.id[:8]} (control: {mapped_control_id})[/dim]"
    )
