"""Bulk operations on findings, issues, and raw events.

Every mutating command supports --dry-run, which shows what WOULD happen
without persisting any changes. --dry-run is the default-safe path.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


@cli.group("bulk", invoke_without_command=True)
@click.pass_context
def bulk(ctx: click.Context) -> None:
    """Bulk operations: suppress, assign, close, tag, export, deduplicate, and more."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _dry_banner(dry_run: bool) -> None:
    if dry_run:
        console.print("[bold yellow][DRY RUN] No changes will be written.[/bold yellow]")


def _done(count: int, action: str, dry_run: bool) -> None:
    prefix = "[bold yellow][DRY RUN][/bold yellow] Would" if dry_run else "OK:"
    console.print(f"{prefix} {action} [bold]{count}[/bold] record(s).")


def _severity_style(sev: str | None) -> str:
    return {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }.get(sev or "", "")


# ---------------------------------------------------------------------------
# suppress
# ---------------------------------------------------------------------------


@bulk.command("suppress")
@click.option("--source", required=True, help="Connector source to target (e.g. aws, okta)")
@click.option(
    "--severity",
    "severities",
    multiple=True,
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Severity filter (repeatable). Omit to suppress all.",
)
@click.option("--reason", required=True, help="Suppression reason for audit trail")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without persisting")
def suppress(source: str, severities: tuple[str, ...], reason: str, dry_run: bool) -> None:
    """Bulk suppress findings from a connector source.

    \b
    Examples:
        warlock bulk suppress --source aws --severity low --reason "Accepted risk" --dry-run
        warlock bulk suppress --source tenable --severity info --severity low --reason "Noise"
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    _dry_banner(dry_run)
    init_db()
    actor = _get_actor()

    with get_session() as session:
        q = session.query(Finding).filter(Finding.source == source)
        if severities:
            q = q.filter(Finding.severity.in_(list(severities)))
        findings = q.all()

        if not findings:
            console.print(
                f"[dim]No findings matching source={source!r} severity={list(severities) or 'any'}.[/dim]"
            )
            return

        table = Table(title=f"{'[DRY RUN] ' if dry_run else ''}Suppress findings ({len(findings)})")
        table.add_column("Finding ID", style="dim", max_width=8)
        table.add_column("Title", max_width=50)
        table.add_column("Severity")
        table.add_column("Provider", style="dim")

        for f in findings[:25]:
            sty = _severity_style(f.severity)
            table.add_row(
                f.id[:8],
                (f.title or "")[:50],
                f"[{sty}]{f.severity}[/]",
                f.provider,
            )
        if len(findings) > 25:
            console.print(f"[dim]... and {len(findings) - 25} more not shown[/dim]")
        console.print(table)

        if not dry_run:
            if not click.confirm(f"This will affect {len(findings)} records. Continue?"):
                return
            # Tag findings with suppression metadata in their detail JSON
            for f in findings:
                detail = dict(f.detail or {})
                detail["suppressed"] = True
                detail["suppressed_reason"] = reason
                detail["suppressed_at"] = datetime.now(timezone.utc).isoformat()
                detail["suppressed_by"] = actor
                f.detail = detail
            session.commit()

    _done(len(findings), f"suppress (reason: {reason!r})", dry_run)


# ---------------------------------------------------------------------------
# unsuppress
# ---------------------------------------------------------------------------


@bulk.command("unsuppress")
@click.option("--source", required=True, help="Connector source")
@click.option(
    "--severity",
    "severities",
    multiple=True,
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Severity filter (repeatable). Omit for all.",
)
@click.option("--dry-run", is_flag=True, default=False, help="Preview without persisting")
def unsuppress(source: str, severities: tuple[str, ...], dry_run: bool) -> None:
    """Bulk unsuppress findings from a connector source."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    _dry_banner(dry_run)
    init_db()

    with get_session() as session:
        q = session.query(Finding).filter(Finding.source == source)
        if severities:
            q = q.filter(Finding.severity.in_(list(severities)))
        findings = q.all()

        # Only those actually suppressed
        suppressed = [f for f in findings if (f.detail or {}).get("suppressed")]

        if not suppressed:
            console.print(f"[dim]No suppressed findings for source={source!r}.[/dim]")
            return

        console.print(f"Found [bold]{len(suppressed)}[/bold] suppressed finding(s) to clear.")

        if not dry_run:
            for f in suppressed:
                detail = dict(f.detail or {})
                detail.pop("suppressed", None)
                detail.pop("suppressed_reason", None)
                detail.pop("suppressed_at", None)
                detail.pop("suppressed_by", None)
                f.detail = detail
            session.commit()

    _done(len(suppressed), "unsuppress", dry_run)


# ---------------------------------------------------------------------------
# assign
# ---------------------------------------------------------------------------


@bulk.command("assign")
@click.option("--filter-framework", "framework", default=None, help="Filter issues by framework")
@click.option(
    "--filter-severity",
    "severity",
    default=None,
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Filter issues by priority",
)
@click.option("--to", "assignee", required=True, help="User ID or email to assign to")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without persisting")
def assign(framework: str | None, severity: str | None, assignee: str, dry_run: bool) -> None:
    """Bulk assign issues to a user.

    \b
    Examples:
        warlock bulk assign --filter-framework nist_800_53 --filter-severity critical --to alice@example.com
        warlock bulk assign --filter-severity high --to bob@example.com --dry-run
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    _dry_banner(dry_run)
    init_db()
    actor = _get_actor()

    with get_session() as session:
        q = session.query(Issue).filter(Issue.status.notin_(["closed", "verified"]))
        if framework:
            q = q.filter(Issue.framework == framework)
        if severity:
            q = q.filter(Issue.priority == severity)
        issues = q.all()

        if not issues:
            console.print("[dim]No matching issues to assign.[/dim]")
            return

        table = Table(
            title=f"{'[DRY RUN] ' if dry_run else ''}Assign {len(issues)} issue(s) to {assignee!r}"
        )
        table.add_column("Issue ID", style="dim", max_width=8)
        table.add_column("Title", max_width=50)
        table.add_column("Priority")
        table.add_column("Current Assignee", style="dim")

        for i in issues[:25]:
            sty = _severity_style(i.priority)
            table.add_row(
                i.id[:8],
                (i.title or "")[:50],
                f"[{sty}]{i.priority}[/]",
                i.assigned_to or "\u2014",
            )
        if len(issues) > 25:
            console.print(f"[dim]... and {len(issues) - 25} more[/dim]")
        console.print(table)

        if not dry_run:
            now = datetime.now(timezone.utc)
            for i in issues:
                i.assigned_to = assignee
                i.assigned_by = actor
                i.assigned_at = now
                if i.status == "open":
                    i.status = "assigned"
            session.commit()

    _done(len(issues), f"assign to {assignee!r}", dry_run)


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


@bulk.command("close")
@click.option(
    "--status",
    required=True,
    type=click.Choice(["closed", "verified", "risk_accepted"]),
    help="Target status",
)
@click.option("--resolution", required=True, help="Resolution note for audit trail")
@click.option(
    "--older-than-days",
    "older_than_days",
    default=None,
    type=int,
    help="Only close issues older than N days",
)
@click.option("--framework", "-f", default=None, help="Limit to a framework")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without persisting")
def close(
    status: str,
    resolution: str,
    older_than_days: int | None,
    framework: str | None,
    dry_run: bool,
) -> None:
    """Bulk close (or verify/risk-accept) issues matching filters.

    \b
    Examples:
        warlock bulk close --status closed --resolution "All remediated" --older-than-days 90
        warlock bulk close --status verified --resolution "Confirmed compliant" --framework soc2
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    _dry_banner(dry_run)
    init_db()

    with get_session() as session:
        q = session.query(Issue).filter(Issue.status.notin_(["closed", "verified"]))
        if framework:
            q = q.filter(Issue.framework == framework)
        if older_than_days:
            cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
            q = q.filter(Issue.created_at <= cutoff)
        issues = q.all()

        if not issues:
            console.print("[dim]No matching issues to close.[/dim]")
            return

        console.print(
            f"[bold]{len(issues)}[/bold] issue(s) would be moved to status=[cyan]{status}[/cyan]."
        )
        if not dry_run:
            if not click.confirm(f"This will affect {len(issues)} records. Continue?"):
                return
            now = datetime.now(timezone.utc)
            for i in issues:
                i.status = status
                i.verification_notes = (i.verification_notes or "") + f"\n[bulk close] {resolution}"
                if status in ("closed",):
                    i.closed_at = now
                elif status == "verified":
                    i.verified_at = now
            session.commit()

    _done(len(issues), f"close (status={status})", dry_run)


# ---------------------------------------------------------------------------
# tag
# ---------------------------------------------------------------------------


@bulk.command("tag")
@click.option("--filter-source", "source", required=True, help="Connector source to filter by")
@click.option("--tag", "tag_value", required=True, help="Tag to apply")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without persisting")
def tag(source: str, tag_value: str, dry_run: bool) -> None:
    """Bulk tag findings from a source.

    \b
    Examples:
        warlock bulk tag --filter-source aws --tag "pci-scope"
        warlock bulk tag --filter-source github --tag "dev-only" --dry-run
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    _dry_banner(dry_run)
    init_db()

    with get_session() as session:
        findings = session.query(Finding).filter(Finding.source == source).all()

        if not findings:
            console.print(f"[dim]No findings for source={source!r}.[/dim]")
            return

        # Only those not already tagged
        to_tag = [f for f in findings if tag_value not in ((f.detail or {}).get("tags") or [])]

        console.print(
            f"[bold]{len(to_tag)}[/bold] finding(s) would receive tag=[cyan]{tag_value!r}[/cyan] "
            f"({len(findings) - len(to_tag)} already tagged)."
        )

        if not dry_run:
            for f in to_tag:
                detail = dict(f.detail or {})
                tags = list(detail.get("tags") or [])
                tags.append(tag_value)
                detail["tags"] = tags
                f.detail = detail
            session.commit()

    _done(len(to_tag), f"tag with {tag_value!r}", dry_run)


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


@bulk.command("export")
@click.option("--source", default=None, help="Filter by connector source")
@click.option(
    "--severity",
    "severities",
    multiple=True,
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Severity filter (repeatable)",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "csv"]),
    default="json",
    help="Output format",
)
@click.option("--limit", "-n", default=1000, help="Max records to export")
def export(source: str | None, severities: tuple[str, ...], fmt: str, limit: int) -> None:
    """Bulk export findings as JSON or CSV.

    \b
    Examples:
        warlock bulk export --source aws --severity critical --format json
        warlock bulk export --severity high --format csv > findings.csv
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        q = session.query(Finding)
        if source:
            q = q.filter(Finding.source == source)
        if severities:
            q = q.filter(Finding.severity.in_(list(severities)))
        findings = q.order_by(Finding.observed_at.desc()).limit(limit).all()

    if not findings:
        console.print("[dim]No findings matched.[/dim]")
        return

    records = [
        {
            "id": f.id,
            "title": f.title,
            "source": f.source,
            "provider": f.provider,
            "severity": f.severity,
            "observation_type": f.observation_type,
            "resource_id": f.resource_id,
            "resource_type": f.resource_type,
            "region": f.region,
            "observed_at": f.observed_at.isoformat() if f.observed_at else None,
            "sha256": f.sha256,
        }
        for f in findings
    ]

    if fmt == "json":
        click.echo(json.dumps(records, indent=2, default=str))
    else:
        if not records:
            return
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)
        click.echo(out.getvalue())


# ---------------------------------------------------------------------------
# deduplicate
# ---------------------------------------------------------------------------


@bulk.command("deduplicate")
@click.option("--source", default=None, help="Limit dedup to a specific source")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without persisting")
def deduplicate(source: str | None, dry_run: bool) -> None:
    """Bulk deduplicate findings by sha256 hash, keeping the earliest ingested record.

    \b
    Examples:
        warlock bulk deduplicate --source aws --dry-run
        warlock bulk deduplicate
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, Finding
    from sqlalchemy import func

    _dry_banner(dry_run)
    init_db()

    with get_session() as session:
        q = (
            session.query(Finding.sha256, func.count(Finding.id).label("cnt"))
            .group_by(Finding.sha256)
            .having(func.count(Finding.id) > 1)
        )
        if source:
            q = q.filter(Finding.source == source)
        dupes = q.all()

        if not dupes:
            console.print("[green]No duplicate findings found.[/green]")
            return

        total_removed = 0
        for row in dupes:
            sha = row.sha256
            instances = (
                session.query(Finding)
                .filter(Finding.sha256 == sha)
                .order_by(Finding.ingested_at.asc())
                .all()
            )
            # Keep the first (earliest), mark the rest for removal
            to_remove = instances[1:]
            total_removed += len(to_remove)
            if not dry_run:
                for f in to_remove:
                    # Remove dependent mappings first to avoid FK constraint errors
                    session.query(ControlMapping).filter(ControlMapping.finding_id == f.id).delete(
                        synchronize_session=False
                    )
                    session.delete(f)

        if not dry_run:
            session.commit()

    console.print(f"Found [bold]{len(dupes)}[/bold] duplicate sha256 group(s) across findings.")
    _done(total_removed, "remove duplicate findings", dry_run)


# ---------------------------------------------------------------------------
# link-findings-to-issues
# ---------------------------------------------------------------------------


@bulk.command("link-findings-to-issues")
@click.option(
    "--severity",
    default="critical,high",
    show_default=True,
    help="Comma-separated severities to link (e.g. critical,high,medium)",
)
@click.option("--dry-run", is_flag=True, default=False, help="Preview without creating issues")
def link_findings_to_issues(severity: str, dry_run: bool) -> None:
    """Create Issues for findings that have no linked Issue record.

    Queries findings at the requested severity levels and creates an Issue for
    each one that is not already referenced by an existing Issue (via
    finding_id).  Use --dry-run to preview what would be created without
    writing anything to the database.

    \b
    Examples:
        warlock bulk link-findings-to-issues --dry-run
        warlock bulk link-findings-to-issues --severity critical,high,medium
        warlock bulk link-findings-to-issues --severity critical
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, Finding, Issue

    _dry_banner(dry_run)
    init_db()
    actor = _get_actor()

    severities = [s.strip().lower() for s in severity.split(",") if s.strip()]
    if not severities:
        _error("--severity must not be empty")
        return

    with get_session() as session:
        # Collect finding IDs that are already referenced by an Issue
        linked_finding_ids: set[str] = {
            row.finding_id
            for row in session.query(Issue.finding_id).filter(Issue.finding_id.isnot(None)).all()
        }

        unlinked = (
            session.query(Finding)
            .filter(
                Finding.severity.in_(severities),
                ~Finding.id.in_(linked_finding_ids),
            )
            .order_by(Finding.severity, Finding.created_at)
            .all()
        )

        if not unlinked:
            console.print(
                f"[green]All {'/'.join(severities)} findings already have linked issues.[/green]"
            )
            return

        # Preview table
        table = Table(title=f"{'[DRY RUN] ' if dry_run else ''}Issues to create ({len(unlinked)})")
        table.add_column("Finding ID", style="dim", max_width=8)
        table.add_column("Title", max_width=50)
        table.add_column("Severity")
        table.add_column("Source", style="cyan")
        table.add_column("Control", style="dim", max_width=20)

        for f in unlinked[:25]:
            sty = _severity_style(f.severity)
            mapping = (
                session.query(ControlMapping).filter(ControlMapping.finding_id == f.id).first()
            )
            control_label = f"{mapping.framework}/{mapping.control_id}" if mapping else "\u2014"
            table.add_row(
                f.id[:8],
                (f.title or "")[:50],
                f"[{sty}]{f.severity}[/]",
                f.source or "\u2014",
                control_label[:20],
            )

        if len(unlinked) > 25:
            console.print(f"[dim]... and {len(unlinked) - 25} more not shown[/dim]")
        console.print(table)

        if dry_run:
            _done(len(unlinked), "create issues for unlinked findings", dry_run=True)
            return

        if not click.confirm(f"Create {len(unlinked)} issue(s)?"):
            return

        created_count = 0
        for f in unlinked:
            mapping = (
                session.query(ControlMapping).filter(ControlMapping.finding_id == f.id).first()
            )
            new_issue = Issue(
                title=f"[Auto] {(f.title or 'Unlinked finding')[:200]}",
                description=(f"Auto-created from finding {f.id} (source: {f.source or 'unknown'})"),
                finding_id=f.id,
                framework=mapping.framework if mapping else None,
                control_id=mapping.control_id if mapping else None,
                priority=f.severity
                if f.severity in ("critical", "high", "medium", "low")
                else "medium",
                status="open",
                source="pipeline",
                created_by=actor,
            )
            session.add(new_issue)
            created_count += 1

        session.commit()

    _done(created_count, "create issues for unlinked findings", dry_run=False)


# ---------------------------------------------------------------------------
# reprocess
# ---------------------------------------------------------------------------


@bulk.command("reprocess")
@click.option("--source", required=True, help="Connector source to reprocess (e.g. aws)")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without persisting")
def reprocess(source: str, dry_run: bool) -> None:
    """Re-normalize raw events from a connector source.

    Deletes existing findings (and downstream mappings) for the source,
    then re-runs normalization from stored RawEvents.

    \b
    Examples:
        warlock bulk reprocess --source aws --dry-run
        warlock bulk reprocess --source tenable
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, Finding, RawEvent

    _dry_banner(dry_run)
    init_db()

    with get_session() as session:
        raw_events = session.query(RawEvent).filter(RawEvent.source == source).all()
        existing_findings = session.query(Finding).filter(Finding.source == source).all()

        console.print(
            f"Source [cyan]{source!r}[/cyan]: "
            f"[bold]{len(raw_events)}[/bold] raw events, "
            f"[bold]{len(existing_findings)}[/bold] existing findings."
        )

        if not raw_events:
            console.print(f"[dim]No raw events for source={source!r}. Nothing to reprocess.[/dim]")
            return

        if dry_run:
            console.print(
                f"[dim]Would delete {len(existing_findings)} findings and re-normalize "
                f"{len(raw_events)} raw events from source={source!r}.[/dim]"
            )
            _done(len(raw_events), f"reprocess raw events for source={source!r}", dry_run)
            return

        # Delete existing findings + their mappings
        finding_ids = [f.id for f in existing_findings]
        if finding_ids:
            session.query(ControlMapping).filter(ControlMapping.finding_id.in_(finding_ids)).delete(
                synchronize_session=False
            )
            for f in existing_findings:
                session.delete(f)
            session.flush()

        # Re-normalize
        try:
            from warlock.normalizers import get_normalizer

            created = 0
            for raw in raw_events:
                normalizer = get_normalizer(raw.event_type)
                if normalizer is None:
                    continue
                findings_data = normalizer.normalize(raw.raw_data)
                if not isinstance(findings_data, list):
                    findings_data = [findings_data]
                for fd in findings_data:
                    new_finding = Finding(
                        raw_event_id=raw.id,
                        observation_type=fd.observation_type,
                        title=fd.title,
                        detail=fd.detail if isinstance(fd.detail, dict) else {},
                        resource_id=getattr(fd, "resource_id", None),
                        resource_type=getattr(fd, "resource_type", None),
                        resource_name=getattr(fd, "resource_name", None),
                        account_id=getattr(fd, "account_id", None),
                        region=getattr(fd, "region", None),
                        source=raw.source,
                        source_type=raw.source_type,
                        provider=raw.provider,
                        severity=fd.severity,
                        confidence=getattr(fd, "confidence", 1.0),
                        observed_at=fd.observed_at,
                        sha256=fd.sha256 if hasattr(fd, "sha256") else raw.sha256,
                    )
                    session.add(new_finding)
                    created += 1
            session.commit()
            console.print(
                f"[green]Re-normalized {created} finding(s) from {len(raw_events)} raw events.[/green]"
            )
        except Exception as exc:
            session.rollback()
            _error(f"Reprocess failed: {exc}")


# ---------------------------------------------------------------------------
# acknowledge
# ---------------------------------------------------------------------------


@bulk.command("acknowledge")
@click.option("--framework", required=True, help="Framework to acknowledge (e.g. nist_800_53)")
@click.option(
    "--control-family",
    "control_families",
    multiple=True,
    help="Control family filter (e.g. AC, AU). Repeatable.",
)
@click.option("--actor", "ack_actor", required=True, help="Who is acknowledging (email or name)")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without persisting")
def acknowledge(
    framework: str, control_families: tuple[str, ...], ack_actor: str, dry_run: bool
) -> None:
    """Bulk acknowledge findings for a framework / control family.

    Acknowledgement tags findings in their detail as reviewed by the actor.

    \b
    Examples:
        warlock bulk acknowledge --framework nist_800_53 --control-family AC --actor alice@example.com
        warlock bulk acknowledge --framework soc2 --actor bob@example.com --dry-run
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, Finding

    _dry_banner(dry_run)
    init_db()

    with get_session() as session:
        q = (
            session.query(Finding)
            .join(ControlMapping, ControlMapping.finding_id == Finding.id)
            .filter(ControlMapping.framework == framework)
        )
        if control_families:
            q = q.filter(ControlMapping.control_family.in_(list(control_families)))
        findings = q.distinct().all()

        if not findings:
            console.print(
                f"[dim]No findings found for framework={framework!r} "
                f"families={list(control_families) or 'any'}.[/dim]"
            )
            return

        console.print(
            f"[bold]{len(findings)}[/bold] finding(s) would be acknowledged by [cyan]{ack_actor!r}[/cyan]."
        )

        if not dry_run:
            now = datetime.now(timezone.utc).isoformat()
            for f in findings:
                detail = dict(f.detail or {})
                acks = list(detail.get("acknowledgements") or [])
                acks.append({"actor": ack_actor, "at": now, "framework": framework})
                detail["acknowledgements"] = acks
                f.detail = detail
            session.commit()

    _done(len(findings), f"acknowledge for {framework!r}", dry_run)


# ---------------------------------------------------------------------------
# escalate
# ---------------------------------------------------------------------------


@bulk.command("escalate")
@click.option(
    "--severity",
    required=True,
    type=click.Choice(["critical", "high"]),
    help="Minimum severity to escalate",
)
@click.option(
    "--older-than-days",
    "older_than_days",
    default=None,
    type=int,
    help="Only escalate issues open longer than N days",
)
@click.option("--to", "assignee", required=True, help="User ID or email to escalate to")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without persisting")
def escalate(severity: str, older_than_days: int | None, assignee: str, dry_run: bool) -> None:
    """Bulk escalate high/critical issues to a specific user.

    \b
    Examples:
        warlock bulk escalate --severity critical --to ciso@example.com --dry-run
        warlock bulk escalate --severity high --older-than-days 30 --to security@example.com
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    _dry_banner(dry_run)
    init_db()
    actor = _get_actor()

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    max_sev_rank = severity_order[severity]

    with get_session() as session:
        q = session.query(Issue).filter(
            Issue.status.notin_(["closed", "verified", "risk_accepted"]),
            Issue.priority.in_([k for k, v in severity_order.items() if v <= max_sev_rank]),
        )
        if older_than_days:
            cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
            q = q.filter(Issue.created_at <= cutoff)
        issues = q.all()

        if not issues:
            console.print("[dim]No matching issues to escalate.[/dim]")
            return

        table = Table(
            title=f"{'[DRY RUN] ' if dry_run else ''}Escalate {len(issues)} issue(s) to {assignee!r}"
        )
        table.add_column("Issue ID", style="dim", max_width=8)
        table.add_column("Title", max_width=50)
        table.add_column("Priority")
        table.add_column("Status")
        table.add_column("Created", style="dim")

        for i in issues[:25]:
            sty = _severity_style(i.priority)
            table.add_row(
                i.id[:8],
                (i.title or "")[:50],
                f"[{sty}]{i.priority}[/]",
                i.status,
                i.created_at.strftime("%Y-%m-%d") if i.created_at else "\u2014",
            )
        if len(issues) > 25:
            console.print(f"[dim]... and {len(issues) - 25} more[/dim]")
        console.print(table)

        if not dry_run:
            now = datetime.now(timezone.utc)
            for i in issues:
                i.assigned_to = assignee
                i.assigned_by = actor
                i.assigned_at = now
                if i.status == "open":
                    i.status = "assigned"
            session.commit()

    _done(len(issues), f"escalate to {assignee!r}", dry_run)


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


@bulk.command("stats")
@click.option("--source", default=None, help="Filter by connector source")
def stats(source: str | None) -> None:
    """Show counts of what each bulk operation would affect.

    Provides a read-only summary to help plan bulk operations before
    running them with or without --dry-run.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, Finding, Issue, RawEvent
    from sqlalchemy import func

    init_db()
    with get_session() as session:
        # Findings
        fq = session.query(Finding)
        if source:
            fq = fq.filter(Finding.source == source)
        total_findings = fq.count()

        # Suppressed findings
        suppressed = sum(1 for f in fq.all() if (f.detail or {}).get("suppressed"))

        # Duplicate findings (by sha256)
        dup_q = (
            session.query(Finding.sha256, func.count(Finding.id).label("cnt"))
            .group_by(Finding.sha256)
            .having(func.count(Finding.id) > 1)
        )
        if source:
            dup_q = dup_q.filter(Finding.source == source)
        dup_groups = dup_q.all()
        dup_count = sum(row.cnt - 1 for row in dup_groups)

        # Raw events
        rq = session.query(RawEvent)
        if source:
            rq = rq.filter(RawEvent.source == source)
        total_raw = rq.count()

        # Open issues
        iq = session.query(Issue).filter(Issue.status.notin_(["closed", "verified"]))
        total_open_issues = iq.count()

        # Unlinked critical/high findings
        linked_ids = set(
            r.finding_id
            for r in session.query(Issue.finding_id).filter(Issue.finding_id.isnot(None)).all()
        )
        uq = session.query(Finding).filter(
            Finding.severity.in_(["critical", "high"]),
            ~Finding.id.in_(linked_ids),
        )
        if source:
            uq = uq.filter(Finding.source == source)
        unlinked_crit_high = uq.count()

        # Orphan findings
        mapped_ids = set(
            r.finding_id for r in session.query(ControlMapping.finding_id).distinct().all()
        )
        orphan_q = session.query(Finding).filter(~Finding.id.in_(mapped_ids))
        if source:
            orphan_q = orphan_q.filter(Finding.source == source)
        orphan_count = orphan_q.count()

    scope = f"source={source!r}" if source else "all sources"
    table = Table(title=f"Bulk operation impact summary ({scope})")
    table.add_column("Operation", style="cyan")
    table.add_column("Would Affect", justify="right")
    table.add_column("Notes", style="dim")

    table.add_row("suppress (all)", str(total_findings - suppressed), "findings not yet suppressed")
    table.add_row("unsuppress", str(suppressed), "currently suppressed findings")
    table.add_row(
        "deduplicate", str(dup_count), f"duplicate records across {len(dup_groups)} sha256 group(s)"
    )
    table.add_row("reprocess", str(total_raw), "raw events available for re-normalization")
    table.add_row(
        "link-findings-to-issues", str(unlinked_crit_high), "critical/high findings without issues"
    )
    table.add_row("assign / escalate (open)", str(total_open_issues), "non-closed issues")
    table.add_row("orphan findings", str(orphan_count), "findings with no control mapping")

    console.print(table)


# ---------------------------------------------------------------------------
# remediate (BK-001)
# ---------------------------------------------------------------------------


@bulk.command("remediate")
@click.option("--framework", "-f", required=True, help="Framework to target")
@click.option("--control-family", default=None, help="Limit to a control family (e.g. AC, AU)")
@click.option("--action", required=True, type=click.Choice(["transition"]), help="Action type")
@click.option("--to", "to_status", required=True, help="Target status for issues")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without persisting")
def remediate(
    framework: str, control_family: str | None, action: str, to_status: str, dry_run: bool
) -> None:
    """Bulk transition issues matching framework/control-family to a new status.

    \b
    Examples:
        warlock bulk remediate --framework nist_800_53 --control-family AC --action transition --to remediated --dry-run
        warlock bulk remediate --framework soc2 --action transition --to closed
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    _dry_banner(dry_run)
    init_db()

    with get_session() as session:
        q = session.query(Issue).filter(
            Issue.framework == framework,
            Issue.status.notin_(["closed", "verified"]),
        )
        if control_family:
            q = q.filter(Issue.control_id.startswith(control_family))
        issues = q.all()

        if not issues:
            console.print(
                f"[dim]No open issues for framework={framework!r} "
                f"family={control_family or 'any'}.[/dim]"
            )
            return

        table = Table(
            title=f"{'[DRY RUN] ' if dry_run else ''}Remediate {len(issues)} issue(s) → {to_status!r}"
        )
        table.add_column("Issue ID", style="dim", max_width=8)
        table.add_column("Control", style="cyan")
        table.add_column("Current Status")
        table.add_column("Title", max_width=50)

        for i in issues[:25]:
            table.add_row(i.id[:8], i.control_id or "—", i.status, escape((i.title or "")[:50]))
        if len(issues) > 25:
            console.print(f"[dim]... and {len(issues) - 25} more[/dim]")
        console.print(table)

        if not dry_run:
            if not click.confirm(f"This will affect {len(issues)} records. Continue?"):
                return
            now = datetime.now(timezone.utc)
            for i in issues:
                i.status = to_status
                i.verification_notes = (
                    i.verification_notes or ""
                ) + f"\n[bulk remediate] transitioned to {to_status} at {now.isoformat()}"
            session.commit()

    _done(len(issues), f"remediate (→ {to_status})", dry_run)


# ---------------------------------------------------------------------------
# attest (BK-002)
# ---------------------------------------------------------------------------


@bulk.command("attest")
@click.option("--framework", "-f", required=True, help="Framework to attest for")
@click.option("--controls", required=True, help="Comma-separated control IDs")
@click.option("--owner", required=True, help="Attestation owner (email or name)")
@click.option("--statement", required=True, help="Attestation statement")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without persisting")
def attest(framework: str, controls: str, owner: str, statement: str, dry_run: bool) -> None:
    """Create attestations for multiple controls at once.

    \b
    Examples:
        warlock bulk attest --framework soc2 --controls CC6.1,CC6.2 --owner alice@co.com --statement "Verified"
        warlock bulk attest --framework nist_800_53 --controls AC-2,AC-3 --owner bob@co.com --statement "Annual review" --dry-run
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    _dry_banner(dry_run)
    init_db()

    control_ids = [c.strip() for c in controls.split(",") if c.strip()]
    if not control_ids:
        _error("No control IDs provided.")

    with get_session() as session:
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.control_id.in_(control_ids),
            )
            .all()
        )

        if not results:
            console.print(
                f"[dim]No control results found for framework={framework!r} "
                f"controls={control_ids}.[/dim]"
            )
            return

        table = Table(
            title=f"{'[DRY RUN] ' if dry_run else ''}Attest {len(results)} control result(s)"
        )
        table.add_column("Control ID", style="cyan")
        table.add_column("Status")
        table.add_column("Owner", style="dim")

        seen: set[str] = set()
        for r in results:
            if r.control_id not in seen:
                table.add_row(r.control_id, r.status, owner)
                seen.add(r.control_id)
        console.print(table)

        if not dry_run:
            now = datetime.now(timezone.utc)
            for r in results:
                detail = dict(r.detail or {}) if hasattr(r, "detail") and r.detail else {}
                attestations = list(detail.get("attestations") or [])
                attestations.append(
                    {
                        "owner": owner,
                        "statement": statement,
                        "attested_at": now.isoformat(),
                        "framework": framework,
                    }
                )
                detail["attestations"] = attestations
                r.detail = detail
            session.commit()

    _done(len(results), f"attest for {framework!r}", dry_run)


# ---------------------------------------------------------------------------
# import-findings (BK-003)
# ---------------------------------------------------------------------------


@bulk.command("import-findings")
@click.option(
    "--file", "filepath", required=True, type=click.Path(exists=True), help="Path to input file"
)
@click.option(
    "--format",
    "fmt",
    default="json",
    type=click.Choice(["json", "csv"]),
    help="Input file format",
)
@click.option("--source", required=True, help="Source identifier (e.g. external-scanner)")
@click.option("--provider", required=True, help="Provider identifier (e.g. qualys)")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without persisting")
def import_findings(filepath: str, fmt: str, source: str, provider: str, dry_run: bool) -> None:
    """Import findings from a JSON or CSV file.

    \b
    JSON format: array of objects with keys: title, severity, observation_type,
    resource_id, resource_type, region, detail.

    CSV format: header row with same keys, one finding per row.

    \b
    Examples:
        warlock bulk import-findings --file findings.json --source ext-scan --provider qualys --dry-run
        warlock bulk import-findings --file findings.csv --format csv --source manual --provider internal
    """
    import hashlib

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    _dry_banner(dry_run)
    init_db()

    # Parse input file
    try:
        with open(filepath) as fh:
            if fmt == "json":
                records = json.load(fh)
                if not isinstance(records, list):
                    _error("JSON file must contain an array of finding objects.")
            else:
                reader = csv.DictReader(fh)
                records = list(reader)
    except (json.JSONDecodeError, OSError) as exc:
        _error(f"Failed to parse {filepath}: {exc}")

    if not records:
        console.print("[dim]No records found in file.[/dim]")
        return

    console.print(f"Parsed [bold]{len(records)}[/bold] record(s) from {filepath}.")

    table = Table(title=f"{'[DRY RUN] ' if dry_run else ''}Import preview (up to 10)")
    table.add_column("Title", max_width=50)
    table.add_column("Severity")
    table.add_column("Resource ID", style="dim")

    for rec in records[:10]:
        table.add_row(
            (rec.get("title") or "")[:50],
            rec.get("severity", "info"),
            (rec.get("resource_id") or "")[:30],
        )
    if len(records) > 10:
        console.print(f"[dim]... and {len(records) - 10} more[/dim]")
    console.print(table)

    if not dry_run:
        if not click.confirm(f"This will import {len(records)} findings. Continue?"):
            return
        now = datetime.now(timezone.utc)
        with get_session() as session:
            created = 0
            for rec in records:
                title = rec.get("title", "Imported finding")
                severity = rec.get("severity", "info")
                obs_type = rec.get("observation_type", "finding")
                detail = rec.get("detail", {})
                if isinstance(detail, str):
                    try:
                        detail = json.loads(detail)
                    except (json.JSONDecodeError, ValueError):
                        detail = {"raw": detail}

                sha_input = f"{source}:{provider}:{title}:{rec.get('resource_id', '')}".encode()
                sha256 = hashlib.sha256(sha_input).hexdigest()

                finding = Finding(
                    observation_type=obs_type,
                    title=title,
                    detail=detail if isinstance(detail, dict) else {},
                    resource_id=rec.get("resource_id"),
                    resource_type=rec.get("resource_type"),
                    resource_name=rec.get("resource_name"),
                    account_id=rec.get("account_id"),
                    region=rec.get("region"),
                    source=source,
                    source_type="import",
                    provider=provider,
                    severity=severity,
                    confidence=float(rec.get("confidence", 1.0)),
                    observed_at=now,
                    sha256=sha256,
                )
                session.add(finding)
                created += 1
            session.commit()
        console.print(f"[green]Imported {created} finding(s).[/green]")
    else:
        _done(len(records), "import findings", dry_run)


# ---------------------------------------------------------------------------
# override-results (BK-004)
# ---------------------------------------------------------------------------


@bulk.command("override-results")
@click.option("--framework", "-f", required=True, help="Framework to target")
@click.option("--controls", required=True, help="Comma-separated control IDs")
@click.option(
    "--status",
    required=True,
    type=click.Choice(["compliant", "non_compliant", "partial"]),
    help="Override status",
)
@click.option("--evidence", required=True, help="Evidence description for the override")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without persisting")
def override_results(
    framework: str, controls: str, status: str, evidence: str, dry_run: bool
) -> None:
    """Bulk override control result statuses with evidence.

    \b
    Examples:
        warlock bulk override-results --framework soc2 --controls CC6.1,CC6.2 --status compliant --evidence "Pen test passed"
        warlock bulk override-results --framework nist_800_53 --controls AC-2 --status partial --evidence "MFA partial rollout" --dry-run
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    _dry_banner(dry_run)
    init_db()
    actor = _get_actor()

    control_ids = [c.strip() for c in controls.split(",") if c.strip()]
    if not control_ids:
        _error("No control IDs provided.")

    with get_session() as session:
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.control_id.in_(control_ids),
            )
            .all()
        )

        if not results:
            console.print(
                f"[dim]No control results for framework={framework!r} controls={control_ids}.[/dim]"
            )
            return

        table = Table(
            title=f"{'[DRY RUN] ' if dry_run else ''}Override {len(results)} result(s) → {status}"
        )
        table.add_column("Control ID", style="cyan")
        table.add_column("Current Status")
        table.add_column("New Status", style="bold")

        for r in results[:25]:
            table.add_row(r.control_id, r.status, status)
        if len(results) > 25:
            console.print(f"[dim]... and {len(results) - 25} more[/dim]")
        console.print(table)

        if not dry_run:
            if not click.confirm(f"This will affect {len(results)} records. Continue?"):
                return
            now = datetime.now(timezone.utc)
            for r in results:
                old_status = r.status
                r.status = status
                detail = dict(r.detail or {}) if hasattr(r, "detail") and r.detail else {}
                overrides = list(detail.get("overrides") or [])
                overrides.append(
                    {
                        "from_status": old_status,
                        "to_status": status,
                        "evidence": evidence,
                        "actor": actor,
                        "overridden_at": now.isoformat(),
                    }
                )
                detail["overrides"] = overrides
                r.detail = detail
            session.commit()

    _done(len(results), f"override results (→ {status})", dry_run)
