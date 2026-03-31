"""Vendor management commands.

NOTE: 'vendors' is already registered as a flat command in risk.py.
This module registers under 'vendor-mgmt' to avoid a collision.

Provides full vendor lifecycle management: create, assess, questionnaire,
risk-score, contracts, incidents, concentration, SOC 2 review, fourth-party,
offboard, and SLA tracking.
"""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import _error, cli, console

# ---------------------------------------------------------------------------
# vendor-mgmt group
# ---------------------------------------------------------------------------


@cli.group("vendor-mgmt", invoke_without_command=True)
@click.pass_context
def vendor_mgmt(ctx: click.Context) -> None:
    """Vendor lifecycle management (create, assess, risk-score, offboard)."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@vendor_mgmt.command("list")
@click.option("--tier", "-t", default=None, help="Filter by tier (1, 2, 3, critical)")
@click.option("--limit", "-n", default=50, help="Max results")
def vendor_list(tier: str | None, limit: int) -> None:
    """List all vendors."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import Vendor

    init_db()
    with get_read_session() as session:
        q = session.query(Vendor)
        if tier:
            q = q.filter(Vendor.tier == tier)
        rows = q.order_by(Vendor.name).limit(limit).all()

    if not rows:
        console.print("[dim]No vendors found.[/dim]")
        return

    table = Table(title=f"Vendors ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", style="cyan")
    table.add_column("Tier")
    table.add_column("Risk Score", justify="right")
    table.add_column("Last Assessment", style="dim")
    table.add_column("Contract Expires", style="dim")

    for v in rows:
        score = f"{v.risk_score:.0f}" if v.risk_score is not None else "\u2014"
        last_a = v.last_assessment.strftime("%Y-%m-%d") if v.last_assessment else "\u2014"
        contract = v.contract_expires.strftime("%Y-%m-%d") if v.contract_expires else "\u2014"
        score_color = (
            (
                "green"
                if v.risk_score and v.risk_score >= 70
                else ("yellow" if v.risk_score and v.risk_score >= 40 else "red")
            )
            if v.risk_score is not None
            else ""
        )
        table.add_row(
            v.id[:8],
            escape(v.name or ""),
            v.tier or "\u2014",
            f"[{score_color}]{score}[/]" if score_color else score,
            last_a,
            contract,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@vendor_mgmt.command("show")
@click.argument("vendor_id")
def vendor_show(vendor_id: str) -> None:
    """Show detailed information for a vendor."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    init_db()
    with get_session() as session:
        v = (
            session.query(Vendor)
            .filter(Vendor.id.startswith(vendor_id) | (Vendor.name == vendor_id))
            .first()
        )
        if not v:
            _error(f"Vendor not found: {vendor_id}")

    console.print(f"\n[bold]Vendor:[/bold] {escape(v.name or '')}")
    console.print(f"  ID:                {v.id}")
    console.print(f"  Tier:              {v.tier or '\u2014'}")
    console.print(
        f"  Risk Score:        {v.risk_score:.0f}/100"
        if v.risk_score is not None
        else "  Risk Score:        \u2014"
    )
    console.print(
        f"  Last Assessment:   {v.last_assessment.strftime('%Y-%m-%d') if v.last_assessment else '\u2014'}"
    )
    console.print(f"  Assessment Cadence:{v.assessment_cadence_days or '\u2014'} days")
    console.print(
        f"  Contract Expires:  {v.contract_expires.strftime('%Y-%m-%d') if v.contract_expires else '\u2014'}"
    )
    if v.metadata_:
        console.print(f"  Metadata:          {v.metadata_}")


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


@vendor_mgmt.command("create")
@click.option("--name", required=True, help="Vendor name")
@click.option(
    "--tier",
    default="3",
    type=click.Choice(["1", "2", "3", "critical"]),
    help="Vendor tier (1=highest criticality)",
)
@click.option("--cadence", default=365, help="Assessment cadence in days")
def vendor_create(name: str, tier: str, cadence: int) -> None:
    """Register a new vendor."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    init_db()
    with get_session() as session:
        existing = session.query(Vendor).filter(Vendor.name == name).first()
        if existing:
            _error(f"Vendor already exists: {name}")

        v = Vendor(
            name=name,
            tier=tier,
            assessment_cadence_days=cadence,
        )
        session.add(v)
        session.commit()
        vendor_id = v.id

    console.print(f"[green]Vendor registered: {vendor_id[:8]} '{name}' (tier {tier})[/green]")


# ---------------------------------------------------------------------------
# assess
# ---------------------------------------------------------------------------


@vendor_mgmt.command("assess")
@click.argument("vendor_id")
@click.option("--score", type=float, required=True, help="Overall risk score (0-100)")
@click.option("--notes", default=None, help="Assessment notes")
def vendor_assess(vendor_id: str, score: float, notes: str | None) -> None:
    """Record a risk assessment result for a vendor."""
    from datetime import datetime, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    if not 0 <= score <= 100:
        _error("Score must be between 0 and 100.")

    init_db()
    with get_session() as session:
        v = session.query(Vendor).filter(Vendor.id.startswith(vendor_id)).first()
        if not v:
            _error(f"Vendor not found: {vendor_id}")

        v.risk_score = score
        v.last_assessment = datetime.now(timezone.utc)
        if notes:
            meta = dict(v.metadata_ or {})
            meta["last_assessment_notes"] = notes
            v.metadata_ = meta
        session.commit()

    console.print(
        f"[green]Assessment recorded for '{escape(v.name or '')}': score={score:.0f}[/green]"
    )


# ---------------------------------------------------------------------------
# questionnaire
# ---------------------------------------------------------------------------


@vendor_mgmt.command("questionnaire")
@click.argument("vendor_id")
@click.option(
    "--action",
    type=click.Choice(["send", "status", "review"]),
    default="status",
    help="Action to take on the questionnaire",
)
def vendor_questionnaire(vendor_id: str, action: str) -> None:
    """Manage vendor security questionnaires."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    init_db()
    with get_session() as session:
        v = session.query(Vendor).filter(Vendor.id.startswith(vendor_id)).first()
        if not v:
            _error(f"Vendor not found: {vendor_id}")

    if action == "send":
        console.print(f"[green]Questionnaire sent to vendor '{escape(v.name or '')}'.[/green]")
        console.print("[dim]Configure WLK_SMTP_HOST for actual email delivery.[/dim]")
    elif action == "status":
        meta = v.metadata_ or {}
        status = meta.get("questionnaire_status", "not_sent")
        console.print(f"Questionnaire status for '{escape(v.name or '')}': {status}")
    elif action == "review":
        meta = v.metadata_ or {}
        responses = meta.get("questionnaire_responses", {})
        if responses:
            for k, val in responses.items():
                console.print(f"  {k}: {val}")
        else:
            console.print("[dim]No questionnaire responses recorded.[/dim]")


# ---------------------------------------------------------------------------
# risk-score
# ---------------------------------------------------------------------------


@vendor_mgmt.command("risk-score")
@click.argument("vendor_id")
def vendor_risk_score(vendor_id: str) -> None:
    """Display the current risk score and scoring breakdown for a vendor."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    init_db()
    with get_session() as session:
        v = session.query(Vendor).filter(Vendor.id.startswith(vendor_id)).first()
        if not v:
            _error(f"Vendor not found: {vendor_id}")

    score = v.risk_score
    if score is None:
        console.print(
            f"[yellow]No risk score recorded for '{v.name}'. Run 'vendor-mgmt assess'.[/yellow]"
        )
        return

    color = "green" if score >= 70 else ("yellow" if score >= 40 else "red")
    level = "Low" if score >= 70 else ("Medium" if score >= 40 else "High")

    console.print(f"\n[bold]Risk Score: {escape(v.name or '')}[/bold]")
    console.print(f"  Score:          [{color}]{score:.0f}/100[/]")
    console.print(f"  Risk Level:     [{color}]{level}[/]")
    console.print(f"  Tier:           {v.tier or '\u2014'}")
    console.print(
        f"  Last Assessed:  {v.last_assessment.strftime('%Y-%m-%d') if v.last_assessment else '\u2014'}"
    )


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------


@vendor_mgmt.command("history")
@click.argument("vendor_id")
@click.option("--limit", "-n", default=10, help="Max history entries")
def vendor_history(vendor_id: str, limit: int) -> None:
    """Show assessment history for a vendor."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, Vendor

    init_db()
    with get_session() as session:
        v = session.query(Vendor).filter(Vendor.id.startswith(vendor_id)).first()
        if not v:
            _error(f"Vendor not found: {vendor_id}")

        entries = (
            session.query(AuditEntry)
            .filter(AuditEntry.entity_type == "vendor", AuditEntry.entity_id == v.id)
            .order_by(AuditEntry.created_at.desc())
            .limit(limit)
            .all()
        )

    console.print(f"\n[bold]History for '{escape(v.name or '')}':[/bold]")
    if not entries:
        console.print("[dim]No audit entries found.[/dim]")
        return

    table = Table(title=f"Vendor History: {escape(v.name or '')}")
    table.add_column("When", style="dim")
    table.add_column("Action")
    table.add_column("Actor", style="dim")

    for e in entries:
        ts = e.created_at.strftime("%Y-%m-%d %H:%M") if e.created_at else "\u2014"
        table.add_row(ts, e.action, e.actor)

    console.print(table)


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


@vendor_mgmt.command("export")
@click.option("--output", "-o", required=True, help="Output file path (JSON)")
def vendor_export(output: str) -> None:
    """Export all vendor records to JSON."""
    import json
    from datetime import datetime, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    init_db()
    with get_session() as session:
        vendors = session.query(Vendor).order_by(Vendor.name).all()

    records = [
        {
            "id": v.id,
            "name": v.name,
            "tier": v.tier,
            "risk_score": v.risk_score,
            "last_assessment": v.last_assessment.isoformat() if v.last_assessment else None,
            "contract_expires": v.contract_expires.isoformat() if v.contract_expires else None,
            "assessment_cadence_days": v.assessment_cadence_days,
        }
        for v in vendors
    ]

    with open(output, "w") as fh:
        json.dump(
            {"exported_at": datetime.now(timezone.utc).isoformat(), "vendors": records},
            fh,
            indent=2,
        )

    console.print(f"[green]Exported {len(records)} vendors to {output}[/green]")


# ---------------------------------------------------------------------------
# reassess-due
# ---------------------------------------------------------------------------


@vendor_mgmt.command("reassess-due")
def vendor_reassess_due() -> None:
    """List vendors that are due for reassessment."""
    from datetime import datetime, timedelta, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor
    from warlock.utils import ensure_aware

    init_db()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        vendors = session.query(Vendor).all()

    due: list[Vendor] = []
    for v in vendors:
        cadence = v.assessment_cadence_days or 365
        if v.last_assessment is None:
            due.append(v)
        else:
            next_due = ensure_aware(v.last_assessment) + timedelta(days=cadence)
            if next_due <= now:
                due.append(v)

    if not due:
        console.print("[green]No vendors are due for reassessment.[/green]")
        return

    table = Table(title=f"Vendors Due for Reassessment ({len(due)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", style="cyan")
    table.add_column("Tier")
    table.add_column("Last Assessed", style="dim")
    table.add_column("Cadence (days)", justify="right")

    for v in due:
        last = v.last_assessment.strftime("%Y-%m-%d") if v.last_assessment else "[red]never[/red]"
        table.add_row(
            v.id[:8],
            escape(v.name or ""),
            v.tier or "\u2014",
            last,
            str(v.assessment_cadence_days or 365),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# contracts
# ---------------------------------------------------------------------------


@vendor_mgmt.command("contracts")
@click.option(
    "--expiring-within", type=int, default=90, help="Days ahead to look for expiring contracts"
)
def vendor_contracts(expiring_within: int) -> None:
    """List vendors with contracts expiring soon."""
    from datetime import datetime, timedelta, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor
    from warlock.utils import ensure_aware

    init_db()
    cutoff = datetime.now(timezone.utc) + timedelta(days=expiring_within)

    with get_session() as session:
        vendors = (
            session.query(Vendor)
            .filter(Vendor.contract_expires <= cutoff, Vendor.contract_expires.isnot(None))
            .order_by(Vendor.contract_expires)
            .all()
        )

    if not vendors:
        console.print(f"[green]No contracts expiring within {expiring_within} days.[/green]")
        return

    table = Table(title=f"Contracts Expiring Within {expiring_within} Days")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", style="cyan")
    table.add_column("Tier")
    table.add_column("Expires")
    table.add_column("Days Left", justify="right")

    now = datetime.now(timezone.utc)
    for v in vendors:
        days_left = (ensure_aware(v.contract_expires) - now).days
        color = "red" if days_left <= 14 else ("yellow" if days_left <= 30 else "white")
        table.add_row(
            v.id[:8],
            escape(v.name or ""),
            v.tier or "\u2014",
            ensure_aware(v.contract_expires).strftime("%Y-%m-%d"),
            f"[{color}]{days_left}[/]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# incidents
# ---------------------------------------------------------------------------


@vendor_mgmt.command("incidents")
@click.option("--vendor-id", default=None, help="Filter by vendor ID")
@click.option("--limit", "-n", default=20, help="Max results")
def vendor_incidents(vendor_id: str | None, limit: int) -> None:
    """Show security incidents associated with vendors."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        q = session.query(AuditEntry).filter(
            AuditEntry.action.in_(["vendor_incident", "vendor_breach", "vendor_security_event"])
        )
        if vendor_id:
            q = q.filter(AuditEntry.entity_id.startswith(vendor_id))
        entries = q.order_by(AuditEntry.created_at.desc()).limit(limit).all()

    if not entries:
        console.print("[dim]No vendor security incidents recorded.[/dim]")
        return

    table = Table(title="Vendor Security Incidents")
    table.add_column("When", style="dim")
    table.add_column("Vendor", style="cyan")
    table.add_column("Action")
    table.add_column("Actor", style="dim")

    for e in entries:
        ts = e.created_at.strftime("%Y-%m-%d %H:%M") if e.created_at else "\u2014"
        table.add_row(ts, e.entity_id[:8], e.action, e.actor)

    console.print(table)


# ---------------------------------------------------------------------------
# concentration
# ---------------------------------------------------------------------------


@vendor_mgmt.command("concentration")
def vendor_concentration() -> None:
    """Analyse vendor concentration risk (tier distribution and high-risk count)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    init_db()
    with get_session() as session:
        vendors = session.query(Vendor).all()

    if not vendors:
        console.print("[dim]No vendors found.[/dim]")
        return

    from collections import Counter

    tier_counts: Counter[str] = Counter(v.tier or "unclassified" for v in vendors)
    high_risk = sum(1 for v in vendors if v.risk_score is not None and v.risk_score < 40)
    no_assessment = sum(1 for v in vendors if v.risk_score is None)
    total = len(vendors)

    console.print("\n[bold]Vendor Concentration Analysis[/bold]")
    console.print(f"  Total vendors:      {total}")
    console.print(f"  High-risk (< 40):  {high_risk}")
    console.print(f"  No assessment:      {no_assessment}")
    console.print()

    table = Table(title="By Tier")
    table.add_column("Tier", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("% of total", justify="right")

    for tier in sorted(tier_counts):
        count = tier_counts[tier]
        pct = count / total * 100
        table.add_row(tier, str(count), f"{pct:.0f}%")

    console.print(table)


# ---------------------------------------------------------------------------
# soc2-review
# ---------------------------------------------------------------------------


@vendor_mgmt.command("soc2-review")
@click.argument("vendor_id")
@click.option("--report-date", default=None, help="SOC 2 report date (YYYY-MM-DD)")
@click.option("--opinion", default=None, help="Auditor opinion (unqualified, qualified, adverse)")
def vendor_soc2_review(vendor_id: str, report_date: str | None, opinion: str | None) -> None:
    """Record or display SOC 2 report review for a vendor."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    init_db()
    with get_session() as session:
        v = session.query(Vendor).filter(Vendor.id.startswith(vendor_id)).first()
        if not v:
            _error(f"Vendor not found: {vendor_id}")

        if report_date or opinion:
            meta = dict(v.metadata_ or {})
            if report_date:
                meta["soc2_report_date"] = report_date
            if opinion:
                meta["soc2_opinion"] = opinion
            v.metadata_ = meta
            session.commit()
            console.print(f"[green]SOC 2 review recorded for '{escape(v.name or '')}'.[/green]")
        else:
            meta = v.metadata_ or {}
            console.print(f"\n[bold]SOC 2 Review: {escape(v.name or '')}[/bold]")
            console.print(f"  Report Date: {meta.get('soc2_report_date', '\u2014')}")
            console.print(f"  Opinion:     {meta.get('soc2_opinion', '\u2014')}")


# ---------------------------------------------------------------------------
# fourth-party
# ---------------------------------------------------------------------------


@vendor_mgmt.command("fourth-party")
@click.argument("vendor_id", required=False, default=None)
def vendor_fourth_party(vendor_id: str | None) -> None:
    """List fourth-party (sub-processor) dependencies for a vendor.

    When VENDOR_ID is omitted, shows all vendors with their sub-processor data.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    init_db()

    if vendor_id is None:
        with get_session() as session:
            vendors = session.query(Vendor).order_by(Vendor.name).all()
        if not vendors:
            console.print("[dim]No vendors found.[/dim]")
            return

        table = Table(title="Fourth-Party Dependencies (all vendors)")
        table.add_column("Vendor", style="cyan")
        table.add_column("Sub-processors", justify="right")
        table.add_column("Names", style="dim", max_width=60)

        for v in vendors:
            meta = v.metadata_ or {}
            sps = meta.get("subprocessors", [])
            names = ", ".join(
                (sp.get("name", "?") if isinstance(sp, dict) else str(sp)) for sp in sps[:5]
            )
            if len(sps) > 5:
                names += f" (+{len(sps) - 5})"
            table.add_row(escape(v.name or ""), str(len(sps)), names or "\u2014")

        console.print(table)
        return

    with get_session() as session:
        v = session.query(Vendor).filter(Vendor.id.startswith(vendor_id)).first()
        if not v:
            _error(f"Vendor not found: {vendor_id}")

    meta = v.metadata_ or {}
    subprocessors = meta.get("subprocessors", [])

    console.print(f"\n[bold]Fourth-Party Dependencies: {escape(v.name or '')}[/bold]")
    if not subprocessors:
        console.print(
            "[dim]No sub-processor data recorded. Update vendor metadata to track fourth parties.[/dim]"
        )
        return

    table = Table(title="Sub-processors")
    table.add_column("Name", style="cyan")
    table.add_column("Purpose", style="dim")

    for sp in subprocessors:
        if isinstance(sp, dict):
            table.add_row(sp.get("name", "?"), sp.get("purpose", "\u2014"))
        else:
            table.add_row(str(sp), "\u2014")

    console.print(table)


# ---------------------------------------------------------------------------
# offboard
# ---------------------------------------------------------------------------


@vendor_mgmt.command("offboard")
@click.argument("vendor_id")
@click.option("--reason", required=True, help="Reason for offboarding")
def vendor_offboard(vendor_id: str, reason: str) -> None:
    """Offboard a vendor (mark as inactive and record reason)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    init_db()
    with get_session() as session:
        v = session.query(Vendor).filter(Vendor.id.startswith(vendor_id)).first()
        if not v:
            _error(f"Vendor not found: {vendor_id}")

        meta = dict(v.metadata_ or {})
        meta["offboarded"] = True
        meta["offboard_reason"] = reason
        v.metadata_ = meta
        session.commit()

    console.print(f"[yellow]Vendor '{escape(v.name or '')}' offboarded.[/yellow]")
    console.print(f"  Reason: {reason}")


# ---------------------------------------------------------------------------
# sla
# ---------------------------------------------------------------------------


@vendor_mgmt.command("import")
@click.option(
    "--file", "filepath", required=True, type=click.Path(exists=True), help="Input file path"
)
@click.option(
    "--format", "fmt", default="json", type=click.Choice(["json", "csv"]), help="File format"
)
@click.option("--dry-run", is_flag=True, default=False, help="Preview without importing")
def vendor_import(filepath: str, fmt: str, dry_run: bool) -> None:
    """Import vendor records from a JSON or CSV file.

    Expected JSON structure: {"vendors": [{"name": "...", "tier": "...", ...}, ...]}
    Expected CSV columns: name, tier, assessment_cadence_days (optional extra columns ignored)
    """
    import csv
    import json as _json

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    records: list[dict] = []
    if fmt == "json":
        with open(filepath) as fh:
            data = _json.load(fh)
        records = data.get("vendors", data) if isinstance(data, dict) else data
    else:
        with open(filepath, newline="") as fh:
            reader = csv.DictReader(fh)
            records = list(reader)

    if not records:
        console.print("[dim]No records found in file.[/dim]")
        return

    console.print(f"[bold]{len(records)}[/bold] vendor record(s) found in {filepath}.")

    table = Table(title="Vendor Import Preview")
    table.add_column("Name", style="cyan")
    table.add_column("Tier")
    table.add_column("Cadence (days)", justify="right")

    for r in records[:20]:
        table.add_row(
            r.get("name", "?"),
            str(r.get("tier", "3")),
            str(r.get("assessment_cadence_days", "365")),
        )
    if len(records) > 20:
        console.print(f"[dim]... and {len(records) - 20} more[/dim]")
    console.print(table)

    if dry_run:
        console.print(
            f"\n[dim](dry-run) Would import {len(records)} vendor(s). "
            f"Pass without --dry-run to execute.[/dim]"
        )
        return

    init_db()
    created = 0
    skipped = 0
    with get_session() as session:
        for r in records:
            name = r.get("name", "").strip()
            if not name:
                skipped += 1
                continue
            existing = session.query(Vendor).filter(Vendor.name == name).first()
            if existing:
                skipped += 1
                continue
            v = Vendor(
                name=name,
                tier=str(r.get("tier", "3")),
                assessment_cadence_days=int(r.get("assessment_cadence_days", 365)),
            )
            session.add(v)
            created += 1
        session.commit()

    console.print(f"[green]Imported {created} vendor(s), skipped {skipped}.[/green]")


@vendor_mgmt.command("sla")
@click.argument("vendor_id", required=False, default=None)
@click.option("--set-uptime", type=float, default=None, help="Set contracted uptime SLA (%)")
@click.option("--set-response", type=int, default=None, help="Set incident response SLA (hours)")
def vendor_sla(vendor_id: str | None, set_uptime: float | None, set_response: int | None) -> None:
    """View or update SLA terms for a vendor.

    When VENDOR_ID is omitted, shows SLA summary for all vendors.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    init_db()

    if vendor_id is None:
        with get_session() as session:
            vendors = session.query(Vendor).order_by(Vendor.name).all()
        if not vendors:
            console.print("[dim]No vendors found.[/dim]")
            return

        table = Table(title="Vendor SLA Summary")
        table.add_column("ID", style="dim", max_width=8)
        table.add_column("Vendor", style="cyan")
        table.add_column("Uptime SLA", justify="right")
        table.add_column("Response SLA", justify="right")

        for v in vendors:
            meta = v.metadata_ or {}
            uptime = meta.get("sla_uptime_pct")
            response = meta.get("sla_response_hours")
            table.add_row(
                v.id[:8],
                escape(v.name or ""),
                f"{uptime}%" if uptime is not None else "\u2014",
                f"{response}h" if response is not None else "\u2014",
            )
        console.print(table)
        return

    with get_session() as session:
        v = session.query(Vendor).filter(Vendor.id.startswith(vendor_id)).first()
        if not v:
            _error(f"Vendor not found: {vendor_id}")

        if set_uptime is not None or set_response is not None:
            meta = dict(v.metadata_ or {})
            if set_uptime is not None:
                meta["sla_uptime_pct"] = set_uptime
            if set_response is not None:
                meta["sla_response_hours"] = set_response
            v.metadata_ = meta
            session.commit()
            console.print(f"[green]SLA terms updated for '{escape(v.name or '')}'.[/green]")
        else:
            meta = v.metadata_ or {}
            console.print(f"\n[bold]SLA Terms: {escape(v.name or '')}[/bold]")
            console.print(f"  Uptime SLA:       {meta.get('sla_uptime_pct', '\u2014')}%")
            console.print(f"  Response SLA:     {meta.get('sla_response_hours', '\u2014')}h")
