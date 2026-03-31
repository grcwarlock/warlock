"""Interactive vendor workflow commands.

Provides guided, multi-step workflows for GRC practitioners managing
third-party vendor risk:

    warlock vendor-review assess <name|id>   -- Guided vendor assessment
    warlock vendor-review onboard            -- Guided vendor onboarding
    warlock vendor-review reassess           -- Batch vendor reassessment
    warlock vendor-review offboard <name|id> -- Guided vendor offboarding
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import click
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from warlock.cli import _error, _get_actor, cli, console
from warlock.utils import ensure_aware

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _resolve_vendor(session, value: str):
    """Resolve a Vendor by ID prefix or case-insensitive name."""
    from warlock.db.models import Vendor

    # Exact ID
    vendor = session.query(Vendor).filter(Vendor.id == value).first()
    if vendor:
        return vendor

    # ID prefix
    vendor = session.query(Vendor).filter(Vendor.id.startswith(value)).first()
    if vendor:
        return vendor

    # Case-insensitive name
    vendor = session.query(Vendor).filter(Vendor.name.ilike(value)).first()
    if vendor:
        return vendor

    # Partial name
    vendor = session.query(Vendor).filter(Vendor.name.ilike(f"%{value}%")).first()
    return vendor


def _risk_tier_cadence(tier: str | None) -> int:
    """Return reassessment cadence in days for a risk tier."""
    return {
        "1": 90,
        "critical": 90,
        "2": 180,
        "high": 180,
        "3": 365,
        "low": 365,
    }.get((tier or "3").lower(), 365)


def _risk_tier_color(tier: str | None) -> str:
    return {
        "1": "red bold",
        "critical": "red bold",
        "2": "yellow",
        "high": "yellow",
        "3": "dim",
        "low": "dim",
    }.get((tier or "").lower(), "white")


def _write_audit_entry(session, action: str, entity_id: str, extra: dict) -> None:
    """Append a hash-chained audit entry for a vendor workflow action."""
    import hashlib
    import json

    from warlock.db.models import AuditEntry

    last = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
    prev_hash = last.entry_hash if last else "genesis"
    seq = (last.sequence + 1) if last else 1

    payload = json.dumps({"action": action, "entity_id": entity_id, "extra": extra}, sort_keys=True)
    entry_hash = hashlib.sha256(f"{prev_hash}:{payload}".encode()).hexdigest()

    entry = AuditEntry(
        id=str(uuid.uuid4()),
        sequence=seq,
        previous_hash=prev_hash,
        entry_hash=entry_hash,
        action=action,
        entity_type="vendor",
        entity_id=entity_id,
        actor=_get_actor(),
        extra=extra,
    )
    session.add(entry)
    session.commit()


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("vendor-review", invoke_without_command=True)
@click.pass_context
def vendor_review(ctx: click.Context) -> None:
    """Interactive vendor management workflows (assess, onboard, offboard)."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# assess
# ---------------------------------------------------------------------------


@vendor_review.command("assess")
@click.argument("vendor_name_or_id")
def vendor_assess(vendor_name_or_id: str) -> None:
    """Guided vendor risk assessment workflow.

    Shows vendor profile, linked findings, questionnaire/SOC 2 status,
    contract details, and a risk score breakdown. Prompts for next actions
    in an interactive loop.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, Issue

    init_db()

    with get_session() as session:
        vendor = _resolve_vendor(session, vendor_name_or_id)
        if not vendor:
            _error(f"Vendor not found: '{vendor_name_or_id}'")

        try:
            _run_vendor_assess_loop(session, vendor, Finding, Issue)
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Session ended.[/dim]")


def _run_vendor_assess_loop(session, vendor, Finding, Issue) -> None:
    """Interactive assessment loop (separated for testability)."""

    while True:
        console.print()

        # --- 1. Vendor profile ---
        tier_style = _risk_tier_color(vendor.tier)
        last_assessed = (
            vendor.last_assessment.strftime("%Y-%m-%d") if vendor.last_assessment else "Never"
        )
        contract_exp = (
            vendor.contract_expires.strftime("%Y-%m-%d") if vendor.contract_expires else "Unknown"
        )
        meta = vendor.metadata_ or {}

        console.print(
            Panel(
                f"[bold]{escape(vendor.name or '')}[/bold]\n\n"
                f"ID: {vendor.id[:8]}  |  "
                f"Category: {meta.get('category', 'unknown')}  |  "
                f"Risk Tier: [{tier_style}]{vendor.tier or 'unset'}[/{tier_style}]\n"
                f"Last Assessment: {last_assessed}  |  "
                f"Contract Expires: {contract_exp}  |  "
                f"Contact: {meta.get('contact', '—')}",
                title="[bold cyan]Vendor Profile[/bold cyan]",
                border_style="cyan",
            )
        )

        # --- 2. Linked findings ---
        linked_findings = (
            session.query(Finding)
            .filter(Finding.source == vendor.name.lower().replace(" ", "_"))
            .order_by(Finding.created_at.desc())
            .limit(5)
            .all()
        )
        if linked_findings:
            ft = Table(title="Linked Findings (latest 5)", show_header=True)
            ft.add_column("ID", style="dim", max_width=8)
            ft.add_column("Title", max_width=50)
            ft.add_column("Severity")
            ft.add_column("Status")
            for f in linked_findings:
                sev_style = {
                    "critical": "red bold",
                    "high": "red",
                    "medium": "yellow",
                    "low": "dim",
                }.get(f.severity or "", "white")
                ft.add_row(
                    f.id[:8],
                    (f.title or "")[:50],
                    f"[{sev_style}]{f.severity or '—'}[/]",
                    f.status or "—",
                )
            console.print(ft)
        else:
            console.print("[dim]No linked findings found for this vendor source.[/dim]")

        # --- 3. Questionnaire status ---
        q_status = meta.get("questionnaire_status", "not_sent")
        q_style = {"sent": "yellow", "pending": "yellow", "complete": "green"}.get(q_status, "dim")
        console.print(
            f"\nQuestionnaire: [{q_style}]{q_status}[/{q_style}]  |  "
            f"SOC 2 Report: {meta.get('soc2_status', 'not_requested')}  |  "
            f"SLA Compliance: {meta.get('sla_compliance', 'unknown')}"
        )

        # --- 4. Risk score breakdown ---
        score = vendor.risk_score or 0.0
        score_color = "red" if score >= 70 else ("yellow" if score >= 40 else "green")
        console.print(f"\nRisk Score: [{score_color}]{score:.1f}/100[/{score_color}]")
        if meta.get("risk_breakdown"):
            for factor, val in meta["risk_breakdown"].items():
                console.print(f"  {factor}: {val}")

        # --- 5. Action menu ---
        console.print()
        choice = Prompt.ask(
            "Actions",
            choices=["u", "s", "r", "c", "q"],
            default="q",
            show_choices=True,
            show_default=True,
            console=console,
        )
        console.print(
            "  [dim]u[/dim]=update risk tier  "
            "[dim]s[/dim]=send questionnaire  "
            "[dim]r[/dim]=review SOC2  "
            "[dim]c[/dim]=create issue  "
            "[dim]q[/dim]=quit"
        )

        if choice == "q":
            console.print("[dim]Exiting assessment.[/dim]")
            break

        elif choice == "u":
            new_tier = Prompt.ask(
                "New risk tier",
                choices=["1", "2", "3", "critical", "high", "low"],
                console=console,
            )
            old_tier = vendor.tier
            vendor.tier = new_tier
            session.commit()
            _write_audit_entry(
                session,
                "vendor_tier_updated",
                vendor.id,
                {"old_tier": old_tier, "new_tier": new_tier},
            )
            console.print(f"[green]Risk tier updated: {old_tier} -> {new_tier}[/green]")

        elif choice == "s":
            meta_new = dict(meta)
            meta_new["questionnaire_status"] = "sent"
            meta_new["questionnaire_sent_at"] = _utcnow().isoformat()
            vendor.metadata_ = meta_new
            session.commit()
            _write_audit_entry(session, "vendor_questionnaire_sent", vendor.id, {})
            console.print(
                f"[green]Questionnaire marked as sent for {escape(vendor.name or '')}.[/green]"
            )

        elif choice == "r":
            soc2_status = Prompt.ask(
                "SOC 2 report status",
                choices=["requested", "received", "reviewed", "expired"],
                default="received",
                console=console,
            )
            meta_new = dict(meta)
            meta_new["soc2_status"] = soc2_status
            meta_new["soc2_updated_at"] = _utcnow().isoformat()
            vendor.metadata_ = meta_new
            session.commit()
            _write_audit_entry(
                session,
                "vendor_soc2_status_updated",
                vendor.id,
                {"soc2_status": soc2_status},
            )
            console.print(f"[green]SOC 2 status set to '{soc2_status}'.[/green]")

        elif choice == "c":
            from warlock.db.models import Issue as IssueModel

            title = Prompt.ask(
                "Issue title", default=f"Vendor risk: {vendor.name}", console=console
            )
            priority = Prompt.ask(
                "Priority",
                choices=["critical", "high", "medium", "low"],
                default="medium",
                console=console,
            )
            issue = IssueModel(
                id=str(uuid.uuid4()),
                title=title,
                description=f"Issue created during vendor assessment for {vendor.name}.",
                priority=priority,
                status="open",
                source="manual",
                tags=["vendor-review", vendor.name],
                created_by=_get_actor(),
            )
            session.add(issue)
            session.commit()
            console.print(f"[green]Issue created: {issue.id[:8]} [{priority}] {title}[/green]")


# ---------------------------------------------------------------------------
# onboard
# ---------------------------------------------------------------------------


@vendor_review.command("onboard")
def vendor_onboard() -> None:
    """Guided vendor onboarding workflow.

    Prompts for vendor details, creates the record, optionally sends a
    questionnaire and SOC 2 request, sets an initial risk tier, and
    records the onboarding in the audit trail.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    init_db()

    try:
        console.print(
            Panel(
                "[bold]Vendor Onboarding Wizard[/bold]\nPress Ctrl-C at any time to cancel.",
                border_style="cyan",
            )
        )

        name = Prompt.ask("Vendor name", console=console)
        if not name.strip():
            _error("Vendor name cannot be empty.")

        category = Prompt.ask(
            "Category",
            choices=[
                "saas",
                "infrastructure",
                "professional_services",
                "hardware",
                "data_processor",
                "other",
            ],
            default="saas",
            console=console,
        )
        contact = Prompt.ask("Primary contact email (optional)", default="", console=console)

        send_questionnaire = Confirm.ask(
            "Send security questionnaire?", default=True, console=console
        )
        request_soc2 = Confirm.ask("Request SOC 2 report?", default=True, console=console)

        # Risk tier based on category
        _default_tier: dict[str, str] = {
            "saas": "2",
            "infrastructure": "1",
            "professional_services": "2",
            "hardware": "3",
            "data_processor": "1",
            "other": "3",
        }
        suggested_tier = _default_tier.get(category, "2")
        tier = Prompt.ask(
            f"Initial risk tier (suggested: {suggested_tier})",
            choices=["1", "2", "3"],
            default=suggested_tier,
            console=console,
        )

        meta: dict = {
            "category": category,
            "contact": contact,
            "questionnaire_status": "sent" if send_questionnaire else "not_sent",
            "soc2_status": "requested" if request_soc2 else "not_requested",
            "onboarded_at": _utcnow().isoformat(),
            "onboarded_by": _get_actor(),
        }
        if send_questionnaire:
            meta["questionnaire_sent_at"] = _utcnow().isoformat()

        vendor = Vendor(
            id=str(uuid.uuid4()),
            name=name.strip(),
            tier=tier,
            risk_score=float({"1": 75, "2": 45, "3": 15}[tier]),
            assessment_cadence_days=_risk_tier_cadence(tier),
            metadata_=meta,
        )

        with get_session() as session:
            existing = session.query(Vendor).filter(Vendor.name.ilike(name.strip())).first()
            if existing:
                _error(
                    f"Vendor '{name.strip()}' already exists (ID: {existing.id[:8]}). "
                    "Use 'warlock vendor-review assess' to review."
                )
            session.add(vendor)
            session.commit()
            _write_audit_entry(
                session,
                "vendor_onboarded",
                vendor.id,
                {
                    "name": vendor.name,
                    "tier": tier,
                    "category": category,
                    "send_questionnaire": send_questionnaire,
                    "request_soc2": request_soc2,
                },
            )

        console.print()
        console.print(
            Panel(
                f"[bold green]Vendor onboarded successfully.[/bold green]\n\n"
                f"ID: {vendor.id[:8]}  |  Name: {escape(vendor.name or '')}  |  "
                f"Tier: {tier}  |  Category: {category}\n"
                f"Questionnaire: {'sent' if send_questionnaire else 'skipped'}  |  "
                f"SOC 2: {'requested' if request_soc2 else 'skipped'}",
                border_style="green",
            )
        )
        console.print(
            f"\n[dim]Next: warlock vendor-review assess '{escape(vendor.name or '')}'[/dim]"
        )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Onboarding cancelled.[/dim]")


# ---------------------------------------------------------------------------
# reassess
# ---------------------------------------------------------------------------


@vendor_review.command("reassess")
def vendor_reassess() -> None:
    """Batch vendor reassessment workflow.

    Shows vendors whose reassessment is overdue based on their risk-tier
    cadence, and walks through each one interactively.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    init_db()

    try:
        with get_session() as session:
            now = _utcnow()
            vendors: list = session.query(Vendor).order_by(Vendor.name).all()

            # Determine which are overdue
            overdue: list[tuple] = []
            for v in vendors:
                cadence = v.assessment_cadence_days or _risk_tier_cadence(v.tier)
                if v.last_assessment is None:
                    overdue.append((v, None, cadence))
                else:
                    days_since = (now - ensure_aware(v.last_assessment)).days
                    if days_since >= cadence:
                        overdue.append((v, days_since, cadence))

            if not overdue:
                console.print("[green]All vendors are within their reassessment cadence.[/green]")
                return

            table = Table(title=f"Vendors Due for Reassessment ({len(overdue)})")
            table.add_column("ID", style="dim", max_width=8)
            table.add_column("Name")
            table.add_column("Tier")
            table.add_column("Last Assessment")
            table.add_column("Days Overdue", justify="right")
            table.add_column("Risk Score", justify="right")

            for v, days_since, cadence in overdue:
                last = v.last_assessment.strftime("%Y-%m-%d") if v.last_assessment else "Never"
                overdue_days = str(days_since - cadence) if days_since is not None else "—"
                score_val = f"{v.risk_score:.1f}" if v.risk_score is not None else "—"
                tier_style = _risk_tier_color(v.tier)
                table.add_row(
                    v.id[:8],
                    v.name,
                    f"[{tier_style}]{v.tier or '—'}[/{tier_style}]",
                    last,
                    overdue_days,
                    score_val,
                )

            console.print(table)
            console.print()

            skip_all = False
            for v, days_since, cadence in overdue:
                if skip_all:
                    break

                console.print(
                    f"\n[bold]{v.name}[/bold] "
                    f"(Tier {v.tier or '?'}, "
                    f"last assessed: "
                    f"{v.last_assessment.strftime('%Y-%m-%d') if v.last_assessment else 'never'})"
                )
                if days_since is not None:
                    console.print(
                        f"  [dim]Overdue by {days_since - cadence} days "
                        f"(cadence: every {cadence}d)[/dim]"
                    )
                if v.risk_score is not None:
                    score_color = (
                        "red"
                        if v.risk_score >= 70
                        else ("yellow" if v.risk_score >= 40 else "green")
                    )
                    console.print(
                        f"  Risk score: [{score_color}]{v.risk_score:.1f}[/{score_color}]"
                    )

                choice = Prompt.ask(
                    f"Reassess '{v.name}'?",
                    choices=["y", "n", "skip-all"],
                    default="n",
                    console=console,
                )

                if choice == "skip-all":
                    skip_all = True
                    console.print("[dim]Skipping remaining vendors.[/dim]")
                    break

                if choice == "n":
                    continue

                # Reassess: update date and optionally recalculate score
                new_score_str = Prompt.ask(
                    "New risk score (0-100, or Enter to keep current)",
                    default=str(int(v.risk_score or 0)),
                    console=console,
                )
                try:
                    new_score = float(new_score_str)
                    new_score = max(0.0, min(100.0, new_score))
                except ValueError:
                    new_score = v.risk_score or 0.0

                old_score = v.risk_score
                v.risk_score = new_score
                v.last_assessment = now
                session.commit()

                _write_audit_entry(
                    session,
                    "vendor_reassessed",
                    v.id,
                    {
                        "old_risk_score": old_score,
                        "new_risk_score": new_score,
                        "assessment_date": now.isoformat(),
                    },
                )
                console.print(
                    f"[green]'{v.name}' reassessed. "
                    f"Score: {old_score:.1f} -> {new_score:.1f}[/green]"
                )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Session ended.[/dim]")


# ---------------------------------------------------------------------------
# offboard
# ---------------------------------------------------------------------------


@vendor_review.command("offboard")
@click.argument("vendor_name_or_id")
def vendor_offboard(vendor_name_or_id: str) -> None:
    """Guided vendor offboarding workflow.

    Walks through the offboarding checklist: data return, access revocation,
    and finding resolution. Marks the vendor inactive and records the
    offboarding in the audit trail.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    init_db()

    try:
        with get_session() as session:
            vendor = _resolve_vendor(session, vendor_name_or_id)
            if not vendor:
                _error(f"Vendor not found: '{vendor_name_or_id}'")

            meta = vendor.metadata_ or {}
            if meta.get("offboarded_at"):
                console.print(
                    f"[yellow]Warning: '{escape(vendor.name or '')}' was already offboarded on "
                    f"{meta['offboarded_at']}.[/yellow]"
                )
                if not Confirm.ask("Continue anyway?", default=False, console=console):
                    return

            console.print(
                Panel(
                    f"[bold]{escape(vendor.name or '')}[/bold]\n\n"
                    f"Tier: {vendor.tier or '—'}  |  "
                    f"Contract expires: "
                    f"{vendor.contract_expires.strftime('%Y-%m-%d') if vendor.contract_expires else '—'}  |  "
                    f"Contact: {meta.get('contact', '—')}",
                    title="[bold red]Vendor Offboarding[/bold red]",
                    border_style="red",
                )
            )

            # Active issues check
            open_issues = (
                session.query(Issue)
                .filter(
                    Issue.tags.contains([vendor.name]),
                    Issue.status.notin_(["closed", "verified"]),
                )
                .count()
            )
            if open_issues:
                console.print(
                    f"[yellow]Warning: {open_issues} open issue(s) linked to this vendor.[/yellow]"
                )

            console.print("\n[bold]Offboarding Checklist[/bold]")

            checklist_results: dict[str, bool] = {}

            data_returned = Confirm.ask(
                "Data return requested from vendor?", default=False, console=console
            )
            checklist_results["data_return_requested"] = data_returned

            access_revoked = Confirm.ask(
                "All vendor access revoked?", default=False, console=console
            )
            checklist_results["access_revoked"] = access_revoked

            findings_resolved = Confirm.ask(
                "All linked findings resolved or accepted?",
                default=False,
                console=console,
            )
            checklist_results["findings_resolved"] = findings_resolved

            contracts_closed = Confirm.ask(
                "Contract closed/terminated?", default=False, console=console
            )
            checklist_results["contracts_closed"] = contracts_closed

            incomplete = [k for k, v in checklist_results.items() if not v]
            if incomplete:
                console.print(
                    f"\n[yellow]Incomplete checklist items: {', '.join(incomplete)}[/yellow]"
                )
                if not Confirm.ask(
                    "Proceed with offboarding despite incomplete checklist?",
                    default=False,
                    console=console,
                ):
                    console.print("[dim]Offboarding cancelled.[/dim]")
                    return

            # Mark inactive
            meta_new = dict(meta)
            meta_new["offboarded_at"] = _utcnow().isoformat()
            meta_new["offboarded_by"] = _get_actor()
            meta_new["offboarding_checklist"] = checklist_results
            meta_new["is_active"] = False
            vendor.metadata_ = meta_new
            session.commit()

            _write_audit_entry(
                session,
                "vendor_offboarded",
                vendor.id,
                {
                    "name": vendor.name,
                    "checklist": checklist_results,
                    "offboarded_by": _get_actor(),
                },
            )

            console.print(
                Panel(
                    f"[bold green]{escape(vendor.name or '')} has been offboarded.[/bold green]\n\n"
                    + "\n".join(
                        f"  {'[green]done[/green]' if v else '[red]incomplete[/red]'}  {k}"
                        for k, v in checklist_results.items()
                    ),
                    border_style="green",
                )
            )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Session ended.[/dim]")
