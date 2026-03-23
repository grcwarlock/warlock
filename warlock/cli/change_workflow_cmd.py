"""Interactive change advisory board (CAB) workflow commands.

Top-level commands for change management:

    warlock change-review   -- Interactive CAB session (review pending changes)
    warlock change-submit   -- Guided change request submission
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

import click
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from warlock.cli import _error, _get_actor, cli, console  # noqa: F401


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


_CHANGE_TYPES = ("standard", "normal", "emergency")
_IMPACT_LEVELS = ("low", "medium", "high", "critical")

_IMPACT_COLOR: dict[str, str] = {
    "low": "dim",
    "medium": "yellow",
    "high": "red",
    "critical": "red bold",
}


def _write_audit_entry(
    session,
    action: str,
    entity_id: str,
    actor: str,
    extra: dict,
) -> None:
    """Append a hash-chained audit entry for a change management action."""
    from warlock.db.models import AuditEntry

    last = (
        session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
    )
    prev_hash = last.entry_hash if last else "genesis"
    seq = (last.sequence + 1) if last else 1

    payload = json.dumps(
        {"action": action, "entity_id": entity_id, "extra": extra}, sort_keys=True
    )
    entry_hash = hashlib.sha256(f"{prev_hash}:{payload}".encode()).hexdigest()

    entry = AuditEntry(
        id=str(uuid.uuid4()),
        sequence=seq,
        previous_hash=prev_hash,
        entry_hash=entry_hash,
        action=action,
        entity_type="change_event",
        entity_id=entity_id,
        actor=actor,
        extra=extra,
    )
    session.add(entry)
    session.commit()


# ---------------------------------------------------------------------------
# warlock change-review
# ---------------------------------------------------------------------------


@cli.command("change-review")
@click.option(
    "--limit",
    "-n",
    default=20,
    show_default=True,
    help="Max pending changes to review.",
)
def change_review(limit: int) -> None:
    """Interactive Change Advisory Board (CAB) session.

    Displays pending change requests and prompts for approve / reject / defer
    decisions.  Records each decision as an audit entry.

    \b
    Examples:
        warlock change-review
        warlock change-review --limit 10
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ChangeEvent

    init_db()
    actor = _get_actor()

    try:
        with get_session() as session:
            # ChangeEvent doesn't have a 'pending' flag — we treat events
            # from the last 30 days whose source is 'servicenow' or 'itsm'
            # as "pending CAB review" (no status field in the model).
            # We surface them all and let the practitioner decide.
            events = (
                session.query(ChangeEvent)
                .filter(ChangeEvent.source_type == "itsm")
                .order_by(ChangeEvent.occurred_at.desc())
                .limit(limit)
                .all()
            )

            if not events:
                # Fall back to showing all recent change events
                events = (
                    session.query(ChangeEvent)
                    .order_by(ChangeEvent.occurred_at.desc())
                    .limit(limit)
                    .all()
                )

            if not events:
                console.print(
                    "[dim]No change events found. Run the pipeline to ingest change data.[/dim]"
                )
                return

            approved = rejected = deferred = 0

            console.print(
                Panel(
                    f"[bold]Change Advisory Board Session[/bold]\n"
                    f"Reviewing [bold]{len(events)}[/bold] change event(s).\n"
                    f"Decisions: [a]pprove  [r]eject  [d]efer  [s]kip",
                    title="[bold cyan]warlock change-review[/bold cyan]",
                    border_style="cyan",
                )
            )

            for idx, event in enumerate(events, 1):
                console.print()
                detail = event.detail or {}
                impact = detail.get("impact", "unknown")
                impact_style = _IMPACT_COLOR.get(impact.lower(), "white")
                change_type = detail.get("change_type", event.event_type or "unknown")

                console.print(
                    Panel(
                        f"[bold]{detail.get('title', event.action)}[/bold]\n\n"
                        f"Type: {change_type}  |  "
                        f"Impact: [{impact_style}]{impact}[/{impact_style}]  |  "
                        f"Source: {event.source}\n"
                        f"Requester: {event.actor or '—'}  |  "
                        f"Occurred: {event.occurred_at.strftime('%Y-%m-%d %H:%M') if event.occurred_at else '—'}\n"
                        f"Resource: {(event.resource_id or '—')[:60]}\n"
                        f"Description: {detail.get('description', '—')[:120]}",
                        title=f"[bold]Change {idx}/{len(events)} — {event.id[:8]}[/bold]",
                        border_style="yellow",
                    )
                )

                choice = Prompt.ask(
                    "Decision",
                    choices=["a", "r", "d", "s", "q"],
                    default="s",
                    show_choices=False,
                )
                console.print("[dim]  a=approve  r=reject  d=defer  s=skip  q=quit session[/dim]")

                if choice == "q":
                    break

                elif choice == "a":
                    conditions = Prompt.ask("Approval conditions (or blank)", default="")
                    _write_audit_entry(
                        session,
                        action="cab_approved",
                        entity_id=event.id,
                        actor=actor,
                        extra={
                            "change_title": detail.get("title", event.action),
                            "conditions": conditions,
                            "impact": impact,
                        },
                    )
                    console.print("[green]Approved.[/green]")
                    approved += 1

                elif choice == "r":
                    reason = Prompt.ask("Rejection reason")
                    _write_audit_entry(
                        session,
                        action="cab_rejected",
                        entity_id=event.id,
                        actor=actor,
                        extra={
                            "change_title": detail.get("title", event.action),
                            "reason": reason,
                            "impact": impact,
                        },
                    )
                    console.print("[red]Rejected.[/red]")
                    rejected += 1

                elif choice == "d":
                    reason = Prompt.ask("Deferral reason", default="Pending more information")
                    _write_audit_entry(
                        session,
                        action="cab_deferred",
                        entity_id=event.id,
                        actor=actor,
                        extra={
                            "change_title": detail.get("title", event.action),
                            "reason": reason,
                            "impact": impact,
                        },
                    )
                    console.print("[yellow]Deferred.[/yellow]")
                    deferred += 1

                # "s" = skip, no action

            # Session summary
            console.print()
            console.print(
                Panel(
                    f"[bold]CAB Session Summary[/bold]\n\n"
                    f"[green]Approved:[/green] {approved}  |  "
                    f"[red]Rejected:[/red] {rejected}  |  "
                    f"[yellow]Deferred:[/yellow] {deferred}  |  "
                    f"Skipped: {len(events) - approved - rejected - deferred}",
                    title="[bold green]Session Complete[/bold green]",
                    border_style="green",
                )
            )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]CAB session ended.[/dim]")


# ---------------------------------------------------------------------------
# warlock change-submit
# ---------------------------------------------------------------------------


@cli.command("change-submit")
def change_submit() -> None:
    """Guided change request submission workflow.

    Prompts for change type, impact, affected systems, and creates a
    ChangeEvent record.  Emergency changes are automatically flagged for
    post-hoc review.

    \b
    Examples:
        warlock change-submit
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ChangeEvent, SystemProfile

    init_db()
    actor = _get_actor()

    try:
        console.print(
            Panel(
                "[bold]Change Request Submission[/bold]\n"
                "Creates a formal change request for CAB review.",
                title="[bold cyan]warlock change-submit[/bold cyan]",
                border_style="cyan",
            )
        )

        # --- Step 1: Change metadata ---
        console.print("\n[bold]Step 1 of 4: Change Metadata[/bold]")
        change_type = Prompt.ask(
            "Change type",
            choices=list(_CHANGE_TYPES),
            default="normal",
        )
        title = Prompt.ask("Change title")
        if not title.strip():
            _error("Change title is required.")
        description = Prompt.ask("Description", default="")

        # --- Step 2: Impact ---
        console.print("\n[bold]Step 2 of 4: Impact Assessment[/bold]")
        impact = Prompt.ask(
            "Impact level",
            choices=list(_IMPACT_LEVELS),
            default="low",
        )

        # --- Step 3: Affected systems ---
        console.print("\n[bold]Step 3 of 4: Affected Systems[/bold]")
        affected_systems: list[str] = []
        with get_session() as session:
            systems = (
                session.query(SystemProfile)
                .filter(SystemProfile.is_active == True)  # noqa: E712
                .order_by(SystemProfile.name)
                .limit(20)
                .all()
            )

        if systems:
            t = Table(show_header=True, header_style="bold")
            t.add_column("#")
            t.add_column("Name")
            t.add_column("Acronym")
            t.add_column("Impact Level")
            for idx, s in enumerate(systems, 1):
                t.add_row(str(idx), s.name, s.acronym or "—", s.overall_impact or "—")
            console.print(t)
            raw = Prompt.ask(
                "Affected system numbers (comma-separated, or blank)", default=""
            )
            if raw.strip():
                for part in raw.split(","):
                    part = part.strip()
                    if part.isdigit():
                        i = int(part) - 1
                        if 0 <= i < len(systems):
                            affected_systems.append(systems[i].name)
        else:
            manual = Prompt.ask("Affected system names (comma-separated, or blank)", default="")
            if manual.strip():
                affected_systems = [s.strip() for s in manual.split(",") if s.strip()]

        # --- Step 4: Emergency justification ---
        justification = ""
        post_hoc_review = False
        if change_type == "emergency":
            console.print("\n[bold]Step 4 of 4: Emergency Justification[/bold]")
            console.print("[yellow]Emergency changes require post-hoc CAB review.[/yellow]")
            justification = Prompt.ask("Business justification for emergency change")
            post_hoc_review = True
        else:
            console.print("\n[bold]Step 4 of 4: Review[/bold]")

        # Summary before creation
        impact_style = _IMPACT_COLOR.get(impact, "white")
        console.print(
            Panel(
                f"[bold]{title}[/bold]\n\n"
                f"Type: [bold]{change_type}[/bold]  |  "
                f"Impact: [{impact_style}]{impact}[/{impact_style}]\n"
                f"Affected systems: {', '.join(affected_systems) or '—'}\n"
                f"Description: {description or '—'}"
                + (f"\nJustification: {justification}" if justification else "")
                + (
                    "\n[yellow]Post-hoc review required.[/yellow]"
                    if post_hoc_review
                    else ""
                ),
                title="[bold]Change Request Summary[/bold]",
                border_style="yellow",
            )
        )

        if not Confirm.ask("Create this change request?", default=True):
            console.print("[dim]Cancelled.[/dim]")
            return

        with get_session() as session:
            import hashlib as _hl

            change_id = str(uuid.uuid4())
            payload_str = json.dumps(
                {
                    "id": change_id,
                    "title": title,
                    "actor": actor,
                    "occurred_at": _utcnow().isoformat(),
                },
                sort_keys=True,
            )
            sha = _hl.sha256(payload_str.encode()).hexdigest()

            event = ChangeEvent(
                id=change_id,
                source="warlock_cli",
                source_type="itsm",
                event_type="change_request",
                actor=actor,
                action=title.strip(),
                resource_type="change_request",
                detail={
                    "title": title.strip(),
                    "description": description.strip(),
                    "change_type": change_type,
                    "impact": impact,
                    "affected_systems": affected_systems,
                    "justification": justification,
                    "post_hoc_review": post_hoc_review,
                    "submitted_by": actor,
                },
                occurred_at=_utcnow(),
                ingested_at=_utcnow(),
                sha256=sha,
            )
            session.add(event)
            session.commit()

            _write_audit_entry(
                session,
                action="change_submitted",
                entity_id=change_id,
                actor=actor,
                extra={
                    "title": title.strip(),
                    "change_type": change_type,
                    "impact": impact,
                    "post_hoc_review": post_hoc_review,
                },
            )

        console.print(
            Panel(
                f"[green]Change request created.[/green]\n\n"
                f"ID: [bold]{change_id}[/bold]\n"
                f"Next step: CAB review via [bold]warlock change-review[/bold]"
                + (
                    "\n[yellow]Remember: post-hoc CAB review is required for this emergency change.[/yellow]"
                    if post_hoc_review
                    else ""
                ),
                title="[bold green]Submitted[/bold green]",
                border_style="green",
            )
        )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Submission cancelled.[/dim]")
