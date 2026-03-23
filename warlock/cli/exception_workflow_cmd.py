"""Interactive exception review workflow command.

Top-level command:

    warlock exception-review  -- Review expiring policy exceptions (RiskAcceptances)
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import click
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from warlock.cli import _get_actor, cli, console


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _write_audit_entry(
    session,
    action: str,
    entity_type: str,
    entity_id: str,
    actor: str,
    extra: dict,
) -> None:
    """Append a hash-chained audit entry."""
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
        entity_type=entity_type,
        entity_id=entity_id,
        actor=actor,
        extra=extra,
    )
    session.add(entry)
    session.commit()


# ---------------------------------------------------------------------------
# warlock exception-review
# ---------------------------------------------------------------------------


@cli.command("exception-review")
@click.option(
    "--days",
    "-d",
    default=30,
    show_default=True,
    help="Look-ahead window in days for expiring exceptions.",
)
def exception_review(days: int) -> None:
    """Review policy exceptions (risk acceptances) expiring within N days.

    For each expiring exception, prompts for renew or revoke decisions.
    Revoked exceptions generate a remediation issue.

    \b
    Examples:
        warlock exception-review
        warlock exception-review --days 60
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue, RiskAcceptance

    init_db()
    actor = _get_actor()

    try:
        with get_session() as session:
            cutoff = _utcnow() + timedelta(days=days)
            exceptions = (
                session.query(RiskAcceptance)
                .filter(
                    RiskAcceptance.expiry_date <= cutoff,
                    RiskAcceptance.expiry_date >= _utcnow(),
                    RiskAcceptance.status.in_(["active", "approved"]),
                )
                .order_by(RiskAcceptance.expiry_date)
                .all()
            )

            if not exceptions:
                console.print(f"[green]No exceptions expiring in the next {days} days.[/green]")
                return

            console.print(
                Panel(
                    f"[bold]Exception Review[/bold]\n"
                    f"[yellow]{len(exceptions)}[/yellow] exception(s) expiring within "
                    f"[bold]{days}[/bold] days.\n"
                    f"Decisions: [r]enew  [re]voke  [s]kip  [q]uit",
                    title="[bold cyan]warlock exception-review[/bold cyan]",
                    border_style="cyan",
                )
            )

            renewed = revoked = 0

            for idx, exc in enumerate(exceptions, 1):
                console.print()
                days_left = (exc.expiry_date - _utcnow()).days if exc.expiry_date else 0
                expiry_str = exc.expiry_date.strftime("%Y-%m-%d") if exc.expiry_date else "—"
                risk_color = {
                    "critical": "red bold",
                    "high": "red",
                    "moderate": "yellow",
                    "low": "dim",
                }.get((exc.risk_level or "").lower(), "white")

                console.print(
                    Panel(
                        f"[bold]{exc.framework} / {exc.control_id}[/bold]\n\n"
                        f"Risk level: [{risk_color}]{exc.risk_level or '—'}[/{risk_color}]  |  "
                        f"Expires: [yellow]{expiry_str}[/yellow] ([bold]{days_left}[/bold] days)\n"
                        f"Requested by: {exc.requested_by or '—'}  |  "
                        f"Approved by: {exc.approved_by or '—'}\n"
                        f"Risk: {(exc.risk_description or '—')[:120]}\n"
                        f"Residual risk: {exc.residual_risk_level or '—'}",
                        title=f"[bold]Exception {idx}/{len(exceptions)} — {exc.id[:8]}[/bold]",
                        border_style="yellow",
                    )
                )

                # Show compensating controls if conditions present
                conditions = exc.conditions or []
                if conditions:
                    ct = Table(title="Conditions", show_header=True, header_style="bold dim")
                    ct.add_column("Condition")
                    ct.add_column("Met")
                    for cond in conditions:
                        met = cond.get("met", False)
                        ct.add_row(
                            cond.get("condition", "—"),
                            "[green]Yes[/green]" if met else "[red]No[/red]",
                        )
                    console.print(ct)

                choice = Prompt.ask(
                    "Decision",
                    choices=["r", "re", "s", "q"],
                    default="s",
                    show_choices=False,
                )
                console.print("[dim]  r=renew  re=revoke  s=skip  q=quit[/dim]")

                if choice == "q":
                    break

                elif choice == "r":
                    new_justification = Prompt.ask(
                        "New justification", default=exc.risk_description or ""
                    )
                    ext_days = Prompt.ask("Extend by how many days?", default="90")
                    try:
                        ext = int(ext_days)
                    except ValueError:
                        ext = 90
                    new_expiry = _utcnow() + timedelta(days=ext)
                    exc.expiry_date = new_expiry
                    exc.risk_description = new_justification
                    exc.updated_at = _utcnow()
                    session.commit()
                    _write_audit_entry(
                        session,
                        action="exception_renewed",
                        entity_type="risk_acceptance",
                        entity_id=exc.id,
                        actor=actor,
                        extra={
                            "framework": exc.framework,
                            "control_id": exc.control_id,
                            "new_expiry": new_expiry.isoformat(),
                            "extended_days": ext,
                        },
                    )
                    console.print(
                        f"[green]Renewed until {new_expiry.strftime('%Y-%m-%d')}.[/green]"
                    )
                    renewed += 1

                elif choice == "re":
                    remediation_plan = Prompt.ask("Remediation plan")
                    exc.status = "revoked"
                    exc.updated_at = _utcnow()
                    session.commit()

                    # Create an issue for remediation tracking
                    issue_id = str(uuid.uuid4())
                    issue = Issue(
                        id=issue_id,
                        title=f"Revoked exception: {exc.framework}/{exc.control_id}",
                        description=(
                            f"Policy exception {exc.id[:8]} was revoked during exception review. "
                            f"Remediation required.\n\nOriginal risk: {exc.risk_description or '—'}"
                        ),
                        framework=exc.framework,
                        control_id=exc.control_id,
                        status="open",
                        priority="high",
                        remediation_plan=remediation_plan,
                        source="manual",
                        created_by=actor,
                        created_at=_utcnow(),
                        updated_at=_utcnow(),
                    )
                    session.add(issue)
                    session.commit()

                    _write_audit_entry(
                        session,
                        action="exception_revoked",
                        entity_type="risk_acceptance",
                        entity_id=exc.id,
                        actor=actor,
                        extra={
                            "framework": exc.framework,
                            "control_id": exc.control_id,
                            "remediation_issue_id": issue_id,
                            "remediation_plan": remediation_plan,
                        },
                    )
                    console.print(f"[red]Revoked.[/red] Remediation issue created: {issue_id[:8]}")
                    revoked += 1

                # "s" = skip

            console.print()
            console.print(
                Panel(
                    f"[bold]Exception Review Summary[/bold]\n\n"
                    f"[green]Renewed:[/green] {renewed}  |  "
                    f"[red]Revoked:[/red] {revoked}  |  "
                    f"Skipped: {len(exceptions) - renewed - revoked}",
                    title="[bold green]Review Complete[/bold green]",
                    border_style="green",
                )
            )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Exception review ended.[/dim]")
