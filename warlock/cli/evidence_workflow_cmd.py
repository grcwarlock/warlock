"""Interactive evidence collection workflow commands.

Top-level commands:

    warlock evidence-sprint <framework>  -- Guided evidence collection sprint
    warlock evidence-collection          -- Interactive evidence collection
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from warlock.cli import _get_actor, cli, console
from warlock.utils import ensure_aware

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_file(path: str) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


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


def _controls_for_framework(session, framework: str) -> list[dict]:
    """Return a list of control dicts with stale/missing evidence for a framework.

    Pulls distinct control IDs from ControlResult and checks PostureSnapshot
    for freshness.  Controls with no snapshot in the last 14 days are flagged.
    """
    from warlock.db.models import ControlResult, PostureSnapshot

    fourteen_days_ago = _utcnow() - timedelta(days=14)

    # All distinct controls for the framework
    rows = (
        session.query(ControlResult.control_id, ControlResult.framework)
        .filter(ControlResult.framework.ilike(framework))
        .distinct()
        .all()
    )

    stale_controls = []
    for row in rows:
        ctrl_id = row.control_id
        # Check if there is a recent posture snapshot
        recent = (
            session.query(PostureSnapshot)
            .filter(
                PostureSnapshot.framework.ilike(framework),
                PostureSnapshot.control_id == ctrl_id,
                PostureSnapshot.snapshot_date >= fourteen_days_ago,
            )
            .first()
        )
        if not recent:
            stale_controls.append({"control_id": ctrl_id, "framework": row.framework})

    return stale_controls


# ---------------------------------------------------------------------------
# warlock evidence-sprint
# ---------------------------------------------------------------------------


@cli.command("evidence-sprint")
@click.argument("framework", required=False, default="nist_800_53")
@click.option(
    "--days",
    "-d",
    default=14,
    show_default=True,
    help="Deadline for evidence requests in days from now.",
)
@click.option(
    "--assignee",
    "-a",
    default=None,
    help="Default assignee for all requests (overrides per-family prompt).",
)
def evidence_sprint(framework: str, days: int, assignee: str | None) -> None:
    """Guided evidence collection sprint for a framework.

    Identifies controls with stale or missing evidence, groups them by control
    family, and creates EvidenceRequest records with assigned owners and deadlines.

    \b
    Examples:
        warlock evidence-sprint nist_800_53
        warlock evidence-sprint soc2 --days 7 --assignee alice@acme.com
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEngagement, EvidenceRequest, ExternalAuditor

    init_db()
    actor = _get_actor()
    deadline = _utcnow() + timedelta(days=days)

    try:
        with get_session() as session:
            console.print(
                Panel(
                    f"[bold]Evidence Collection Sprint[/bold]\n"
                    f"Framework: [bold]{framework}[/bold]  |  "
                    f"Deadline: [yellow]{deadline.strftime('%Y-%m-%d')}[/yellow] "
                    f"({days} days)",
                    title="[bold cyan]warlock evidence-sprint[/bold cyan]",
                    border_style="cyan",
                )
            )

            # Find stale/missing controls
            stale = _controls_for_framework(session, framework)

            if not stale:
                console.print(
                    f"[green]All controls for [bold]{framework}[/bold] have fresh evidence. "
                    f"No sprint needed.[/green]"
                )
                return

            console.print(
                f"\n[bold]{len(stale)}[/bold] control(s) with stale or missing evidence.\n"
            )

            # Group by control family (first component before "-" or first 2 chars)
            families: dict[str, list[dict]] = defaultdict(list)
            for ctrl in stale:
                cid = ctrl["control_id"]
                if "-" in cid:
                    family = cid.split("-")[0]
                elif "." in cid:
                    family = cid.split(".")[0]
                else:
                    family = cid[:2] if len(cid) >= 2 else cid
                families[family].append(ctrl)

            # Get or create a default engagement for this framework
            engagement = (
                session.query(AuditEngagement)
                .filter(
                    AuditEngagement.framework.ilike(framework),
                    AuditEngagement.status == "active",
                )
                .first()
            )
            if not engagement:
                engagement = AuditEngagement(
                    id=str(uuid.uuid4()),
                    name=f"{framework} Evidence Sprint {_utcnow().strftime('%Y-%m')}",
                    framework=framework,
                    period_start=_utcnow(),
                    period_end=deadline,
                    status="active",
                    created_at=_utcnow(),
                )
                session.add(engagement)
                session.flush()

            # Get or create a placeholder auditor record for CLI-submitted requests
            auditor = session.query(ExternalAuditor).filter(ExternalAuditor.email == actor).first()
            if not auditor:
                auditor = ExternalAuditor(
                    id=str(uuid.uuid4()),
                    email=actor,
                    name=actor,
                    firm="Internal",
                    is_active=True,
                    created_at=_utcnow(),
                )
                session.add(auditor)
                session.flush()

            total_requests = 0
            total_controls = 0

            for family, controls in sorted(families.items()):
                console.print()
                ft = Table(
                    title=f"Control Family: [bold]{family}[/bold] ({len(controls)} controls)",
                    show_header=True,
                    header_style="bold",
                )
                ft.add_column("Control ID")
                ft.add_column("Framework")
                for c in controls[:15]:
                    ft.add_row(c["control_id"], c["framework"])
                if len(controls) > 15:
                    ft.add_row(f"... and {len(controls) - 15} more", "")
                console.print(ft)

                if not Confirm.ask(
                    f"Create evidence requests for family [bold]{family}[/bold]?",
                    default=True,
                ):
                    continue

                family_assignee = assignee
                if not family_assignee:
                    family_assignee = Prompt.ask(
                        "Assign to (email or name)",
                        default=actor,
                    )

                # Create one EvidenceRequest per control
                for ctrl in controls:
                    req = EvidenceRequest(
                        id=str(uuid.uuid4()),
                        engagement_id=engagement.id,
                        auditor_id=auditor.id,
                        framework=ctrl["framework"],
                        control_id=ctrl["control_id"],
                        description=(
                            f"Collect current evidence demonstrating compliance with "
                            f"{ctrl['framework']} / {ctrl['control_id']}. "
                            f"Assigned to: {family_assignee}. "
                            f"Deadline: {deadline.strftime('%Y-%m-%d')}."
                        ),
                        status="requested",
                        created_at=_utcnow(),
                        updated_at=_utcnow(),
                    )
                    session.add(req)
                    total_requests += 1
                    total_controls += 1

                session.commit()
                console.print(
                    f"[green]{len(controls)} request(s) created for family {family}.[/green]"
                )

            _write_audit_entry(
                session,
                action="evidence_sprint_created",
                entity_type="audit_engagement",
                entity_id=engagement.id,
                actor=actor,
                extra={
                    "framework": framework,
                    "total_requests": total_requests,
                    "total_controls": total_controls,
                    "deadline": deadline.isoformat(),
                },
            )

            console.print(
                Panel(
                    f"[bold]Sprint Summary[/bold]\n\n"
                    f"[green]{total_requests}[/green] evidence request(s) created covering "
                    f"[green]{total_controls}[/green] control(s)\n"
                    f"Framework: {framework}  |  Deadline: {deadline.strftime('%Y-%m-%d')}\n"
                    f"Engagement ID: {engagement.id[:8]}\n\n"
                    f"Next step: [bold]warlock evidence-collection[/bold]",
                    title="[bold green]Sprint Created[/bold green]",
                    border_style="green",
                )
            )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Evidence sprint cancelled.[/dim]")


# ---------------------------------------------------------------------------
# warlock evidence-collection
# ---------------------------------------------------------------------------


@cli.command("evidence-collection")
@click.option(
    "--framework",
    "-f",
    default=None,
    help="Filter evidence requests to a specific framework.",
)
@click.option(
    "--assignee",
    "-a",
    default=None,
    help="Filter to requests assigned to this person (default: current actor).",
)
def evidence_collection(framework: str | None, assignee: str | None) -> None:
    """Interactive evidence collection: fulfill pending evidence requests.

    Shows pending requests, allows file attachment (with SHA-256 hash), and
    marks each request as fulfilled.

    \b
    Examples:
        warlock evidence-collection
        warlock evidence-collection --framework soc2
        warlock evidence-collection --assignee alice@acme.com
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import EvidenceRequest

    init_db()
    actor = _get_actor()

    try:
        with get_session() as session:
            q = session.query(EvidenceRequest).filter(EvidenceRequest.status == "requested")
            if framework:
                q = q.filter(EvidenceRequest.framework.ilike(framework))

            pending = q.order_by(EvidenceRequest.created_at).limit(50).all()

            if not pending:
                console.print("[green]No pending evidence requests found.[/green]")
                return

            console.print(
                Panel(
                    f"[bold]Evidence Collection[/bold]\n"
                    f"[bold]{len(pending)}[/bold] pending request(s).\n"
                    f"For each request, attach a file or type 'skip' to move on.",
                    title="[bold cyan]warlock evidence-collection[/bold cyan]",
                    border_style="cyan",
                )
            )

            fulfilled = 0

            for idx, req in enumerate(pending, 1):
                console.print()
                due_str = (
                    "—"  # EvidenceRequest has no due_date field — use the engagement period_end
                )
                # Pull from engagement if available
                if req.engagement_id:
                    from warlock.db.models import AuditEngagement

                    eng = (
                        session.query(AuditEngagement)
                        .filter(AuditEngagement.id == req.engagement_id)
                        .first()
                    )
                    if eng and eng.period_end:
                        due_str = ensure_aware(eng.period_end).strftime("%Y-%m-%d")
                        days_left = (ensure_aware(eng.period_end) - _utcnow()).days
                        if days_left < 0:
                            due_str += " [red](OVERDUE)[/red]"
                        elif days_left <= 3:
                            due_str += f" [yellow]({days_left}d left)[/yellow]"
                        else:
                            due_str += f" ({days_left}d left)"

                console.print(
                    Panel(
                        f"[bold]{req.framework} / {req.control_id}[/bold]\n\n"
                        f"Description: {(req.description or '—')[:200]}\n"
                        f"Deadline: {due_str}\n"
                        f"Request ID: {req.id[:8]}",
                        title=f"[bold]Request {idx}/{len(pending)}[/bold]",
                        border_style="yellow",
                    )
                )

                file_input = Prompt.ask(
                    "Attach file path (or 'skip' to skip, 'q' to quit)",
                    default="skip",
                )

                if file_input.strip().lower() == "q":
                    break

                if file_input.strip().lower() in ("skip", "s", ""):
                    continue

                # Validate file path
                file_path = file_input.strip()
                if not os.path.isfile(file_path):
                    console.print(f"[red]File not found: {file_path}[/red]")
                    if not Confirm.ask("Skip this request?", default=True):
                        # Retry
                        file_input = Prompt.ask("Try a different path", default="skip")
                        if file_input.strip().lower() in ("skip", "s", ""):
                            continue
                        file_path = file_input.strip()
                        if not os.path.isfile(file_path):
                            console.print("[red]File still not found. Skipping.[/red]")
                            continue
                    else:
                        continue

                # Compute SHA-256
                try:
                    file_sha = _sha256_file(file_path)
                    file_size = os.path.getsize(file_path)
                    file_name = Path(file_path).name
                except OSError as e:
                    console.print(f"[red]Failed to read file: {e}[/red]")
                    continue

                console.print(
                    f"[dim]File: {file_name}  |  Size: {file_size:,} bytes  |  "
                    f"SHA-256: {file_sha[:16]}...[/dim]"
                )

                notes = Prompt.ask("Fulfillment notes (optional)", default="")

                # Mark as fulfilled
                req.status = "fulfilled"
                req.fulfilled_by = actor
                req.fulfilled_at = _utcnow()
                req.fulfillment_notes = notes.strip() or None
                req.evidence_ids = [file_sha]
                req.updated_at = _utcnow()
                session.commit()

                _write_audit_entry(
                    session,
                    action="evidence_fulfilled",
                    entity_type="evidence_request",
                    entity_id=req.id,
                    actor=actor,
                    extra={
                        "framework": req.framework,
                        "control_id": req.control_id,
                        "file_name": file_name,
                        "file_sha256": file_sha,
                        "file_size": file_size,
                        "notes": notes.strip(),
                    },
                )

                console.print(
                    f"[green]Fulfilled. Evidence hash recorded: {file_sha[:16]}...[/green]"
                )
                fulfilled += 1

            console.print()
            console.print(
                Panel(
                    f"[bold]Collection Session Summary[/bold]\n\n"
                    f"[green]Fulfilled:[/green] {fulfilled}  |  "
                    f"Remaining: {len(pending) - fulfilled}",
                    title="[bold green]Session Complete[/bold green]",
                    border_style="green",
                )
            )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Evidence collection ended.[/dim]")
