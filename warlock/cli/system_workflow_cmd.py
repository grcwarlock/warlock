"""Interactive system authorization workflow commands.

Top-level and group commands for managing system security authorization:

    warlock onboard-system      -- Guided system authorization workflow
    warlock system-review <id>  -- Interactive system security review
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

from warlock.cli import _error, _get_actor, cli, console


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


_IMPACT_LEVELS = ("low", "moderate", "high")

_IMPACT_CONTROLS: dict[str, list[str]] = {
    "low": ["AC-2", "AC-3", "AU-2", "CA-7", "CM-2", "IA-2", "IR-4", "SC-7", "SI-2"],
    "moderate": [
        "AC-2",
        "AC-3",
        "AC-6",
        "AU-2",
        "AU-9",
        "CA-7",
        "CM-2",
        "CM-6",
        "IA-2",
        "IA-5",
        "IR-4",
        "IR-6",
        "PE-2",
        "SC-7",
        "SC-28",
        "SI-2",
        "SI-3",
    ],
    "high": [
        "AC-2",
        "AC-3",
        "AC-6",
        "AC-17",
        "AU-2",
        "AU-9",
        "AU-12",
        "CA-2",
        "CA-7",
        "CM-2",
        "CM-6",
        "CM-7",
        "IA-2",
        "IA-5",
        "IA-8",
        "IR-4",
        "IR-6",
        "PE-2",
        "PE-3",
        "SC-7",
        "SC-8",
        "SC-28",
        "SI-2",
        "SI-3",
        "SI-7",
    ],
}


def _overall_impact(c: str, i: str, a: str) -> str:
    """Calculate FIPS 199 overall impact as the highest of the three values."""
    rank = {"low": 0, "moderate": 1, "high": 2}
    best = max(c, i, a, key=lambda v: rank.get(v.lower(), 0))
    return best.lower()


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
        entity_type=entity_type,
        entity_id=entity_id,
        actor=actor,
        extra=extra,
    )
    session.add(entry)
    session.commit()


# ---------------------------------------------------------------------------
# warlock onboard-system
# ---------------------------------------------------------------------------


@cli.command("onboard-system")
def onboard_system() -> None:
    """Guided system authorization (ATO) onboarding workflow.

    Walks through FIPS 199 security categorization, responsible parties,
    dependency mapping, and recommended control baseline selection.

    \b
    Examples:
        warlock onboard-system
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SystemDependency, SystemProfile

    init_db()
    actor = _get_actor()

    console.print(
        Panel(
            "[bold]System Authorization Onboarding[/bold]\n"
            "This wizard creates a SystemProfile and calculates your\n"
            "FIPS 199 impact level and recommended NIST 800-53 control baseline.",
            title="[bold cyan]warlock onboard-system[/bold cyan]",
            border_style="cyan",
        )
    )

    try:
        # --- Step 1: System identity ---
        console.print("\n[bold]Step 1 of 5: System Identity[/bold]")
        name = Prompt.ask("System name")
        if not name.strip():
            _error("System name is required.")
        acronym = Prompt.ask("Acronym (e.g. WGRC)", default="")
        description = Prompt.ask("Brief description", default="")

        # --- Step 2: FIPS 199 categorization ---
        console.print("\n[bold]Step 2 of 5: FIPS 199 Security Categorization[/bold]")
        console.print("[dim]Values: low / moderate / high[/dim]")

        confidentiality = Prompt.ask(
            "Confidentiality impact", choices=list(_IMPACT_LEVELS), default="moderate"
        )
        integrity = Prompt.ask(
            "Integrity impact", choices=list(_IMPACT_LEVELS), default="moderate"
        )
        availability = Prompt.ask(
            "Availability impact", choices=list(_IMPACT_LEVELS), default="moderate"
        )
        overall = _overall_impact(confidentiality, integrity, availability)
        console.print(
            f"\nOverall impact level: [bold yellow]{overall.upper()}[/bold yellow]"
        )

        # --- Step 3: Responsible parties ---
        console.print("\n[bold]Step 3 of 5: Responsible Parties[/bold]")
        system_owner = Prompt.ask("System owner name")
        system_owner_email = Prompt.ask("System owner email", default="")
        isso = Prompt.ask("ISSO (Information System Security Officer)", default="")
        isso_email = Prompt.ask("ISSO email", default="")

        # --- Step 4: Recommended controls ---
        console.print("\n[bold]Step 4 of 5: Recommended Control Baseline[/bold]")
        recommended = _IMPACT_CONTROLS.get(overall, _IMPACT_CONTROLS["moderate"])
        console.print(
            f"For a [bold]{overall.upper()}[/bold] system, the recommended NIST 800-53 "
            f"baseline includes [bold]{len(recommended)}[/bold] priority controls:\n"
        )
        console.print("  " + "  ".join(recommended))

        # --- Step 5: Dependency mapping ---
        console.print("\n[bold]Step 5 of 5: System Dependencies[/bold]")
        dep_ids: list[str] = []
        with get_session() as session:
            existing_systems = (
                session.query(SystemProfile)
                .filter(SystemProfile.is_active == True)  # noqa: E712
                .order_by(SystemProfile.name)
                .limit(20)
                .all()
            )

        if existing_systems and Confirm.ask(
            "Map dependencies to existing systems?", default=False
        ):
            t = Table(show_header=True, header_style="bold")
            t.add_column("#")
            t.add_column("Name")
            t.add_column("Acronym")
            t.add_column("Impact")
            for idx, sp in enumerate(existing_systems, 1):
                t.add_row(
                    str(idx),
                    sp.name,
                    sp.acronym or "—",
                    sp.overall_impact or "—",
                )
            console.print(t)

            raw = Prompt.ask(
                "Enter dependency numbers (comma-separated, or blank to skip)",
                default="",
            )
            if raw.strip():
                for part in raw.split(","):
                    part = part.strip()
                    if part.isdigit():
                        idx = int(part) - 1
                        if 0 <= idx < len(existing_systems):
                            dep_ids.append(existing_systems[idx].id)

        # --- Create records ---
        with get_session() as session:
            sp = SystemProfile(
                id=str(uuid.uuid4()),
                name=name.strip(),
                acronym=acronym.strip() or None,
                description=description.strip() or None,
                confidentiality_impact=confidentiality,
                integrity_impact=integrity,
                availability_impact=availability,
                overall_impact=overall,
                system_owner=system_owner.strip() or None,
                system_owner_email=system_owner_email.strip() or None,
                isso=isso.strip() or None,
                isso_email=isso_email.strip() or None,
                authorization_status="not_authorized",
                is_active=True,
                created_at=_utcnow(),
                updated_at=_utcnow(),
            )
            session.add(sp)
            session.flush()

            for provider_id in dep_ids:
                dep = SystemDependency(
                    id=str(uuid.uuid4()),
                    consumer_system_id=sp.id,
                    provider_system_id=provider_id,
                    dependency_type="infrastructure",
                    description="Dependency set during onboarding",
                    created_at=_utcnow(),
                )
                session.add(dep)

            session.commit()

            _write_audit_entry(
                session,
                action="system_onboarded",
                entity_type="system_profile",
                entity_id=sp.id,
                actor=actor,
                extra={
                    "name": sp.name,
                    "overall_impact": overall,
                    "dependencies": dep_ids,
                },
            )

            console.print(
                Panel(
                    f"[green]System profile created.[/green]\n\n"
                    f"ID: [bold]{sp.id}[/bold]\n"
                    f"Name: {sp.name}  |  Acronym: {sp.acronym or '—'}\n"
                    f"Impact: [bold yellow]{overall.upper()}[/bold yellow]  |  "
                    f"Controls recommended: {len(recommended)}\n"
                    f"Dependencies linked: {len(dep_ids)}",
                    title="[bold green]Onboarding Complete[/bold green]",
                    border_style="green",
                )
            )
            console.print(
                "\n[bold]Next steps:[/bold]\n"
                "  1. Assign controls:       warlock system-review " + sp.id[:8] + "\n"
                "  2. Schedule ATO review:   warlock calendar add-event\n"
                "  3. Run pipeline:          warlock run\n"
            )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Onboarding cancelled.[/dim]")


# ---------------------------------------------------------------------------
# warlock system-review
# ---------------------------------------------------------------------------


@cli.command("system-review")
@click.argument("system_id")
def system_review(system_id: str) -> None:
    """Interactive system security review.

    Displays compliance posture, dependencies, personnel, and ATO status
    for the specified system, then offers an interactive action menu.

    \b
    Examples:
        warlock system-review <system-id-or-acronym>
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        ControlResult,
        Personnel,
        SystemDependency,
        SystemProfile,
    )

    init_db()

    try:
        with get_session() as session:
            from warlock.cli import _resolve_system_id

            resolved_id = _resolve_system_id(session, system_id)
            sp = (
                session.query(SystemProfile)
                .filter(SystemProfile.id == resolved_id)
                .first()
            )
            if not sp:
                _error(f"System not found: '{system_id}'")

            while True:
                console.print()

                # --- Profile panel ---
                auth_color = {
                    "authorized": "green",
                    "in_process": "yellow",
                    "not_authorized": "red",
                    "denied": "red bold",
                    "revoked": "red bold",
                }.get(sp.authorization_status or "", "white")

                auth_expiry = (
                    sp.authorization_expiry.strftime("%Y-%m-%d")
                    if sp.authorization_expiry
                    else "—"
                )
                auth_date = (
                    sp.authorization_date.strftime("%Y-%m-%d")
                    if sp.authorization_date
                    else "—"
                )

                console.print(
                    Panel(
                        f"[bold]{sp.name}[/bold]"
                        + (f" ({sp.acronym})" if sp.acronym else "")
                        + f"\n\n{sp.description or '(no description)'}\n\n"
                        f"Impact: [bold yellow]{(sp.overall_impact or '—').upper()}[/bold yellow]  |  "
                        f"Status: [{auth_color}]{sp.authorization_status or '—'}[/{auth_color}]\n"
                        f"ATO Date: {auth_date}  |  ATO Expiry: {auth_expiry}\n"
                        f"System Owner: {sp.system_owner or '—'}  |  ISSO: {sp.isso or '—'}",
                        title=f"[bold cyan]System: {sp.id[:8]}[/bold cyan]",
                        border_style="cyan",
                    )
                )

                # --- Compliance posture ---
                results = (
                    session.query(ControlResult)
                    .filter(ControlResult.system_profile_id == sp.id)
                    .all()
                )
                total = len(results)
                if total:
                    compliant = sum(1 for r in results if r.status == "compliant")
                    non_compliant = sum(
                        1 for r in results if r.status == "non_compliant"
                    )
                    pct = (compliant / total * 100) if total else 0.0
                    pct_color = "green" if pct >= 80 else ("yellow" if pct >= 60 else "red")
                    console.print(
                        f"\n[bold]Compliance Posture:[/bold] "
                        f"[{pct_color}]{pct:.1f}%[/{pct_color}] compliant "
                        f"({compliant}/{total})  |  Non-compliant: {non_compliant}"
                    )
                else:
                    console.print(
                        "\n[dim]No control results scoped to this system yet.[/dim]"
                    )

                # --- Dependencies ---
                deps_out = (
                    session.query(SystemDependency)
                    .filter(SystemDependency.consumer_system_id == sp.id)
                    .all()
                )
                deps_in = (
                    session.query(SystemDependency)
                    .filter(SystemDependency.provider_system_id == sp.id)
                    .all()
                )
                if deps_out or deps_in:
                    console.print(
                        f"\n[bold]Dependencies:[/bold] "
                        f"Upstream (provides to): {len(deps_in)}  |  "
                        f"Downstream (depends on): {len(deps_out)}"
                    )

                # --- Personnel ---
                personnel = (
                    session.query(Personnel)
                    .filter(Personnel.is_active == True)  # noqa: E712
                    .limit(5)
                    .all()
                )
                if personnel:
                    console.print(
                        f"\n[bold]Active Personnel (sample):[/bold] "
                        + ", ".join(p.full_name for p in personnel[:5])
                    )

                # --- Action menu ---
                console.print()
                choice = Prompt.ask(
                    "Actions",
                    choices=["u", "a", "r", "q"],
                    default="q",
                    show_choices=False,
                )
                console.print(
                    "[dim]  u=update profile  a=add dependency  r=review controls  q=quit[/dim]"
                )

                if choice == "q":
                    break

                elif choice == "u":
                    new_status = Prompt.ask(
                        "Authorization status",
                        choices=[
                            "not_authorized",
                            "in_process",
                            "authorized",
                            "denied",
                            "revoked",
                        ],
                        default=sp.authorization_status or "not_authorized",
                    )
                    sp.authorization_status = new_status
                    sp.updated_at = _utcnow()
                    session.commit()
                    console.print(
                        f"[green]Authorization status updated to: {new_status}[/green]"
                    )

                elif choice == "a":
                    all_systems = (
                        session.query(SystemProfile)
                        .filter(
                            SystemProfile.is_active == True,  # noqa: E712
                            SystemProfile.id != sp.id,
                        )
                        .order_by(SystemProfile.name)
                        .limit(20)
                        .all()
                    )
                    if not all_systems:
                        console.print("[dim]No other systems to link.[/dim]")
                    else:
                        t = Table(show_header=True, header_style="bold")
                        t.add_column("#")
                        t.add_column("Name")
                        t.add_column("Acronym")
                        for idx, s in enumerate(all_systems, 1):
                            t.add_row(str(idx), s.name, s.acronym or "—")
                        console.print(t)
                        raw = Prompt.ask("Provider system number", default="")
                        if raw.strip().isdigit():
                            idx = int(raw.strip()) - 1
                            if 0 <= idx < len(all_systems):
                                dep_type = Prompt.ask(
                                    "Dependency type",
                                    choices=["infrastructure", "identity", "network", "application"],
                                    default="infrastructure",
                                )
                                new_dep = SystemDependency(
                                    id=str(uuid.uuid4()),
                                    consumer_system_id=sp.id,
                                    provider_system_id=all_systems[idx].id,
                                    dependency_type=dep_type,
                                    description="Added via system-review workflow",
                                    created_at=_utcnow(),
                                )
                                session.add(new_dep)
                                session.commit()
                                console.print(
                                    f"[green]Dependency linked: {all_systems[idx].name}[/green]"
                                )

                elif choice == "r":
                    if not results:
                        console.print("[dim]No control results to review.[/dim]")
                    else:
                        rt = Table(title="Control Results (non-compliant)", show_header=True)
                        rt.add_column("Framework")
                        rt.add_column("Control ID")
                        rt.add_column("Status")
                        rt.add_column("Severity")
                        nc = [r for r in results if r.status == "non_compliant"][:20]
                        for r in nc:
                            rt.add_row(
                                r.framework,
                                r.control_id,
                                f"[red]{r.status}[/red]",
                                r.severity or "—",
                            )
                        console.print(rt)

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Session ended.[/dim]")
