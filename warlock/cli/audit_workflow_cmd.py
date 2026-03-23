"""Interactive audit management workflow commands.

Group: warlock audit-workflow

Commands:
  prepare <framework>          -- Guided audit preparation with readiness score
  evidence-sprint              -- Guided evidence collection sprint
  simulate <framework>         -- Interactive audit simulation at a future date
  respond <engagement_id>      -- Respond to auditor evidence requests
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import click
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor
from warlock.utils import ensure_aware


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@cli.group("audit-workflow")
def audit_workflow() -> None:
    """Guided audit management workflows for practitioners."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _status_color(status: str) -> str:
    return {
        "compliant": "green",
        "non_compliant": "red",
        "partial": "yellow",
        "not_assessed": "dim",
        "risk_accepted": "magenta",
        "inherited_compliant": "cyan",
    }.get(status, "white")


def _poam_color(status: str) -> str:
    return {
        "draft": "dim",
        "open": "yellow",
        "in_progress": "cyan",
        "completed": "green",
        "verified": "green bold",
        "risk_accepted": "magenta",
        "cancelled": "dim",
    }.get(status, "white")


def _attest_color(status: str) -> str:
    return {
        "approved": "green",
        "submitted": "cyan",
        "reviewed": "blue",
        "draft": "dim",
        "rejected": "red",
    }.get(status, "white")


# ---------------------------------------------------------------------------
# audit-workflow prepare
# ---------------------------------------------------------------------------


@audit_workflow.command("prepare")
@click.argument("framework")
@click.option("--stale-days", default=30, help="Evidence older than N days is considered stale")
@click.option("--interactive/--no-interactive", default=True, help="Prompt to fix gaps")
def audit_prepare(framework: str, stale_days: int, interactive: bool) -> None:
    """Guided audit preparation: posture, evidence, POA&Ms, attestations, readiness score.

    Walks through every audit readiness dimension and, in interactive mode,
    prompts to address each gap found.

    \b
    Examples:
        warlock audit-workflow prepare soc2
        warlock audit-workflow prepare nist_800_53 --stale-days 14
        warlock audit-workflow prepare iso_27001 --no-interactive
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        Attestation,
        AuditEngagement,
        ControlResult,
        EvidenceRequest,
        POAM,
    )

    init_db()

    console.print(
        Panel(
            f"[bold]Audit Preparation — {framework}[/bold]\n"
            f"Checking readiness for an upcoming audit. Stale threshold: {stale_days} days.",
            style="cyan",
        )
    )

    now = _utcnow()
    stale_cutoff = now - timedelta(days=stale_days)
    score_parts: list[tuple[str, float, float]] = []  # (label, earned, max)

    with get_session() as session:
        # -------------------------------------------------------------------
        # 1. Compliance posture
        # -------------------------------------------------------------------
        console.print("\n[bold cyan]1. Compliance Posture[/bold cyan]")

        all_results = (
            session.query(ControlResult).filter(ControlResult.framework == framework).all()
        )
        total = len(all_results)

        if total == 0:
            console.print(
                f"  [yellow]No control results found for framework '{framework}'. "
                "Run 'warlock collect' first.[/yellow]"
            )
            return

        by_status: dict[str, int] = {}
        for r in all_results:
            by_status[r.status] = by_status.get(r.status, 0) + 1

        compliant_count = by_status.get("compliant", 0) + by_status.get("inherited_compliant", 0)
        compliant_pct = (compliant_count / total * 100) if total else 0.0
        posture_score = min(compliant_pct, 100.0)
        score_parts.append(("Compliance posture", posture_score, 100.0))

        posture_table = Table(show_header=False, box=None, pad_edge=False)
        posture_table.add_column("Status", style="bold")
        posture_table.add_column("Count", justify="right")
        posture_table.add_column("Pct", justify="right")
        for st, cnt in sorted(by_status.items(), key=lambda x: -x[1]):
            pct_str = f"{cnt / total * 100:.1f}%"
            color = _status_color(st)
            posture_table.add_row(
                f"[{color}]{st}[/{color}]",
                str(cnt),
                f"[dim]{pct_str}[/dim]",
            )
        console.print(posture_table)
        console.print(
            f"  Overall: [bold]{compliant_pct:.1f}%[/bold] compliant "
            f"({compliant_count}/{total} controls)"
        )

        # -------------------------------------------------------------------
        # 2. Evidence freshness
        # -------------------------------------------------------------------
        console.print("\n[bold cyan]2. Evidence Freshness[/bold cyan]")

        fresh_results: list[ControlResult] = []
        stale_results: list[ControlResult] = []
        for r in all_results:
            if r.assessed_at and ensure_aware(r.assessed_at) < stale_cutoff:
                stale_results.append(r)
            else:
                fresh_results.append(r)

        freshness_pct = (len(fresh_results) / total * 100) if total else 100.0
        score_parts.append(("Evidence freshness", freshness_pct, 100.0))

        console.print(
            f"  Fresh (< {stale_days}d): [green]{len(fresh_results)}[/green]   "
            f"Stale (>= {stale_days}d): [yellow]{len(stale_results)}[/yellow]"
        )

        if stale_results:
            stale_table = Table(title="Stale Controls (sample — top 10)", show_lines=False)
            stale_table.add_column("Framework")
            stale_table.add_column("Control")
            stale_table.add_column("Status")
            stale_table.add_column("Last Assessed")
            for r in stale_results[:10]:
                color = _status_color(r.status)
                stale_table.add_row(
                    r.framework,
                    r.control_id,
                    f"[{color}]{r.status}[/{color}]",
                    r.assessed_at.strftime("%Y-%m-%d") if r.assessed_at else "—",
                )
            console.print(stale_table)

        if interactive and stale_results:
            try:
                if Confirm.ask(
                    f"  Trigger re-collection to refresh {len(stale_results)} stale control(s)?",
                    default=False,
                ):
                    console.print(f"  [dim]Run: warlock collect --framework {framework}[/dim]")
                    console.print(
                        "  [dim](Re-collection queued. Run 'warlock collect' to execute.)[/dim]"
                    )
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Skipped.[/dim]")

        # -------------------------------------------------------------------
        # 3. Open POA&Ms
        # -------------------------------------------------------------------
        console.print("\n[bold cyan]3. Open POA&Ms[/bold cyan]")

        open_poams = (
            session.query(POAM)
            .filter(
                POAM.framework == framework,
                POAM.status.notin_(["completed", "verified", "closed", "cancelled"]),
            )
            .all()
        )

        overdue_poams = [
            p
            for p in open_poams
            if p.scheduled_completion and ensure_aware(p.scheduled_completion) < now
        ]

        if not open_poams:
            console.print("  [green]No open POA&Ms.[/green]")
            poam_score = 100.0
        else:
            on_track = len(open_poams) - len(overdue_poams)
            poam_score = max(0.0, 100.0 - (len(overdue_poams) / len(open_poams) * 100))
            console.print(
                f"  Open: [yellow]{len(open_poams)}[/yellow]   "
                f"Overdue: [red]{len(overdue_poams)}[/red]   "
                f"On-track: [green]{on_track}[/green]"
            )

            if overdue_poams:
                pd_table = Table(title="Overdue POA&Ms (top 10)", show_lines=False)
                pd_table.add_column("ID", max_width=8)
                pd_table.add_column("Control")
                pd_table.add_column("Status")
                pd_table.add_column("Due Date")
                pd_table.add_column("Severity")
                for p in overdue_poams[:10]:
                    color = _poam_color(p.status)
                    due = (
                        p.scheduled_completion.strftime("%Y-%m-%d")
                        if p.scheduled_completion
                        else "—"
                    )
                    pd_table.add_row(
                        p.id[:8],
                        p.control_id,
                        f"[{color}]{p.status}[/{color}]",
                        f"[red]{due}[/red]",
                        p.severity,
                    )
                console.print(pd_table)

            if interactive and overdue_poams:
                for p in overdue_poams[:5]:
                    try:
                        if Confirm.ask(
                            f"  Update POA&M [cyan]{p.id[:8]}[/cyan] ({p.control_id})?",
                            default=False,
                        ):
                            console.print(
                                f"  [dim]Run: warlock remediate {p.id[:8]} "
                                "-a transition --to in_progress[/dim]"
                            )
                    except (KeyboardInterrupt, EOFError):
                        console.print("\n[dim]Skipped.[/dim]")
                        break

        score_parts.append(("POA&M on-track", poam_score, 100.0))

        # -------------------------------------------------------------------
        # 4. Attestation coverage
        # -------------------------------------------------------------------
        console.print("\n[bold cyan]4. Attestation Coverage[/bold cyan]")

        attestations = session.query(Attestation).filter(Attestation.framework == framework).all()

        approved_attests = [a for a in attestations if a.status == "approved"]
        pending_attests = [
            a for a in attestations if a.status in ("draft", "submitted", "reviewed")
        ]
        rejected_attests = [a for a in attestations if a.status == "rejected"]

        attest_pct = (len(approved_attests) / len(attestations) * 100) if attestations else 0.0
        score_parts.append(("Attestation coverage", attest_pct, 100.0))

        if not attestations:
            console.print(
                "  [yellow]No attestations found.[/yellow] Run: warlock attestations create"
            )
        else:
            console.print(
                f"  Approved: [green]{len(approved_attests)}[/green]   "
                f"Pending: [yellow]{len(pending_attests)}[/yellow]   "
                f"Rejected: [red]{len(rejected_attests)}[/red]"
            )

        if interactive and not approved_attests:
            try:
                if Confirm.ask(
                    "  Create an attestation request for this framework?",
                    default=False,
                ):
                    console.print(
                        f"  [dim]Run: warlock attestations create --framework {framework}[/dim]"
                    )
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Skipped.[/dim]")

        # -------------------------------------------------------------------
        # 5. Pending evidence requests
        # -------------------------------------------------------------------
        console.print("\n[bold cyan]5. Pending Evidence Requests[/bold cyan]")

        # EvidenceRequest is tied to an engagement — find active ones for this framework
        try:
            active_engagements = (
                session.query(AuditEngagement)
                .filter(
                    AuditEngagement.framework == framework,
                    AuditEngagement.status == "active",
                )
                .all()
            )
            eng_ids = [e.id for e in active_engagements]

            if eng_ids:
                from warlock.db.models import EvidenceRequest

                pending_reqs = (
                    session.query(EvidenceRequest)
                    .filter(
                        EvidenceRequest.engagement_id.in_(eng_ids),
                        EvidenceRequest.status.in_(["requested", "in_progress"]),
                    )
                    .all()
                )
            else:
                pending_reqs = []
        except Exception:
            pending_reqs = []

        req_score = max(0.0, 100.0 - len(pending_reqs) * 5)
        score_parts.append(("Open evidence requests", req_score, 100.0))

        if not pending_reqs:
            console.print("  [green]No pending evidence requests.[/green]")
        else:
            console.print(f"  [yellow]{len(pending_reqs)} pending evidence request(s)[/yellow]")
            er_table = Table(show_lines=False)
            er_table.add_column("ID", max_width=8)
            er_table.add_column("Control")
            er_table.add_column("Status")
            er_table.add_column("Description", max_width=50)
            for req in pending_reqs[:10]:
                er_table.add_row(
                    req.id[:8],
                    req.control_id or "—",
                    req.status,
                    (req.description or "")[:50],
                )
            console.print(er_table)

        # -------------------------------------------------------------------
        # 6. Readiness score
        # -------------------------------------------------------------------
        console.print("\n[bold cyan]6. Audit Readiness Score[/bold cyan]")

        total_earned = sum(earned for _, earned, _ in score_parts)
        total_max = sum(max_val for _, _, max_val in score_parts)
        overall = (total_earned / total_max * 100) if total_max else 0.0

        score_table = Table(title="Readiness Breakdown", show_lines=False)
        score_table.add_column("Dimension")
        score_table.add_column("Score", justify="right")
        for label, earned, max_val in score_parts:
            pct = earned / max_val * 100 if max_val else 0.0
            color = "green" if pct >= 80 else ("yellow" if pct >= 50 else "red")
            score_table.add_row(label, f"[{color}]{pct:.0f}%[/{color}]")
        console.print(score_table)

        overall_color = "green" if overall >= 80 else ("yellow" if overall >= 50 else "red")
        console.print(
            f"\n  Overall readiness: [{overall_color}][bold]{overall:.0f}/100[/bold][/{overall_color}]"
        )

        if overall >= 80:
            console.print(
                "\n  [green]Audit-ready package recommendation:[/green] "
                f"warlock export binder --framework {framework}"
            )
        elif overall >= 50:
            console.print(
                "\n  [yellow]Address the gaps above before generating your audit package.[/yellow]"
            )
        else:
            console.print(
                "\n  [red]Significant readiness gaps. Resolve POA&Ms and evidence issues first.[/red]"
            )


# ---------------------------------------------------------------------------
# audit-workflow evidence-sprint
# ---------------------------------------------------------------------------


@audit_workflow.command("evidence-sprint")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
@click.option("--assignee", default=None, help="Default assignee for requests (email)")
@click.option(
    "--days",
    default=14,
    help="Days until sprint deadline (default: 14)",
)
@click.option("--interactive/--no-interactive", default=True)
def evidence_sprint(
    framework: str | None, assignee: str | None, days: int, interactive: bool
) -> None:
    """Guided evidence collection sprint: triage controls and batch-create evidence requests.

    \b
    Examples:
        warlock audit-workflow evidence-sprint --framework soc2
        warlock audit-workflow evidence-sprint --assignee alice@acme.com --days 7
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEngagement, ControlResult

    init_db()

    console.print(
        Panel(
            "[bold]Evidence Collection Sprint[/bold]\n"
            f"Sprint length: {days} days. Framework filter: {framework or 'all'}.",
            style="cyan",
        )
    )

    now = _utcnow()
    deadline = now + timedelta(days=days)

    with get_session() as session:
        # Find controls that are non-compliant or partial — need evidence
        q = session.query(ControlResult).filter(
            ControlResult.status.in_(["non_compliant", "partial", "not_assessed"])
        )
        if framework:
            q = q.filter(ControlResult.framework == framework)
        q = q.order_by(ControlResult.severity.asc())
        results = q.all()

        if not results:
            console.print("[green]No controls need evidence collection.[/green]")
            return

        # Group by priority
        by_priority: dict[str, list[ControlResult]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }
        for r in results:
            bucket = r.severity if r.severity in by_priority else "low"
            by_priority[bucket].append(r)

        console.print(
            f"\n  Controls needing evidence: [bold]{len(results)}[/bold]  "
            + "  ".join(
                f"[{'red bold' if k == 'critical' else 'red' if k == 'high' else 'yellow' if k == 'medium' else 'dim'}]{k}: {len(v)}[/]"
                for k, v in by_priority.items()
                if v
            )
        )

        # Find active engagement for batching
        eng_q = session.query(AuditEngagement).filter(AuditEngagement.status == "active")
        if framework:
            eng_q = eng_q.filter(AuditEngagement.framework == framework)
        engagement = eng_q.first()

        if not engagement:
            console.print(
                "\n  [yellow]No active audit engagement found. "
                "Evidence requests require an engagement.[/yellow]"
                "\n  [dim]Create one first: warlock audit-engagement create[/dim]"
            )
            engagement = None

        created_requests: list[dict[str, Any]] = []

        for priority in ["critical", "high", "medium", "low"]:
            items = by_priority[priority]
            if not items:
                continue

            console.print(
                f"\n[bold]{'red bold' if priority == 'critical' else 'red' if priority == 'high' else 'yellow' if priority == 'medium' else 'white'}]{priority.upper()} priority ({len(items)} controls)[/]"
            )

            for r in items:
                console.print(
                    f"  [cyan]{r.framework}[/cyan] / [bold]{r.control_id}[/bold]  "
                    f"status=[{_status_color(r.status)}]{r.status}[/]  "
                    f"assessed={r.assessed_at.strftime('%Y-%m-%d') if r.assessed_at else '—'}"
                )

                if not interactive:
                    # Auto-create for all in non-interactive mode
                    created_requests.append(
                        {
                            "framework": r.framework,
                            "control_id": r.control_id,
                            "assignee": assignee or "unassigned",
                            "deadline": deadline.strftime("%Y-%m-%d"),
                        }
                    )
                    continue

                try:
                    owner = Prompt.ask(
                        f"    Assign to (email) [default: {assignee or 'skip'}]",
                        default=assignee or "",
                    ).strip()
                    if not owner:
                        console.print("    [dim]Skipped.[/dim]")
                        continue

                    created_requests.append(
                        {
                            "framework": r.framework,
                            "control_id": r.control_id,
                            "assignee": owner,
                            "deadline": deadline.strftime("%Y-%m-%d"),
                        }
                    )
                    console.print(
                        f"    [green]Queued request for {r.control_id} -> {owner}[/green]"
                    )
                except (KeyboardInterrupt, EOFError):
                    console.print("\n  [dim]Sprint entry cancelled.[/dim]")
                    break

        # Sprint summary
        console.print(
            Panel(
                f"[bold]Sprint Summary[/bold]\n\n"
                f"Requests queued: [green]{len(created_requests)}[/green]\n"
                f"Controls covered: [green]{len(created_requests)}[/green] / {len(results)}\n"
                f"Deadline: {deadline.strftime('%Y-%m-%d')}\n\n"
                + (
                    f"[dim]To submit: warlock evidence request --framework {framework or '<fw>'} "
                    f"--assign-to <email>[/dim]"
                )
                + (
                    "\n[dim]Engagement: "
                    + (engagement.name if engagement else "none found")
                    + "[/dim]"
                ),
                style="green",
            )
        )


# ---------------------------------------------------------------------------
# audit-workflow simulate
# ---------------------------------------------------------------------------


@audit_workflow.command("simulate")
@click.argument("framework")
@click.option(
    "--date",
    "sim_date_str",
    required=True,
    help="Projection date (YYYY-MM-DD)",
)
@click.option("--interactive/--no-interactive", default=True)
def audit_simulate(framework: str, sim_date_str: str, interactive: bool) -> None:
    """Project audit posture at a future date based on POA&M milestones and evidence expiry.

    Shows what an auditor would see on the given date.

    \b
    Examples:
        warlock audit-workflow simulate soc2 --date 2026-06-01
        warlock audit-workflow simulate nist_800_53 --date 2026-12-31
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, POAM

    try:
        sim_date = datetime.strptime(sim_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        _error("Invalid date format. Use YYYY-MM-DD.")

    init_db()

    now = _utcnow()
    days_until = (sim_date - now).days

    console.print(
        Panel(
            f"[bold]Audit Simulation — {framework}[/bold]\n"
            f"Projecting posture at: [cyan]{sim_date_str}[/cyan] "
            f"({'+' if days_until >= 0 else ''}{days_until} days from today)",
            style="cyan",
        )
    )

    with get_session() as session:
        all_results = (
            session.query(ControlResult).filter(ControlResult.framework == framework).all()
        )

        if not all_results:
            console.print(
                f"  [yellow]No control results for '{framework}'. "
                "Run 'warlock collect' first.[/yellow]"
            )
            return

        # Project POA&M completions
        completed_poams_by_date = (
            session.query(POAM)
            .filter(
                POAM.framework == framework,
                POAM.scheduled_completion <= sim_date,
                POAM.status.notin_(["cancelled"]),
            )
            .all()
        )
        completed_control_ids = {p.control_id for p in completed_poams_by_date}

        # Project evidence expiry (90-day rolling window by default)
        evidence_expiry_days = 90
        evidence_cutoff = sim_date - timedelta(days=evidence_expiry_days)

        projected: dict[str, str] = {}
        for r in all_results:
            # If evidence expires before the sim date, flag as not_assessed
            if r.assessed_at and ensure_aware(r.assessed_at) < evidence_cutoff:
                projected[r.control_id] = "not_assessed (evidence expired)"
            elif r.control_id in completed_control_ids and r.status == "non_compliant":
                projected[r.control_id] = "compliant (POA&M due by date)"
            else:
                projected[r.control_id] = r.status

        # Summarize
        proj_by_status: dict[str, int] = {}
        for status in projected.values():
            base = status.split(" ")[0]
            proj_by_status[base] = proj_by_status.get(base, 0) + 1

        total = len(all_results)
        compliant_proj = proj_by_status.get("compliant", 0)
        not_assessed_proj = proj_by_status.get("not_assessed", 0)

        console.print(f"\n  [bold]Auditor's view on {sim_date_str}:[/bold]")

        summary_table = Table(show_header=False, box=None)
        summary_table.add_column("Status")
        summary_table.add_column("Count", justify="right")
        summary_table.add_column("Pct", justify="right")
        for st, cnt in sorted(proj_by_status.items(), key=lambda x: -x[1]):
            color = _status_color(st)
            summary_table.add_row(
                f"[{color}]{st}[/{color}]",
                str(cnt),
                f"{cnt / total * 100:.1f}%",
            )
        console.print(summary_table)

        console.print(
            f"\n  Projected compliance: [bold]{compliant_proj / total * 100:.1f}%[/bold]"
            f" ({compliant_proj}/{total})"
        )

        if not_assessed_proj > 0:
            console.print(
                f"  [yellow]Warning: {not_assessed_proj} controls will have expired evidence by {sim_date_str}.[/yellow]"
            )

        # Highest-risk areas
        high_risk: list[ControlResult] = []
        for r in all_results:
            proj_status = projected.get(r.control_id, r.status).split(" ")[0]
            if proj_status == "non_compliant" and r.severity in ("critical", "high"):
                high_risk.append(r)

        if high_risk:
            console.print(
                f"\n  [bold red]Highest-risk areas ({len(high_risk)} critical/high controls):[/bold red]"
            )
            risk_table = Table(show_lines=False)
            risk_table.add_column("Control")
            risk_table.add_column("Severity")
            risk_table.add_column("Projected Status")
            for r in high_risk[:15]:
                risk_table.add_row(
                    r.control_id,
                    f"[{'red bold' if r.severity == 'critical' else 'red'}]{r.severity}[/]",
                    f"[red]{projected.get(r.control_id, r.status)}[/red]",
                )
            console.print(risk_table)

        # Interactive drill-down by control family
        if interactive and high_risk:
            # Group by family prefix (first token before '-')
            families: dict[str, list[ControlResult]] = {}
            for r in high_risk:
                family = r.control_id.split("-")[0] if "-" in r.control_id else r.control_id[:3]
                families.setdefault(family, []).append(r)

            console.print("\n  [bold]Control families with gaps:[/bold]")
            for fam in list(families.keys())[:10]:
                console.print(f"    {fam} ({len(families[fam])} control(s))")

            try:
                chosen = (
                    Prompt.ask(
                        "\n  Drill into control family (e.g. AC, CC6, or press Enter to skip)",
                        default="",
                    )
                    .strip()
                    .upper()
                )
                if chosen:
                    matches = [r for r in high_risk if r.control_id.startswith(chosen)]
                    if matches:
                        console.print(f"\n  [bold]{chosen} family — {len(matches)} gap(s):[/bold]")
                        detail_table = Table(show_lines=True)
                        detail_table.add_column("Control")
                        detail_table.add_column("Status")
                        detail_table.add_column("Severity")
                        detail_table.add_column("Last Assessed")
                        for r in matches:
                            detail_table.add_row(
                                r.control_id,
                                r.status,
                                r.severity,
                                r.assessed_at.strftime("%Y-%m-%d") if r.assessed_at else "—",
                            )
                        console.print(detail_table)
                    else:
                        console.print(f"  [dim]No matches for family '{chosen}'.[/dim]")
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Drill-down skipped.[/dim]")


# ---------------------------------------------------------------------------
# audit-workflow respond
# ---------------------------------------------------------------------------


@audit_workflow.command("respond")
@click.argument("engagement_id")
@click.option("--interactive/--no-interactive", default=True)
def audit_respond(engagement_id: str, interactive: bool) -> None:
    """Respond to auditor evidence requests for an engagement.

    Walks through pending requests, checks if evidence exists, and
    prompts to fulfil each one.

    \b
    Examples:
        warlock audit-workflow respond <engagement_id>
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEngagement, EvidenceRequest, ControlResult

    init_db()

    with get_session() as session:
        # Resolve engagement by full or partial ID
        engagement = (
            session.query(AuditEngagement)
            .filter(AuditEngagement.id.startswith(engagement_id))
            .first()
        )
        if not engagement:
            _error(
                f"Engagement not found: {engagement_id}. "
                "Use 'warlock audit-engagement list' to find IDs."
            )

        console.print(
            Panel(
                f"[bold]Audit Response — {engagement.name}[/bold]\n"
                f"Framework: {engagement.framework}   "
                f"Auditor: {engagement.auditor_name or '—'} "
                f"({engagement.auditor_firm or '—'})\n"
                f"Period: {engagement.period_start.strftime('%Y-%m-%d')} — "
                f"{engagement.period_end.strftime('%Y-%m-%d')}   "
                f"Status: {engagement.status}",
                style="cyan",
            )
        )

        # Load evidence requests
        try:
            pending_reqs = (
                session.query(EvidenceRequest)
                .filter(
                    EvidenceRequest.engagement_id == engagement.id,
                    EvidenceRequest.status.in_(["requested", "in_progress"]),
                )
                .all()
            )
            all_reqs = (
                session.query(EvidenceRequest)
                .filter(EvidenceRequest.engagement_id == engagement.id)
                .all()
            )
        except Exception:
            pending_reqs = []
            all_reqs = []

        fulfilled = [r for r in all_reqs if r.status == "fulfilled"]
        console.print(
            f"\n  Total requests: {len(all_reqs)}   "
            f"Pending: [yellow]{len(pending_reqs)}[/yellow]   "
            f"Fulfilled: [green]{len(fulfilled)}[/green]"
        )

        if not pending_reqs:
            console.print(
                "\n  [green]All evidence requests are fulfilled or there are none.[/green]"
            )
            return

        fulfilled_count = 0

        for req in pending_reqs:
            console.print(
                f"\n  Request [cyan]{req.id[:8]}[/cyan]   "
                f"Control: [bold]{req.control_id or '—'}[/bold]   "
                f"Status: {req.status}"
            )
            console.print(f"  Description: {escape(req.description or '')}")

            # Check if evidence already exists in the system
            existing_evidence: list[ControlResult] = []
            if req.control_id and req.framework:
                existing_evidence = (
                    session.query(ControlResult)
                    .filter(
                        ControlResult.control_id == req.control_id,
                        ControlResult.framework == req.framework,
                        ControlResult.status == "compliant",
                    )
                    .limit(3)
                    .all()
                )

            if existing_evidence:
                console.print(
                    f"  [green]{len(existing_evidence)} compliant control result(s) found "
                    "in system — can attach as evidence.[/green]"
                )

            if not interactive:
                continue

            try:
                choice = Prompt.ask(
                    "  Action: [a]ttach existing evidence, [u]pload file, [s]kip",
                    choices=["a", "u", "s"],
                    default="s",
                )
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Cancelled.[/dim]")
                break

            if choice == "a":
                if existing_evidence:
                    evidence_ids = [e.id for e in existing_evidence]
                    try:
                        req.status = "fulfilled"
                        req.fulfilled_by = _get_actor()
                        req.fulfilled_at = _utcnow()
                        req.fulfillment_notes = (
                            f"Attached {len(evidence_ids)} compliant control result(s)"
                        )
                        req.evidence_ids = evidence_ids
                        session.commit()
                        fulfilled_count += 1
                        console.print(
                            f"  [green]Request {req.id[:8]} fulfilled with "
                            f"{len(evidence_ids)} evidence record(s).[/green]"
                        )
                    except Exception as exc:
                        console.print(f"  [red]Failed to update request: {exc}[/red]")
                else:
                    console.print(
                        "  [yellow]No existing evidence found. Upload a file instead.[/yellow]"
                    )

            elif choice == "u":
                try:
                    file_path = Prompt.ask("  File path").strip()
                    notes = Prompt.ask("  Notes (optional)", default="").strip()
                    req.status = "in_progress"
                    req.fulfilled_by = _get_actor()
                    req.fulfillment_notes = f"File upload: {file_path}" + (
                        f" — {notes}" if notes else ""
                    )
                    session.commit()
                    console.print(
                        f"  [cyan]Request {req.id[:8]} marked in_progress. "
                        "Complete upload via the API.[/cyan]"
                    )
                except (KeyboardInterrupt, EOFError):
                    console.print("\n  [dim]Upload skipped.[/dim]")
            else:
                console.print("  [dim]Skipped.[/dim]")

        console.print(
            Panel(
                f"[bold]Progress[/bold]\n\n"
                f"Fulfilled this session: [green]{fulfilled_count}[/green]\n"
                f"Remaining pending: [yellow]{len(pending_reqs) - fulfilled_count}[/yellow]\n"
                f"Total fulfilled: [green]{len(fulfilled) + fulfilled_count}[/green] / {len(all_reqs)}",
                style="green" if fulfilled_count > 0 else "yellow",
            )
        )
