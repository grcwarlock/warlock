"""Interactive incident response workflow commands.

Provides guided, multi-step workflows for GRC practitioners managing
security incidents:

    warlock incident-response new                 -- Guided incident creation
    warlock incident-response manage <id>         -- Incident lifecycle loop
    warlock incident-response postmortem <id>     -- Guided post-mortem
    warlock incident-response drill               -- Tabletop exercise
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone

import click
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from warlock.cli import cli, console, _error, _get_actor


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEVERITIES = ["critical", "high", "medium", "low"]
_CLASSIFICATIONS = [
    "data_breach",
    "unauthorized_access",
    "malware",
    "dos",
    "insider_threat",
    "other",
]
_INCIDENT_STATUSES = ["open", "investigating", "contained", "eradicated", "resolved", "closed"]

_SEV_STYLE: dict[str, str] = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
}

_STATUS_STYLE: dict[str, str] = {
    "open": "yellow",
    "investigating": "cyan",
    "contained": "blue",
    "eradicated": "magenta",
    "resolved": "green",
    "closed": "dim",
}

# Tabletop scenario library
_SCENARIOS = [
    {
        "name": "Ransomware on Finance Workstation",
        "description": (
            "An employee in finance reports their workstation is locked with a ransom note. "
            "EDR alerts show lateral movement attempts on the same subnet."
        ),
        "severity": "critical",
        "classification": "malware",
        "systems": ["finance-workstation-01", "file-server-finance", "corp-vpn"],
    },
    {
        "name": "Credential Stuffing Against Customer Portal",
        "description": (
            "SIEM detected 50,000 failed login attempts over 2 hours against the customer "
            "portal from 300+ distinct IPs. 12 accounts show successful logins."
        ),
        "severity": "high",
        "classification": "unauthorized_access",
        "systems": ["customer-portal", "auth-service", "user-db"],
    },
    {
        "name": "Suspected Data Exfiltration by Departing Employee",
        "description": (
            "DLP alerts show a soon-to-depart engineer uploaded 2 GB to a personal "
            "Google Drive account over the past week. Data may include source code."
        ),
        "severity": "high",
        "classification": "insider_threat",
        "systems": ["github-enterprise", "dlp-gateway", "hr-system"],
    },
    {
        "name": "S3 Bucket Publicly Exposed",
        "description": (
            "AWS Config flagged an S3 bucket containing customer PII as publicly readable. "
            "Bucket has been accessible for approximately 72 hours."
        ),
        "severity": "critical",
        "classification": "data_breach",
        "systems": ["aws-s3-prod-data", "cloudtrail", "customer-db"],
    },
    {
        "name": "DDoS Against Public API",
        "description": (
            "The public REST API is responding with 503s. CloudFront shows 10x normal "
            "traffic volume. WAF rate-limiting is active but insufficient."
        ),
        "severity": "medium",
        "classification": "dos",
        "systems": ["api-gateway", "cloudfront", "waf", "backend-services"],
    },
]

_RESPONSE_PHASES = [
    ("detect", "Detection & Analysis", "How did you detect this? What indicators confirm it?"),
    ("triage", "Triage", "What is the scope? How many systems/users affected?"),
    ("contain", "Containment", "What immediate steps stop the spread or limit damage?"),
    ("eradicate", "Eradication", "How do you remove the threat completely?"),
    ("recover", "Recovery", "How do you restore systems to normal operation?"),
]

_SCORING_CRITERIA = [
    ("Containment speed", "Did the team isolate the threat quickly?"),
    ("Communication", "Were stakeholders notified appropriately?"),
    ("Evidence preservation", "Was forensic evidence preserved?"),
    ("Root cause identification", "Was the root cause clearly identified?"),
    ("Escalation", "Was escalation to leadership appropriate and timely?"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _resolve_incident(session, incident_id: str):
    """Resolve an incident Issue by ID prefix."""
    from warlock.db.models import Issue

    issue = session.query(Issue).filter(Issue.id.startswith(incident_id)).first()
    if issue and "incident" in (issue.tags or []):
        return issue
    # Fall back: any issue with matching ID prefix
    return session.query(Issue).filter(Issue.id.startswith(incident_id)).first()


def _format_timeline(issue) -> None:
    """Print a Rich timeline for the issue."""
    created = issue.created_at.strftime("%Y-%m-%d %H:%M UTC") if issue.created_at else "unknown"
    console.print(f"\n[bold]Timeline for incident {issue.id[:8]}[/bold]")
    console.print(f"  Created:   {created}")
    if issue.assigned_at:
        console.print(
            f"  Assigned:  {issue.assigned_at.strftime('%Y-%m-%d %H:%M UTC')} to {issue.assigned_to}"
        )
    if issue.remediated_at:
        console.print(f"  Remediated: {issue.remediated_at.strftime('%Y-%m-%d %H:%M UTC')}")
    if issue.verified_at:
        console.print(f"  Verified:  {issue.verified_at.strftime('%Y-%m-%d %H:%M UTC')}")
    if issue.closed_at:
        console.print(f"  Closed:    {issue.closed_at.strftime('%Y-%m-%d %H:%M UTC')}")


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("incident-response", invoke_without_command=True)
@click.pass_context
def incident_response(ctx: click.Context) -> None:
    """Interactive incident response workflows (new, manage, postmortem, drill)."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# new
# ---------------------------------------------------------------------------


@incident_response.command("new")
def incident_new() -> None:
    """Guided incident creation workflow.

    Prompts for severity, classification, title, and description. Auto-searches
    for related findings and lets you link them before creating the incident record.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, Issue

    init_db()

    try:
        console.print(
            Panel(
                "[bold]Incident Response — New Incident[/bold]\n"
                "Press Ctrl-C at any time to cancel.",
                border_style="red",
            )
        )

        severity = Prompt.ask(
            "Severity",
            choices=_SEVERITIES,
            default="high",
            console=console,
        )
        classification = Prompt.ask(
            "Classification",
            choices=_CLASSIFICATIONS,
            default="other",
            console=console,
        )
        title = Prompt.ask("Incident title", console=console)
        if not title.strip():
            _error("Title cannot be empty.")

        description = Prompt.ask(
            "Description (brief, press Enter to skip)",
            default="",
            console=console,
        )

        with get_session() as session:
            # Auto-search for related findings by keyword
            keywords = [w for w in title.lower().split() if len(w) > 3]
            linked_finding_ids: list[str] = []

            if keywords:
                console.print("\n[dim]Searching for related findings...[/dim]")
                for kw in keywords[:3]:
                    matches = (
                        session.query(Finding).filter(Finding.title.ilike(f"%{kw}%")).limit(5).all()
                    )
                    for f in matches:
                        if f.id not in linked_finding_ids:
                            sev_style = _SEV_STYLE.get(f.severity or "", "white")
                            console.print(
                                f"  Found: [{sev_style}]{f.severity}[/] "
                                f"{f.id[:8]} — {(f.title or '')[:60]}"
                            )
                            if Confirm.ask(
                                f"  Link finding {f.id[:8]}?",
                                default=False,
                                console=console,
                            ):
                                linked_finding_ids.append(f.id)

            # Create the incident
            incident_id = str(uuid.uuid4())
            tags = ["incident", classification, severity]

            issue = Issue(
                id=incident_id,
                title=title.strip(),
                description=description.strip() or None,
                priority=severity,
                status="open",
                source="manual",
                tags=tags,
                created_by=_get_actor(),
                finding_id=linked_finding_ids[0] if linked_finding_ids else None,
            )
            session.add(issue)
            session.commit()

            console.print()
            console.print(
                Panel(
                    f"[bold green]Incident created.[/bold green]\n\n"
                    f"ID: {incident_id[:8]}  |  "
                    f"Severity: [{_SEV_STYLE.get(severity, '')}]{severity}[/]  |  "
                    f"Classification: {classification}\n"
                    f"Findings linked: {len(linked_finding_ids)}",
                    border_style="green",
                )
            )
            console.print("\n[bold]Next steps:[/bold]")
            console.print(
                f"  warlock incident-response manage {incident_id[:8]}  # manage lifecycle"
            )
            console.print(
                f"  warlock incident-response postmortem {incident_id[:8]}  # after resolution"
            )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Incident creation cancelled.[/dim]")


# ---------------------------------------------------------------------------
# manage
# ---------------------------------------------------------------------------


@incident_response.command("manage")
@click.argument("incident_id")
def incident_manage(incident_id: str) -> None:
    """Incident lifecycle management loop.

    Shows the incident detail, timeline, and linked findings, then provides
    an interactive action menu. Loops until you choose quit.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, IssueComment

    init_db()

    try:
        with get_session() as session:
            issue = _resolve_incident(session, incident_id)
            if not issue:
                _error(f"Incident not found: '{incident_id}'")

            while True:
                sev_style = _SEV_STYLE.get(issue.priority or "", "white")
                status_style = _STATUS_STYLE.get(issue.status or "", "white")

                console.print()
                console.print(
                    Panel(
                        f"[bold]{escape(issue.title or '')}[/bold]\n\n"
                        f"ID: {issue.id[:8]}  |  "
                        f"Severity: [{sev_style}]{issue.priority}[/{sev_style}]  |  "
                        f"Status: [{status_style}]{issue.status}[/{status_style}]\n"
                        f"Assigned: {issue.assigned_to or '[dim]unassigned[/dim]'}  |  "
                        f"Created: "
                        f"{issue.created_at.strftime('%Y-%m-%d %H:%M UTC') if issue.created_at else '—'}",
                        title="[bold red]Incident[/bold red]",
                        border_style="red",
                    )
                )

                if issue.description:
                    console.print(f"\n[dim]{escape(issue.description)}[/dim]")

                _format_timeline(issue)

                # Linked findings
                if issue.finding_id:
                    f = session.query(Finding).filter(Finding.id == issue.finding_id).first()
                    if f:
                        console.print(
                            f"\nLinked finding: {f.id[:8]} — {escape((f.title or '')[:60])}"
                        )

                # Recent comments
                recent_comments = (
                    session.query(IssueComment)
                    .filter(IssueComment.issue_id == issue.id)
                    .order_by(IssueComment.created_at.desc())
                    .limit(5)
                    .all()
                )
                if recent_comments:
                    console.print("\n[bold]Recent events:[/bold]")
                    for c in reversed(recent_comments):
                        ts = c.created_at.strftime("%Y-%m-%d %H:%M") if c.created_at else "—"
                        console.print(
                            f"  [{ts}] {c.author}: {escape(c.content[:80] if c.content else '')}"
                        )

                console.print()
                choice = Prompt.ask(
                    "Actions: [u]pdate status  [a]dd event  [l]ink finding  "
                    "[r]esponders  [c]lose  [q]uit",
                    choices=["u", "a", "l", "r", "c", "q"],
                    default="q",
                    console=console,
                )

                if choice == "q":
                    console.print("[dim]Exiting incident management.[/dim]")
                    break

                elif choice == "u":
                    new_status = Prompt.ask(
                        "New status",
                        choices=_INCIDENT_STATUSES,
                        default=issue.status or "open",
                        console=console,
                    )
                    issue.status = new_status
                    if new_status == "resolved":
                        issue.remediated_at = _utcnow()
                    elif new_status == "closed":
                        issue.closed_at = _utcnow()
                    session.commit()
                    console.print(f"[green]Status updated to '{new_status}'.[/green]")

                elif choice == "a":
                    event_text = Prompt.ask("Event description", console=console)
                    comment = IssueComment(
                        id=str(uuid.uuid4()),
                        issue_id=issue.id,
                        author=_get_actor(),
                        content=event_text.strip(),
                        comment_type="comment",
                    )
                    session.add(comment)
                    session.commit()
                    console.print("[green]Event recorded.[/green]")

                elif choice == "l":
                    fid = Prompt.ask("Finding ID (prefix)", console=console)
                    from warlock.db.models import Finding as FindingModel

                    found = (
                        session.query(FindingModel).filter(FindingModel.id.startswith(fid)).first()
                    )
                    if found:
                        issue.finding_id = found.id
                        session.commit()
                        console.print(
                            f"[green]Linked finding {found.id[:8]}: {(found.title or '')[:50]}[/green]"
                        )
                    else:
                        console.print(f"[yellow]Finding '{fid}' not found.[/yellow]")

                elif choice == "r":
                    responder = Prompt.ask("Assign to (email)", console=console)
                    issue.assigned_to = responder
                    issue.assigned_by = _get_actor()
                    issue.assigned_at = _utcnow()
                    if issue.status == "open":
                        issue.status = "investigating"
                    session.commit()
                    console.print(
                        f"[green]Incident assigned to {responder}. Status -> investigating.[/green]"
                    )

                elif choice == "c":
                    if not Confirm.ask(
                        "Close this incident? This cannot be undone easily.",
                        default=False,
                        console=console,
                    ):
                        continue
                    issue.status = "closed"
                    issue.closed_at = _utcnow()
                    session.commit()
                    console.print(
                        f"[green]Incident {issue.id[:8]} closed.[/green]\n"
                        f"[dim]Run 'warlock incident-response postmortem {issue.id[:8]}' "
                        f"to document lessons learned.[/dim]"
                    )
                    break

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Session ended.[/dim]")


# ---------------------------------------------------------------------------
# postmortem
# ---------------------------------------------------------------------------


@incident_response.command("postmortem")
@click.argument("incident_id")
def incident_postmortem(incident_id: str) -> None:
    """Guided post-mortem documentation workflow.

    Walks through root cause, contributing factors, impact, corrective
    actions, and lessons learned. Generates a markdown post-mortem report
    and optionally creates follow-up issues.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    init_db()

    try:
        with get_session() as session:
            issue = _resolve_incident(session, incident_id)
            if not issue:
                _error(f"Incident not found: '{incident_id}'")

            console.print(
                Panel(
                    f"[bold]Post-Mortem: {issue.title}[/bold]\n"
                    f"ID: {issue.id[:8]}  |  Status: {issue.status}",
                    title="[bold cyan]Post-Mortem Wizard[/bold cyan]",
                    border_style="cyan",
                )
            )

            _format_timeline(issue)
            console.print()

            root_cause = Prompt.ask(
                "Root cause (what was the underlying technical/process failure?)",
                console=console,
            )
            contributing = Prompt.ask(
                "Contributing factors (comma-separated)",
                default="",
                console=console,
            )
            impact = Prompt.ask(
                "Impact assessment (users affected, data exposed, downtime, etc.)",
                console=console,
            )

            console.print("\n[bold]Corrective actions[/bold] (what will prevent recurrence?)")
            corrective_actions: list[str] = []
            while True:
                action = Prompt.ask(
                    f"  Action {len(corrective_actions) + 1} (or Enter to finish)",
                    default="",
                    console=console,
                )
                if not action.strip():
                    break
                corrective_actions.append(action.strip())

            lessons = Prompt.ask(
                "Lessons learned",
                default="",
                console=console,
            )

            # Generate markdown report
            now_str = _utcnow().strftime("%Y-%m-%d")
            created_str = (
                issue.created_at.strftime("%Y-%m-%d %H:%M UTC") if issue.created_at else "unknown"
            )
            closed_str = (
                issue.closed_at.strftime("%Y-%m-%d %H:%M UTC") if issue.closed_at else "open"
            )

            report_lines = [
                f"# Post-Mortem Report — {issue.title}",
                f"\n**Date:** {now_str}  |  **Incident ID:** {issue.id[:8]}",
                f"**Severity:** {issue.priority}  |  **Status:** {issue.status}",
                f"**Opened:** {created_str}  |  **Closed:** {closed_str}",
                "\n## Root Cause\n",
                root_cause,
                "\n## Contributing Factors\n",
                contributing or "None identified.",
                "\n## Impact Assessment\n",
                impact,
                "\n## Corrective Actions\n",
            ]
            for i, act in enumerate(corrective_actions, 1):
                report_lines.append(f"{i}. {act}")
            if not corrective_actions:
                report_lines.append("None recorded.")

            report_lines += ["\n## Lessons Learned\n", lessons or "None recorded."]

            report = "\n".join(report_lines)

            console.print("\n[bold]Generated Post-Mortem Report:[/bold]")
            console.print(Panel(report, border_style="dim"))

            # Save report to issue remediation plan
            issue.remediation_plan = report
            issue.verification_notes = f"Post-mortem completed on {now_str} by {_get_actor()}"
            session.commit()
            console.print("[green]Report saved to incident record.[/green]")

            # Optionally create follow-up issues
            if corrective_actions and Confirm.ask(
                f"Create {len(corrective_actions)} follow-up issue(s) for corrective actions?",
                default=True,
                console=console,
            ):
                for action_text in corrective_actions:
                    followup = Issue(
                        id=str(uuid.uuid4()),
                        title=f"[Post-mortem] {action_text[:100]}",
                        description=(
                            f"Follow-up from incident {issue.id[:8]}: {issue.title}\n\n"
                            f"Corrective action: {action_text}"
                        ),
                        priority="medium",
                        status="open",
                        source="manual",
                        tags=["post-mortem", f"incident:{issue.id[:8]}"],
                        created_by=_get_actor(),
                    )
                    session.add(followup)
                session.commit()
                console.print(
                    f"[green]{len(corrective_actions)} follow-up issue(s) created.[/green]"
                )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Session ended.[/dim]")


# ---------------------------------------------------------------------------
# drill
# ---------------------------------------------------------------------------


@incident_response.command("drill")
def incident_drill() -> None:
    """Tabletop exercise — simulated incident response drill.

    Generates a random realistic incident scenario, walks through all five
    response phases, prompts for the team's actions at each step, scores
    the response, and generates an after-action report.
    """
    try:
        scenario = random.choice(_SCENARIOS)  # noqa: S311 — not security-sensitive

        console.print()
        console.print(
            Panel(
                f"[bold red]TABLETOP EXERCISE — SIMULATED INCIDENT[/bold red]\n\n"
                f"[bold]{scenario['name']}[/bold]\n\n"
                f"{scenario['description']}\n\n"
                f"Severity: [{_SEV_STYLE.get(scenario['severity'], '')}]{scenario['severity']}[/]  |  "
                f"Classification: {scenario['classification']}\n"
                f"Affected systems: {', '.join(scenario['systems'])}",
                border_style="red",
            )
        )
        console.print("\n[dim]This is a simulated exercise. No real systems are affected.[/dim]\n")

        if not Confirm.ask("Begin the drill?", default=True, console=console):
            console.print("[dim]Drill cancelled.[/dim]")
            return

        responses: list[dict] = []
        scores: list[int] = []

        for phase_id, phase_name, phase_prompt in _RESPONSE_PHASES:
            console.print(f"\n[bold cyan]Phase: {phase_name}[/bold cyan]")
            console.print(f"[dim]{phase_prompt}[/dim]")

            response = Prompt.ask(
                f"Your team's response for '{phase_name}'",
                console=console,
            )
            responses.append({"phase": phase_name, "response": response})

            # Simple scoring: check for keywords suggesting good practice
            score = 5  # default mid-range
            response_lower = response.lower()
            good_indicators = [
                "isolat",
                "contain",
                "notif",
                "escalat",
                "document",
                "log",
                "evidence",
                "backup",
                "restore",
                "patch",
                "monitor",
                "alert",
                "communicat",
                "stakeholder",
                "revok",
                "block",
                "quarantin",
            ]
            hit = sum(1 for kw in good_indicators if kw in response_lower)
            score = min(10, 3 + hit * 2)
            scores.append(score)
            console.print("  [dim]Response recorded.[/dim]")

        # Score the overall response
        avg_score = sum(scores) / len(scores) if scores else 0
        grade = "Excellent" if avg_score >= 8 else "Good" if avg_score >= 6 else "Needs Improvement"
        grade_color = "green" if avg_score >= 8 else ("yellow" if avg_score >= 6 else "red")

        console.print("\n[bold]Scoring Criteria Review[/bold]")
        crit_scores: list[int] = []
        for crit_name, crit_desc in _SCORING_CRITERIA:
            console.print(f"\n[bold]{crit_name}[/bold]")
            console.print(f"  {crit_desc}")
            crit_score = Prompt.ask(
                "  Self-assessment score (1-10)",
                choices=[str(i) for i in range(1, 11)],
                default="5",
                console=console,
            )
            crit_scores.append(int(crit_score))

        overall_crit = sum(crit_scores) / len(crit_scores) if crit_scores else avg_score

        # After-action report
        console.print()
        report = [
            f"# After-Action Report — {scenario['name']}",
            f"\n**Date:** {_utcnow().strftime('%Y-%m-%d')}",
            f"**Scenario:** {scenario['name']}",
            f"**Severity:** {scenario['severity']}  |  "
            f"**Classification:** {scenario['classification']}",
            "\n## Scenario Summary\n",
            scenario["description"],
            f"\n**Affected systems:** {', '.join(scenario['systems'])}",
            "\n## Phase Responses\n",
        ]
        for i, (resp, sc) in enumerate(zip(responses, scores)):
            report.append(f"### {resp['phase']} (score: {sc}/10)")
            report.append(resp["response"])
            report.append("")

        report += [
            "\n## Scoring Summary\n",
            "| Criterion | Score |",
            "|---|---|",
        ]
        for (crit_name, _), cs in zip(_SCORING_CRITERIA, crit_scores):
            report.append(f"| {crit_name} | {cs}/10 |")

        report += [
            f"\n**Overall response quality:** "
            f"[{grade_color}]{grade}[/{grade_color}] "
            f"({overall_crit:.1f}/10)",
            "\n## Identified Gaps\n",
            "Review phase responses where score < 6 for improvement opportunities.",
            "\n## Recommended Follow-ups\n",
            "- Update incident response playbook based on lessons learned",
            "- Schedule follow-up drills for phases with low scores",
            "- Verify contact lists and escalation paths are current",
        ]

        console.print(
            Panel(
                "\n".join(report),
                title="[bold]After-Action Report[/bold]",
                border_style="cyan",
            )
        )
        console.print(
            f"\n[bold]Overall grade: [{grade_color}]{grade}[/{grade_color}] "
            f"({overall_crit:.1f}/10)[/bold]"
        )

        if avg_score < 6:
            console.print(
                "\n[yellow]Recommendation: Schedule a focused training session "
                "on the phases with the lowest scores.[/yellow]"
            )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Drill ended.[/dim]")
