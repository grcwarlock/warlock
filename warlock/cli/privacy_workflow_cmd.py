"""Interactive privacy operations workflow commands.

Provides guided, multi-step workflows for GRC practitioners managing
privacy compliance obligations:

    warlock privacy-ops dsar-intake           -- Guided DSAR processing
    warlock privacy-ops breach-response       -- Guided breach notification
    warlock privacy-ops data-map-review       -- Interactive data map review
    warlock privacy-ops impact-assessment <s> -- Guided DPIA
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import click
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DSAR_TYPES = ["access", "deletion", "portability", "rectification"]
_CLASSIFICATION_ORDER = ["restricted", "confidential", "internal", "public", "unknown"]
_CLASSIFICATION_STYLE: dict[str, str] = {
    "restricted": "red bold",
    "confidential": "red",
    "internal": "yellow",
    "public": "green",
    "unknown": "dim",
}

_JURISDICTIONS = {
    "GDPR (EU/EEA)": {
        "deadline_hours": 72,
        "authority": "Supervisory Authority",
        "threshold": "Any breach likely to result in risk to individuals",
    },
    "UK GDPR": {
        "deadline_hours": 72,
        "authority": "ICO (UK)",
        "threshold": "Any breach likely to result in risk to individuals",
    },
    "CCPA (California)": {
        "deadline_hours": None,
        "authority": "California AG",
        "threshold": "Unauthorised access to personal information",
    },
    "HIPAA (US)": {
        "deadline_hours": 1440,  # 60 days
        "authority": "HHS OCR",
        "threshold": "Breach of unsecured PHI",
    },
}

_DPIA_QUESTIONS = [
    (
        "data_collected",
        "What personal data is processed?",
        "Describe the categories of personal data (name, email, health, financial, etc.)",
    ),
    (
        "legal_basis",
        "What is the legal basis for processing?",
        "e.g., consent, legitimate interest, contract, legal obligation, vital interest, public task",
    ),
    (
        "necessity",
        "Is the processing necessary and proportionate?",
        "Could the same purpose be achieved with less data or less invasive means?",
    ),
    (
        "risks",
        "What are the risks to data subjects?",
        "Consider: discrimination, identity theft, financial loss, reputational damage, loss of control",
    ),
    (
        "mitigations",
        "What measures mitigate those risks?",
        "e.g., encryption, pseudonymisation, access controls, data minimisation, retention limits",
    ),
    (
        "residual_risk",
        "What residual risk remains after mitigations?",
        "After all measures are applied, what risk level remains? (low/medium/high)",
    ),
    (
        "dpo_consultation",
        "Has the DPO been consulted?",
        "Note any DPO advice or recommendations received",
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _gdpr_deadline(days: int = 30) -> str:
    return (_utcnow() + timedelta(days=days)).strftime("%Y-%m-%d")


def _write_audit_entry(
    session, action: str, entity_type: str, entity_id: str, extra: dict
) -> None:
    """Append a hash-chained audit entry."""
    import hashlib

    from warlock.db.models import AuditEntry

    last = (
        session.query(AuditEntry)
        .order_by(AuditEntry.sequence.desc())
        .first()
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
        actor=_get_actor(),
        extra=extra,
    )
    session.add(entry)
    session.commit()


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("privacy-ops")
def privacy_ops() -> None:
    """Interactive privacy compliance workflows (DSAR, breach, data map, DPIA)."""


# ---------------------------------------------------------------------------
# dsar-intake
# ---------------------------------------------------------------------------


@privacy_ops.command("dsar-intake")
def privacy_dsar_intake() -> None:
    """Guided Data Subject Access Request intake and processing workflow.

    Prompts for the subject's details and request type, auto-searches data
    silos for the subject's data, calculates the response deadline, creates
    the DSAR audit record, and optionally assigns it.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, DataSilo

    init_db()

    try:
        console.print(
            Panel(
                "[bold]Data Subject Access Request (DSAR) Intake[/bold]\n"
                "Press Ctrl-C at any time to cancel.",
                border_style="cyan",
            )
        )

        subject_name = Prompt.ask("Subject full name", console=console)
        subject_email = Prompt.ask("Subject email address", console=console)

        if not subject_email.strip():
            _error("Subject email is required.")

        request_type = Prompt.ask(
            "Request type",
            choices=_DSAR_TYPES,
            default="access",
            console=console,
        )
        regulation = Prompt.ask(
            "Applicable regulation",
            choices=["gdpr", "uk_gdpr", "ccpa", "pipeda", "other"],
            default="gdpr",
            console=console,
        )

        # Deadline calculation
        deadline_days = 30 if regulation in ("gdpr", "uk_gdpr", "pipeda") else 45
        deadline_str = _gdpr_deadline(deadline_days)

        with get_session() as session:
            # Auto-search data silos for subject's data
            console.print(
                f"\n[dim]Searching data silos for '{subject_email}'...[/dim]"
            )

            all_silos = (
                session.query(DataSilo).filter(DataSilo.is_active.is_(True)).all()
            )

            pii_silos = [s for s in all_silos if s.contains_pii]

            if pii_silos:
                table = Table(title=f"Data Silos Containing PII ({len(pii_silos)} found)")
                table.add_column("ID", style="dim", max_width=8)
                table.add_column("Name")
                table.add_column("Type")
                table.add_column("Classification")
                table.add_column("Records", justify="right")
                table.add_column("Owner")

                for silo in pii_silos[:20]:
                    cls_style = _CLASSIFICATION_STYLE.get(
                        silo.data_classification or "unknown", "white"
                    )
                    records = str(silo.total_records) if silo.total_records else "unknown"
                    table.add_row(
                        silo.id[:8],
                        silo.name,
                        silo.silo_type,
                        f"[{cls_style}]{silo.data_classification}[/{cls_style}]",
                        records,
                        silo.owner or "—",
                    )
                console.print(table)
                console.print(
                    f"\n[yellow]Note: Verify whether '{subject_email}' has records in each silo above.[/yellow]"
                )
            else:
                console.print("[dim]No PII-containing data silos found.[/dim]")

            # Create DSAR record as an AuditEntry
            dsar_id = str(uuid.uuid4())
            dsar_data: dict = {
                "dsar_id": dsar_id,
                "subject_name": subject_name.strip(),
                "subject_email": subject_email.strip(),
                "request_type": request_type,
                "regulation": regulation,
                "deadline": deadline_str,
                "status": "open",
                "pii_silos_count": len(pii_silos),
                "created_by": _get_actor(),
            }

            # Optional assignment
            assignee = Prompt.ask(
                "Assign to (user ID or email, or Enter to skip)",
                default="",
                console=console,
            )
            if assignee.strip():
                dsar_data["assigned_to"] = assignee.strip()

            _write_audit_entry(
                session, "dsar_created", "dsar", dsar_id, dsar_data
            )

            console.print()
            console.print(
                Panel(
                    f"[bold green]DSAR created.[/bold green]\n\n"
                    f"ID: {dsar_id[:8]}  |  "
                    f"Subject: {subject_name.strip()} <{subject_email.strip()}>\n"
                    f"Type: {request_type}  |  Regulation: {regulation.upper()}\n"
                    f"Deadline: [bold]{deadline_str}[/bold] "
                    f"({deadline_days} days)  |  "
                    f"PII silos to check: {len(pii_silos)}"
                    + (
                        f"\nAssigned to: {assignee.strip()}"
                        if assignee.strip()
                        else ""
                    ),
                    border_style="green",
                )
            )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]DSAR intake cancelled.[/dim]")


# ---------------------------------------------------------------------------
# breach-response
# ---------------------------------------------------------------------------


@privacy_ops.command("breach-response")
def privacy_breach_response() -> None:
    """Guided data breach notification workflow.

    Prompts for breach details, calculates the 72-hour GDPR notification
    deadline, shows affected data silos, generates a breach notification
    report, and records regulatory notifications.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DataSilo, Issue

    init_db()

    try:
        console.print(
            Panel(
                "[bold red]Data Breach Response Workflow[/bold red]\n"
                "Press Ctrl-C at any time to cancel.",
                border_style="red",
            )
        )

        what_happened = Prompt.ask(
            "What happened? (brief description of the breach)", console=console
        )
        discovered_str = Prompt.ask(
            "When was the breach discovered? (YYYY-MM-DD HH:MM or press Enter for now)",
            default=_utcnow().strftime("%Y-%m-%d %H:%M"),
            console=console,
        )
        try:
            discovered_dt = datetime.strptime(discovered_str, "%Y-%m-%d %H:%M").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            discovered_dt = _utcnow()

        data_affected = Prompt.ask(
            "What data was affected? (categories, e.g. names, emails, health data)",
            console=console,
        )

        with get_session() as session:
            # 72-hour GDPR deadline
            gdpr_deadline = discovered_dt + timedelta(hours=72)
            hours_remaining = (gdpr_deadline - _utcnow()).total_seconds() / 3600
            deadline_color = "red" if hours_remaining < 24 else ("yellow" if hours_remaining < 48 else "green")

            console.print(
                f"\n[bold]GDPR 72-hour notification deadline:[/bold] "
                f"[{deadline_color}]{gdpr_deadline.strftime('%Y-%m-%d %H:%M UTC')}[/{deadline_color}]"
            )
            if hours_remaining < 0:
                console.print("[red bold]DEADLINE PASSED — immediate action required.[/red bold]")
            else:
                console.print(f"  [{deadline_color}]{hours_remaining:.1f} hours remaining[/{deadline_color}]")

            # Show affected data silos
            affected_silos = (
                session.query(DataSilo)
                .filter(DataSilo.is_active.is_(True))
                .filter(
                    DataSilo.contains_pii.is_(True)
                    | DataSilo.contains_phi.is_(True)
                    | DataSilo.contains_pci.is_(True)
                )
                .all()
            )

            total_records = sum(
                s.total_records or 0 for s in affected_silos if s.total_records
            )

            if affected_silos:
                console.print(
                    f"\nAffected PII/PHI/PCI silos: {len(affected_silos)}  |  "
                    f"Estimated records at risk: {total_records:,}"
                )

            # Regulatory notification requirements
            console.print("\n[bold]Regulatory Notification Requirements:[/bold]")
            notifications: list[dict] = []

            for jurisdiction, info in _JURISDICTIONS.items():
                console.print(f"\n  [cyan]{jurisdiction}[/cyan]")
                console.print(f"  Threshold: {info['threshold']}")
                if info["deadline_hours"]:
                    deadline = discovered_dt + timedelta(hours=info["deadline_hours"])
                    console.print(
                        f"  Notification deadline: "
                        f"{deadline.strftime('%Y-%m-%d %H:%M UTC')} "
                        f"({info['deadline_hours']}h)"
                    )
                else:
                    console.print("  Notification deadline: Varies (no fixed window)")

                if Confirm.ask(
                    f"  Record notification to {info['authority']}?",
                    default=(jurisdiction.startswith("GDPR")),
                    console=console,
                ):
                    notifications.append(
                        {
                            "jurisdiction": jurisdiction,
                            "authority": info["authority"],
                            "notified_at": _utcnow().isoformat(),
                            "notified_by": _get_actor(),
                        }
                    )
                    console.print(
                        f"  [green]Notification to {info['authority']} recorded.[/green]"
                    )

            # Create breach record
            breach_id = str(uuid.uuid4())
            breach_data: dict = {
                "breach_id": breach_id,
                "what_happened": what_happened,
                "discovered_at": discovered_dt.isoformat(),
                "data_affected": data_affected,
                "gdpr_deadline": gdpr_deadline.isoformat(),
                "affected_silos": len(affected_silos),
                "estimated_records": total_records,
                "notifications": notifications,
                "reported_by": _get_actor(),
            }

            _write_audit_entry(session, "breach_reported", "privacy_breach", breach_id, breach_data)

            # Generate breach notification report
            report_lines = [
                f"# Data Breach Notification Report",
                f"\n**Date:** {_utcnow().strftime('%Y-%m-%d')}  "
                f"**Breach ID:** {breach_id[:8]}",
                "\n## Breach Summary\n",
                f"**What happened:** {what_happened}",
                f"**Discovered:** {discovered_dt.strftime('%Y-%m-%d %H:%M UTC')}",
                f"**Data affected:** {data_affected}",
                f"**Affected silos:** {len(affected_silos)}",
                f"**Estimated records:** {total_records:,}",
                "\n## GDPR 72-hour Deadline\n",
                f"**Deadline:** {gdpr_deadline.strftime('%Y-%m-%d %H:%M UTC')}",
                "\n## Regulatory Notifications\n",
            ]
            if notifications:
                for n in notifications:
                    report_lines.append(
                        f"- {n['jurisdiction']}: {n['authority']} — notified {n['notified_at']}"
                    )
            else:
                report_lines.append("No regulatory notifications recorded.")

            report_lines += [
                "\n## Follow-up Tasks\n",
                "- [ ] Complete investigation and identify all affected data subjects",
                "- [ ] Notify affected individuals where required",
                "- [ ] Remediate the vulnerability that caused the breach",
                "- [ ] Review and update security controls",
            ]

            console.print()
            console.print(
                Panel(
                    "\n".join(report_lines),
                    title="[bold]Breach Notification Report[/bold]",
                    border_style="red",
                )
            )
            console.print(f"[green]Breach record {breach_id[:8]} saved to audit trail.[/green]")

            # Create follow-up issue
            if Confirm.ask(
                "Create a follow-up issue to track remediation?",
                default=True,
                console=console,
            ):
                issue = Issue(
                    id=str(uuid.uuid4()),
                    title=f"[Breach] {what_happened[:100]}",
                    description=(
                        f"Data breach incident {breach_id[:8]}.\n\n"
                        f"Data affected: {data_affected}\n"
                        f"Silos: {len(affected_silos)}  |  Est. records: {total_records:,}"
                    ),
                    priority="critical",
                    status="open",
                    source="manual",
                    tags=["breach", "privacy", f"breach:{breach_id[:8]}"],
                    created_by=_get_actor(),
                )
                session.add(issue)
                session.commit()
                console.print(f"[green]Follow-up issue created: {issue.id[:8]}[/green]")

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Breach response session ended.[/dim]")


# ---------------------------------------------------------------------------
# data-map-review
# ---------------------------------------------------------------------------


@privacy_ops.command("data-map-review")
def privacy_data_map_review() -> None:
    """Interactive data map review workflow.

    Shows all data silos grouped by classification, highlights compliance
    gaps (missing legal basis, expired retention, missing DPIA), and
    prompts to update classifications interactively.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DataSilo

    init_db()

    try:
        with get_session() as session:
            silos: list = (
                session.query(DataSilo)
                .filter(DataSilo.is_active.is_(True))
                .order_by(DataSilo.data_classification, DataSilo.name)
                .all()
            )

            if not silos:
                console.print("[dim]No active data silos found.[/dim]")
                return

            # Group by classification
            by_class: dict[str, list] = {}
            for silo in silos:
                cls = silo.data_classification or "unknown"
                by_class.setdefault(cls, []).append(silo)

            for cls in _CLASSIFICATION_ORDER:
                group = by_class.get(cls, [])
                if not group:
                    continue

                cls_style = _CLASSIFICATION_STYLE.get(cls, "white")
                table = Table(
                    title=f"[{cls_style}]{cls.upper()}[/{cls_style}] ({len(group)} silos)"
                )
                table.add_column("ID", style="dim", max_width=8)
                table.add_column("Name", max_width=35)
                table.add_column("Type")
                table.add_column("PII")
                table.add_column("PHI")
                table.add_column("PCI")
                table.add_column("Retention (days)", justify="right")
                table.add_column("Owner")

                for silo in group:
                    def _yn(v: bool | None) -> str:  # noqa: E306
                        if v is True:
                            return "[yellow]yes[/yellow]"
                        if v is False:
                            return "[dim]no[/dim]"
                        return "[dim]?[/dim]"

                    table.add_row(
                        silo.id[:8],
                        silo.name[:35],
                        silo.silo_type,
                        _yn(silo.contains_pii),
                        _yn(silo.contains_phi),
                        _yn(silo.contains_pci),
                        str(silo.retention_days) if silo.retention_days else "—",
                        silo.owner or "—",
                    )

                console.print(table)

            # Highlight gaps
            console.print("\n[bold yellow]Compliance Gaps[/bold yellow]")
            gaps_found = False

            no_retention = [s for s in silos if not s.retention_days and (s.contains_pii or s.contains_phi)]
            if no_retention:
                console.print(
                    f"\n  [yellow]Missing retention policy:[/yellow] {len(no_retention)} PII/PHI silo(s)"
                )
                for s in no_retention[:5]:
                    console.print(f"    - {s.name} ({s.silo_type})")
                if len(no_retention) > 5:
                    console.print(f"    ... and {len(no_retention) - 5} more")
                gaps_found = True

            no_encryption = [s for s in silos if s.encrypted_at_rest is False and (s.contains_pii or s.contains_phi)]
            if no_encryption:
                console.print(
                    f"\n  [red]Not encrypted at rest:[/red] {len(no_encryption)} PII/PHI silo(s)"
                )
                for s in no_encryption[:5]:
                    console.print(f"    - {s.name} ({s.silo_type})")
                gaps_found = True

            unknown_class = [s for s in silos if not s.data_classification or s.data_classification == "unknown"]
            if unknown_class:
                console.print(
                    f"\n  [dim]Unclassified silos:[/dim] {len(unknown_class)}"
                )
                gaps_found = True

            if not gaps_found:
                console.print("  [green]No significant gaps detected.[/green]")

            # Interactive classification update
            console.print()
            if not Confirm.ask(
                "Update classifications interactively?", default=False, console=console
            ):
                return

            for silo in silos:
                if silo.data_classification and silo.data_classification != "unknown":
                    continue

                cls_style = _CLASSIFICATION_STYLE.get(
                    silo.data_classification or "unknown", "white"
                )
                console.print(
                    f"\n[bold]{silo.name}[/bold] ({silo.silo_type}, owner: {silo.owner or '—'})"
                )
                console.print(
                    f"  Current: [{cls_style}]{silo.data_classification or 'unknown'}[/{cls_style}]  |  "
                    f"PII: {silo.contains_pii}  PHI: {silo.contains_phi}  PCI: {silo.contains_pci}"
                )

                if not Confirm.ask(
                    "  Update classification?", default=False, console=console
                ):
                    continue

                new_cls = Prompt.ask(
                    "  New classification",
                    choices=["public", "internal", "confidential", "restricted"],
                    default="internal",
                    console=console,
                )
                silo.data_classification = new_cls
                session.commit()
                _write_audit_entry(
                    session,
                    "data_silo_reclassified",
                    "data_silo",
                    silo.id,
                    {
                        "name": silo.name,
                        "old_classification": silo.data_classification,
                        "new_classification": new_cls,
                    },
                )
                console.print(f"  [green]Classification updated to '{new_cls}'.[/green]")

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Session ended.[/dim]")


# ---------------------------------------------------------------------------
# impact-assessment (DPIA)
# ---------------------------------------------------------------------------


@privacy_ops.command("impact-assessment")
@click.argument("system")
def privacy_impact_assessment(system: str) -> None:
    """Guided Data Protection Impact Assessment (DPIA) for a system.

    Walks through the seven standard DPIA questions, calculates a risk
    score, generates a DPIA report, and optionally submits it for DPO
    review via an audit trail entry.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DataSilo

    init_db()

    try:
        console.print(
            Panel(
                f"[bold]Data Protection Impact Assessment (DPIA)[/bold]\n"
                f"System: [cyan]{system}[/cyan]\n\n"
                "Press Ctrl-C at any time to cancel.",
                border_style="cyan",
            )
        )

        with get_session() as session:
            # Show matching data silos for context
            silos = (
                session.query(DataSilo)
                .filter(
                    DataSilo.name.ilike(f"%{system}%")
                    | DataSilo.location.ilike(f"%{system}%")
                    | DataSilo.team.ilike(f"%{system}%"),
                    DataSilo.is_active.is_(True),
                )
                .all()
            )

            if silos:
                console.print(
                    f"\n[bold]Relevant data silos for '{system}'[/bold]"
                )
                for silo in silos[:10]:
                    cls_style = _CLASSIFICATION_STYLE.get(
                        silo.data_classification or "unknown", "white"
                    )
                    console.print(
                        f"  {silo.id[:8]}  [{cls_style}]{silo.data_classification}[/{cls_style}]  "
                        f"{silo.name} ({silo.silo_type})  "
                        f"PII: {silo.contains_pii}  PHI: {silo.contains_phi}"
                    )
                console.print()
            else:
                console.print(
                    f"[dim]No data silos found matching '{system}'.[/dim]\n"
                )

            # Walk through DPIA questions
            answers: dict[str, str] = {}
            for q_id, q_title, q_hint in _DPIA_QUESTIONS:
                console.print(f"\n[bold cyan]Q: {q_title}[/bold cyan]")
                console.print(f"  [dim]{q_hint}[/dim]")
                answer = Prompt.ask("  Your answer", console=console)
                answers[q_id] = answer.strip()

            # Risk score calculation
            # Simple heuristic: flag negative-sentiment responses
            _risk_keywords = [
                "high risk", "significant", "sensitive", "health", "financial",
                "criminal", "children", "large scale", "systematic", "vulnerable",
                "profiling", "automated decision",
            ]
            risk_hits = sum(
                1
                for ans in answers.values()
                for kw in _risk_keywords
                if kw in ans.lower()
            )
            # Residual risk from explicit answer
            residual_lower = answers.get("residual_risk", "").lower()
            if "high" in residual_lower:
                base_risk = 75
            elif "medium" in residual_lower:
                base_risk = 45
            else:
                base_risk = 20

            risk_score = min(100, base_risk + risk_hits * 5)
            risk_color = "red" if risk_score >= 70 else ("yellow" if risk_score >= 40 else "green")
            risk_label = (
                "HIGH — Prior consultation with supervisory authority may be required"
                if risk_score >= 70
                else "MEDIUM — Additional mitigations recommended"
                if risk_score >= 40
                else "LOW — Processing appears proportionate and safe"
            )

            # Generate DPIA report
            now_str = _utcnow().strftime("%Y-%m-%d")
            report_lines = [
                f"# Data Protection Impact Assessment (DPIA)",
                f"\n**System:** {system}  |  **Date:** {now_str}",
                f"**Conducted by:** {_get_actor()}",
                "\n## Assessment\n",
            ]
            for q_id, q_title, _ in _DPIA_QUESTIONS:
                report_lines.append(f"### {q_title}\n")
                report_lines.append(answers.get(q_id, "Not answered"))
                report_lines.append("")

            report_lines += [
                "\n## Risk Score\n",
                f"**Score:** {risk_score}/100  [{risk_color}]{risk_label}[/{risk_color}]",
                "\n## Recommendation\n",
            ]

            if risk_score >= 70:
                report_lines.append(
                    "Consult the supervisory authority before proceeding. "
                    "Review and strengthen all mitigations."
                )
            elif risk_score >= 40:
                report_lines.append(
                    "Review mitigations and confirm with DPO before go-live. "
                    "Schedule a re-assessment after 6 months."
                )
            else:
                report_lines.append(
                    "Processing appears to meet GDPR proportionality requirements. "
                    "Document and retain this DPIA for 3 years."
                )

            report = "\n".join(report_lines)

            console.print()
            console.print(
                Panel(
                    report,
                    title="[bold]DPIA Report[/bold]",
                    border_style="cyan",
                )
            )
            console.print(
                f"\n[bold]Risk score: [{risk_color}]{risk_score}/100[/{risk_color}][/bold]"
            )
            console.print(f"[{risk_color}]{risk_label}[/{risk_color}]")

            # Optionally submit for DPO review
            if Confirm.ask(
                "\nSubmit for DPO review?", default=(risk_score >= 40), console=console
            ):
                dpia_id = str(uuid.uuid4())
                _write_audit_entry(
                    session,
                    "dpia_submitted_for_review",
                    "dpia",
                    dpia_id,
                    {
                        "system": system,
                        "risk_score": risk_score,
                        "risk_label": risk_label,
                        "answers": answers,
                        "submitted_by": _get_actor(),
                        "report": report,
                    },
                )
                console.print(
                    f"[green]DPIA submitted for DPO review. Record ID: {dpia_id[:8]}[/green]"
                )
            else:
                # Still save locally
                dpia_id = str(uuid.uuid4())
                _write_audit_entry(
                    session,
                    "dpia_completed",
                    "dpia",
                    dpia_id,
                    {
                        "system": system,
                        "risk_score": risk_score,
                        "answers": answers,
                        "completed_by": _get_actor(),
                    },
                )
                console.print(
                    f"[green]DPIA saved to audit trail. Record ID: {dpia_id[:8]}[/green]"
                )

    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]DPIA session ended.[/dim]")
