"""CLI command: warlock control-hub — cross-domain control view."""

from __future__ import annotations

import click
from rich.panel import Panel

from warlock.cli import cli, console


@cli.command("control-hub")
@click.argument("control_id")
@click.option("--framework", "-f", default=None, help="Framework context")
@click.option(
    "--format", "fmt", default="table", type=click.Choice(["table", "json"]), help="Output format"
)
def control_hub(control_id, framework, fmt):
    """Cross-domain view of a control: status, evidence, issues, POA&Ms, attestations, exceptions, OPA coverage."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        Attestation,
        ControlResult,
        EvidenceRequest,
        Issue,
        POAM,
    )
    from warlock.domains.registry import DomainRegistry
    from warlock.domains.controls import ControlsDomainService
    from warlock.domains.issues import IssuesDomainService
    from warlock.domains.evidence import EvidenceDomainService

    init_db()
    hub_data: dict = {"control_id": control_id, "framework": framework}

    with get_session() as session:
        # Domain registry for cross-domain links
        registry = DomainRegistry()
        registry.register(ControlsDomainService(session))
        registry.register(IssuesDomainService(session))
        registry.register(EvidenceDomainService(session))
        related = registry.get_related_to("control", control_id)

        # Direct DB queries for additional data
        cr_q = session.query(ControlResult).filter(ControlResult.control_id == control_id)
        if framework:
            cr_q = cr_q.filter(ControlResult.framework == framework)
        control_results = cr_q.all()

        # POA&Ms linked to this control
        poam_q = session.query(POAM).filter(POAM.control_id == control_id)
        if framework:
            poam_q = poam_q.filter(POAM.framework == framework)
        poams = poam_q.all()

        # Attestations linked to this control
        att_q = session.query(Attestation).filter(Attestation.control_id == control_id)
        if framework:
            att_q = att_q.filter(Attestation.framework == framework)
        attestations = att_q.all()

        # Issues linked via control_id in tags or detail
        issues = session.query(Issue).filter(Issue.control_id == control_id).all()

        # Evidence requests
        ev_q = session.query(EvidenceRequest).filter(EvidenceRequest.control_id == control_id)
        if framework:
            ev_q = ev_q.filter(EvidenceRequest.framework == framework)
        evidence_requests = ev_q.all()

    if fmt == "json":
        hub_data["control_results"] = [
            {"status": r.status, "framework": r.framework, "assessed_at": str(r.assessed_at)}
            for r in control_results
        ]
        hub_data["poams"] = [
            {"id": p.id[:8], "status": p.status, "due": str(p.scheduled_completion)} for p in poams
        ]
        hub_data["attestations"] = [
            {"id": a.id[:8], "status": a.status, "owner": a.owner} for a in attestations
        ]
        hub_data["issues"] = [
            {"id": i.id[:8], "title": i.title, "status": i.status} for i in issues
        ]
        hub_data["evidence_requests"] = [
            {"id": e.id[:8], "status": e.status} for e in evidence_requests
        ]
        hub_data["domain_links"] = {
            k: [{"summary": i.summary, "status": i.status} for i in v]
            for k, v in (related or {}).items()
        }
        console.print_json(data=hub_data)
        return

    fw_label = f" ({framework})" if framework else ""
    console.print(Panel(f"[bold]Control: {control_id}{fw_label}[/bold]", style="cyan"))

    # Compliance status
    if control_results:
        console.print("\n[bold cyan]Compliance Status[/bold cyan]")
        for r in control_results:
            style = {"compliant": "green", "non_compliant": "red", "partial": "yellow"}.get(
                r.status, "dim"
            )
            console.print(
                f"  [{style}]{r.status}[/{style}] — {r.framework} (assessed {r.assessed_at or 'never'})"
            )
    else:
        console.print("\n[dim]No compliance results found.[/dim]")

    # POA&Ms
    if poams:
        console.print(f"\n[bold cyan]POA&Ms ({len(poams)})[/bold cyan]")
        for p in poams:
            style = "red" if p.status in ("open", "in_progress") else "green"
            console.print(
                f"  [{style}]{p.id[:8]}[/{style}] — {p.status} (due {p.scheduled_completion or 'TBD'})"
            )

    # Attestations
    if attestations:
        console.print(f"\n[bold cyan]Attestations ({len(attestations)})[/bold cyan]")
        for a in attestations:
            style = "green" if a.status == "approved" else "yellow"
            console.print(
                f"  [{style}]{a.id[:8]}[/{style}] — {a.status} (owner: {a.owner or 'unassigned'})"
            )

    # Issues
    if issues:
        console.print(f"\n[bold cyan]Issues ({len(issues)})[/bold cyan]")
        for i in issues:
            style = "red" if i.status in ("open",) else "dim"
            console.print(f"  [{style}]{i.id[:8]}[/{style}] — {i.title[:50]} ({i.status})")

    # Evidence requests
    if evidence_requests:
        console.print(f"\n[bold cyan]Evidence Requests ({len(evidence_requests)})[/bold cyan]")
        for e in evidence_requests:
            console.print(f"  {e.id[:8]} — {e.status}")

    # Domain registry links
    if related:
        domain_labels = {
            "controls": "Compliance Status (registry)",
            "issues": "Open Issues (registry)",
            "evidence": "Evidence (registry)",
            "risk": "Risk",
            "personnel": "Ownership",
        }
        for domain_name, items in related.items():
            label = domain_labels.get(domain_name, domain_name.title())
            if items:
                console.print(f"\n[bold]{label}:[/bold]")
                for item in items:
                    severity_str = f" [{item.severity}]" if item.severity else ""
                    status_str = f" ({item.status})" if item.status else ""
                    console.print(f"  {item.summary}{severity_str}{status_str}")

    # OPA policy coverage check
    try:
        from pathlib import Path

        policies_dir = Path("policies")
        if policies_dir.exists():
            matching = list(policies_dir.rglob(f"*{control_id.lower().replace('-', '_')}*"))
            if matching:
                console.print("\n[bold cyan]OPA Policy Coverage[/bold cyan]")
                console.print(f"  {len(matching)} policy file(s) found for {control_id}")
                for p in matching[:5]:
                    console.print(f"  [dim]{p}[/dim]")
            else:
                console.print(f"\n[yellow]No OPA policies found for {control_id}[/yellow]")
    except Exception:
        pass

    console.print("\n[dim]Actions:[/dim]")
    console.print(f"  warlock incidents create --control {control_id} --title '...'")
    console.print("  warlock remediate <issue-id>")
    console.print(f"  warlock evidence refresh --control {control_id}")
    if framework:
        console.print(f"  warlock comply readiness-score {framework}")
        console.print(f"  warlock risk analyze -f {framework}")
