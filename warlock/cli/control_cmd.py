"""CLI command: warlock control-hub — cross-domain control view."""

from __future__ import annotations

import click
from rich.panel import Panel

from warlock.cli import cli, console


@cli.command("control-hub")
@click.argument("control_id")
@click.option("--framework", "-f", default=None, help="Framework context")
def control_hub(control_id, framework):
    """Cross-domain view of a control: status, evidence, issues, risk, owner."""
    from warlock.db.engine import get_session
    from warlock.domains.registry import DomainRegistry
    from warlock.domains.controls import ControlsDomainService
    from warlock.domains.issues import IssuesDomainService
    from warlock.domains.evidence import EvidenceDomainService

    with get_session() as session:
        registry = DomainRegistry()
        registry.register(ControlsDomainService(session))
        registry.register(IssuesDomainService(session))
        registry.register(EvidenceDomainService(session))
        related = registry.get_related_to("control", control_id)

    if not related:
        console.print(f"[dim]No data found for control {control_id}.[/dim]")
        return

    fw_label = f" ({framework})" if framework else ""
    console.print(Panel(f"[bold]Control: {control_id}{fw_label}[/bold]", style="cyan"))

    domain_labels = {
        "controls": "Compliance Status",
        "issues": "Open Issues & POAMs",
        "evidence": "Evidence",
        "risk": "Risk",
        "personnel": "Ownership",
    }

    for domain_name, items in related.items():
        label = domain_labels.get(domain_name, domain_name.title())
        console.print(f"\n[bold]{label}:[/bold]")
        for item in items:
            severity_str = f" [{item.severity}]" if item.severity else ""
            status_str = f" ({item.status})" if item.status else ""
            console.print(f"  {item.summary}{severity_str}{status_str}")

    console.print(f"\n[dim]Actions:[/dim]")
    console.print(f"  warlock remediate <issue-id>")
    console.print(f"  warlock evidence refresh --control {control_id}")
    if framework:
        console.print(f"  warlock risk analyze -f {framework}")
