"""CLI -- the interface to the pipeline."""

from __future__ import annotations

import logging
import os

import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table

console = Console()


def _error(msg: str) -> None:
    """Print error to stderr and exit with code 1."""
    console.print(f"[red]{escape(msg)}[/red]")
    raise SystemExit(1)


def _get_actor() -> str:
    """Return the actor identity from env or default."""
    return os.environ.get("WLK_CLI_ACTOR", "cli@warlock")


def _check_ai_available(use_ai: bool | None) -> bool:
    """Check if AI is available when --ai was requested. Returns True if AI should be attempted."""
    if use_ai is False:
        return False
    if use_ai is True:
        from warlock.ai.service import get_ai_service

        svc = get_ai_service()
        if not svc.is_available():
            console.print(
                "[dim](AI requested but not configured -- run 'warlock ai configure' to enable)[/dim]"
            )
            return False
    return True


def _parse_ai_response(value) -> str:
    """Extract text from an AI response value, handling JSON wrapping."""
    import json as _json

    response_text = value if isinstance(value, str) else str(value)
    try:
        parsed = _json.loads(response_text)
        response_text = parsed.get("response") or str(parsed)
    except (ValueError, KeyError):
        pass
    return response_text


def _ai_repl(svc, session_id: str, ctx, entity_label: str) -> None:
    """Run an interactive AI conversation REPL.

    Parameters
    ----------
    svc: AI service instance
    session_id: conversation session ID
    ctx: ConversationContext for the AI service
    entity_label: human-readable label shown in the REPL prompt
    """
    console.print(f"[cyan]Entering interactive AI session for {entity_label}.[/cyan]")
    console.print(
        "[dim]Type your question and press Enter. Type 'exit' or press Ctrl-C to quit.[/dim]\n"
    )
    while True:
        try:
            user_input = input("You: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Session ended.[/dim]")
            break
        if not user_input or user_input.lower() in ("exit", "quit", "q"):
            console.print("[dim]Session ended.[/dim]")
            break
        result = svc.converse(session_id=session_id, message=user_input, context=ctx)
        if result.ai_used:
            response_text = _parse_ai_response(result.value)
            console.print(f"AI: {escape(response_text)}\n")
        else:
            console.print(f"[yellow]AI unavailable: {escape(str(result.fallback_reason))}[/yellow]")
            break


def _resolve_system_id(session, value: str) -> str:
    """Resolve a system profile ID from a UUID, partial UUID, or acronym."""
    from warlock.db.models import SystemProfile

    # C-1: Guard against empty string (startswith("") matches everything)
    if not value or not value.strip():
        return value

    # Try exact UUID match first
    sp = session.query(SystemProfile).filter(SystemProfile.id == value).first()
    if sp:
        return sp.id

    # C-5: Try case-insensitive acronym match, warn on ambiguous
    matches = session.query(SystemProfile).filter(SystemProfile.acronym.ilike(value)).all()
    if len(matches) > 1:
        console.print(
            f"[yellow]Warning: ambiguous system match for '{escape(value)}'. "
            f"Matches: {', '.join(m.id[:8] + ' (' + escape(m.name or '') + ')' for m in matches)}. "
            f"Using first match.[/yellow]"
        )
        return matches[0].id
    if matches:
        return matches[0].id

    # C-5: Try partial UUID prefix, warn on ambiguous
    matches = session.query(SystemProfile).filter(SystemProfile.id.startswith(value)).all()
    if len(matches) > 1:
        console.print(
            f"[yellow]Warning: ambiguous system match for '{escape(value)}'. "
            f"Matches: {', '.join(m.id[:8] + ' (' + escape(m.name or '') + ')' for m in matches)}. "
            f"Using first match.[/yellow]"
        )
        return matches[0].id
    if matches:
        return matches[0].id

    # Fall through -- return as-is, let the query return empty
    return value


def _print_stats(stats) -> None:
    table = Table(title="Pipeline Run")
    table.add_column("Metric", style="cyan")
    table.add_column("Value")
    table.add_row("Raw events collected", str(stats.raw_events_collected))
    table.add_row("Findings normalized", str(stats.findings_normalized))
    table.add_row("Controls mapped", str(stats.controls_mapped))
    table.add_row("Results assessed", str(stats.results_assessed))
    table.add_row("Connectors OK", str(stats.connectors_succeeded))
    table.add_row("Connectors failed", str(stats.connectors_failed))
    table.add_row(
        "Duration", f"{stats.duration_seconds:.1f}s" if stats.duration_seconds else "\u2014"
    )
    if stats.errors:
        table.add_row("Errors", str(len(stats.errors)))
    console.print(table)

    if stats.errors:
        console.print(f"\n[yellow]Errors ({len(stats.errors)}):[/yellow]")
        for err in stats.errors[:10]:
            console.print(f"  [dim]\u2022 {escape(str(err))}[/dim]")
        if len(stats.errors) > 10:
            console.print(f"  [dim]... and {len(stats.errors) - 10} more[/dim]")


@click.group(invoke_without_command=True)
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output (for scripting)")
@click.option(
    "--output-format",
    "global_format",
    type=click.Choice(["table", "json"]),
    default=None,
    help="Override output format for all commands",
)
@click.pass_context
def cli(ctx: click.Context, verbose: bool, quiet: bool, global_format: str | None) -> None:
    """Warlock -- compliance telemetry pipeline."""
    ctx.ensure_object(dict)
    ctx.obj["quiet"] = quiet
    ctx.obj["global_format"] = global_format
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s -- %(message)s",
        datefmt="%H:%M:%S",
    )


# Import sub-modules to register commands
from warlock.cli import pipeline as _pipeline  # noqa: F401, E402
from warlock.cli import compliance as _compliance  # noqa: F401, E402
from warlock.cli import governance as _governance  # noqa: F401, E402
from warlock.cli import risk as _risk  # noqa: F401, E402
from warlock.cli import monitoring as _monitoring  # noqa: F401, E402
from warlock.cli import admin as _admin  # noqa: F401, E402
from warlock.cli import ai_cmd as _ai_cmd  # noqa: F401, E402
from warlock.cli import export as _export  # noqa: F401, E402
from warlock.cli import lake as _lake  # noqa: F401, E402
from warlock.cli import policy_cmd as _policy_cmd  # noqa: F401, E402
from warlock.cli import briefing_cmd as _briefing_cmd  # noqa: F401, E402
from warlock.cli import control_cmd as _control_cmd  # noqa: F401, E402

# Phase 2 — Workflow CLI modules
from warlock.cli import incidents_cmd as _incidents_cmd  # noqa: F401, E402
from warlock.cli import evidence_cmd as _evidence_cmd  # noqa: F401, E402
from warlock.cli import attestations_cmd as _attestations_cmd  # noqa: F401, E402
from warlock.cli import privacy_cmd as _privacy_cmd  # noqa: F401, E402
from warlock.cli import access_review_cmd as _access_review_cmd  # noqa: F401, E402
from warlock.cli import change_mgmt_cmd as _change_mgmt_cmd  # noqa: F401, E402
from warlock.cli import exceptions_cmd as _exceptions_cmd  # noqa: F401, E402
from warlock.cli import calendar_cmd as _calendar_cmd  # noqa: F401, E402
from warlock.cli import audit_engagement_cmd as _audit_engagement_cmd  # noqa: F401, E402
from warlock.cli import control_tests_cmd as _control_tests_cmd  # noqa: F401, E402
from warlock.cli import training_cmd as _training_cmd  # noqa: F401, E402
from warlock.cli import bcp_cmd as _bcp_cmd  # noqa: F401, E402

# Phase 3 — CLI expansion modules
from warlock.cli import connectors_cmd as _connectors_cmd  # noqa: F401, E402
from warlock.cli import assertions_cmd as _assertions_cmd  # noqa: F401, E402
from warlock.cli import findings_cmd as _findings_cmd  # noqa: F401, E402
from warlock.cli import frameworks_cmd as _frameworks_cmd  # noqa: F401, E402
from warlock.cli import policies_opa_cmd as _policies_opa_cmd  # noqa: F401, E402
from warlock.cli import audit_trail_cmd as _audit_trail_cmd  # noqa: F401, E402
from warlock.cli import users_cmd as _users_cmd  # noqa: F401, E402
from warlock.cli import reports_cmd as _reports_cmd  # noqa: F401, E402
from warlock.cli import vendors_cmd as _vendors_cmd  # noqa: F401, E402
from warlock.cli import integrations_cmd as _integrations_cmd  # noqa: F401, E402
from warlock.cli import oscal_cmd as _oscal_cmd  # noqa: F401, E402
from warlock.cli import pipeline_ext_cmd as _pipeline_ext_cmd  # noqa: F401, E402
from warlock.cli import vulns_cmd as _vulns_cmd  # noqa: F401, E402
from warlock.cli import conmon_cmd as _conmon_cmd  # noqa: F401, E402
from warlock.cli import sod_cmd as _sod_cmd  # noqa: F401, E402
from warlock.cli import poam_cmd as _poam_cmd  # noqa: F401, E402
from warlock.cli import terraform_cmd as _terraform_cmd  # noqa: F401, E402

# Phase 3+ — Analytics, correlation, AI, automation
from warlock.cli import correlate_cmd as _correlate_cmd  # noqa: F401, E402
from warlock.cli import bulk_cmd as _bulk_cmd  # noqa: F401, E402
from warlock.cli import risk_engine_cmd as _risk_engine_cmd  # noqa: F401, E402
from warlock.cli import comply_cmd as _comply_cmd  # noqa: F401, E402
from warlock.cli import lake_analytics_cmd as _lake_analytics_cmd  # noqa: F401, E402
from warlock.cli import dashboard_cmd as _dashboard_cmd  # noqa: F401, E402
from warlock.cli import ai_ops_cmd as _ai_ops_cmd  # noqa: F401, E402
from warlock.cli import automation_cmd as _automation_cmd  # noqa: F401, E402
from warlock.cli import investigate_cmd as _investigate_cmd  # noqa: F401, E402

# Interactive workflows — guided GRC practitioner UX
from warlock.cli import vendor_workflow_cmd as _vendor_workflow_cmd  # noqa: F401, E402
from warlock.cli import incident_workflow_cmd as _incident_workflow_cmd  # noqa: F401, E402
from warlock.cli import privacy_workflow_cmd as _privacy_workflow_cmd  # noqa: F401, E402
from warlock.cli import audit_workflow_cmd as _audit_workflow_cmd  # noqa: F401, E402
from warlock.cli import risk_workflow_cmd as _risk_workflow_cmd  # noqa: F401, E402
from warlock.cli import ops_workflow_cmd as _ops_workflow_cmd  # noqa: F401, E402
from warlock.cli import system_workflow_cmd as _system_workflow_cmd  # noqa: F401, E402
from warlock.cli import change_workflow_cmd as _change_workflow_cmd  # noqa: F401, E402
from warlock.cli import training_workflow_cmd as _training_workflow_cmd  # noqa: F401, E402
from warlock.cli import exception_workflow_cmd as _exception_workflow_cmd  # noqa: F401, E402
from warlock.cli import conmon_workflow_cmd as _conmon_workflow_cmd  # noqa: F401, E402
from warlock.cli import evidence_workflow_cmd as _evidence_workflow_cmd  # noqa: F401, E402
from warlock.cli import lifecycle_cmd as _lifecycle_cmd  # noqa: F401, E402

# Phase 4 — Alerts & Remediation
from warlock.cli import alerts_cmd as _alerts_cmd  # noqa: F401, E402
from warlock.cli import remediation_cmd as _remediation_cmd  # noqa: F401, E402

# Phase 5 — Interoperability & AI-assisted
from warlock.cli import interop_cmd as _interop_cmd  # noqa: F401, E402
from warlock.cli import ai_assist_cmd as _ai_assist_cmd  # noqa: F401, E402


# ---------------------------------------------------------------------------
# UX-005: Conceptual help topics
# ---------------------------------------------------------------------------
_HELP_TOPICS = {
    "audit-prep": (
        "Audit Preparation Workflow\n"
        "  1. warlock comply readiness-score <framework>    — Check readiness\n"
        "  2. warlock correlate gap-analysis <framework>    — Identify gaps\n"
        "  3. warlock evidence-sprint                       — Plan evidence collection\n"
        "  4. warlock audit-prep                            — Pre-audit checklist\n"
        "  5. warlock audit engagement create               — Create engagement\n"
        "  6. warlock oscal ssp -f <framework>              — Generate SSP\n"
        "  7. warlock oscal assessment-results               — Export assessment"
    ),
    "first-run": (
        "Getting Started\n"
        "  1. warlock pipeline init                          — Initialize database\n"
        "  2. warlock collect                                — Run all connectors\n"
        "  3. warlock dashboard posture                      — View compliance posture\n"
        "  4. warlock morning                                — Morning operations review\n"
        "  5. warlock triage                                 — Triage new findings"
    ),
    "fedramp": (
        "FedRAMP Workflow\n"
        "  1. warlock onboard-system                         — Register system\n"
        "  2. warlock comply readiness-score fedramp          — Check readiness\n"
        "  3. warlock conmon-monthly -f fedramp              — Monthly ConMon\n"
        "  4. warlock oscal ssp -f fedramp                   — Generate SSP\n"
        "  5. warlock oscal assessment-results -f fedramp    — Assessment results"
    ),
    "soc2": (
        "SOC 2 Workflow\n"
        "  1. warlock comply readiness-score soc2            — Check readiness\n"
        "  2. warlock simulate-audit -f soc2                 — Simulate audit\n"
        "  3. warlock evidence freshness -f soc2             — Check evidence\n"
        "  4. warlock reports executive -f soc2              — Executive summary\n"
        "  5. warlock oscal ssp -f soc2                     — Generate SSP"
    ),
}


@cli.command("help-topic")
@click.argument("topic", required=False, default=None)
def help_topic(topic: str | None) -> None:
    """Show workflow guides for common GRC tasks."""
    if not topic:
        console.print("[bold]Available help topics:[/bold]\n")
        for name, content in _HELP_TOPICS.items():
            first_line = content.split("\n")[0]
            console.print(f"  [cyan]{name:20s}[/cyan] — {first_line}")
        console.print("\n[dim]Usage: warlock help-topic <topic>[/dim]")
        return

    content = _HELP_TOPICS.get(topic)
    if not content:
        console.print(
            f"[yellow]Unknown topic '{topic}'. Available: {', '.join(_HELP_TOPICS.keys())}[/yellow]"
        )
        return

    from rich.panel import Panel

    console.print(Panel(content, title=f"[bold]{topic}[/bold]", border_style="cyan"))


if __name__ == "__main__":
    cli()
