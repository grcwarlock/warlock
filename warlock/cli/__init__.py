"""CLI -- the interface to the pipeline."""

from __future__ import annotations

import logging
import os

import click
from rich.console import Console
from rich.table import Table

console = Console()


def _error(msg: str) -> None:
    """Print error to stderr and exit with code 1."""
    console.print(f"[red]{msg}[/red]")
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
            console.print(f"AI: {response_text}\n")
        else:
            console.print(f"[yellow]AI unavailable: {result.fallback_reason}[/yellow]")
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
            f"[yellow]Warning: ambiguous system match for '{value}'. "
            f"Matches: {', '.join(m.id[:8] + ' (' + (m.name or '') + ')' for m in matches)}. "
            f"Using first match.[/yellow]"
        )
        return matches[0].id
    if matches:
        return matches[0].id

    # C-5: Try partial UUID prefix, warn on ambiguous
    matches = session.query(SystemProfile).filter(SystemProfile.id.startswith(value)).all()
    if len(matches) > 1:
        console.print(
            f"[yellow]Warning: ambiguous system match for '{value}'. "
            f"Matches: {', '.join(m.id[:8] + ' (' + (m.name or '') + ')' for m in matches)}. "
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
            console.print(f"  [dim]\u2022 {err}[/dim]")
        if len(stats.errors) > 10:
            console.print(f"  [dim]... and {len(stats.errors) - 10} more[/dim]")


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def cli(verbose: bool) -> None:
    """Warlock -- compliance telemetry pipeline."""
    level = logging.DEBUG if verbose else logging.INFO
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


if __name__ == "__main__":
    cli()
