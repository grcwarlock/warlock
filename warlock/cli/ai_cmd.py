"""AI commands: ai (group with status, models, configure, test)."""

from __future__ import annotations

import os

import click

from warlock.cli import cli, console, _error


@cli.group(invoke_without_command=True)
@click.pass_context
def ai(ctx: click.Context) -> None:
    """AI reasoning management -- status, models, configuration."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@ai.command("status")
def ai_status() -> None:
    """Show AI service status -- provider, model, availability."""
    from warlock.ai.service import get_ai_service

    svc = get_ai_service()
    available = svc.is_available()

    if available:
        console.print("[green]AI enabled[/green]")
        console.print(f"  Provider:  {svc._provider_name}")
        console.print(f"  Model:     {svc._model}")
        console.print(f"  Base URL:  {svc._base_url or '(default)'}")
        console.print(f"  Max tokens: {svc._max_tokens}")
    else:
        console.print("[yellow]AI not configured or disabled[/yellow]")
        console.print("  Set WLK_AI_PROVIDER, WLK_AI_API_KEY, and WLK_AI_MODEL to enable.")
        console.print("  Or use: warlock ai configure --provider ollama --model qwen3-coder:30b")


@ai.command("models")
def ai_models() -> None:
    """List available models for the configured provider."""
    from warlock.ai.service import get_ai_service

    svc = get_ai_service()
    if not svc.is_available():
        _error("AI not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY first.")

    console.print(f"[dim]Discovering models for {svc._provider_name}...[/dim]")
    try:
        models = svc.list_models()
    except Exception as exc:
        _error(f"Model discovery failed: {exc}")

    if not models:
        console.print("[yellow]No models found.[/yellow]")
        return

    from rich.table import Table

    table = Table(title=f"Available Models ({svc._provider_name})")
    table.add_column("Model ID", style="cyan")
    table.add_column("Display Name")
    table.add_column("Verified", justify="center")

    for m in models:
        verified = "[green]yes[/green]" if m.verified else "[yellow]no[/yellow]"
        table.add_row(m.id, m.display_name, verified)

    console.print(table)
    console.print(f"\n[dim]Current model: {svc._model}[/dim]")


@ai.command("configure")
@click.option(
    "--provider",
    "-p",
    required=True,
    type=click.Choice(["anthropic", "openai", "gemini", "ollama"]),
    help="AI provider",
)
@click.option("--api-key", "-k", default=None, help="API key (or set WLK_AI_API_KEY)")
@click.option("--model", "-m", default=None, help="Model to use (omit to see available models)")
@click.option("--base-url", "-u", default="", help="Base URL (for Ollama cloud/local)")
def ai_configure(provider: str, api_key: str | None, model: str | None, base_url: str) -> None:
    """Configure the AI provider -- discover models and validate connectivity."""
    from warlock.ai.discovery import ModelDiscovery

    from rich.table import Table

    key = api_key or os.environ.get("WLK_AI_API_KEY", "")
    if not key:
        _error("API key required. Pass --api-key or set WLK_AI_API_KEY.")

    console.print(f"[dim]Connecting to {provider}...[/dim]")
    discovery = ModelDiscovery()
    result = discovery.discover(provider, key, base_url)

    if result.connected:
        console.print(f"[green]Connected to {provider}[/green]")
    else:
        console.print(f"[yellow]Could not connect to {provider}: {result.error}[/yellow]")
        if result.models:
            console.print("[dim]Showing fallback model list:[/dim]")

    if result.models:
        table = Table(title="Available Models")
        table.add_column("Model ID", style="cyan")
        table.add_column("Verified", justify="center")
        for m in result.models:
            verified = "[green]yes[/green]" if m.verified else "[dim]fallback[/dim]"
            table.add_row(m.id, verified)
        console.print(table)

    if model:
        console.print(f"\n[dim]Validating model '{model}'...[/dim]")
        valid = discovery.validate_model(provider, key, model, base_url)
        if valid:
            console.print(f"[green]Model '{model}' is accessible.[/green]")
        else:
            console.print(f"[red]Model '{model}' could not be validated.[/red]")

    console.print("\n[bold]To activate, set these environment variables:[/bold]")
    console.print(f"  export WLK_AI_PROVIDER={provider}")
    console.print("  export WLK_AI_API_KEY=<your-key>")
    if model:
        console.print(f"  export WLK_AI_MODEL={model}")
    if base_url:
        console.print(f"  export WLK_AI_BASE_URL={base_url}")


@ai.command("test")
@click.option(
    "--prompt", "-p", default="Respond with OK if you can read this.", help="Test prompt to send"
)
def ai_test(prompt: str) -> None:
    """Send a test prompt to verify the AI provider is working."""
    from warlock.ai.service import get_ai_service
    from warlock.ai.types import AITask

    svc = get_ai_service()
    if not svc.is_available():
        _error("AI not configured. Run 'warlock ai configure' first.")

    console.print(f"[dim]Sending test prompt to {svc._provider_name}/{svc._model}...[/dim]")
    try:
        result = svc.reason(
            task=AITask.FOLLOW_UP,
            context={
                "question": prompt,
                "entity_summary": "Test prompt",
                "compliance_context": "None",
            },
        )
        if result.ai_used:
            console.print(f"[green]Response received ({result.latency_ms}ms):[/green]")
            console.print(f"  {result.value}")
            if result.token_usage:
                console.print(
                    f"  [dim]Tokens: {result.token_usage.input_tokens} in / {result.token_usage.output_tokens} out[/dim]"
                )
        else:
            console.print(f"[yellow]AI not used: {result.fallback_reason}[/yellow]")
    except Exception as exc:
        _error(f"AI test failed: {exc}")
