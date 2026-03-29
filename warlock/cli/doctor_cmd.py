"""Diagnostic command: warlock doctor.

Checks database connectivity, OPA availability, AI service status,
disk space, and migration status. Reports results in a Rich table.
"""

from __future__ import annotations

import logging
import os
import shutil

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console

log = logging.getLogger(__name__)


def _check(label: str) -> tuple[str, str, str]:
    """Run a single diagnostic check and return (label, status, detail)."""
    try:
        if label == "database":
            return _check_database()
        if label == "opa":
            return _check_opa()
        if label == "ai":
            return _check_ai()
        if label == "disk":
            return _check_disk()
        if label == "migrations":
            return _check_migrations()
        if label == "config":
            return _check_config()
        return (label, "skip", "Unknown check")
    except Exception as exc:
        return (label, "fail", str(exc)[:120])


def _check_database() -> tuple[str, str, str]:
    from warlock.db.engine import get_read_session, init_db

    init_db()
    with get_read_session() as session:
        row = session.execute(__import__("sqlalchemy").text("SELECT 1")).scalar()
        if row == 1:
            return ("Database", "ok", "Connection successful")
    return ("Database", "fail", "Unexpected query result")


def _check_opa() -> tuple[str, str, str]:
    from warlock.config import get_settings

    settings = get_settings()
    opa_url = settings.opa_url
    if not opa_url:
        return ("OPA", "skip", "OPA URL not configured")

    import httpx

    try:
        resp = httpx.get(f"{opa_url}/health", timeout=3.0)
        if resp.status_code == 200:
            return ("OPA", "ok", f"Healthy at {opa_url}")
        return ("OPA", "warn", f"Status {resp.status_code} from {opa_url}")
    except httpx.ConnectError:
        return ("OPA", "warn", f"Cannot reach {opa_url} (not running?)")
    except Exception as exc:
        return ("OPA", "warn", str(exc)[:80])


def _check_ai() -> tuple[str, str, str]:
    from warlock.config import get_settings

    settings = get_settings()
    if not settings.ai_enabled:
        return ("AI Service", "skip", "WLK_AI_ENABLED=false")

    try:
        from warlock.ai.service import get_ai_service

        svc = get_ai_service()
        if svc.is_available():
            return ("AI Service", "ok", f"Provider: {settings.ai_provider}")
        return ("AI Service", "warn", "Configured but not available")
    except Exception as exc:
        return ("AI Service", "warn", str(exc)[:80])


def _check_disk() -> tuple[str, str, str]:
    from warlock.config import get_settings

    settings = get_settings()
    lake_path = settings.lake_path
    check_path = lake_path if os.path.exists(lake_path) else os.getcwd()

    usage = shutil.disk_usage(check_path)
    free_gb = usage.free / (1024**3)
    total_gb = usage.total / (1024**3)
    pct_free = (usage.free / usage.total) * 100

    status = "ok" if pct_free > 10 else ("warn" if pct_free > 5 else "fail")
    detail = f"{free_gb:.1f} GB free of {total_gb:.1f} GB ({pct_free:.0f}%)"
    if lake_path and os.path.exists(lake_path):
        detail += f" | lake: {lake_path}"
    return ("Disk Space", status, detail)


def _check_migrations() -> tuple[str, str, str]:
    import subprocess

    try:
        result = subprocess.run(
            ["alembic", "current"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=os.getcwd(),
        )
        output = result.stdout.strip()
        if "head" in output.lower():
            return ("Migrations", "ok", output.split("\n")[-1][:80])
        if output:
            return ("Migrations", "warn", f"Not at head: {output[:80]}")
        return ("Migrations", "warn", "No migration info (alembic not initialized?)")
    except FileNotFoundError:
        return ("Migrations", "skip", "alembic CLI not found")
    except subprocess.TimeoutExpired:
        return ("Migrations", "warn", "Timed out checking migration status")
    except Exception as exc:
        return ("Migrations", "warn", str(exc)[:80])


def _check_config() -> tuple[str, str, str]:
    from warlock.config import get_settings

    settings = get_settings()
    warnings: list[str] = []
    if not settings.jwt_secret:
        warnings.append("jwt_secret empty")
    if not settings.encryption_key:
        warnings.append("encryption_key empty")
    if settings.opa_fail_mode != "closed":
        warnings.append(f"opa_fail_mode={settings.opa_fail_mode}")

    if warnings:
        return ("Config", "warn", "; ".join(warnings))
    return ("Config", "ok", "Production-safe defaults")


_STATUS_STYLES = {
    "ok": "green",
    "warn": "yellow",
    "fail": "red bold",
    "skip": "dim",
}

_CHECKS = ["database", "config", "opa", "ai", "disk", "migrations"]


@cli.command("doctor")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def doctor(as_json: bool) -> None:
    """Run diagnostic checks on the Warlock environment."""
    import json as _json

    results = [_check(c) for c in _CHECKS]

    if as_json:
        data = [{"check": r[0], "status": r[1], "detail": r[2]} for r in results]
        click.echo(_json.dumps(data, indent=2))
        return

    table = Table(title="Warlock Diagnostics")
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Detail")

    for label, status, detail in results:
        sty = _STATUS_STYLES.get(status, "")
        table.add_row(
            label,
            f"[{sty}]{status.upper()}[/{sty}]",
            escape(detail),
        )

    console.print(table)

    fail_count = sum(1 for _, s, _ in results if s == "fail")
    warn_count = sum(1 for _, s, _ in results if s == "warn")
    if fail_count:
        console.print(f"\n[red bold]{fail_count} check(s) failed.[/red bold]")
        raise SystemExit(1)
    if warn_count:
        console.print(f"\n[yellow]{warn_count} warning(s).[/yellow]")
