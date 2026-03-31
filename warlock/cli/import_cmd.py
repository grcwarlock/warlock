"""Bulk finding import — CSV and JSON file ingestion.

Supports column mapping for common scanner formats (Qualys, Nessus, Burp)
and generic CSV/JSON with Warlock-native field names.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import click
from rich.markup import escape
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from warlock.cli import _error, cli, console

# ---------------------------------------------------------------------------
# Column mappings for common scanner formats
# ---------------------------------------------------------------------------

_SCANNER_MAPPINGS: dict[str, dict[str, str]] = {
    "qualys": {
        "QID": "title",
        "Title": "title",
        "Severity": "severity",
        "IP": "resource_id",
        "DNS": "resource_name",
        "OS": "resource_type",
        "Results": "detail",
        "Type": "observation_type",
        "Port": "port",
        "Protocol": "protocol",
    },
    "nessus": {
        "Plugin ID": "title",
        "Name": "title",
        "Risk": "severity",
        "Host": "resource_id",
        "Synopsis": "detail",
        "Plugin Output": "detail",
        "Protocol": "protocol",
        "Port": "port",
        "CVSS": "cvss",
    },
    "burp": {
        "Issue name": "title",
        "Severity": "severity",
        "URL": "resource_id",
        "Host": "resource_name",
        "Path": "resource_type",
        "Detail": "detail",
        "Confidence": "confidence",
        "Issue background": "background",
    },
}

_SEVERITY_MAP = {
    # Qualys
    "1": "info",
    "2": "low",
    "3": "medium",
    "4": "high",
    "5": "critical",
    # Nessus
    "none": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    # Burp
    "information": "info",
    "false positive": "info",
}


def _normalize_severity(raw: str) -> str:
    """Map scanner severity values to Warlock's 5-level severity."""
    lower = raw.strip().lower()
    if lower in ("critical", "high", "medium", "low", "info"):
        return lower
    return _SEVERITY_MAP.get(lower, "info")


def _apply_mapping(row: dict[str, str], mapping: dict[str, str]) -> dict[str, str]:
    """Apply a column mapping to a row dict. Unmapped columns go into detail."""
    result: dict[str, str] = {}
    extras: dict[str, str] = {}
    for src_col, value in row.items():
        target = mapping.get(src_col)
        if target:
            # If target already set (e.g., multiple cols -> detail), merge
            if target in result and target == "detail":
                result[target] = result[target] + " | " + value
            else:
                result[target] = value
        else:
            extras[src_col] = value
    # Unmapped columns go into detail dict
    if extras:
        existing_detail = result.get("detail", "")
        if existing_detail:
            result["_detail_text"] = existing_detail
        result["_extras"] = json.dumps(extras, default=str)
    return result


def _row_to_finding_kwargs(row: dict[str, str]) -> dict:
    """Convert a mapped row to FindingData constructor kwargs."""
    detail_text = row.get("detail", "")
    extras_text = row.get("_extras", "{}")
    detail_text_extra = row.get("_detail_text", "")

    detail: dict = {}
    if detail_text:
        detail["description"] = detail_text
    if detail_text_extra:
        detail["description"] = detail_text_extra
        detail["extended"] = detail_text
    try:
        extras = json.loads(extras_text)
        detail.update(extras)
    except (json.JSONDecodeError, TypeError):
        pass

    severity = _normalize_severity(row.get("severity", "info"))
    title = row.get("title", "Imported finding")

    return {
        "observation_type": row.get("observation_type", "vulnerability"),
        "title": title,
        "detail": detail or {"imported": True},
        "resource_id": row.get("resource_id", ""),
        "resource_type": row.get("resource_type", ""),
        "resource_name": row.get("resource_name", ""),
        "severity": severity,
        "source": row.get("source", "import"),
        "source_type": row.get("source_type", "scanner"),
        "provider": row.get("provider", "csv_import"),
    }


def _parse_csv(content: str) -> list[dict[str, str]]:
    """Parse CSV content into list of row dicts."""
    reader = csv.DictReader(io.StringIO(content))
    return list(reader)


def _parse_json(content: str) -> list[dict]:
    """Parse JSON content — supports array of objects or single object."""
    data = json.loads(content)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Check for common wrapper keys
        for key in ("findings", "results", "items", "data", "vulnerabilities", "issues"):
            if key in data and isinstance(data[key], list):
                return data[key]
        return [data]
    return []


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@cli.group("import", invoke_without_command=True)
@click.pass_context
def import_group(ctx: click.Context) -> None:
    """Bulk import data from files (CSV, JSON)."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@import_group.command("findings")
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["auto", "csv", "json"]),
    default="auto",
    help="File format (default: auto-detect from extension)",
)
@click.option(
    "--scanner",
    type=click.Choice(["auto", "qualys", "nessus", "burp", "generic"]),
    default="auto",
    help="Scanner format for column mapping (default: auto-detect)",
)
@click.option("--source", default=None, help="Override source name")
@click.option("--provider", default=None, help="Override provider name")
@click.option("--dry-run", is_flag=True, help="Validate without importing")
@click.option("--batch-size", default=500, help="Commit batch size")
def import_findings(
    file: str,
    fmt: str,
    scanner: str,
    source: str | None,
    provider: str | None,
    dry_run: bool,
    batch_size: int,
) -> None:
    """Import findings from a CSV or JSON file.

    Supports Qualys, Nessus, and Burp scanner formats with automatic
    column mapping. Generic CSV/JSON files should use Warlock field names
    (title, severity, resource_id, observation_type, detail).

    Examples:

        warlock import findings scan_results.csv --scanner qualys

        warlock import findings findings.json

        warlock import findings nessus_export.csv --scanner nessus --source acme-scan
    """
    import hashlib
    from datetime import datetime, timezone
    from uuid import uuid4

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, Finding, RawEvent

    path = Path(file)
    content = path.read_text(encoding="utf-8", errors="replace")

    # Detect format
    if fmt == "auto":
        ext = path.suffix.lower()
        if ext == ".csv":
            fmt = "csv"
        elif ext in (".json", ".jsonl"):
            fmt = "json"
        else:
            _error(f"Cannot auto-detect format for extension '{ext}'. Use --format.")

    # Parse file
    try:
        if fmt == "csv":
            rows = _parse_csv(content)
        else:
            rows = _parse_json(content)
    except Exception as exc:
        _error(f"Failed to parse {fmt.upper()} file: {exc}")

    if not rows:
        _error("No records found in file.")

    console.print(f"[cyan]Parsed {len(rows)} records from {escape(str(path))}[/cyan]")

    # Detect scanner format
    if scanner == "auto":
        if fmt == "csv" and rows:
            headers = set(rows[0].keys())
            if "QID" in headers or {"Title", "Severity", "IP"}.issubset(headers):
                scanner = "qualys"
            elif "Plugin ID" in headers or {"Name", "Risk", "Host"}.issubset(headers):
                scanner = "nessus"
            elif "Issue name" in headers or {"URL", "Host", "Path"}.issubset(headers):
                scanner = "burp"
            else:
                scanner = "generic"
        else:
            scanner = "generic"

    if scanner != "generic":
        console.print(f"  Scanner format: [bold]{scanner}[/bold]")

    mapping = _SCANNER_MAPPINGS.get(scanner, {})

    # Process rows
    imported = 0
    skipped = 0
    errored = 0
    errors: list[str] = []

    if dry_run:
        console.print("[yellow]DRY RUN — validating without importing[/yellow]")

    init_db()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Importing...", total=len(rows))

        if not dry_run:
            with get_session() as session:
                # Create a connector run for this import
                run_id = str(uuid4())
                connector_run = ConnectorRun(
                    id=run_id,
                    connector_name=f"import-{scanner}",
                    source=source or "import",
                    source_type="scanner",
                    provider=provider or scanner,
                    status="running",
                    started_at=datetime.now(timezone.utc),
                )
                session.add(connector_run)
                session.flush()

                for i, row in enumerate(rows):
                    try:
                        # Apply column mapping
                        if mapping:
                            mapped = _apply_mapping(
                                {str(k): str(v) for k, v in row.items()}, mapping
                            )
                        else:
                            mapped = {str(k): str(v) for k, v in row.items()}

                        kwargs = _row_to_finding_kwargs(mapped)

                        # Override source/provider if specified
                        if source:
                            kwargs["source"] = source
                        if provider:
                            kwargs["provider"] = provider

                        # Create raw event
                        raw_data = dict(row)
                        raw_json = json.dumps(raw_data, sort_keys=True, default=str)
                        sha = hashlib.sha256(raw_json.encode()).hexdigest()

                        raw_event = RawEvent(
                            id=str(uuid4()),
                            connector_run_id=run_id,
                            source=kwargs.get("source", "import"),
                            source_type=kwargs.get("source_type", "scanner"),
                            provider=kwargs.get("provider", scanner),
                            event_type="imported_finding",
                            raw_data=raw_data,
                            sha256=sha,
                            ingested_at=datetime.now(timezone.utc),
                        )
                        session.add(raw_event)

                        # Create finding (sha256 from detail for integrity)
                        finding_json = json.dumps(kwargs["detail"], sort_keys=True, default=str)
                        finding_sha = hashlib.sha256(finding_json.encode()).hexdigest()

                        finding = Finding(
                            id=str(uuid4()),
                            raw_event_id=raw_event.id,
                            observation_type=kwargs["observation_type"],
                            title=kwargs["title"],
                            detail=kwargs["detail"],
                            resource_id=kwargs.get("resource_id", ""),
                            resource_type=kwargs.get("resource_type", ""),
                            resource_name=kwargs.get("resource_name", ""),
                            source=kwargs.get("source", "import"),
                            source_type=kwargs.get("source_type", "scanner"),
                            provider=kwargs.get("provider", scanner),
                            severity=kwargs["severity"],
                            confidence=1.0,
                            observed_at=datetime.now(timezone.utc),
                            ingested_at=datetime.now(timezone.utc),
                            sha256=finding_sha,
                        )
                        session.add(finding)
                        imported += 1

                        # Batch flush
                        if (i + 1) % batch_size == 0:
                            session.flush()

                    except Exception as exc:
                        errored += 1
                        if len(errors) < 20:
                            errors.append(f"Row {i + 1}: {exc}")

                    progress.advance(task)

                # Update connector run
                connector_run.status = "success" if errored == 0 else "partial"
                connector_run.event_count = imported
                connector_run.error_count = errored
                connector_run.completed_at = datetime.now(timezone.utc)
                if errors:
                    connector_run.errors = errors[:20]

        else:
            # Dry run — just validate
            for i, row in enumerate(rows):
                try:
                    if mapping:
                        mapped = _apply_mapping({str(k): str(v) for k, v in row.items()}, mapping)
                    else:
                        mapped = {str(k): str(v) for k, v in row.items()}

                    kwargs = _row_to_finding_kwargs(mapped)
                    if not kwargs.get("title"):
                        raise ValueError("Missing required field: title")
                    imported += 1
                except Exception as exc:
                    errored += 1
                    if len(errors) < 20:
                        errors.append(f"Row {i + 1}: {exc}")
                progress.advance(task)

    # Summary
    table = Table(title="Import Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("File", str(path))
    table.add_row("Format", f"{fmt.upper()} ({scanner})")
    table.add_row("Total records", str(len(rows)))
    table.add_row("Imported", f"[green]{imported}[/green]")
    table.add_row("Skipped", str(skipped))
    table.add_row("Errors", f"[red]{errored}[/red]" if errored else "0")
    if dry_run:
        table.add_row("Mode", "[yellow]DRY RUN[/yellow]")
    console.print(table)

    if errors:
        console.print(f"\n[yellow]Errors ({len(errors)}):[/yellow]")
        for err in errors[:10]:
            console.print(f"  [dim]{escape(err)}[/dim]")
        if len(errors) > 10:
            console.print(f"  [dim]... and {len(errors) - 10} more[/dim]")

    if errored and not dry_run:
        raise SystemExit(1)
