"""Shared CLI output formatting: table, JSON, and CSV.

Every list command should delegate final rendering through ``format_output``
so that ``--output-format`` (table / json / csv) and ``--export`` work
uniformly across the CLI.
"""

from __future__ import annotations

import csv
import io
import json
import sys
from typing import Any, Sequence

import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table

console = Console()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def format_output(
    data: Sequence[dict[str, Any]],
    columns: list[dict[str, str]],
    fmt: str = "table",
    title: str | None = None,
    style_map: dict[str, dict[str, str]] | None = None,
    export_path: str | None = None,
) -> None:
    """Render *data* in the requested format.

    Parameters
    ----------
    data:
        List of row dicts.  Keys must match *columns[n]["key"]*.
    columns:
        Column definitions.  Each is a dict with at least ``key`` (data key)
        and ``header`` (display name).  Optional: ``style``, ``max_width``,
        ``justify``.
    fmt:
        One of ``"table"``, ``"json"``, ``"csv"``.
    title:
        Rich table title (only used in table mode).
    style_map:
        Optional per-column value-based styling.
        ``{ column_key: { cell_value: rich_style, ... }, ... }``
        Only applied in table mode.
    export_path:
        When provided, write output to this file path instead of stdout.
        Supported for json and csv formats.  Table format ignores this
        (Rich tables are for terminal display).
    """
    if not data:
        console.print("[dim]No data.[/dim]")
        return

    if fmt == "json":
        _render_json(data, export_path)
    elif fmt == "csv":
        _render_csv(data, columns, export_path)
    else:
        _render_table(data, columns, title, style_map)


def get_output_format(ctx: click.Context, local_fmt: str | None = None) -> str:
    """Resolve effective output format.

    Precedence: local ``--format`` flag  >  global ``--output-format``  >  ``"table"``.
    """
    if local_fmt:
        return local_fmt
    global_fmt = (ctx.obj or {}).get("global_format")
    if global_fmt:
        return global_fmt
    return "table"


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _render_json(data: Sequence[dict[str, Any]], export_path: str | None) -> None:
    text = json.dumps(list(data), indent=2, default=str)
    if export_path:
        with open(export_path, "w") as fh:
            fh.write(text)
        console.print(f"[green]Wrote {len(data)} records to {export_path}[/green]")
    else:
        console.print(text)


def _render_csv(
    data: Sequence[dict[str, Any]],
    columns: list[dict[str, str]],
    export_path: str | None,
) -> None:
    headers = [c["header"] for c in columns]
    keys = [c["key"] for c in columns]

    if export_path:
        with open(export_path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(headers)
            for row in data:
                writer.writerow([_plain(row.get(k, "")) for k in keys])
        console.print(f"[green]Wrote {len(data)} records to {export_path}[/green]")
    else:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(headers)
        for row in data:
            writer.writerow([_plain(row.get(k, "")) for k in keys])
        sys.stdout.write(buf.getvalue())


def _render_table(
    data: Sequence[dict[str, Any]],
    columns: list[dict[str, str]],
    title: str | None,
    style_map: dict[str, dict[str, str]] | None,
) -> None:
    table = Table(title=title or "")
    for col in columns:
        kwargs: dict[str, Any] = {}
        if "style" in col:
            kwargs["style"] = col["style"]
        if "max_width" in col:
            kwargs["max_width"] = int(col["max_width"])
        if "justify" in col:
            kwargs["justify"] = col["justify"]
        table.add_column(col["header"], **kwargs)

    keys = [c["key"] for c in columns]
    for row in data:
        cells: list[str] = []
        for k in keys:
            val = str(row.get(k, "") or "")
            sty = (style_map or {}).get(k, {}).get(val, "")
            if sty:
                cells.append(f"[{sty}]{escape(val)}[/{sty}]")
            else:
                cells.append(escape(val))
        table.add_row(*cells)

    console.print(table)


def render_csv(
    data: Sequence[dict[str, Any]],
    keys: list[str],
    headers: list[str] | None = None,
) -> None:
    """Write CSV to stdout from a list of dicts.

    Lightweight helper for commands that build JSON-style dicts but
    don't use the full ``format_output`` pipeline.

    Parameters
    ----------
    data:
        List of row dicts (same structure used for JSON output).
    keys:
        Dict keys to include, in column order.
    headers:
        Column headers for the CSV.  Defaults to *keys* if omitted.
    """
    if not data:
        console.print("[dim]No data.[/dim]")
        return
    hdrs = headers or keys
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(hdrs)
    for row in data:
        writer.writerow([_plain(row.get(k, "")) for k in keys])
    sys.stdout.write(buf.getvalue())


def _plain(value: Any) -> str:
    """Convert a value to a plain string suitable for CSV."""
    if value is None:
        return ""
    return str(value)
