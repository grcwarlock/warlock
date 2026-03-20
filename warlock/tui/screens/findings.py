"""Findings browser screen for the Warlock TUI.

Interactive findings table with search, severity/source filtering,
and a detail panel for inspecting individual findings.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Select,
    Static,
)

from sqlalchemy import func

from warlock.db.engine import get_session, init_db
from warlock.db.models import Finding

# ---------------------------------------------------------------------------
# Severity styling
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "#ff8c00",
    "medium": "yellow",
    "low": "dim",
    "info": "dim italic",
}


def _sev_markup(severity: str) -> str:
    style = _SEVERITY_COLORS.get(severity, "")
    return f"[{style}]{severity}[/]"


def _ts_short(dt: datetime | None) -> str:
    if dt is None:
        return "---"
    return dt.strftime("%Y-%m-%d %H:%M")


# ---------------------------------------------------------------------------
# Stats header widget
# ---------------------------------------------------------------------------


class FindingsStats(Static):
    """Compact stats bar showing finding counts by severity and source."""

    stats_text: reactive[str] = reactive("Loading findings...")

    def render(self) -> str:
        return self.stats_text


# ---------------------------------------------------------------------------
# Detail panel widget
# ---------------------------------------------------------------------------


class FindingDetail(Static):
    """Displays full detail for a selected finding."""

    DEFAULT_CSS = """
    FindingDetail {
        height: auto;
        max-height: 50%;
        overflow-y: auto;
        border-top: solid $accent;
        padding: 1 2;
    }
    """

    detail_text: reactive[str] = reactive("")

    def render(self) -> str:
        return self.detail_text or "[dim]Select a finding to view details.[/dim]"


# ---------------------------------------------------------------------------
# Findings screen
# ---------------------------------------------------------------------------


class FindingsScreen(Screen):
    """Interactive findings browser with filtering and detail view."""

    TITLE = "Findings Browser"
    SUB_TITLE = "Warlock GRC"

    DEFAULT_CSS = """
    FindingsScreen {
        layout: vertical;
    }

    #findings-stats {
        height: 3;
        padding: 0 2;
        background: $surface;
        border-bottom: solid $primary-background;
    }

    #filter-bar {
        height: 3;
        padding: 0 1;
    }

    #search {
        width: 1fr;
        margin-right: 1;
    }

    #severity-filter {
        width: 20;
        margin-right: 1;
    }

    #source-filter {
        width: 25;
    }

    #findings-table {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("r", "refresh", "Refresh"),
        ("slash", "focus_search", "Search"),
    ]

    # Internal state ---------------------------------------------------------

    _findings: list[Any] = []
    _filtered: list[Any] = []
    _sources: list[str] = []
    _selected_severity: str = "all"
    _selected_source: str = "all"
    _search_text: str = ""

    # Compose ----------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        yield FindingsStats(id="findings-stats")
        with Horizontal(id="filter-bar"):
            yield Input(placeholder="Search findings (title, resource, control)...", id="search")
            yield Select(
                [
                    ("All Severities", "all"),
                    ("Critical", "critical"),
                    ("High", "high"),
                    ("Medium", "medium"),
                    ("Low", "low"),
                    ("Info", "info"),
                ],
                value="all",
                id="severity-filter",
                allow_blank=False,
            )
            yield Select([], value="all", id="source-filter", allow_blank=False)
        yield DataTable(id="findings-table", cursor_type="row", zebra_stripes=True)
        yield FindingDetail(id="finding-detail")
        yield Footer()

    # Lifecycle --------------------------------------------------------------

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns(
            "Severity",
            "Source",
            "Resource",
            "Control IDs",
            "Title",
            "Observed",
        )
        self._load_findings()

    # Data loading -----------------------------------------------------------

    @work(thread=True)
    def _load_findings(self) -> None:
        """Load all findings from the database in a worker thread."""
        init_db()
        with get_session() as session:
            rows = session.query(Finding).order_by(Finding.observed_at.desc()).all()
            # Detach from session so we can use them on the main thread.
            session.expunge_all()

            # Gather unique sources for the filter dropdown.
            source_rows = session.query(Finding.source).distinct().order_by(Finding.source).all()
            sources = [r[0] for r in source_rows]

            # Pre-fetch severity counts for the stats bar.
            severity_counts = dict(
                session.query(Finding.severity, func.count(Finding.id))
                .group_by(Finding.severity)
                .all()
            )
            source_counts = dict(
                session.query(Finding.source, func.count(Finding.id)).group_by(Finding.source).all()
            )

        self._findings = rows
        self._sources = sources

        # Build stats text.
        total = len(rows)
        parts = [f"[bold]Total:[/bold] {total}"]
        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(sev, 0)
            if count:
                parts.append(f"[{_SEVERITY_COLORS.get(sev, '')}]{sev}: {count}[/]")
        top_sources = sorted(source_counts.items(), key=lambda x: -x[1])[:5]
        if top_sources:
            src_parts = ", ".join(f"{s}: {c}" for s, c in top_sources)
            parts.append(f"Sources: {src_parts}")
        stats_str = "  |  ".join(parts)

        # Schedule UI updates on the main thread.
        self.app.call_from_thread(self._apply_loaded_data, stats_str, sources)

    def _apply_loaded_data(self, stats_str: str, sources: list[str]) -> None:
        """Apply loaded data to the UI (must run on main thread)."""
        self.query_one("#findings-stats", FindingsStats).stats_text = stats_str

        # Populate source filter dropdown.
        source_options: list[tuple[str, str]] = [("All Sources", "all")]
        for s in sources:
            source_options.append((s, s))
        source_select = self.query_one("#source-filter", Select)
        source_select.set_options(source_options)

        self._apply_filters()

    # Filtering --------------------------------------------------------------

    def _apply_filters(self) -> None:
        """Filter findings based on current search text, severity, and source."""
        results = self._findings
        search = self._search_text.strip().lower()

        if search:
            results = [
                f
                for f in results
                if search in (f.title or "").lower()
                or search in (f.resource_id or "").lower()
                or search in (f.resource_type or "").lower()
                or search in (f.provider or "").lower()
                or search in (f.source or "").lower()
            ]

        if self._selected_severity != "all":
            results = [f for f in results if f.severity == self._selected_severity]

        if self._selected_source != "all":
            results = [f for f in results if f.source == self._selected_source]

        self._filtered = results
        self._populate_table()

    def _populate_table(self) -> None:
        """Rebuild the DataTable rows from the filtered findings list."""
        table = self.query_one("#findings-table", DataTable)
        table.clear()

        for f in self._filtered:
            sev_display = _sev_markup(f.severity)
            table.add_row(
                sev_display,
                f.source or "",
                _truncate(f.resource_id or f.resource_type or "", 40),
                "",  # Control IDs filled lazily or left empty for speed
                _truncate(f.title, 60),
                _ts_short(f.observed_at),
                key=f.id,
            )

    # Event handlers ---------------------------------------------------------

    @on(Input.Changed, "#search")
    def _on_search_changed(self, event: Input.Changed) -> None:
        self._search_text = event.value
        self._apply_filters()

    @on(Select.Changed, "#severity-filter")
    def _on_severity_changed(self, event: Select.Changed) -> None:
        self._selected_severity = str(event.value)
        self._apply_filters()

    @on(Select.Changed, "#source-filter")
    def _on_source_changed(self, event: Select.Changed) -> None:
        self._selected_source = str(event.value)
        self._apply_filters()

    @on(DataTable.RowSelected, "#findings-table")
    def _on_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None:
            return
        finding_id = str(event.row_key.value)
        self._show_detail(finding_id)

    @on(DataTable.RowHighlighted, "#findings-table")
    def _on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        finding_id = str(event.row_key.value)
        self._show_detail(finding_id)

    # Detail panel -----------------------------------------------------------

    def _show_detail(self, finding_id: str) -> None:
        """Populate the detail panel for a given finding."""
        finding = next((f for f in self._filtered if f.id == finding_id), None)
        if finding is None:
            return

        lines: list[str] = []
        lines.append(f"[bold]{finding.title}[/bold]")
        lines.append("")

        # Core fields
        lines.append(f"  [bold]ID:[/bold]           {finding.id}")
        lines.append(f"  [bold]Severity:[/bold]     {_sev_markup(finding.severity)}")
        lines.append(f"  [bold]Type:[/bold]         {finding.observation_type}")
        lines.append(f"  [bold]Confidence:[/bold]   {finding.confidence}")
        lines.append(f"  [bold]Source:[/bold]       {finding.source} / {finding.provider}")
        lines.append(f"  [bold]Source Type:[/bold]  {finding.source_type}")
        lines.append("")

        # Resource
        lines.append(f"  [bold]Resource ID:[/bold]   {finding.resource_id or '---'}")
        lines.append(f"  [bold]Resource Type:[/bold] {finding.resource_type or '---'}")
        lines.append(f"  [bold]Resource Name:[/bold] {finding.resource_name or '---'}")
        lines.append(f"  [bold]Account:[/bold]       {finding.account_id or '---'}")
        lines.append(f"  [bold]Region:[/bold]        {finding.region or '---'}")
        lines.append("")

        # Timestamps
        lines.append(f"  [bold]Observed:[/bold]  {_ts_short(finding.observed_at)}")
        lines.append(f"  [bold]Ingested:[/bold]  {_ts_short(finding.ingested_at)}")
        lines.append(f"  [bold]SHA-256:[/bold]   {finding.sha256[:16]}...")
        lines.append("")

        # Detail / raw_data preview
        if finding.detail:
            detail_data = finding.detail
            if isinstance(detail_data, dict):
                preview = json.dumps(detail_data, indent=2, default=str)
            else:
                preview = str(detail_data)
            # Truncate very long detail blocks
            if len(preview) > 800:
                preview = preview[:800] + "\n  ... (truncated)"
            lines.append("  [bold]Detail:[/bold]")
            for dl in preview.split("\n"):
                lines.append(f"    {dl}")

        self.query_one("#finding-detail", FindingDetail).detail_text = "\n".join(lines)

    # Actions ----------------------------------------------------------------

    def action_refresh(self) -> None:
        """Reload findings from the database."""
        self._findings = []
        self._filtered = []
        self.query_one("#findings-stats", FindingsStats).stats_text = "Reloading..."
        self.query_one("#finding-detail", FindingDetail).detail_text = ""
        self._load_findings()

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate(text: str, length: int) -> str:
    if len(text) <= length:
        return text
    return text[: length - 1] + "\u2026"
