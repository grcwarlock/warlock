"""Framework compliance coverage detail screen."""

from __future__ import annotations

import logging
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.widgets import Button, DataTable, Input, Label, Select, Static
from textual import work

from sqlalchemy import case, func

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data access
# ---------------------------------------------------------------------------


def _query_frameworks() -> list[str]:
    """Return sorted list of distinct frameworks with results."""
    from warlock.db.engine import get_session
    from warlock.db.models import ControlResult

    with get_session() as session:
        rows = (
            session.query(ControlResult.framework)
            .distinct()
            .order_by(ControlResult.framework)
            .all()
        )
    return [r[0] for r in rows]


def _query_coverage_stats(framework: str) -> dict[str, int]:
    """Return status counts for a single framework."""
    from warlock.db.engine import get_session
    from warlock.db.models import ControlResult

    with get_session() as session:
        rows = (
            session.query(ControlResult.status, func.count(ControlResult.id))
            .filter(ControlResult.framework == framework)
            .group_by(ControlResult.status)
            .all()
        )
    return {status: count for status, count in rows}


def _query_control_results(
    framework: str,
    status_filter: str | None = None,
    search: str | None = None,
) -> list[dict[str, Any]]:
    """Return control results for a framework, with optional filters."""
    from warlock.db.engine import get_session
    from warlock.db.models import ControlResult

    with get_session() as session:
        q = session.query(ControlResult).filter(ControlResult.framework == framework)
        if status_filter and status_filter != "all":
            q = q.filter(ControlResult.status == status_filter)
        if search:
            term = f"%{search}%"
            q = q.filter(
                ControlResult.control_id.ilike(term)
                | ControlResult.assertion_name.ilike(term)
                | ControlResult.assessor.ilike(term)
            )

        # Order: non-compliant first, then by control_id
        severity_order = case(
            (ControlResult.status == "non_compliant", 0),
            (ControlResult.status == "partial", 1),
            (ControlResult.status == "not_assessed", 2),
            (ControlResult.status == "compliant", 3),
            else_=4,
        )
        q = q.order_by(severity_order, ControlResult.control_id)
        rows = q.limit(2000).all()

        return [
            {
                "control_id": r.control_id,
                "status": r.status,
                "severity": r.severity,
                "assessor": r.assessor or "",
                "assertion": r.assertion_name or "",
                "ai_confidence": r.ai_confidence,
                "assessed_at": (r.assessed_at.strftime("%Y-%m-%d %H:%M") if r.assessed_at else ""),
            }
            for r in rows
        ]


# ---------------------------------------------------------------------------
# Helper: colors
# ---------------------------------------------------------------------------


def _status_color(status: str) -> str:
    return {
        "compliant": "green",
        "non_compliant": "red",
        "partial": "yellow",
        "not_assessed": "dim",
        "not_applicable": "dim italic",
        "risk_accepted": "magenta",
        "inherited_compliant": "cyan",
        "inherited_at_risk": "dark_orange",
    }.get(status, "")


def _rate_color(rate: float) -> str:
    if rate >= 80:
        return "green"
    if rate >= 50:
        return "yellow"
    return "red"


def _severity_color(severity: str) -> str:
    return {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }.get(severity, "")


# ---------------------------------------------------------------------------
# Widgets
# ---------------------------------------------------------------------------


class CoverageStatsPanel(Static):
    """Coverage statistics for the selected framework."""

    DEFAULT_CSS = """
    CoverageStatsPanel {
        width: 100%;
        height: auto;
        padding: 1 2;
        border: solid $primary;
        margin-bottom: 1;
    }
    """

    def set_stats(self, framework: str, stats: dict[str, int]) -> None:
        total = sum(stats.values())
        compliant = stats.get("compliant", 0)
        non_compliant = stats.get("non_compliant", 0)
        partial = stats.get("partial", 0)
        not_assessed = stats.get("not_assessed", 0)
        rate = (compliant / total * 100) if total else 0.0

        bar_width = 40
        filled = int(rate / 100 * bar_width)
        color = _rate_color(rate)
        bar = f"[{color}]{'█' * filled}[/][#444444]{'░' * (bar_width - filled)}[/]"

        name = framework.replace("_", " ").upper()
        self.update(
            f"[bold]{name}[/bold]\n\n"
            f"  {bar} [{color}]{rate:.1f}%[/]\n\n"
            f"  [green]Compliant:      {compliant:>6,}[/]    "
            f"[red]Non-Compliant:  {non_compliant:>6,}[/]\n"
            f"  [yellow]Partial:        {partial:>6,}[/]    "
            f"[dim]Not Assessed:   {not_assessed:>6,}[/]\n"
            f"  [bold]Total:          {total:>6,}[/]"
        )


class ControlDetailPanel(Static):
    """Expandable detail panel for a selected control row.

    Shows control header, passing/failing resource breakdown, KB remediation
    steps, and an optional AI remediation button.
    """

    DEFAULT_CSS = """
    ControlDetailPanel {
        width: 100%;
        height: auto;
        max-height: 24;
        padding: 1 2;
        border: solid $primary;
        margin-top: 1;
        overflow-y: auto;
    }

    ControlDetailPanel.--hidden {
        display: none;
    }

    #ai-remediation-btn {
        margin-top: 1;
        min-width: 28;
    }

    #ai-remediation-output {
        width: 100%;
        height: auto;
        padding: 1 2;
        margin-top: 1;
        border: solid $accent;
    }

    #ai-remediation-output.--hidden {
        display: none;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._detail: dict[str, Any] | None = None
        self._ai_available: bool = False

    def compose(self) -> ComposeResult:
        yield Static(id="detail-content")
        yield Button(
            "Get AI Remediation",
            id="ai-remediation-btn",
            variant="primary",
            classes="--hidden",
        )
        yield Static(id="ai-remediation-output", classes="--hidden")

    def show_loading(self, control_id: str, framework: str) -> None:
        """Display a loading indicator while detail is fetched."""
        content = self.query_one("#detail-content", Static)
        content.update(
            f"[bold]{control_id}[/bold]  |  {framework.replace('_', ' ').upper()}\n\n"
            f"[dim]Loading control detail...[/]"
        )
        self.remove_class("--hidden")
        # Hide AI elements while loading
        try:
            self.query_one("#ai-remediation-btn", Button).add_class("--hidden")
            self.query_one("#ai-remediation-output", Static).add_class("--hidden")
        except Exception:
            pass

    def set_detail(self, detail: dict[str, Any]) -> None:
        """Render the full control detail from get_control_detail() output."""
        self._detail = detail
        self.remove_class("--hidden")

        control_id = detail.get("control_id", "")
        frameworks = detail.get("frameworks", [])
        fw_display = ", ".join(f.replace("_", " ").upper() for f in frameworks)
        total = detail.get("total_resources", 0)
        passing = detail.get("passing_resources", [])
        failing = detail.get("failing_resources", [])

        # Status counts summary
        status_counts = detail.get("status_counts", {})
        status_parts: list[str] = []
        for status, count in sorted(status_counts.items()):
            color = _status_color(status)
            label = status.replace("_", " ").title()
            status_parts.append(f"[{color}]{label}: {count}[/]")
        status_line = "  ".join(status_parts) if status_parts else "[dim]No results[/]"

        # Build header
        lines: list[str] = [
            f"[bold]{control_id}[/bold]  |  {fw_display}  |  Total resources: {total}",
            f"  {status_line}",
            "",
        ]

        # Passing resources
        if passing:
            lines.append(f"[green bold]Passing Resources ({len(passing)})[/]")
            for r in passing[:20]:
                rid = r.get("resource_id", "?")
                rtype = r.get("resource_type", "")
                source = r.get("source", "")
                lines.append(f"  [green]{rid}[/]  {rtype}  [dim]{source}[/]")
            if len(passing) > 20:
                lines.append(f"  [dim]... and {len(passing) - 20} more[/]")
            lines.append("")

        # Failing resources
        if failing:
            lines.append(f"[red bold]Failing Resources ({len(failing)})[/]")
            for r in failing[:20]:
                rid = r.get("resource_id", "?")
                rtype = r.get("resource_type", "")
                source = r.get("source", "")
                severity = r.get("severity", "")
                sev_color = _severity_color(severity)
                sev_tag = f"  [{sev_color}]{severity}[/]" if severity else ""
                lines.append(f"  [red]{rid}[/]  {rtype}  [dim]{source}[/]{sev_tag}")
            if len(failing) > 20:
                lines.append(f"  [dim]... and {len(failing) - 20} more[/]")
            lines.append("")

        # Remediation
        remediation = detail.get("remediation") or {}
        summary = remediation.get("summary", "")
        steps = remediation.get("remediation_steps") or remediation.get("steps") or []
        console_path = remediation.get("console_path", "")

        if summary or steps:
            lines.append("[bold cyan]Remediation[/]")
            if summary:
                lines.append(f"  {summary}")
                lines.append("")
            if steps:
                for i, step in enumerate(steps, 1):
                    lines.append(f"  {i}. {step}")
                lines.append("")
            if console_path:
                lines.append(f"  [bold]Console path:[/bold] {console_path}")
                lines.append("")

        lines.append("[dim]Press Escape to close this panel[/]")

        content = self.query_one("#detail-content", Static)
        content.update("\n".join(lines))

        # Show AI button if AI is configured and there are failing resources
        self._check_ai_button(failing)

    def _check_ai_button(self, failing: list[dict[str, Any]]) -> None:
        """Show the AI remediation button when AI is available and resources fail."""
        btn = self.query_one("#ai-remediation-btn", Button)
        if not failing:
            btn.add_class("--hidden")
            return

        try:
            from warlock.ai.service import get_ai_service

            svc = get_ai_service()
            if svc.is_available():
                self._ai_available = True
                btn.remove_class("--hidden")
            else:
                btn.add_class("--hidden")
        except Exception:
            btn.add_class("--hidden")

    def set_ai_remediation(self, ai_result: dict[str, Any] | None) -> None:
        """Display AI-generated per-resource remediation commands."""
        output = self.query_one("#ai-remediation-output", Static)

        if ai_result is None:
            output.update("[yellow]AI remediation unavailable. Showing KB guidance only.[/]")
            output.remove_class("--hidden")
            return

        lines: list[str] = ["[bold magenta]AI Remediation Commands[/]", ""]

        # The AI result may contain various structures; handle common ones
        if isinstance(ai_result, dict):
            guidance = ai_result.get("guidance", "")
            if guidance:
                lines.append(str(guidance))
                lines.append("")

            ai_steps = ai_result.get("steps", [])
            if isinstance(ai_steps, list):
                for i, step in enumerate(ai_steps, 1):
                    lines.append(f"  {i}. {step}")
                if ai_steps:
                    lines.append("")

            commands = ai_result.get("commands", [])
            if isinstance(commands, list):
                for cmd in commands:
                    if isinstance(cmd, dict):
                        res = cmd.get("resource_id", "")
                        cli = cmd.get("command", "")
                        lines.append(f"  [bold]{res}[/]")
                        lines.append(f"    [green]$ {cli}[/]")
                    else:
                        lines.append(f"  [green]$ {cmd}[/]")
                if commands:
                    lines.append("")

            # Fallback: render any remaining string value
            if not guidance and not ai_steps and not commands:
                for key, val in ai_result.items():
                    lines.append(f"  [bold]{key}:[/] {val}")
        elif isinstance(ai_result, str):
            lines.append(ai_result)
        else:
            lines.append(str(ai_result))

        output.update("\n".join(lines))
        output.remove_class("--hidden")

    def set_ai_loading(self) -> None:
        """Show a loading indicator for AI remediation."""
        output = self.query_one("#ai-remediation-output", Static)
        output.update("[dim]Generating AI remediation commands...[/]")
        output.remove_class("--hidden")

        btn = self.query_one("#ai-remediation-btn", Button)
        btn.disabled = True
        btn.label = "Generating..."

    def reset_ai_button(self) -> None:
        """Reset the AI button to its default state after generation."""
        try:
            btn = self.query_one("#ai-remediation-btn", Button)
            btn.disabled = False
            btn.label = "Get AI Remediation"
        except Exception:
            pass

    def dismiss(self) -> None:
        """Hide the detail panel."""
        self.add_class("--hidden")
        self._detail = None
        try:
            self.query_one("#ai-remediation-btn", Button).add_class("--hidden")
            self.query_one("#ai-remediation-output", Static).add_class("--hidden")
        except Exception:
            pass

    @property
    def is_visible(self) -> bool:
        """Whether the detail panel is currently showing."""
        return not self.has_class("--hidden")

    @property
    def current_detail(self) -> dict[str, Any] | None:
        """The currently displayed control detail, if any."""
        return self._detail


class FrameworkSelector(VerticalScroll):
    """Left-panel list of frameworks to select from."""

    DEFAULT_CSS = """
    FrameworkSelector {
        width: 28;
        height: 100%;
        border: solid $surface;
        padding: 0;
    }

    FrameworkSelector > .fw-item {
        width: 100%;
        height: 1;
        padding: 0 1;
    }

    FrameworkSelector > .fw-item.--selected {
        background: $primary;
        color: $text;
        text-style: bold;
    }
    """

    def __init__(self, frameworks: list[str], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._frameworks = frameworks
        self._selected: str = frameworks[0] if frameworks else ""

    @property
    def selected(self) -> str:
        return self._selected

    def compose(self) -> ComposeResult:
        yield Label("[bold]Frameworks[/bold]", classes="section-title")
        for fw in self._frameworks:
            display_name = fw.replace("_", " ").upper()
            if len(display_name) > 24:
                display_name = display_name[:24]
            item = Static(display_name, classes="fw-item", id=f"fw-{fw}")
            yield item

    def on_mount(self) -> None:
        self._highlight_selected()

    def on_click(self, event: Any) -> None:
        """Handle clicks on framework items."""
        widget = event.widget if hasattr(event, "widget") else None
        if widget is None:
            return
        # Walk up to find fw-item
        target = widget
        for _ in range(5):
            if target is None:
                break
            widget_id = getattr(target, "id", "") or ""
            if widget_id.startswith("fw-"):
                fw_name = widget_id[3:]
                if fw_name in self._frameworks:
                    self._selected = fw_name
                    self._highlight_selected()
                    self.post_message(self.FrameworkChanged(fw_name))
                break
            target = target.parent

    def _highlight_selected(self) -> None:
        for fw in self._frameworks:
            try:
                item = self.query_one(f"#fw-{fw}", Static)
                if fw == self._selected:
                    item.add_class("--selected")
                else:
                    item.remove_class("--selected")
            except Exception:
                pass

    class FrameworkChanged(Message):
        """Message posted when framework selection changes."""

        def __init__(self, framework: str) -> None:
            super().__init__()
            self.framework = framework


# ---------------------------------------------------------------------------
# Main coverage screen
# ---------------------------------------------------------------------------


class CoverageScreen(Vertical):
    """Detailed framework-by-framework compliance view."""

    DEFAULT_CSS = """
    CoverageScreen {
        padding: 1 1;
    }

    #coverage-top {
        height: auto;
        margin-bottom: 1;
    }

    #coverage-main {
        height: 1fr;
    }

    #coverage-right {
        width: 1fr;
        padding: 0 0 0 1;
    }

    #filter-bar {
        height: 3;
        margin-bottom: 1;
    }

    #filter-bar > * {
        margin-right: 1;
    }

    #status-filter {
        width: 24;
    }

    #search-box {
        width: 32;
    }

    #results-table {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("escape", "close_detail", "Close detail panel"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._frameworks: list[str] = []
        self._current_framework: str = ""
        self._status_filter: str = "all"
        self._search_term: str = ""
        self._table_rows: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        yield CoverageStatsPanel(id="coverage-stats")
        with Horizontal(id="coverage-main"):
            yield FrameworkSelector([], id="framework-selector")
            with Vertical(id="coverage-right"):
                with Horizontal(id="filter-bar"):
                    yield Select(
                        [
                            ("All Statuses", "all"),
                            ("Compliant", "compliant"),
                            ("Non-Compliant", "non_compliant"),
                            ("Partial", "partial"),
                            ("Not Assessed", "not_assessed"),
                        ],
                        value="all",
                        id="status-filter",
                        allow_blank=False,
                    )
                    yield Input(
                        placeholder="Search control ID or assessor...",
                        id="search-box",
                    )
                yield DataTable(id="results-table")
                yield ControlDetailPanel(id="control-detail", classes="--hidden")

    def on_mount(self) -> None:
        try:
            from warlock.db.engine import init_db

            init_db()
        except Exception:
            pass

        try:
            self._frameworks = _query_frameworks()
        except Exception:
            self._frameworks = []

        if self._frameworks:
            self._current_framework = self._frameworks[0]
            # Rebuild the selector with actual data
            selector = self.query_one("#framework-selector", FrameworkSelector)
            selector._frameworks = self._frameworks
            selector._selected = self._current_framework
            selector.remove_children()
            selector.mount(Label("[bold]Frameworks[/bold]", classes="section-title"))
            for fw in self._frameworks:
                display_name = fw.replace("_", " ").upper()
                if len(display_name) > 24:
                    display_name = display_name[:24]
                selector.mount(Static(display_name, classes="fw-item", id=f"fw-{fw}"))
            selector._highlight_selected()
            self._refresh_data()

        # Set up table columns
        table = self.query_one("#results-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True

    def _refresh_data(self) -> None:
        """Reload stats and table for current framework + filters."""
        if not self._current_framework:
            return

        # Dismiss any open detail panel when data changes
        try:
            detail_panel = self.query_one("#control-detail", ControlDetailPanel)
            detail_panel.dismiss()
        except Exception:
            pass

        # Stats panel
        try:
            stats = _query_coverage_stats(self._current_framework)
        except Exception:
            stats = {}

        stats_panel = self.query_one("#coverage-stats", CoverageStatsPanel)
        stats_panel.set_stats(self._current_framework, stats)

        # Results table
        try:
            results = _query_control_results(
                self._current_framework,
                status_filter=self._status_filter,
                search=self._search_term or None,
            )
        except Exception:
            results = []

        self._table_rows = results

        table = self.query_one("#results-table", DataTable)
        table.clear(columns=True)
        table.add_columns(
            "Control ID",
            "Status",
            "Severity",
            "Assessor",
            "Assertion",
            "AI Conf.",
            "Assessed At",
        )

        for r in results:
            status = r["status"]
            _status_color(status)
            severity = r["severity"]
            _severity_color(severity)
            ai_conf = f"{r['ai_confidence']:.0%}" if r["ai_confidence"] is not None else ""
            table.add_row(
                r["control_id"],
                status.replace("_", " "),
                severity,
                r["assessor"],
                r["assertion"],
                ai_conf,
                r["assessed_at"],
            )

    # ----- Row selection / click-to-detail ---------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row click or Enter on the results table."""
        if event.data_table.id != "results-table":
            return
        row_index = event.cursor_row
        if row_index < 0 or row_index >= len(self._table_rows):
            return

        row_data = self._table_rows[row_index]
        control_id = row_data["control_id"]
        framework = self._current_framework

        # Show loading state immediately
        detail_panel = self.query_one("#control-detail", ControlDetailPanel)
        detail_panel.show_loading(control_id, framework)

        # Fetch full detail in a worker thread
        self._load_control_detail(control_id, framework)

    @work(thread=True, exclusive=True, group="control-detail")
    def _load_control_detail(self, control_id: str, framework: str) -> None:
        """Load control detail from the database in a background thread."""
        try:
            from warlock.assessors.remediation_loader import get_control_detail
            from warlock.db.engine import get_session, init_db

            init_db()
            with get_session() as session:
                detail = get_control_detail(session, control_id, framework)

            if detail:
                self.app.call_from_thread(self._apply_control_detail, detail)
            else:
                self.app.call_from_thread(
                    self._apply_control_detail_error,
                    control_id,
                    framework,
                    "No detail found for this control.",
                )
        except Exception as exc:
            log.exception("Failed to load control detail for %s/%s", framework, control_id)
            self.app.call_from_thread(
                self._apply_control_detail_error,
                control_id,
                framework,
                str(exc),
            )

    def _apply_control_detail(self, detail: dict[str, Any]) -> None:
        """Apply fetched control detail to the panel (main thread)."""
        try:
            panel = self.query_one("#control-detail", ControlDetailPanel)
            panel.set_detail(detail)
        except Exception:
            pass

    def _apply_control_detail_error(self, control_id: str, framework: str, error: str) -> None:
        """Show an error message in the detail panel (main thread)."""
        try:
            panel = self.query_one("#control-detail", ControlDetailPanel)
            content = panel.query_one("#detail-content", Static)
            content.update(
                f"[bold]{control_id}[/bold]  |  {framework.replace('_', ' ').upper()}\n\n"
                f"[red]Error: {error}[/]\n\n"
                f"[dim]Press Escape to close this panel[/]"
            )
            panel.remove_class("--hidden")
        except Exception:
            pass

    # ----- AI remediation button -------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle the AI remediation button press."""
        if event.button.id != "ai-remediation-btn":
            return

        panel = self.query_one("#control-detail", ControlDetailPanel)
        detail = panel.current_detail
        if not detail:
            return

        panel.set_ai_loading()
        self._fetch_ai_remediation(
            detail["control_id"],
            detail.get("frameworks", [""])[0] if detail.get("frameworks") else "",
            detail.get("failing_resources", []),
            detail.get("remediation"),
        )

    @work(thread=True, exclusive=True, group="ai-remediation")
    def _fetch_ai_remediation(
        self,
        control_id: str,
        framework: str,
        failing_resources: list[dict[str, Any]],
        remediation: dict[str, Any] | None,
    ) -> None:
        """Call AI remediation in a background thread."""
        try:
            from warlock.assessors.remediation_loader import (
                get_ai_control_remediation,
            )

            ai_result = get_ai_control_remediation(
                control_id=control_id,
                framework=framework,
                failing_resources=failing_resources,
                remediation=remediation,
            )
            self.app.call_from_thread(self._apply_ai_remediation, ai_result)
        except Exception as exc:
            log.exception("AI remediation failed for %s/%s", framework, control_id)
            self.app.call_from_thread(self._apply_ai_remediation_error, str(exc))

    def _apply_ai_remediation(self, ai_result: dict[str, Any] | None) -> None:
        """Display AI remediation result (main thread)."""
        try:
            panel = self.query_one("#control-detail", ControlDetailPanel)
            panel.set_ai_remediation(ai_result)
            panel.reset_ai_button()
        except Exception:
            pass

    def _apply_ai_remediation_error(self, error: str) -> None:
        """Display AI remediation error (main thread)."""
        try:
            panel = self.query_one("#control-detail", ControlDetailPanel)
            output = panel.query_one("#ai-remediation-output", Static)
            output.update(f"[red]AI remediation failed: {error}[/]")
            output.remove_class("--hidden")
            panel.reset_ai_button()
        except Exception:
            pass

    # ----- Escape to close -------------------------------------------------

    def action_close_detail(self) -> None:
        """Close the control detail panel on Escape."""
        try:
            panel = self.query_one("#control-detail", ControlDetailPanel)
            if panel.is_visible:
                panel.dismiss()
        except Exception:
            pass

    # ----- Existing event handlers -----------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle status filter dropdown change."""
        if event.select.id == "status-filter":
            self._status_filter = str(event.value)
            self._refresh_data()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle search box input."""
        if event.input.id == "search-box":
            self._search_term = event.value.strip()
            self._refresh_data()

    def on_framework_selector_framework_changed(
        self, message: FrameworkSelector.FrameworkChanged
    ) -> None:
        """Handle framework selection from the sidebar."""
        self._current_framework = message.framework
        self._refresh_data()

    def refresh_data(self) -> None:
        """Public method for the app to trigger a data reload."""
        self._refresh_data()
