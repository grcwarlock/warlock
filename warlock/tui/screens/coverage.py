"""Framework compliance coverage detail screen."""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.widgets import DataTable, Input, Label, Select, Static

from sqlalchemy import case, func


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

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._frameworks: list[str] = []
        self._current_framework: str = ""
        self._status_filter: str = "all"
        self._search_term: str = ""

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
            {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "dim",
                "info": "dim",
            }.get(severity, "")
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
