"""WarlockApp — the main Textual application.

Single-screen architecture: the sidebar is always visible, and the main
content area swaps between different view widgets (remediations, findings, etc.)
"""

from __future__ import annotations

import logging
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical

from warlock.tui.widgets.sidebar import Sidebar

log = logging.getLogger(__name__)

THEME_CSS = Path(__file__).parent / "theme.tcss"

# View ID -> (module_path, class_name) for lazy imports
_VIEW_REGISTRY: dict[str, tuple[str, str]] = {
    "dashboard": ("warlock.tui.screens.dashboard", "DashboardView"),
    "remed": ("warlock.tui.screens.remediations", "RemediationsView"),
    "findings": ("warlock.tui.screens.findings", "FindingsView"),
    "controls": ("warlock.tui.screens.controls", "ControlsView"),
    "poam": ("warlock.tui.screens.poam", "POAMView"),
    "incidents": ("warlock.tui.screens.incidents", "IncidentsView"),
    "alerts": ("warlock.tui.screens.alerts", "AlertsView"),
    "evidence": ("warlock.tui.screens.evidence", "EvidenceView"),
    "privacy": ("warlock.tui.screens.privacy", "PrivacyView"),
    "pipeline": ("warlock.tui.screens.pipeline", "PipelineView"),
    "frameworks": ("warlock.tui.screens.frameworks", "FrameworksView"),
    "vendors": ("warlock.tui.screens.vendors", "VendorsView"),
    "personnel": ("warlock.tui.screens.personnel", "PersonnelView"),
    "training": ("warlock.tui.screens.training", "TrainingView"),
    "audits": ("warlock.tui.screens.audit_engagements", "AuditEngagementsView"),
    "changes": ("warlock.tui.screens.change_requests", "ChangeRequestsView"),
    "calendar": ("warlock.tui.screens.calendar", "CalendarView"),
    "search": ("warlock.tui.screens.search", "SearchView"),
    "reports": ("warlock.tui.screens.reports", "ReportsView"),
    "risk": ("warlock.tui.screens.risk", "RiskView"),
}


class WarlockApp(App):
    """Warlock TUI — compliance telemetry dashboard."""

    TITLE = "Warlock"
    SUB_TITLE = "GRC Platform"
    CSS_PATH = str(THEME_CSS)

    BINDINGS = [
        Binding("ctrl+k", "command_palette", "Commands", priority=True),
        Binding("question_mark", "show_help", "Help", show=False),
        Binding("1", "switch_dashboard", "Dashboard", show=False),
        Binding("2", "switch_remed", "Remediations", show=False),
        Binding("3", "switch_findings", "Findings", show=False),
        Binding("4", "switch_controls", "Controls", show=False),
        Binding("5", "switch_poam", "POA&M", show=False),
        Binding("6", "switch_incidents", "Incidents", show=False),
        Binding("7", "switch_alerts", "Alerts", show=False),
        Binding("8", "switch_evidence", "Evidence", show=False),
        Binding("9", "switch_privacy", "Privacy", show=False),
        Binding("0", "switch_pipeline", "Pipeline", show=False),
        Binding("q", "quit", "Quit"),
    ]

    # -- Dark/light mode state --
    _dark_mode: bool = True

    def __init__(self) -> None:
        super().__init__()
        self._sidebar: Sidebar | None = None
        self._current_view: str = ""
        self._saved_views: dict[str, str] = {}  # name -> view_id (Item 73)

    def compose(self) -> ComposeResult:
        self._sidebar = Sidebar()
        yield self._sidebar
        yield Horizontal(id="view-container")

    def on_mount(self) -> None:
        self.run_worker(self._init_db, thread=True)
        # Dashboard is the new home screen (Item 27)
        self._switch_view("dashboard")

    def _init_db(self) -> None:
        try:
            from warlock.db.engine import init_db

            init_db()
        except Exception:
            log.debug("Failed to initialize database on TUI startup", exc_info=True)

    def _switch_view(self, view_id: str) -> None:
        """Swap the main content area to a different view."""
        if view_id == self._current_view:
            return
        self._current_view = view_id
        if self._sidebar:
            self._sidebar.active_screen = view_id

        container = self.query_one("#view-container", Horizontal)
        container.remove_children()

        view_widget = self._build_view(view_id)
        container.mount(view_widget)

    def _build_view(self, view_id: str) -> Vertical:
        """Build the content widget for a view via lazy import."""
        import importlib

        entry = _VIEW_REGISTRY.get(view_id)
        if entry is None:
            # Fallback to dashboard
            entry = _VIEW_REGISTRY["dashboard"]

        module_path, class_name = entry
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        return cls()

    def switch_screen_by_id(self, screen_id: str) -> None:
        """Public API for sidebar clicks."""
        self._switch_view(screen_id)

    # ---- Screen switching actions ----

    def action_switch_dashboard(self) -> None:
        self._switch_view("dashboard")

    def action_switch_remed(self) -> None:
        self._switch_view("remed")

    def action_switch_findings(self) -> None:
        self._switch_view("findings")

    def action_switch_controls(self) -> None:
        self._switch_view("controls")

    def action_switch_poam(self) -> None:
        self._switch_view("poam")

    def action_switch_incidents(self) -> None:
        self._switch_view("incidents")

    def action_switch_alerts(self) -> None:
        self._switch_view("alerts")

    def action_switch_evidence(self) -> None:
        self._switch_view("evidence")

    def action_switch_privacy(self) -> None:
        self._switch_view("privacy")

    def action_switch_pipeline(self) -> None:
        self._switch_view("pipeline")

    def action_switch_frameworks(self) -> None:
        self._switch_view("frameworks")

    def action_switch_vendors(self) -> None:
        self._switch_view("vendors")

    # ---- Global actions ----

    def action_command_palette(self) -> None:
        from warlock.tui.widgets.command_palette import CommandPalette

        def handle_result(result: dict | None) -> None:
            if result is None:
                return
            rtype = result.get("type", "")
            if rtype == "command":
                cmd_name = result.get("id", "")
                self.notify(f"Command: warlock {cmd_name}")
            elif rtype == "navigate":
                view_id = result.get("id", "")
                if view_id in _VIEW_REGISTRY:
                    self._switch_view(view_id)
            elif rtype == "saved_view":
                view_id = result.get("view_id", "")
                if view_id in _VIEW_REGISTRY:
                    self._switch_view(view_id)
            elif rtype == "remediation":
                self._switch_view("remed")
            elif rtype == "finding":
                self._switch_view("findings")
            elif rtype == "control":
                self._switch_view("controls")

        self.push_screen(CommandPalette(), handle_result)

    def action_show_help(self) -> None:
        self.notify(
            "1-9,0: screens  Ctrl+K: commands  j/k: navigate  Enter: expand  q: quit",
            title="Keyboard Shortcuts",
        )

    # ---- Saved views (Item 73) ----

    def save_current_view(self, name: str) -> None:
        """Save the current view as a bookmark."""
        self._saved_views[name] = self._current_view
        self.notify(f"Saved view: {name}")

    def get_saved_views(self) -> dict[str, str]:
        """Return saved view bookmarks."""
        return dict(self._saved_views)

    # ---- Dark/light toggle (Item 115) ----

    def action_toggle_dark(self) -> None:
        """Toggle between dark and light mode."""
        self._dark_mode = not self._dark_mode
        self.dark = self._dark_mode
