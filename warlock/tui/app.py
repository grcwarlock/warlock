"""WarlockApp — the main Textual application.

Single-screen architecture: the sidebar is always visible, and the main
content area swaps between different view widgets (remediations, findings, etc.)
"""

from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical

from warlock.tui.widgets.sidebar import Sidebar

THEME_CSS = Path(__file__).parent / "theme.tcss"


class WarlockApp(App):
    """Warlock TUI — compliance telemetry dashboard."""

    TITLE = "Warlock"
    SUB_TITLE = "GRC Platform"
    CSS_PATH = str(THEME_CSS)

    BINDINGS = [
        Binding("ctrl+k", "command_palette", "Commands", priority=True),
        Binding("question_mark", "show_help", "Help", show=False),
        Binding("1", "switch_remed", "Remediations", show=False),
        Binding("2", "switch_findings", "Findings", show=False),
        Binding("3", "switch_controls", "Controls", show=False),
        Binding("4", "switch_poam", "POA&M", show=False),
        Binding("5", "switch_pipeline", "Pipeline", show=False),
        Binding("6", "switch_frameworks", "Frameworks", show=False),
        Binding("7", "switch_vendors", "Vendors", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._sidebar: Sidebar | None = None
        self._current_view: str = ""

    def compose(self) -> ComposeResult:
        self._sidebar = Sidebar()
        yield self._sidebar
        yield Horizontal(id="view-container")

    def on_mount(self) -> None:
        self.run_worker(self._init_db, thread=True)
        # Load the home screen
        self._switch_view("remed")

    def _init_db(self) -> None:
        try:
            from warlock.db.engine import init_db

            init_db()
        except Exception:
            pass

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
        """Build the content widget for a view."""
        from warlock.tui.screens.remediations import RemediationsView
        from warlock.tui.screens.findings import FindingsView
        from warlock.tui.screens.controls import ControlsView
        from warlock.tui.screens.poam import POAMView
        from warlock.tui.screens.pipeline import PipelineView
        from warlock.tui.screens.frameworks import FrameworksView
        from warlock.tui.screens.vendors import VendorsView

        views = {
            "remed": RemediationsView,
            "findings": FindingsView,
            "controls": ControlsView,
            "poam": POAMView,
            "pipeline": PipelineView,
            "frameworks": FrameworksView,
            "vendors": VendorsView,
        }
        cls = views.get(view_id, RemediationsView)
        return cls()

    def switch_screen_by_id(self, screen_id: str) -> None:
        """Public API for sidebar clicks."""
        self._switch_view(screen_id)

    # ---- Screen switching actions ----

    def action_switch_remed(self) -> None:
        self._switch_view("remed")

    def action_switch_findings(self) -> None:
        self._switch_view("findings")

    def action_switch_controls(self) -> None:
        self._switch_view("controls")

    def action_switch_poam(self) -> None:
        self._switch_view("poam")

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
            elif rtype == "remediation":
                self._switch_view("remed")
            elif rtype == "finding":
                self._switch_view("findings")
            elif rtype == "control":
                self._switch_view("controls")

        self.push_screen(CommandPalette(), handle_result)

    def action_show_help(self) -> None:
        self.notify(
            "1-7: screens  Ctrl+K: commands  j/k: navigate  Enter: expand  q: quit",
            title="Keyboard Shortcuts",
        )
