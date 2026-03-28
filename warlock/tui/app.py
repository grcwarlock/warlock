"""WarlockApp — the main Textual application.

Registers all screens, global keybindings, and the Arcane Elegance theme.
"""

from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding

from warlock.tui.widgets.sidebar import Sidebar


# Path to the theme CSS file
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
        self._current_screen_id = "remed"

    def on_mount(self) -> None:
        """Initialize DB and install screens."""
        # Init DB in background thread to avoid blocking UI
        self.run_worker(self._init_db, thread=True)

        # Install named screens (lazy loaded)
        from warlock.tui.screens.remediations import RemediationsScreen
        from warlock.tui.screens.findings import FindingsScreen
        from warlock.tui.screens.controls import ControlsScreen
        from warlock.tui.screens.poam import POAMScreen
        from warlock.tui.screens.pipeline import PipelineScreen
        from warlock.tui.screens.frameworks import FrameworksScreen
        from warlock.tui.screens.vendors import VendorsScreen

        self.install_screen(RemediationsScreen, name="remed")
        self.install_screen(FindingsScreen, name="findings")
        self.install_screen(ControlsScreen, name="controls")
        self.install_screen(POAMScreen, name="poam")
        self.install_screen(PipelineScreen, name="pipeline")
        self.install_screen(FrameworksScreen, name="frameworks")
        self.install_screen(VendorsScreen, name="vendors")

        # Push the home screen
        self.push_screen("remed")

    def _init_db(self) -> None:
        try:
            from warlock.db.engine import init_db

            init_db()
        except Exception:
            pass

    def compose(self) -> ComposeResult:
        self._sidebar = Sidebar()
        yield self._sidebar

    def switch_screen_by_id(self, screen_id: str) -> None:
        """Switch to a named screen, updating the sidebar."""
        if screen_id == self._current_screen_id:
            return
        self._current_screen_id = screen_id
        if self._sidebar:
            self._sidebar.active_screen = screen_id
        self.switch_screen(screen_id)

    # ---- Screen switching actions ----

    def action_switch_remed(self) -> None:
        self.switch_screen_by_id("remed")

    def action_switch_findings(self) -> None:
        self.switch_screen_by_id("findings")

    def action_switch_controls(self) -> None:
        self.switch_screen_by_id("controls")

    def action_switch_poam(self) -> None:
        self.switch_screen_by_id("poam")

    def action_switch_pipeline(self) -> None:
        self.switch_screen_by_id("pipeline")

    def action_switch_frameworks(self) -> None:
        self.switch_screen_by_id("frameworks")

    def action_switch_vendors(self) -> None:
        self.switch_screen_by_id("vendors")

    # ---- Global actions ----

    def action_command_palette(self) -> None:
        from warlock.tui.widgets.command_palette import CommandPalette

        def handle_result(result: dict | None) -> None:
            if result is None:
                return
            if result.get("type") == "command":
                # Run CLI command inline
                cmd_name = result.get("id", "")
                self.notify(f"Command: warlock {cmd_name}")
            elif result.get("type") == "remediation":
                self.switch_screen_by_id("remed")
            elif result.get("type") == "finding":
                self.switch_screen_by_id("findings")
            elif result.get("type") == "control":
                self.switch_screen_by_id("controls")

        self.push_screen(CommandPalette(), handle_result)

    def action_show_help(self) -> None:
        self.notify(
            "1-7: screens  Ctrl+K: commands  j/k: navigate  Enter: expand  q: quit",
            title="Keyboard Shortcuts",
        )
