"""Warlock GRC Platform — Textual TUI dashboard."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header, Static, TabbedContent, TabPane

from warlock import __version__
from warlock.tui.screens.coverage import CoverageScreen
from warlock.tui.screens.overview import OverviewScreen


class WarlockDashboard(App):
    """Main TUI application for the Warlock GRC Platform."""

    CSS_PATH = "app.tcss"
    TITLE = "Warlock GRC Platform"
    SUB_TITLE = f"v{__version__}"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("question_mark", "help", "Help"),
    ]

    # Auto-refresh interval in seconds
    AUTO_REFRESH_SECONDS: int = 30

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(id="main-tabs"):
            with TabPane("Overview", id="tab-overview"):
                yield OverviewScreen(id="overview-screen")
            with TabPane("Coverage", id="tab-coverage"):
                yield CoverageScreen(id="coverage-screen")
            with TabPane("Findings", id="tab-findings"):
                yield Static(
                    "[dim]Findings screen — coming soon[/dim]",
                    classes="placeholder-tab",
                )
            with TabPane("Risk", id="tab-risk"):
                yield Static(
                    "[dim]Risk analysis screen — coming soon[/dim]",
                    classes="placeholder-tab",
                )
            with TabPane("Issues", id="tab-issues"):
                yield Static(
                    "[dim]Issues screen — coming soon[/dim]",
                    classes="placeholder-tab",
                )
            with TabPane("Pipeline", id="tab-pipeline"):
                yield Static(
                    "[dim]Pipeline screen — coming soon[/dim]",
                    classes="placeholder-tab",
                )
            with TabPane("AI", id="tab-ai"):
                yield Static(
                    "[dim]AI reasoning screen — coming soon[/dim]",
                    classes="placeholder-tab",
                )
        yield Footer()

    def on_mount(self) -> None:
        """Start auto-refresh timer."""
        self.set_interval(self.AUTO_REFRESH_SECONDS, self._auto_refresh)

    def action_refresh(self) -> None:
        """Manually refresh all visible data."""
        self._refresh_active_tab()
        self.notify("Data refreshed", severity="information", timeout=2)

    def action_help(self) -> None:
        """Show keybinding help."""
        self.notify(
            "q=Quit  r=Refresh  Tab=Next tab  ?=Help",
            severity="information",
            timeout=5,
        )

    def _auto_refresh(self) -> None:
        """Timer callback: silently refresh the active tab's data."""
        self._refresh_active_tab()

    def _refresh_active_tab(self) -> None:
        """Refresh data on whichever tab is currently visible."""
        try:
            overview = self.query_one("#overview-screen", OverviewScreen)
            # Check if the overview tab is active by testing if it's visible
            if overview.display:
                overview.refresh_data()
        except Exception:
            pass

        try:
            coverage = self.query_one("#coverage-screen", CoverageScreen)
            if coverage.display:
                coverage.refresh_data()
        except Exception:
            pass


def main() -> None:
    """Entry point for the TUI dashboard."""
    app = WarlockDashboard()
    app.run()


if __name__ == "__main__":
    main()
