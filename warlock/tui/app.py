"""Warlock GRC Platform — Textual TUI dashboard."""

from __future__ import annotations

import logging

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header, TabbedContent, TabPane

from warlock import __version__
from warlock.tui.screens.ai_panel import AIPanelScreen
from warlock.tui.screens.coverage import CoverageScreen
from warlock.tui.screens.findings import FindingsScreen
from warlock.tui.screens.issues import IssuesScreen
from warlock.tui.screens.overview import OverviewScreen
from warlock.tui.screens.pipeline import PipelineScreen
from warlock.tui.screens.risk import RiskScreen

log = logging.getLogger(__name__)


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

    AUTO_REFRESH_SECONDS: int = 30

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(id="main-tabs"):
            with TabPane("Overview", id="tab-overview"):
                yield OverviewScreen()
            with TabPane("Coverage", id="tab-coverage"):
                yield CoverageScreen()
            with TabPane("Findings", id="tab-findings"):
                yield FindingsScreen()
            with TabPane("Risk", id="tab-risk"):
                yield RiskScreen()
            with TabPane("Issues", id="tab-issues"):
                yield IssuesScreen()
            with TabPane("Pipeline", id="tab-pipeline"):
                yield PipelineScreen()
            with TabPane("AI", id="tab-ai"):
                yield AIPanelScreen()
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(self.AUTO_REFRESH_SECONDS, self._auto_refresh)

    def action_refresh(self) -> None:
        self.notify("Data refreshed", severity="information", timeout=2)

    def action_help(self) -> None:
        self.notify(
            "q=Quit  r=Refresh  Tab=Next tab  ?=Help",
            severity="information",
            timeout=5,
        )

    def _auto_refresh(self) -> None:
        pass  # TODO: wire per-tab refresh


def main() -> None:
    """Entry point for the TUI dashboard."""
    app = WarlockDashboard()
    app.run()


if __name__ == "__main__":
    main()
