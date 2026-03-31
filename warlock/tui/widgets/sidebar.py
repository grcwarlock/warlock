"""Left navigation sidebar with icon + label nav items."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.reactive import reactive
from textual.widgets import Static

NAV_ITEMS = [
    ("dashboard", "\u25c6 Dash", "Dashboard"),
    ("remed", "\u2699 Remed", "Remediations"),
    ("findings", "\u26a0 Finds", "Findings"),
    ("controls", "\u25a0 Ctrls", "Controls"),
    ("poam", "\u2630 POA&M", "POA&M"),
    ("incidents", "\u2605 Issue", "Incidents"),
    ("alerts", "\u25b2 Alert", "Alerts"),
    ("evidence", "\u25a3 Evid", "Evidence"),
    ("privacy", "\u25c8 Priv", "Privacy"),
    ("pipeline", "\u25b6 Pipe", "Pipeline"),
    ("frameworks", "\u2606 Frmwk", "Frameworks"),
    ("vendors", "\u25c7 Vendr", "Vendors"),
    ("personnel", "\u263b Ppl", "Personnel"),
    ("training", "\u2713 Train", "Training"),
    ("audits", "\u2611 Audit", "Audits"),
    ("changes", "\u21c4 Chg", "Changes"),
    ("calendar", "\u25d2 Cal", "Calendar"),
    ("search", "\u2315 Srch", "Search"),
    ("reports", "\u2261 Rpt", "Reports"),
    ("risk", "\u2622 Risk", "Risk"),
]


class NavItem(Static):
    """A single navigation item in the sidebar."""

    def __init__(self, screen_id: str, label: str, full_name: str, index: int) -> None:
        super().__init__(label)
        self.screen_id = screen_id
        self.full_name = full_name
        self.nav_index = index
        self.add_class("nav-item")

    def on_click(self) -> None:
        self.app.switch_screen_by_id(self.screen_id)


class Sidebar(Vertical):
    """Persistent left navigation sidebar. IS the #sidebar element."""

    active_screen: reactive[str] = reactive("remed")

    def __init__(self) -> None:
        super().__init__(id="sidebar")

    def compose(self) -> ComposeResult:
        yield Static("\u25c6 WRLK", id="sidebar-logo")
        for i, (screen_id, label, _full_name) in enumerate(NAV_ITEMS):
            yield NavItem(screen_id, label, _full_name, i)
        yield Static("\u2318K  ?", id="sidebar-footer")

    def watch_active_screen(self, value: str) -> None:
        for child in self.query(NavItem):
            child.remove_class("--active")
            if child.screen_id == value:
                child.add_class("--active")
