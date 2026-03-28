"""Left navigation sidebar with icon + label nav items."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static


NAV_ITEMS = [
    ("remed", "\u2699 Remed", "Remediations"),
    ("findings", "\u26a0 Finds", "Findings"),
    ("controls", "\u25a0 Ctrls", "Controls"),
    ("poam", "\u2630 POA&M", "POA&M"),
    ("pipeline", "\u25b2 Pipe", "Pipeline"),
    ("frameworks", "\u2605 Frmwk", "Frameworks"),
    ("vendors", "\u25c6 Vendor", "Vendors"),
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


class Sidebar(Widget):
    """Persistent left navigation sidebar."""

    active_screen: reactive[str] = reactive("remed")

    def compose(self) -> ComposeResult:
        with Vertical(id="sidebar"):
            yield Static("\u25c6 WRLK", id="sidebar-logo")
            for i, (screen_id, label, _full_name) in enumerate(NAV_ITEMS):
                yield NavItem(screen_id, label, _full_name, i)
            yield Static("\u2318K  ?", id="sidebar-footer")

    def watch_active_screen(self, value: str) -> None:
        for child in self.query(NavItem):
            child.remove_class("--active")
            if child.screen_id == value:
                child.add_class("--active")
