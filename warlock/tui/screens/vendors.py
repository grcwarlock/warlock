"""Vendors screen — vendor risk list with detail pane."""

from __future__ import annotations

from typing import Any

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Static, ListView, ListItem


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

TIER_STYLE = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "dim",
}

STATUS_STYLE = {
    "active": "green",
    "under_review": "yellow",
    "suspended": "red",
    "inactive": "dim",
    "onboarding": "dodger_blue2",
}


def _tier(t: str) -> str:
    style = TIER_STYLE.get(t.lower(), "white") if t else "dim"
    return f"[{style}]{(t or '--'):<8}[/]"


def _vendor_status(s: str) -> str:
    style = STATUS_STYLE.get(s.lower(), "white") if s else "dim"
    return f"[{style}]{(s or '--'):<12}[/]"


def _risk_score(score: float | int | None) -> str:
    if score is None:
        return "[dim]  --[/]"
    if score >= 80:
        return f"[bold red]{score:>4.0f}[/]"
    if score >= 50:
        return f"[yellow]{score:>4.0f}[/]"
    return f"[green]{score:>4.0f}[/]"


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class VendorRow(ListItem):
    """A single vendor in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        name = escape(d["name"])
        if len(name) > 30:
            name = name[:27] + "..."
        line = f"{name:<30}  {_tier(d.get('tier', ''))}  risk {_risk_score(d.get('risk_score'))}"
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail pane                                                          #
# ------------------------------------------------------------------ #


class VendorDetailPane(Widget):
    """Right-side detail pane for a selected vendor."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select a vendor[/]"
        d = self.item
        lines: list[str] = []

        lines.append(f"[bold #a78bfa]{escape(d['name'])}[/]")
        lines.append("")
        lines.append(f"  ID         [dim]{d['id'][:12]}[/]")
        lines.append(f"  Tier       {_tier(d.get('tier', ''))}")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 RISK ASSESSMENT[/]")
        score = d.get("risk_score")
        lines.append(f"  Risk score  {_risk_score(score)}")
        if score is not None:
            bar_width = 20
            filled = int(min(score, 100) / 100 * bar_width)
            empty = bar_width - filled
            if score >= 80:
                color = "red"
            elif score >= 50:
                color = "yellow"
            else:
                color = "green"
            lines.append(f"  [{color}]{'█' * filled}[/][dim]{'░' * empty}[/]")
            lines.append("")
            if score >= 80:
                lines.append("[bold red]\u26a0 HIGH RISK — immediate review required[/]")
            elif score >= 50:
                lines.append("[yellow]\u26a0 Moderate risk — monitor closely[/]")
            else:
                lines.append("[green]\u2713 Low risk[/]")
        else:
            lines.append("  [dim]No risk score available[/]")
        lines.append("")

        tier = (d.get("tier") or "").lower()
        if tier:
            lines.append("[bold #a78bfa]\u25c6 TIER DETAILS[/]")
            tier_desc = {
                "critical": "Business-critical vendor. Disruption causes major impact.",
                "high": "Important vendor. Disruption causes significant impact.",
                "medium": "Standard vendor. Disruption causes moderate impact.",
                "low": "Non-critical vendor. Disruption causes minimal impact.",
            }
            desc = tier_desc.get(tier, f"Tier: {tier}")
            lines.append(f"  {desc}")
            lines.append("")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# Screen                                                               #
# ------------------------------------------------------------------ #


class VendorsScreen(Screen):
    """Vendors list with detail pane."""

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("enter", "select_vendor", "Select"),
        Binding("escape", "go_back", "Back", show=False),
        Binding("r", "refresh_data", "Refresh"),
    ]

    _items: reactive[list[dict]] = reactive(list, layout=True)

    def compose(self) -> ComposeResult:
        with Horizontal(id="main-content"):
            with Vertical(id="list-panel"):
                yield Static("", id="header-bar")
                yield ListView(id="vendor-list")
                yield Static("", id="footer-bar")
            yield VerticalScroll(VendorDetailPane(id="detail-view"), id="detail-pane")

    def on_mount(self) -> None:
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_vendors

            items = get_vendors()
            self.app.call_from_thread(self._set_data, items)
        except Exception as e:
            self.app.call_from_thread(self._set_error, str(e))

    def _set_data(self, items: list[dict]) -> None:
        self._items = items

        high_risk = sum(1 for i in items if (i.get("risk_score") or 0) >= 80)
        header = self.query_one("#header-bar", Static)
        header.update(
            f" [bold]Vendors[/]  [dim]{len(items)} vendors[/]"
            + (f"    [on dark_red] {high_risk} high risk [/]" if high_risk else "")
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#vendor-list", ListView)
        lv.clear()
        for item in items:
            lv.append(VendorRow(item))

        if items:
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading vendors:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, VendorRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, VendorRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", VendorDetailPane)
        detail.item = item

    def action_select_vendor(self) -> None:
        lv = self.query_one("#vendor-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, VendorRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_cursor_down(self) -> None:
        self.query_one("#vendor-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#vendor-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
