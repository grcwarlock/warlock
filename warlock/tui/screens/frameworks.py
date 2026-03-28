"""Frameworks posture screen — compliance posture by framework."""

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


def _posture_color(pct: float) -> str:
    if pct >= 80:
        return "green"
    if pct >= 50:
        return "yellow"
    return "red"


def _posture_bar(pct: float, width: int = 16) -> str:
    filled = int(pct / 100 * width)
    empty = width - filled
    color = _posture_color(pct)
    return f"[{color}]{'█' * filled}[/][dim]{'░' * empty}[/]"


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class FrameworkRow(ListItem):
    """A single framework in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        name = escape(d["framework"])
        if len(name) > 24:
            name = name[:21] + "..."
        pct = d["posture_pct"]
        color = _posture_color(pct)
        nc = d["non_compliant"]
        nc_label = f"[red]{nc}[/]" if nc else "[dim]0[/]"
        line = (
            f"{name:<24}  "
            f"[{color}]{pct:>5.1f}%[/]  "
            f"{_posture_bar(pct)}  "
            f"[dim]{d['total']:>5} ctrl[/]  "
            f"nc {nc_label}"
        )
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail pane                                                          #
# ------------------------------------------------------------------ #


class FrameworkDetailPane(Widget):
    """Right-side detail pane for a selected framework."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select a framework[/]"
        d = self.item
        lines: list[str] = []

        name = escape(d["framework"])
        lines.append(f"[bold #a78bfa]{name}[/]")
        lines.append("")

        pct = d["posture_pct"]
        color = _posture_color(pct)
        lines.append(f"  Posture  [{color}]{pct:.1f}%[/]")
        lines.append(f"  {_posture_bar(pct, width=30)}")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 CONTROL BREAKDOWN[/]")
        total = d["total"]
        compliant = d["compliant"]
        non_compliant = d["non_compliant"]
        not_assessed = total - compliant - non_compliant

        lines.append(f"  Total controls      [bold]{total:>6,}[/]")
        lines.append(f"  Compliant           [green]{compliant:>6,}[/]")
        lines.append(f"  Non-compliant       [red]{non_compliant:>6,}[/]")
        lines.append(f"  Not assessed        [dim]{not_assessed:>6,}[/]")
        lines.append("")

        # Percentages
        if total > 0:
            lines.append("[bold #a78bfa]\u25c6 DISTRIBUTION[/]")
            c_pct = 100 * compliant / total
            nc_pct = 100 * non_compliant / total
            na_pct = 100 * not_assessed / total
            lines.append(f"  [green]{'█' * int(c_pct / 3)}[/] Compliant {c_pct:.1f}%")
            lines.append(f"  [red]{'█' * int(nc_pct / 3)}[/] Non-compliant {nc_pct:.1f}%")
            lines.append(f"  [dim]{'█' * int(na_pct / 3)}[/] Not assessed {na_pct:.1f}%")
            lines.append("")

        if non_compliant > 0:
            lines.append(
                f"[yellow]\u26a0 {non_compliant} control{'s' if non_compliant != 1 else ''} "
                f"require remediation[/]"
            )
        else:
            lines.append("[green]\u2713 All assessed controls are compliant[/]")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# Screen                                                               #
# ------------------------------------------------------------------ #


class FrameworksScreen(Screen):
    """Frameworks posture list with detail pane."""

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("enter", "select_fw", "Select"),
        Binding("escape", "go_back", "Back", show=False),
        Binding("r", "refresh_data", "Refresh"),
    ]

    _items: reactive[list[dict]] = reactive(list, layout=True)

    def compose(self) -> ComposeResult:
        with Horizontal(id="main-content"):
            with Vertical(id="list-panel"):
                yield Static("", id="header-bar")
                yield ListView(id="fw-list")
                yield Static("", id="footer-bar")
            yield VerticalScroll(FrameworkDetailPane(id="detail-view"), id="detail-pane")

    def on_mount(self) -> None:
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_frameworks_summary

            items = get_frameworks_summary()
            self.app.call_from_thread(self._set_data, items)
        except Exception as e:
            self.app.call_from_thread(self._set_error, str(e))

    def _set_data(self, items: list[dict]) -> None:
        self._items = items

        total_ctrl = sum(i["total"] for i in items)
        total_nc = sum(i["non_compliant"] for i in items)
        header = self.query_one("#header-bar", Static)
        header.update(
            f" [bold]Frameworks[/]  [dim]{len(items)} frameworks[/]"
            f"    [dim]{total_ctrl:,} controls[/]"
            f"  [red]{total_nc:,} non-compliant[/]"
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#fw-list", ListView)
        lv.clear()
        for item in items:
            lv.append(FrameworkRow(item))

        if items:
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading frameworks:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, FrameworkRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, FrameworkRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", FrameworkDetailPane)
        detail.item = item

    def action_select_fw(self) -> None:
        lv = self.query_one("#fw-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, FrameworkRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_cursor_down(self) -> None:
        self.query_one("#fw-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#fw-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
