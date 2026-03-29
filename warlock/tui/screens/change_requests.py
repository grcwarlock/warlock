"""Change Requests view — change request list with CAB approval status."""

from __future__ import annotations

from typing import Any

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static, ListView, ListItem

from warlock.utils import ensure_aware


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

STATUS_STYLE = {
    "draft": "dim",
    "submitted": "yellow",
    "approved": "green",
    "rejected": "bold red",
    "implemented": "cyan",
    "rolled_back": "dark_orange",
}

CAB_STYLE = {
    "approved": "green",
    "rejected": "bold red",
    "deferred": "yellow",
}

RISK_STYLE = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "dim",
}


def _status(s: str) -> str:
    style = STATUS_STYLE.get(s, "white")
    return f"[{style}]{s:<12}[/]"


def _cab(s: str) -> str:
    if not s:
        return "[dim]pending[/]"
    style = CAB_STYLE.get(s, "white")
    return f"[{style}]{s:<10}[/]"


def _risk(s: str) -> str:
    if not s:
        return "[dim]\u2014[/]"
    style = RISK_STYLE.get(s.lower(), "dim")
    return f"[{style}]{s:<8}[/]"


def _ts(dt) -> str:
    if dt is None:
        return "[dim]\u2014[/]"
    aware = ensure_aware(dt)
    return f"[dim]{aware:%Y-%m-%d}[/]"


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class ChangeRequestRow(ListItem):
    """A single change request in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        title = escape(d["title"])
        if len(title) > 40:
            title = title[:37] + "..."
        ctype = escape(d["change_type"][:10]) if d["change_type"] else "[dim]\u2014[/]"
        line = (
            f"{_status(d['status'])} {title:<40}  {ctype:<10}  "
            f"{_risk(d['risk_level'])}  CAB {_cab(d.get('cab_decision', ''))}  "
            f"{_ts(d.get('created_at'))}"
        )
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail pane                                                          #
# ------------------------------------------------------------------ #


class ChangeRequestDetailPane(Widget):
    """Right-side detail pane for a selected change request."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select a change request[/]"
        d = self.item
        lines: list[str] = []

        lines.append(f"[bold #a78bfa]{escape(d['title'])}[/]")
        lines.append("")
        lines.append(f"  Status       {_status(d['status'])}")
        lines.append(f"  Type         {escape(d.get('change_type') or '--')}")
        lines.append(f"  Risk Level   {_risk(d.get('risk_level', ''))}")
        lines.append(f"  Requester    {escape(d['requester'])}")
        lines.append(f"  Created      {_ts(d.get('created_at'))}")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 CAB REVIEW[/]")
        lines.append(f"  Decision     {_cab(d.get('cab_decision', ''))}")
        if d.get("implementation_date"):
            lines.append(f"  Implement    {_ts(d['implementation_date'])}")
        lines.append("")

        if d.get("description"):
            lines.append("[bold #a78bfa]\u25c6 DESCRIPTION[/]")
            desc = escape(d["description"])
            if len(desc) > 300:
                desc = desc[:297] + "..."
            lines.append(f"  {desc}")
            lines.append("")

        if d.get("rollback_plan"):
            lines.append("[bold #a78bfa]\u25c6 ROLLBACK PLAN[/]")
            lines.append(f"  {escape(d['rollback_plan'])}")
            lines.append("")

        fid = d.get("id", "")
        if fid:
            lines.append(f"  [dim]ID: {fid}[/]")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class ChangeRequestsView(Vertical):
    """Change requests list with detail pane."""

    can_focus = True

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("enter", "select_item", "Select", show=False),
        Binding("escape", "go_back", "Back", show=False),
        Binding("r", "refresh_data", "Refresh", show=False),
    ]

    _items: reactive[list[dict]] = reactive(list, layout=True)

    def compose(self) -> ComposeResult:
        yield Static("", id="header-bar")
        with Horizontal():
            with Vertical(id="list-panel"):
                yield ListView(id="cr-list")
            yield VerticalScroll(ChangeRequestDetailPane(id="detail-view"), id="detail-pane")
        yield Static("", id="footer-bar")

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import (
                get_change_requests,
                get_change_request_counts,
            )

            items = get_change_requests()
            counts = get_change_request_counts()
            self.app.call_from_thread(self._set_data, items, counts)
        except Exception as e:
            try:
                self.app.call_from_thread(self._set_error, str(e))
            except Exception:
                pass

    def _set_data(self, items: list[dict], counts: dict) -> None:
        self._items = items

        header = self.query_one("#header-bar", Static)
        header.update(
            f" [bold]Change Requests[/]  [dim]{counts['total']} total[/]"
            f"    [on #442200] {counts['pending']} pending CAB [/]"
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#cr-list", ListView)
        lv.clear()
        for item in items:
            lv.append(ChangeRequestRow(item))

        if items:
            lv.index = 0
            lv.focus()
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading change requests:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, ChangeRequestRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, ChangeRequestRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", ChangeRequestDetailPane)
        detail.item = item

    def action_select_item(self) -> None:
        lv = self.query_one("#cr-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, ChangeRequestRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        pass

    def action_cursor_down(self) -> None:
        self.query_one("#cr-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#cr-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
