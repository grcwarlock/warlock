"""Alerts view — active alerts with severity colors and acknowledge/dismiss."""

from __future__ import annotations

from typing import Any

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import ListItem, ListView, Static

from warlock.utils import ensure_aware

# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

SEV_STYLE = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "dim",
    "info": "dim",
}

STATUS_STYLE = {
    "open": "yellow",
    "acknowledged": "cyan",
    "investigating": "dodger_blue2",
    "resolved": "green",
    "dismissed": "dim",
}


def _sev(s: str) -> str:
    style = SEV_STYLE.get(s, "white")
    return f"[{style}]{s:<8}[/]"


def _status(s: str) -> str:
    style = STATUS_STYLE.get(s, "white")
    return f"[{style}]{s:<14}[/]"


def _ts(dt) -> str:
    if dt is None:
        return "[dim]\u2014[/]"
    aware = ensure_aware(dt)
    return f"[dim]{aware:%Y-%m-%d %H:%M}[/]"


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class AlertRow(ListItem):
    """A single alert in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        title = escape(d["title"])
        if len(title) > 44:
            title = title[:41] + "..."
        cat = escape(d["category"][:14]) if d["category"] else "[dim]\u2014[/]"
        line = (
            f"{_sev(d['severity'])} {_status(d['status'])} "
            f"{title:<44}  {cat:<14}  {_ts(d.get('triggered_at'))}"
        )
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail pane                                                          #
# ------------------------------------------------------------------ #


class AlertDetailPane(Widget):
    """Right-side detail pane for a selected alert."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select an alert[/]"
        d = self.item
        lines: list[str] = []

        lines.append(f"[bold #a78bfa]{escape(d['title'])}[/]")
        lines.append("")
        lines.append(f"  Severity     {_sev(d['severity'])}")
        lines.append(f"  Status       {_status(d['status'])}")
        lines.append(f"  Category     {escape(d['category'])}")
        lines.append(f"  Triggered    {_ts(d.get('triggered_at'))}")

        if d.get("framework"):
            lines.append(
                f"  Framework    [#a78bfa]{escape(d['framework'])} "
                f"{escape(d.get('control_id', ''))}[/]"
            )
        if d.get("connector_name"):
            lines.append(f"  Connector    [dim]{escape(d['connector_name'])}[/]")
        if d.get("rule_name"):
            lines.append(f"  Rule         [dim]{escape(d['rule_name'])}[/]")
        lines.append("")

        if d.get("description"):
            lines.append("[bold #a78bfa]\u25c6 DESCRIPTION[/]")
            desc = escape(d["description"])
            if len(desc) > 300:
                desc = desc[:297] + "..."
            lines.append(f"  {desc}")
            lines.append("")

        if d.get("acknowledged_by"):
            lines.append(f"  Acknowledged by  {escape(d['acknowledged_by'])}")
        if d.get("resolved_by"):
            lines.append(f"  Resolved by      [green]{escape(d['resolved_by'])}[/]")
        if d.get("resolution_notes"):
            lines.append(f"  Resolution       {escape(d['resolution_notes'])}")
        lines.append("")

        fid = d.get("id", "")
        if fid:
            lines.append(f"  [dim]ID: {fid}[/]")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class AlertsView(Vertical):
    """Alerts list with detail pane."""

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
                yield ListView(id="alert-list")
            yield VerticalScroll(AlertDetailPane(id="detail-view"), id="detail-pane")
        yield Static("", id="footer-bar")

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_alert_counts, get_alerts

            items = get_alerts()
            counts = get_alert_counts()
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
            f" [bold]Alerts[/]  [dim]{counts['total']} total[/]"
            f"    [on dark_red] {counts['open']} open [/]"
            f"  [on dark_red] {counts['critical']} critical [/]"
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#alert-list", ListView)
        lv.clear()
        for item in items:
            lv.append(AlertRow(item))

        if items:
            lv.index = 0
            lv.focus()
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading alerts:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, AlertRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, AlertRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", AlertDetailPane)
        detail.item = item

    def action_select_item(self) -> None:
        lv = self.query_one("#alert-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, AlertRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        pass

    def action_cursor_down(self) -> None:
        self.query_one("#alert-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#alert-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
