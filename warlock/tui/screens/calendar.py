"""Compliance Calendar view — upcoming deadlines with countdown."""

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

STATUS_STYLE = {
    "pending": "yellow",
    "in_progress": "dodger_blue2",
    "completed": "green",
    "overdue": "bold red",
}

FREQ_STYLE = {
    "monthly": "cyan",
    "quarterly": "#a78bfa",
    "annual": "dark_orange",
}


def _ob_status(s: str) -> str:
    style = STATUS_STYLE.get(s, "dim")
    return f"[{style}]{s:<12}[/]"


def _freq(s: str) -> str:
    if not s:
        return "[dim]\u2014[/]"
    style = FREQ_STYLE.get(s.lower(), "dim")
    return f"[{style}]{s:<10}[/]"


def _countdown(item: dict) -> str:
    days = item.get("days_until_due")
    if days is None:
        return "[dim]\u2014[/]"
    if item.get("overdue"):
        return f"[bold red]{abs(days)}d overdue[/]"
    if days <= 7:
        return f"[yellow]{days}d[/]"
    if days <= 30:
        return f"[cyan]{days}d[/]"
    return f"[dim]{days}d[/]"


def _ts(dt) -> str:
    if dt is None:
        return "[dim]\u2014[/]"
    aware = ensure_aware(dt)
    return f"[dim]{aware:%Y-%m-%d}[/]"


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class ObligationRow(ListItem):
    """A single compliance obligation in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        title = escape(d["title"])
        if len(title) > 40:
            title = title[:37] + "..."
        fw = escape(d["framework"][:12]) if d["framework"] else "[dim]\u2014[/]"
        otype = escape(d["obligation_type"][:10]) if d["obligation_type"] else "[dim]\u2014[/]"
        line = (
            f"{_countdown(d):<14}  {_ob_status(d['status'])}  "
            f"{title:<40}  [#a78bfa]{fw:<12}[/]  {otype:<10}  "
            f"{_freq(d.get('frequency', ''))}"
        )
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail pane                                                          #
# ------------------------------------------------------------------ #


class CalendarDetailPane(Widget):
    """Right-side detail pane for a selected obligation."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select an obligation[/]"
        d = self.item
        lines: list[str] = []

        lines.append(f"[bold #a78bfa]{escape(d['title'])}[/]")
        lines.append("")
        lines.append(f"  Status       {_ob_status(d['status'])}")
        lines.append(f"  Countdown    {_countdown(d)}")
        lines.append(f"  Next Due     {_ts(d.get('next_due'))}")
        lines.append(f"  Frequency    {_freq(d.get('frequency', ''))}")
        if d.get("framework"):
            lines.append(f"  Framework    [#a78bfa]{escape(d['framework'])}[/]")
        if d.get("obligation_type"):
            lines.append(f"  Type         {escape(d['obligation_type'])}")
        if d.get("owner"):
            lines.append(f"  Owner        {escape(d['owner'])}")
        lines.append("")

        if d.get("overdue"):
            lines.append("[bold red]\u26a0 OVERDUE \u2014 immediate action required[/]")
            lines.append("")

        fid = d.get("id", "")
        if fid:
            lines.append(f"  [dim]ID: {fid}[/]")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class CalendarView(Vertical):
    """Compliance calendar list with detail pane."""

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
                yield ListView(id="calendar-list")
            yield VerticalScroll(CalendarDetailPane(id="detail-view"), id="detail-pane")
        yield Static("", id="footer-bar")

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_compliance_obligations

            items = get_compliance_obligations()
            self.app.call_from_thread(self._set_data, items)
        except Exception as e:
            try:
                self.app.call_from_thread(self._set_error, str(e))
            except Exception:
                pass

    def _set_data(self, items: list[dict]) -> None:
        self._items = items

        overdue = sum(1 for i in items if i.get("overdue"))
        header = self.query_one("#header-bar", Static)
        header.update(
            f" [bold]Compliance Calendar[/]  [dim]{len(items)} obligations[/]"
            + (f"    [on dark_red] {overdue} overdue [/]" if overdue else "")
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#calendar-list", ListView)
        lv.clear()
        for item in items:
            lv.append(ObligationRow(item))

        if items:
            lv.index = 0
            lv.focus()
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading calendar:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, ObligationRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, ObligationRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", CalendarDetailPane)
        detail.item = item

    def action_select_item(self) -> None:
        lv = self.query_one("#calendar-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, ObligationRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        pass

    def action_cursor_down(self) -> None:
        self.query_one("#calendar-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#calendar-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
