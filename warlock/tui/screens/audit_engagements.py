"""Audit Engagements view — engagement list with auditor info and status."""

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
    "active": "green",
    "completed": "cyan",
    "archived": "dim",
}


def _eng_status(s: str) -> str:
    style = STATUS_STYLE.get(s, "white")
    return f"[{style}]{s:<10}[/]"


def _ts(dt) -> str:
    if dt is None:
        return "[dim]\u2014[/]"
    aware = ensure_aware(dt)
    return f"[dim]{aware:%Y-%m-%d}[/]"


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class EngagementRow(ListItem):
    """A single audit engagement in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        name = escape(d["name"])
        if len(name) > 34:
            name = name[:31] + "..."
        fw = escape(d["framework"][:14]) if d["framework"] else "[dim]\u2014[/]"
        auditor = escape(d["auditor_firm"][:16]) if d["auditor_firm"] else "[dim]\u2014[/]"
        line = (
            f"{name:<34}  [#a78bfa]{fw:<14}[/]  {_eng_status(d['status'])}  "
            f"{_ts(d.get('period_start'))} \u2014 {_ts(d.get('period_end'))}  "
            f"{auditor}"
        )
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail pane                                                          #
# ------------------------------------------------------------------ #


class EngagementDetailPane(Widget):
    """Right-side detail pane for a selected audit engagement."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select an engagement[/]"
        d = self.item
        lines: list[str] = []

        lines.append(f"[bold #a78bfa]{escape(d['name'])}[/]")
        lines.append("")
        lines.append(f"  Framework    [#a78bfa]{escape(d['framework'])}[/]")
        lines.append(f"  Status       {_eng_status(d['status'])}")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 AUDIT PERIOD[/]")
        lines.append(f"  Start        {_ts(d.get('period_start'))}")
        lines.append(f"  End          {_ts(d.get('period_end'))}")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 AUDITOR[/]")
        if d.get("auditor_name"):
            lines.append(f"  Name         {escape(d['auditor_name'])}")
        if d.get("auditor_firm"):
            lines.append(f"  Firm         {escape(d['auditor_firm'])}")
        lines.append("")

        fid = d.get("id", "")
        if fid:
            lines.append(f"  [dim]ID: {fid}[/]")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class AuditEngagementsView(Vertical):
    """Audit engagements list with detail pane."""

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
                yield ListView(id="engagement-list")
            yield VerticalScroll(EngagementDetailPane(id="detail-view"), id="detail-pane")
        yield Static("", id="footer-bar")

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_audit_engagements

            items = get_audit_engagements()
            self.app.call_from_thread(self._set_data, items)
        except Exception as e:
            try:
                self.app.call_from_thread(self._set_error, str(e))
            except Exception:
                pass

    def _set_data(self, items: list[dict]) -> None:
        self._items = items

        active = sum(1 for i in items if i["status"] == "active")
        header = self.query_one("#header-bar", Static)
        header.update(
            f" [bold]Audit Engagements[/]  [dim]{len(items)} engagements[/]"
            f"    [on #003300] {active} active [/]"
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#engagement-list", ListView)
        lv.clear()
        for item in items:
            lv.append(EngagementRow(item))

        if items:
            lv.index = 0
            lv.focus()
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading engagements:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, EngagementRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, EngagementRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", EngagementDetailPane)
        detail.item = item

    def action_select_item(self) -> None:
        lv = self.query_one("#engagement-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, EngagementRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        pass

    def action_cursor_down(self) -> None:
        self.query_one("#engagement-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#engagement-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
