"""Findings view — severity-prioritized finding list with detail pane."""

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


SEV_STYLE = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "dim",
}


def _sev(s: str) -> str:
    style = SEV_STYLE.get(s, "white")
    return f"[{style}]{s:<8}[/]"


def _ts(dt) -> str:
    if dt is None:
        return "[dim]\u2014[/]"
    aware = ensure_aware(dt)
    return f"[dim]{aware:%Y-%m-%d %H:%M}[/]"


class FindingRow(ListItem):
    """A single finding in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        source = escape(d["source"][:14]) if d["source"] else "[dim]\u2014[/]"
        title = escape(d["title"])
        if len(title) > 44:
            title = title[:41] + "..."
        obs_type = d.get("observation_type", "")[:14]
        line = (
            f"{_sev(d['severity'])} {source:<14}  {title:<44}  "
            f"[#a78bfa]{obs_type:<14}[/]  {_ts(d.get('ingested_at'))}"
        )
        yield Static(line)


class FindingDetailPane(Widget):
    """Right-side detail pane showing selected finding info."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select a finding[/]"
        d = self.item
        lines: list[str] = []

        lines.append(f"[bold #a78bfa]{escape(d['title'])}[/]")
        lines.append("")
        lines.append(f"  Severity    {_sev(d['severity'])}")
        lines.append(f"  Source      {escape(d['source']) or '[dim]\u2014[/]'}")
        lines.append(f"  Type        {d.get('observation_type', '')}")
        lines.append(f"  Ingested    {_ts(d.get('ingested_at'))}")
        lines.append("")

        resource = d.get("resource_type", "")
        provider = d.get("provider", "")
        if resource or provider:
            lines.append("[bold #a78bfa]\u25c6 RESOURCE[/]")
            if provider:
                lines.append(f"  Provider    [#a78bfa]{escape(provider)}[/]")
            if resource:
                lines.append(f"  Type        [#a78bfa]{escape(resource)}[/]")
            lines.append("")

        fid = d.get("id", "")
        if fid:
            lines.append(f"  [dim]ID: {fid}[/]")

        return "\n".join(lines)


class FindingsView(Vertical):
    """Findings list with detail pane."""

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
                yield ListView(id="finding-list")
            yield VerticalScroll(FindingDetailPane(id="detail-view"), id="detail-pane")
        yield Static("", id="footer-bar")

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_findings, get_finding_counts

            items = get_findings()
            counts = get_finding_counts()
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
            f" [bold]Findings[/]  [dim]{counts['total']} total[/]"
            f"    [on dark_red] {counts['critical']} critical [/]"
            f"  [on #442200] {counts['high']} high [/]"
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#finding-list", ListView)
        lv.clear()
        for item in items:
            lv.append(FindingRow(item))

        if items:
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading findings:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, FindingRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, FindingRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", FindingDetailPane)
        detail.item = item

    def action_select_item(self) -> None:
        lv = self.query_one("#finding-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, FindingRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        pass

    def action_cursor_down(self) -> None:
        self.query_one("#finding-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#finding-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
