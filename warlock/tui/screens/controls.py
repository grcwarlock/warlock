"""Controls view — compliance control results with detail pane."""

from __future__ import annotations

from typing import Any

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static, ListView, ListItem


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

STATUS_STYLE = {
    "compliant": "green",
    "non_compliant": "bold red",
    "partial": "yellow",
    "not_assessed": "dim",
    "not_applicable": "dim",
}


def _ctrl_status(s: str) -> str:
    style = STATUS_STYLE.get(s, "white")
    label = s.replace("_", " ")
    return f"[{style}]{label:<14}[/]"


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class ControlRow(ListItem):
    """A single control result in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        fw = escape(d["framework"])
        if len(fw) > 14:
            fw = fw[:11] + "..."
        cid = escape(d["control_id"])
        if len(cid) > 12:
            cid = cid[:9] + "..."
        title = escape(d["control_title"])
        if len(title) > 44:
            title = title[:41] + "..."
        line = f"[#a78bfa]{fw:<14}[/]  {cid:<12}  {title:<44}  {_ctrl_status(d['status'])}"
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail pane                                                          #
# ------------------------------------------------------------------ #


class ControlDetailPane(Widget):
    """Right-side detail pane showing selected control info."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select a control[/]"
        d = self.item
        lines: list[str] = []

        title = escape(d["control_title"]) if d["control_title"] else d["control_id"]
        lines.append(f"[bold #a78bfa]{title}[/]")
        lines.append("")
        lines.append(f"  Framework    [#a78bfa]{escape(d['framework'])}[/]")
        lines.append(f"  Control ID   [#a78bfa]{escape(d['control_id'])}[/]")
        lines.append(f"  Status       {_ctrl_status(d['status'])}")
        lines.append("")

        fid = d.get("id", "")
        if fid:
            lines.append(f"  [dim]ID: {fid}[/]")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class ControlsView(Vertical):
    """Control results list with detail pane."""

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
                yield ListView(id="control-list")
            yield VerticalScroll(ControlDetailPane(id="detail-view"), id="detail-pane")
        yield Static("", id="footer-bar")

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_control_results, get_control_counts

            items = get_control_results()
            counts = get_control_counts()
            self.app.call_from_thread(self._set_data, items, counts)
        except Exception as e:
            self.app.call_from_thread(self._set_error, str(e))

    def _set_data(self, items: list[dict], counts: dict) -> None:
        self._items = items

        header = self.query_one("#header-bar", Static)
        header.update(
            f" [bold]Controls[/]  [dim]{counts['total']} total[/]"
            f"    [on dark_red] {counts['non_compliant']} non-compliant [/]"
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#control-list", ListView)
        lv.clear()
        for item in items:
            lv.append(ControlRow(item))

        if items:
            lv.index = 0
            lv.focus()
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading controls:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, ControlRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, ControlRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", ControlDetailPane)
        detail.item = item

    def action_select_item(self) -> None:
        lv = self.query_one("#control-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, ControlRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        pass

    def action_cursor_down(self) -> None:
        self.query_one("#control-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#control-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
