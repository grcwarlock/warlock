"""POA&M screen — plan of action & milestones with detail pane."""

from __future__ import annotations

from typing import Any

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import ListItem, ListView, Static

from warlock.utils import ensure_aware

STATUS_STYLE = {
    "draft": "dim",
    "open": "yellow",
    "in_progress": "dodger_blue2",
    "remediated": "cyan",
    "verified": "medium_purple",
    "completed": "green",
    "risk_accepted": "dark_orange",
    "cancelled": "dim",
}
SEV_STYLE = {"critical": "bold red", "high": "dark_orange", "moderate": "yellow", "low": "dim"}


def _poam_status(s: str) -> str:
    style = STATUS_STYLE.get(s, "white")
    return f"[{style}]{s:<14}[/]"


def _sev(s: str) -> str:
    style = SEV_STYLE.get(s, "white")
    return f"[{style}]{s:<8}[/]"


def _due(dt, overdue: bool) -> str:
    if dt is None:
        return "[dim]\u2014[/]"
    aware = ensure_aware(dt)
    label = f"{aware:%Y-%m-%d}"
    if overdue:
        return f"[bold red]{label}[/]"
    return f"[dim]{label}[/]"


class POAMRow(ListItem):
    """A single POA&M in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        cid = escape(d["control_id"])
        if len(cid) > 12:
            cid = cid[:9] + "..."
        weakness = escape(d["weakness"])
        if len(weakness) > 40:
            weakness = weakness[:37] + "..."
        assignee = escape(d["assigned_to"][:12]) if d["assigned_to"] else "[dim]\u2014[/]"
        line = (
            f"{cid:<12}  {weakness:<40}  {_poam_status(d['status'])}  "
            f"{_due(d.get('due_date'), d.get('overdue', False)):<14}  {assignee}"
        )
        yield Static(line)


class POAMDetailPane(Widget):
    """Right-side detail pane showing selected POA&M info."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select a POA&M[/]"
        d = self.item
        lines: list[str] = []
        weakness = escape(d["weakness"]) if d["weakness"] else "(no weakness)"
        lines.append(f"[bold #a78bfa]{weakness}[/]")
        lines.append("")
        lines.append(f"  Control ID   [#a78bfa]{escape(d['control_id'])}[/]")
        if d.get("framework"):
            lines.append(f"  Framework    [#a78bfa]{escape(d['framework'])}[/]")
        lines.append(f"  Status       {_poam_status(d['status'])}")
        lines.append(f"  Severity     {_sev(d['severity'])}")
        lines.append(f"  Due Date     {_due(d.get('due_date'), d.get('overdue', False))}")
        assignee = escape(d["assigned_to"]) if d["assigned_to"] else "[dim]unassigned[/]"
        lines.append(f"  Assigned To  {assignee}")
        cost = d.get("cost_estimate")
        if cost is not None:
            lines.append(f"  Cost         [#a78bfa]${cost:,.2f}[/]")
        fid = d.get("id", "")
        if fid:
            lines.append(f"\n  [dim]ID: {fid}[/]")

        return "\n".join(lines)


class POAMView(Vertical):
    can_focus = True
    """POA&M list with detail pane."""

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("enter", "select_item", "Select"),
        Binding("escape", "go_back", "Back", show=False),
        Binding("r", "refresh_data", "Refresh"),
    ]

    _items: reactive[list[dict]] = reactive(list, layout=True)

    def compose(self) -> ComposeResult:

        with Vertical(id="list-panel"):
            yield Static("", id="header-bar")
            yield ListView(id="poam-list")
            yield Static("", id="footer-bar")
        yield VerticalScroll(POAMDetailPane(id="detail-view"), id="detail-pane")

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_poam_counts, get_poams

            items = get_poams()
            counts = get_poam_counts()
            self.app.call_from_thread(self._set_data, items, counts)
        except Exception as e:
            self.app.call_from_thread(self._set_error, str(e))

    def _set_data(self, items: list[dict], counts: dict) -> None:
        self._items = items

        header = self.query_one("#header-bar", Static)
        header.update(
            f" [bold]POA&Ms[/]  [dim]{counts['total']} total[/]"
            f"    [on dark_red] {counts['open']} open [/]"
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#poam-list", ListView)
        lv.clear()
        for item in items:
            lv.append(POAMRow(item))

        if items:
            lv.index = 0
            lv.focus()
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading POA&Ms:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, POAMRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, POAMRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", POAMDetailPane)
        detail.item = item

    def action_select_item(self) -> None:
        lv = self.query_one("#poam-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, POAMRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        pass

    def action_cursor_down(self) -> None:
        self.query_one("#poam-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#poam-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
