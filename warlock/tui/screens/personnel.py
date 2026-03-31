"""Personnel view — personnel records with training status and compliance flags."""

from __future__ import annotations

from typing import Any

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import ListItem, ListView, Static

# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

TRAINING_STYLE = {
    "current": "green",
    "overdue": "bold red",
    "not_enrolled": "dim",
}

HR_STYLE = {
    "active": "green",
    "terminated": "red",
    "leave": "yellow",
}


def _training(s: str) -> str:
    style = TRAINING_STYLE.get(s, "dim")
    return f"[{style}]{s:<12}[/]"


def _hr_status(s: str) -> str:
    style = HR_STYLE.get(s, "dim")
    return f"[{style}]{s:<10}[/]"


def _risk_score(score: float | int | None) -> str:
    if score is None or score == 0:
        return "[dim]  --[/]"
    if score >= 70:
        return f"[bold red]{score:>4.0f}[/]"
    if score >= 40:
        return f"[yellow]{score:>4.0f}[/]"
    return f"[green]{score:>4.0f}[/]"


def _mfa(enabled: bool | None) -> str:
    if enabled is True:
        return "[green]\u2713[/]"
    if enabled is False:
        return "[bold red]\u2717[/]"
    return "[dim]?[/]"


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class PersonnelRow(ListItem):
    """A single personnel record in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        name = escape(d["full_name"])
        if len(name) > 24:
            name = name[:21] + "..."
        dept = escape(d["department"][:14]) if d["department"] else "[dim]\u2014[/]"
        line = (
            f"{name:<24}  {dept:<14}  "
            f"{_hr_status(d['hr_status'])}  "
            f"{_training(d['training_status'])}  "
            f"MFA {_mfa(d.get('mfa_enabled'))}  "
            f"risk {_risk_score(d.get('risk_score'))}"
        )
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail pane                                                          #
# ------------------------------------------------------------------ #


class PersonnelDetailPane(Widget):
    """Right-side detail pane for a selected personnel record."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select a person[/]"
        d = self.item
        lines: list[str] = []

        lines.append(f"[bold #a78bfa]{escape(d['full_name'])}[/]")
        if d.get("title"):
            lines.append(f"  [dim]{escape(d['title'])}[/]")
        lines.append("")
        lines.append(f"  Email        {escape(d['email'])}")
        lines.append(f"  Department   {escape(d['department']) or '[dim]\u2014[/]'}")
        lines.append(f"  Type         {escape(d['employee_type'])}")
        lines.append(f"  HR Status    {_hr_status(d['hr_status'])}")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 SECURITY[/]")
        lines.append(f"  MFA Enabled          {_mfa(d.get('mfa_enabled'))}")
        bg = d.get("background_check_status", "")
        bg_color = "green" if bg == "completed" else "yellow" if bg == "pending" else "dim"
        lines.append(f"  Background Check     [{bg_color}]{bg or 'unknown'}[/]")
        ar = d.get("access_review_status", "")
        ar_color = "green" if ar == "completed" else "red" if ar == "overdue" else "dim"
        lines.append(f"  Access Review        [{ar_color}]{ar or 'unknown'}[/]")
        lines.append(f"  Risk Score           {_risk_score(d.get('risk_score'))}")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 TRAINING[/]")
        lines.append(f"  Status       {_training(d['training_status'])}")
        if d.get("last_training_date"):
            from warlock.utils import ensure_aware

            lt = ensure_aware(d["last_training_date"])
            lines.append(f"  Last Date    [dim]{lt:%Y-%m-%d}[/]")
        phish = d.get("phishing_score")
        if phish is not None:
            p_color = "green" if phish <= 20 else "yellow" if phish <= 50 else "red"
            lines.append(f"  Phishing     [{p_color}]{phish:.0f}%[/]")
        lines.append("")

        flags = d.get("flags") or []
        if flags:
            lines.append(f"[bold red]\u25c6 FLAGS ({len(flags)})[/]")
            for flag in flags:
                lines.append(f"  [red]\u26a0[/] {escape(str(flag))}")
            lines.append("")

        fid = d.get("id", "")
        if fid:
            lines.append(f"  [dim]ID: {fid}[/]")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class PersonnelView(Vertical):
    """Personnel list with detail pane."""

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
                yield ListView(id="personnel-list")
            yield VerticalScroll(PersonnelDetailPane(id="detail-view"), id="detail-pane")
        yield Static("", id="footer-bar")

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_personnel, get_personnel_counts

            items = get_personnel()
            counts = get_personnel_counts()
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
            f" [bold]Personnel[/]  [dim]{counts['total']} people[/]"
            f"    [on dark_red] {counts['flagged']} flagged [/]"
            f"  [on #442200] {counts['overdue_training']} training overdue [/]"
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#personnel-list", ListView)
        lv.clear()
        for item in items:
            lv.append(PersonnelRow(item))

        if items:
            lv.index = 0
            lv.focus()
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading personnel:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, PersonnelRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, PersonnelRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", PersonnelDetailPane)
        detail.item = item

    def action_select_item(self) -> None:
        lv = self.query_one("#personnel-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, PersonnelRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        pass

    def action_cursor_down(self) -> None:
        self.query_one("#personnel-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#personnel-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
