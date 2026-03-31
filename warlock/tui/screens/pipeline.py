"""Pipeline runs view — list/detail view of pipeline executions."""

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

STATUS_STYLE = {
    "completed": "green",
    "running": "dodger_blue2",
    "failed": "bold red",
    "cancelled": "yellow",
    "unknown": "dim",
}


def _status(s: str) -> str:
    style = STATUS_STYLE.get(s, "dim")
    return f"[{style}]{s:<10}[/]"


def _fmt_dt(dt: Any) -> str:
    if dt is None:
        return "[dim]--[/]"
    return f"[dim]{dt:%Y-%m-%d %H:%M}[/]"


def _fmt_duration(secs: float | int | None) -> str:
    if secs is None:
        return "[dim]--[/]"
    m, s = divmod(int(secs), 60)
    return f"[dim]{m}m{s:02d}s[/]"


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class PipelineRunRow(ListItem):
    """A single pipeline run in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        short_id = d["id"][:8]
        errors = d.get("errors") or []
        err_count = len(errors)
        err_label = f"[red]{err_count}[/]" if err_count else "[dim]0[/]"
        line = (
            f"[#a78bfa]{short_id}[/]  "
            f"{_fmt_dt(d['started_at'])}  "
            f"{_fmt_duration(d.get('duration_seconds'))}  "
            f"findings [bold]{d.get('findings', 0):>5}[/]  "
            f"err {err_label}  "
            f"{_status(d['status'])}"
        )
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail pane                                                          #
# ------------------------------------------------------------------ #


class PipelineDetailPane(Widget):
    """Right-side detail pane for a selected pipeline run."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select a pipeline run[/]"
        d = self.item
        lines: list[str] = []

        lines.append(f"[bold #a78bfa]Pipeline Run {d['id'][:8]}[/]")
        lines.append("")
        lines.append(f"  Status       {_status(d['status'])}")
        lines.append(f"  Started      {_fmt_dt(d.get('started_at'))}")
        lines.append(f"  Completed    {_fmt_dt(d.get('completed_at'))}")
        lines.append(f"  Duration     {_fmt_duration(d.get('duration_seconds'))}")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 PIPELINE STATS[/]")
        lines.append(f"  Raw events       [bold]{d.get('raw_events', 0):>7,}[/]")
        lines.append(f"  Findings         [bold]{d.get('findings', 0):>7,}[/]")
        lines.append(f"  Controls mapped  [bold]{d.get('controls_mapped', 0):>7,}[/]")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 CONNECTORS[/]")
        ok = d.get("connectors_ok", 0)
        failed = d.get("connectors_failed", 0)
        lines.append(f"  Succeeded  [green]{ok}[/]")
        if failed:
            lines.append(f"  Failed     [red]{failed}[/]")
        else:
            lines.append("  Failed     [dim]0[/]")
        lines.append("")

        errors = d.get("errors") or []
        if errors:
            lines.append(f"[bold red]\u25c6 ERRORS ({len(errors)})[/]")
            for err in errors[:20]:
                if isinstance(err, dict):
                    msg = err.get("message", str(err))
                else:
                    msg = str(err)
                lines.append(f"  [red]\u2717[/] {escape(msg[:80])}")
            if len(errors) > 20:
                lines.append(f"  [dim]... and {len(errors) - 20} more[/]")
            lines.append("")
        else:
            lines.append("[dim]No errors[/]")
            lines.append("")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class PipelineView(Vertical):
    """Pipeline runs list with detail pane."""

    can_focus = True

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("enter", "select_run", "Select", show=False),
        Binding("escape", "go_back", "Back", show=False),
        Binding("r", "refresh_data", "Refresh", show=False),
    ]

    _items: reactive[list[dict]] = reactive(list, layout=True)

    def compose(self) -> ComposeResult:
        yield Static("", id="header-bar")
        with Horizontal():
            with Vertical(id="list-panel"):
                yield ListView(id="pipeline-list")
            yield VerticalScroll(PipelineDetailPane(id="detail-view"), id="detail-pane")
        yield Static("", id="footer-bar")

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_pipeline_runs

            items = get_pipeline_runs()
            self.app.call_from_thread(self._set_data, items)
        except Exception as e:
            self.app.call_from_thread(self._set_error, str(e))

    def _set_data(self, items: list[dict]) -> None:
        self._items = items

        header = self.query_one("#header-bar", Static)
        header.update(f" [bold]Pipeline Runs[/]  [dim]{len(items)} runs[/]")

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#pipeline-list", ListView)
        lv.clear()
        for item in items:
            lv.append(PipelineRunRow(item))

        if items:
            lv.index = 0
            lv.focus()
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading pipeline runs:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, PipelineRunRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, PipelineRunRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", PipelineDetailPane)
        detail.item = item

    def action_select_run(self) -> None:
        lv = self.query_one("#pipeline-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, PipelineRunRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        pass

    def action_cursor_down(self) -> None:
        self.query_one("#pipeline-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#pipeline-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
