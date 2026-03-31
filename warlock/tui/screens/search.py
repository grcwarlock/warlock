"""Search view — full-text search with results across all entities."""

from __future__ import annotations

from typing import Any

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import Input, ListItem, ListView, Static

# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

TYPE_STYLE = {
    "remediation": ("REM", "red"),
    "finding": ("FND", "yellow"),
    "control": ("CTL", "magenta"),
    "poam": ("POA", "cyan"),
    "command": ("CMD", "green"),
}


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class SearchResultRow(ListItem):
    """A single search result."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        tag, color = TYPE_STYLE.get(d.get("type", ""), ("???", "white"))
        label = escape(d.get("label", ""))
        if len(label) > 60:
            label = label[:57] + "..."
        detail = escape(d.get("detail", ""))
        if len(detail) > 40:
            detail = detail[:37] + "..."
        line = f"[bold {color}]{tag}[/]  {label:<60}  [dim]{detail}[/]"
        yield Static(line)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class SearchView(Vertical):
    """Full-text search across all entities."""

    can_focus = True

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("enter", "select_result", "Select", show=False),
        Binding("escape", "go_back", "Back", show=False),
    ]

    _results: reactive[list[dict]] = reactive(list, layout=True)

    def compose(self) -> ComposeResult:
        yield Static(
            " [bold]Search[/]  [dim]type to search across all entities[/]",
            id="header-bar",
        )
        yield Input(
            placeholder="Search remediations, findings, controls, POA&Ms...",
            id="search-input",
        )
        yield VerticalScroll(ListView(id="search-results"), id="list-panel")
        yield Static(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  [#a78bfa]Enter[/] navigate  [#a78bfa]Esc[/] back",
            id="footer-bar",
        )

    def on_mount(self) -> None:
        self.query_one("#search-input", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        query = event.value.strip()
        if len(query) < 2:
            self._clear_results()
            return
        self.run_worker(lambda: self._do_search(query), thread=True)

    def _do_search(self, query: str) -> None:
        try:
            from warlock.tui.data.queries import search_entities

            results = search_entities(query, limit=50)
            self.app.call_from_thread(self._set_results, results)
        except Exception:
            pass

    def _set_results(self, results: list[dict]) -> None:
        self._results = results
        lv = self.query_one("#search-results", ListView)
        lv.clear()
        for r in results:
            lv.append(SearchResultRow(r))

        header = self.query_one("#header-bar", Static)
        header.update(f" [bold]Search[/]  [dim]{len(results)} results[/]")

        if results:
            lv.index = 0
            lv.focus()

    def _clear_results(self) -> None:
        lv = self.query_one("#search-results", ListView)
        lv.clear()
        self._results = []
        header = self.query_one("#header-bar", Static)
        header.update(" [bold]Search[/]  [dim]type to search across all entities[/]")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, SearchResultRow):
            self._navigate_to(event.item.data)

    def _navigate_to(self, result: dict) -> None:
        """Navigate to the entity's screen."""
        rtype = result.get("type", "")
        view_map = {
            "remediation": "remed",
            "finding": "findings",
            "control": "controls",
            "poam": "poam",
        }
        view_id = view_map.get(rtype)
        if view_id:
            self.app.switch_screen_by_id(view_id)

    def action_select_result(self) -> None:
        lv = self.query_one("#search-results", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, SearchResultRow):
            self._navigate_to(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        self.query_one("#search-input", Input).focus()

    def action_cursor_down(self) -> None:
        self.query_one("#search-results", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#search-results", ListView).action_cursor_up()
