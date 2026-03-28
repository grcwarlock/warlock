"""Command palette overlay — Ctrl+K fuzzy search across entities and commands."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Input, Static


# Static command registry — introspected from Click at startup
_COMMAND_REGISTRY: list[dict] = []


def build_command_registry() -> None:
    """Introspect Click command tree to populate the command registry."""
    global _COMMAND_REGISTRY
    if _COMMAND_REGISTRY:
        return
    try:
        from warlock.cli import cli as click_cli

        for name, cmd in sorted(click_cli.commands.items()):
            help_text = (
                cmd.get_short_help_str() if hasattr(cmd, "get_short_help_str") else ""
            ) or ""
            _COMMAND_REGISTRY.append(
                {
                    "type": "command",
                    "id": name,
                    "label": f"warlock {name}",
                    "detail": help_text[:80],
                }
            )
    except Exception:
        pass


def _fuzzy_match(query: str, text: str) -> bool:
    """Simple substring match."""
    return query.lower() in text.lower()


def _search(query: str) -> list[dict]:
    """Search commands and entities."""
    if not query or len(query) < 1:
        # Show recent/popular commands
        return _COMMAND_REGISTRY[:10]

    results: list[dict] = []
    q = query.lower()

    # Search commands
    for cmd in _COMMAND_REGISTRY:
        if q in cmd["label"].lower() or q in cmd["detail"].lower():
            results.append(cmd)

    # Search entities
    try:
        from warlock.tui.data.queries import search_entities

        entities = search_entities(query, limit=10)
        results.extend(entities)
    except Exception:
        pass

    return results[:20]


TYPE_LABELS = {
    "command": ("CMD", "green"),
    "remediation": ("REM", "red"),
    "finding": ("FND", "yellow"),
    "control": ("CTL", "magenta"),
    "poam": ("POA", "cyan"),
}


class PaletteResult(Static):
    """Single result row in the command palette."""

    def __init__(self, result: dict, index: int) -> None:
        self.result = result
        self.result_index = index
        type_tag, _color = TYPE_LABELS.get(result["type"], ("???", "white"))
        label = result.get("label", "")
        detail = result.get("detail", "")
        super().__init__(f"[bold]{type_tag}[/] {label}  [dim]{detail}[/]")
        self.add_class("palette-result")

    def on_click(self) -> None:
        self.screen.select_result(self.result)


class CommandPalette(ModalScreen[dict | None]):
    """Modal command palette with fuzzy search."""

    BINDINGS = [
        ("escape", "dismiss_palette", "Close"),
        ("up", "move_up", "Up"),
        ("down", "move_down", "Down"),
        ("enter", "select", "Select"),
    ]

    selected_index: reactive[int] = reactive(0)

    def __init__(self) -> None:
        super().__init__()
        self._results: list[dict] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="command-palette"):
            with Vertical(id="palette-container"):
                yield Input(
                    placeholder="\u25c6 Search commands and entities...", id="palette-input"
                )
                yield VerticalScroll(id="palette-results")

    def on_mount(self) -> None:
        build_command_registry()
        self._update_results("")
        self.query_one("#palette-input", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        self._update_results(event.value)

    def _update_results(self, query: str) -> None:
        self._results = _search(query)
        self.selected_index = 0
        container = self.query_one("#palette-results", VerticalScroll)
        container.remove_children()
        for i, result in enumerate(self._results):
            widget = PaletteResult(result, i)
            if i == 0:
                widget.add_class("--selected")
            container.mount(widget)

    def watch_selected_index(self, value: int) -> None:
        for child in self.query(PaletteResult):
            child.remove_class("--selected")
            if child.result_index == value:
                child.add_class("--selected")

    def action_move_up(self) -> None:
        if self.selected_index > 0:
            self.selected_index -= 1

    def action_move_down(self) -> None:
        if self.selected_index < len(self._results) - 1:
            self.selected_index += 1

    def action_select(self) -> None:
        if self._results and 0 <= self.selected_index < len(self._results):
            self.select_result(self._results[self.selected_index])

    def select_result(self, result: dict) -> None:
        self.dismiss(result)

    def action_dismiss_palette(self) -> None:
        self.dismiss(None)
