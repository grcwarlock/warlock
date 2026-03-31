"""Privacy view — data silos with classification and sensitivity indicators."""

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

CLASS_STYLE = {
    "restricted": "bold red",
    "confidential": "dark_orange",
    "internal": "yellow",
    "public": "green",
    "unknown": "dim",
}


def _classification(c: str) -> str:
    style = CLASS_STYLE.get(c.lower(), "dim")
    return f"[{style}]{c:<12}[/]"


def _flags(d: dict) -> str:
    parts: list[str] = []
    if d.get("contains_pii"):
        parts.append("[bold red]PII[/]")
    if d.get("contains_phi"):
        parts.append("[bold red]PHI[/]")
    if d.get("contains_pci"):
        parts.append("[dark_orange]PCI[/]")
    return " ".join(parts) if parts else "[dim]\u2014[/]"


def _enc_status(d: dict) -> str:
    rest = d.get("encrypted_at_rest")
    transit = d.get("encrypted_in_transit")
    parts: list[str] = []
    if rest is True:
        parts.append("[green]\u2713rest[/]")
    elif rest is False:
        parts.append("[red]\u2717rest[/]")
    if transit is True:
        parts.append("[green]\u2713transit[/]")
    elif transit is False:
        parts.append("[red]\u2717transit[/]")
    return " ".join(parts) if parts else "[dim]\u2014[/]"


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class DataSiloRow(ListItem):
    """A single data silo in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        name = escape(d["name"])
        if len(name) > 28:
            name = name[:25] + "..."
        stype = escape(d["silo_type"][:14]) if d["silo_type"] else "[dim]\u2014[/]"
        line = (
            f"{name:<28}  {stype:<14}  "
            f"{_classification(d['data_classification'])}  {_flags(d):<20}  "
            f"{_enc_status(d)}"
        )
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail pane                                                          #
# ------------------------------------------------------------------ #


class PrivacyDetailPane(Widget):
    """Right-side detail pane for a selected data silo."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select a data silo[/]"
        d = self.item
        lines: list[str] = []

        lines.append(f"[bold #a78bfa]{escape(d['name'])}[/]")
        lines.append("")
        lines.append(f"  Type           {escape(d['silo_type'])}")
        if d.get("provider"):
            lines.append(f"  Provider       [#a78bfa]{escape(d['provider'])}[/]")
        lines.append(f"  Classification {_classification(d['data_classification'])}")
        lines.append(f"  Sensitive Data {_flags(d)}")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 ENCRYPTION[/]")
        rest = d.get("encrypted_at_rest")
        transit = d.get("encrypted_in_transit")
        if rest is True:
            lines.append("  At rest        [green]\u2713 Encrypted[/]")
        elif rest is False:
            lines.append("  At rest        [bold red]\u2717 NOT Encrypted[/]")
        else:
            lines.append("  At rest        [dim]Unknown[/]")
        if transit is True:
            lines.append("  In transit     [green]\u2713 Encrypted[/]")
        elif transit is False:
            lines.append("  In transit     [bold red]\u2717 NOT Encrypted[/]")
        else:
            lines.append("  In transit     [dim]Unknown[/]")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 SCAN STATUS[/]")
        scan = d.get("scan_status", "not_scanned")
        scan_color = "green" if scan == "completed" else "yellow" if scan == "scanning" else "dim"
        lines.append(f"  Status         [{scan_color}]{scan}[/]")
        lines.append(f"  Sensitive fields  [bold]{d.get('sensitive_field_count', 0)}[/]")
        if d.get("last_scan_date"):
            from warlock.utils import ensure_aware

            ls = ensure_aware(d["last_scan_date"])
            lines.append(f"  Last scan      [dim]{ls:%Y-%m-%d %H:%M}[/]")
        lines.append("")

        if d.get("owner"):
            lines.append(f"  Owner          {escape(d['owner'])}")

        fws = d.get("applicable_frameworks") or []
        if fws:
            lines.append("[bold #a78bfa]\u25c6 APPLICABLE FRAMEWORKS[/]")
            for fw in fws:
                lines.append(f"  \u2022 {escape(str(fw))}")
            lines.append("")

        fid = d.get("id", "")
        if fid:
            lines.append(f"  [dim]ID: {fid}[/]")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class PrivacyView(Vertical):
    """Privacy data silos list with detail pane."""

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
                yield ListView(id="privacy-list")
            yield VerticalScroll(PrivacyDetailPane(id="detail-view"), id="detail-pane")
        yield Static("", id="footer-bar")

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_privacy_counts, get_privacy_data_silos

            items = get_privacy_data_silos()
            counts = get_privacy_counts()
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
            f" [bold]Privacy[/]  [dim]{counts['total']} data silos[/]"
            f"    [on dark_red] {counts['pii']} PII [/]"
            f"  [on dark_red] {counts['phi']} PHI [/]"
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#privacy-list", ListView)
        lv.clear()
        for item in items:
            lv.append(DataSiloRow(item))

        if items:
            lv.index = 0
            lv.focus()
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading privacy data:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, DataSiloRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, DataSiloRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", PrivacyDetailPane)
        detail.item = item

    def action_select_item(self) -> None:
        lv = self.query_one("#privacy-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, DataSiloRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        pass

    def action_cursor_down(self) -> None:
        self.query_one("#privacy-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#privacy-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
