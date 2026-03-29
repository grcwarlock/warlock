"""Evidence view — attestation records with freshness indicators."""

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
    "draft": "dim",
    "submitted": "yellow",
    "reviewed": "cyan",
    "approved": "green",
    "rejected": "bold red",
}


def _ev_status(s: str) -> str:
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


class EvidenceRow(ListItem):
    """A single evidence/attestation record in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        fw = escape(d["framework"])
        if len(fw) > 14:
            fw = fw[:11] + "..."
        cid = escape(d["control_id"]) if d["control_id"] else "[dim]\u2014[/]"
        if len(cid) > 12:
            cid = cid[:9] + "..."
        stmt = escape(d["statement"])
        if len(stmt) > 40:
            stmt = stmt[:37] + "..."
        refs = d.get("evidence_references") or []
        ref_count = len(refs)
        ref_label = f"[#a78bfa]{ref_count}[/]" if ref_count else "[dim]0[/]"
        line = (
            f"[#a78bfa]{fw:<14}[/]  {cid:<12}  {_ev_status(d['status'])}  "
            f"{stmt:<40}  refs {ref_label}  {_ts(d.get('created_at'))}"
        )
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail pane                                                          #
# ------------------------------------------------------------------ #


class EvidenceDetailPane(Widget):
    """Right-side detail pane for a selected evidence record."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select an evidence record[/]"
        d = self.item
        lines: list[str] = []

        fw_label = escape(d["framework"])
        cid_label = escape(d["control_id"]) if d["control_id"] else "(framework-level)"
        lines.append(f"[bold #a78bfa]{fw_label} {cid_label}[/]")
        lines.append("")
        lines.append(f"  Status       {_ev_status(d['status'])}")
        lines.append(f"  Created      {_ts(d.get('created_at'))}")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 STATEMENT[/]")
        stmt = escape(d["statement"])
        # Word-wrap long statements
        while len(stmt) > 70:
            lines.append(f"  {stmt[:70]}")
            stmt = stmt[70:]
        lines.append(f"  {stmt}")
        lines.append("")

        # Actors
        lines.append("[bold #a78bfa]\u25c6 WORKFLOW[/]")
        if d.get("prepared_by"):
            lines.append(f"  Prepared by  {escape(d['prepared_by'])}")
        if d.get("reviewed_by"):
            lines.append(f"  Reviewed by  {escape(d['reviewed_by'])}")
        if d.get("approved_by"):
            lines.append(f"  Approved by  [green]{escape(d['approved_by'])}[/]")
        lines.append("")

        # Evidence references
        refs = d.get("evidence_references") or []
        if refs:
            lines.append(f"[bold #a78bfa]\u25c6 EVIDENCE REFERENCES ({len(refs)})[/]")
            for ref in refs[:10]:
                desc = ref.get("description", "attachment") if isinstance(ref, dict) else str(ref)
                lines.append(f"  \u2022 {escape(str(desc))}")
            lines.append("")

        fid = d.get("id", "")
        if fid:
            lines.append(f"  [dim]ID: {fid}[/]")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class EvidenceView(Vertical):
    """Evidence/attestation list with detail pane."""

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
                yield ListView(id="evidence-list")
            yield VerticalScroll(EvidenceDetailPane(id="detail-view"), id="detail-pane")
        yield Static("", id="footer-bar")

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_evidence_records, get_evidence_counts

            items = get_evidence_records()
            counts = get_evidence_counts()
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
            f" [bold]Evidence[/]  [dim]{counts['total']} records[/]"
            f"    [on #003300] {counts['approved']} approved [/]"
            f"  [dim]{counts['draft']} draft[/]"
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#evidence-list", ListView)
        lv.clear()
        for item in items:
            lv.append(EvidenceRow(item))

        if items:
            lv.index = 0
            lv.focus()
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading evidence:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, EvidenceRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, EvidenceRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", EvidenceDetailPane)
        detail.item = item

    def action_select_item(self) -> None:
        lv = self.query_one("#evidence-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, EvidenceRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        pass

    def action_cursor_down(self) -> None:
        self.query_one("#evidence-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#evidence-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
