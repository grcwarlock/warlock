"""Reports view — report generation interface (select framework, type, generate)."""

from __future__ import annotations

from typing import Any

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import ListItem, ListView, Static

# ------------------------------------------------------------------ #
# Report type definitions                                              #
# ------------------------------------------------------------------ #

REPORT_TYPES = [
    {
        "id": "posture",
        "name": "Compliance Posture",
        "description": "Per-framework compliance score with control breakdown",
    },
    {
        "id": "gap",
        "name": "Gap Analysis",
        "description": "Non-compliant and not-assessed controls requiring action",
    },
    {
        "id": "findings",
        "name": "Findings Summary",
        "description": "All findings by severity with source breakdown",
    },
    {
        "id": "poam",
        "name": "POA&M Status",
        "description": "Open POA&Ms with overdue highlighting and cost totals",
    },
    {
        "id": "vendor",
        "name": "Vendor Risk",
        "description": "Vendor risk scores with tier distribution",
    },
    {
        "id": "oscal",
        "name": "OSCAL Export",
        "description": "Generate OSCAL SSP/SAR/POA&M packages",
    },
    {
        "id": "executive",
        "name": "Executive Summary",
        "description": "Board-level risk posture with KRIs and trends",
    },
]


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class ReportTypeRow(ListItem):
    """A single report type in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        name = d["name"]
        desc = d["description"]
        if len(desc) > 60:
            desc = desc[:57] + "..."
        line = f"[bold #a78bfa]{name:<24}[/]  [dim]{desc}[/]"
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail / preview pane                                                #
# ------------------------------------------------------------------ #


class ReportPreviewPane(Static):
    """Shows preview of selected report type with framework posture data."""

    item: reactive[dict | None] = reactive(None, layout=True)
    frameworks: reactive[list[dict]] = reactive(list, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select a report type[/]"

        d = self.item
        lines: list[str] = []
        lines.append(f"[bold #a78bfa]{d['name']}[/]")
        lines.append(f"[dim]{d['description']}[/]")
        lines.append("")

        if d["id"] == "posture" and self.frameworks:
            lines.append("[bold #a78bfa]\u25c6 PREVIEW: Framework Posture[/]")
            lines.append("")
            for fw in self.frameworks:
                name = escape(fw["framework"])
                if len(name) > 20:
                    name = name[:17] + "..."
                pct = fw["posture_pct"]
                color = "green" if pct >= 80 else "yellow" if pct >= 50 else "red"
                filled = int(pct / 100 * 20)
                empty = 20 - filled
                bar = f"[{color}]{'\u2588' * filled}[/][dim]{'\u2591' * empty}[/]"
                lines.append(f"  {name:<20}  [{color}]{pct:>5.1f}%[/]  {bar}")
            lines.append("")
        elif d["id"] == "gap" and self.frameworks:
            lines.append("[bold #a78bfa]\u25c6 PREVIEW: Gap Summary[/]")
            lines.append("")
            total_nc = sum(fw["non_compliant"] for fw in self.frameworks)
            lines.append(f"  Total non-compliant controls: [bold red]{total_nc:,}[/]")
            lines.append("")
            for fw in self.frameworks:
                nc = fw["non_compliant"]
                if nc > 0:
                    lines.append(f"  {escape(fw['framework']):<20}  [red]{nc:>4} gaps[/]")
            lines.append("")

        lines.append("[dim]Use CLI to generate full report:[/]")
        lines.append(f"  [#e0e0e0]warlock report --type {d['id']}[/]")
        if d["id"] == "oscal":
            lines.append("  [#e0e0e0]warlock export oscal --framework <name>[/]")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class ReportsView(Vertical):
    """Report generation interface."""

    can_focus = True

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("enter", "select_report", "Select", show=False),
        Binding("escape", "go_back", "Back", show=False),
        Binding("r", "refresh_data", "Refresh", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield Static(
            " [bold]Reports[/]  [dim]select a report type[/]",
            id="header-bar",
        )
        yield ListView(id="report-list")
        yield VerticalScroll(ReportPreviewPane(id="report-preview"), id="detail-pane")
        yield Static(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  [#a78bfa]Enter[/] select  [#a78bfa]r[/] refresh",
            id="footer-bar",
        )

    def on_mount(self) -> None:
        self.focus()
        lv = self.query_one("#report-list", ListView)
        for rt in REPORT_TYPES:
            lv.append(ReportTypeRow(rt))
        if REPORT_TYPES:
            lv.index = 0
            self._update_preview(REPORT_TYPES[0])
        # Load framework data for previews
        self.run_worker(self._fetch_frameworks, thread=True)

    def _fetch_frameworks(self) -> None:
        try:
            from warlock.tui.data.queries import get_frameworks_summary

            fws = get_frameworks_summary()
            self.app.call_from_thread(self._set_frameworks, fws)
        except Exception:
            pass

    def _set_frameworks(self, fws: list[dict]) -> None:
        preview = self.query_one("#report-preview", ReportPreviewPane)
        preview.frameworks = fws

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, ReportTypeRow):
            self._update_preview(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, ReportTypeRow):
            self._update_preview(event.item.data)

    def _update_preview(self, item: dict) -> None:
        preview = self.query_one("#report-preview", ReportPreviewPane)
        preview.item = item

    def action_select_report(self) -> None:
        lv = self.query_one("#report-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, ReportTypeRow):
            rt = lv.highlighted_child.data
            self.notify(
                f"Generate with: warlock report --type {rt['id']}",
                title=rt["name"],
            )

    def action_go_back(self) -> None:
        pass

    def action_cursor_down(self) -> None:
        self.query_one("#report-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#report-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self.run_worker(self._fetch_frameworks, thread=True)
        self.notify("Refreshed")
