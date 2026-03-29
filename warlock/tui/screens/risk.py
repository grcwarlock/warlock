"""Risk view — FAIR risk analysis results with Monte Carlo output."""

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


def _fmt_dollars(amount: float | int | None) -> str:
    if amount is None:
        return "[dim]--[/]"
    if amount >= 1_000_000:
        return f"[bold]${amount / 1_000_000:,.1f}M[/]"
    if amount >= 1_000:
        return f"[bold]${amount / 1_000:,.0f}K[/]"
    return f"[bold]${amount:,.0f}[/]"


def _ale_color(ale: float) -> str:
    if ale >= 1_000_000:
        return "bold red"
    if ale >= 100_000:
        return "dark_orange"
    if ale >= 10_000:
        return "yellow"
    return "green"


def _effectiveness(pct: float | None) -> str:
    if pct is None:
        return "[dim]--[/]"
    if pct >= 0.8:
        return f"[green]{pct:.0%}[/]"
    if pct >= 0.5:
        return f"[yellow]{pct:.0%}[/]"
    return f"[red]{pct:.0%}[/]"


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class RiskRow(ListItem):
    """A single risk analysis in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        scenario = escape(d["scenario_name"])
        if len(scenario) > 34:
            scenario = scenario[:31] + "..."
        fw = escape(d["framework"][:12]) if d["framework"] else "[dim]\u2014[/]"
        ale = d["mean_ale"]
        color = _ale_color(ale)
        line = (
            f"{scenario:<34}  [#a78bfa]{fw:<12}[/]  "
            f"ALE [{color}]{_fmt_dollars(ale)}[/]  "
            f"VaR95 {_fmt_dollars(d['var_95'])}  "
            f"eff {_effectiveness(d.get('control_effectiveness'))}"
        )
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail pane                                                          #
# ------------------------------------------------------------------ #


class RiskDetailPane(Widget):
    """Right-side detail pane for a selected risk analysis."""

    item: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select a risk scenario[/]"
        d = self.item
        lines: list[str] = []

        lines.append(f"[bold #a78bfa]{escape(d['scenario_name'])}[/]")
        lines.append("")
        if d.get("framework"):
            lines.append(f"  Framework       [#a78bfa]{escape(d['framework'])}[/]")
        lines.append(f"  Iterations      [dim]{d.get('iterations', 10000):,}[/]")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 FAIR QUANTIFICATION[/]")
        ale = d["mean_ale"]
        color = _ale_color(ale)
        lines.append(f"  Mean ALE        [{color}]{_fmt_dollars(ale)}[/]")
        lines.append(f"  VaR 95%         {_fmt_dollars(d['var_95'])}")
        lines.append(f"  VaR 99%         {_fmt_dollars(d['var_99'])}")
        lines.append("")

        eff = d.get("control_effectiveness")
        lines.append("[bold #a78bfa]\u25c6 CONTROL EFFECTIVENESS[/]")
        lines.append(f"  Effectiveness   {_effectiveness(eff)}")
        if eff is not None:
            bar_w = 30
            filled = int(eff * bar_w)
            empty = bar_w - filled
            e_color = "green" if eff >= 0.8 else "yellow" if eff >= 0.5 else "red"
            lines.append(f"  [{e_color}]{'\u2588' * filled}[/][dim]{'\u2591' * empty}[/]")
        lines.append("")

        # Loss exceedance visualization (text-based)
        lines.append("[bold #a78bfa]\u25c6 LOSS EXCEEDANCE (approx)[/]")
        var95 = d["var_95"]
        var99 = d["var_99"]
        mean = d["mean_ale"]
        # Simple text bars showing relative magnitude
        max_val = max(var99, 1)
        for label, val in [("Mean ALE", mean), ("VaR 95%", var95), ("VaR 99%", var99)]:
            bar_len = int(val / max_val * 25)
            v_color = _ale_color(val)
            lines.append(f"  {label:<10}  [{v_color}]{'\u2588' * bar_len}[/] {_fmt_dollars(val)}")
        lines.append("")

        # Risk culture metrics
        rcs = d.get("risk_culture_score")
        mttr = d.get("mttr_days")
        if rcs is not None or mttr is not None:
            lines.append("[bold #a78bfa]\u25c6 RISK CULTURE[/]")
            if rcs is not None:
                rc_color = "green" if rcs >= 70 else "yellow" if rcs >= 40 else "red"
                lines.append(f"  Culture Score   [{rc_color}]{rcs:.0f}/100[/]")
            if mttr is not None:
                mt_color = "green" if mttr <= 7 else "yellow" if mttr <= 30 else "red"
                lines.append(f"  MTTR            [{mt_color}]{mttr:.1f} days[/]")
            lines.append("")

        if d.get("created_at"):
            from warlock.utils import ensure_aware

            ts = ensure_aware(d["created_at"])
            lines.append(f"  [dim]Analyzed: {ts:%Y-%m-%d %H:%M}[/]")

        fid = d.get("id", "")
        if fid:
            lines.append(f"  [dim]ID: {fid}[/]")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class RiskView(Vertical):
    """Risk analysis list with detail pane."""

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
                yield ListView(id="risk-list")
            yield VerticalScroll(RiskDetailPane(id="detail-view"), id="detail-pane")
        yield Static("", id="footer-bar")

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_risk_analyses

            items = get_risk_analyses()
            self.app.call_from_thread(self._set_data, items)
        except Exception as e:
            try:
                self.app.call_from_thread(self._set_error, str(e))
            except Exception:
                pass

    def _set_data(self, items: list[dict]) -> None:
        self._items = items

        total_ale = sum(i["mean_ale"] for i in items)
        header = self.query_one("#header-bar", Static)
        header.update(
            f" [bold]Risk Analysis[/]  [dim]{len(items)} scenarios[/]"
            f"    [dim]Total ALE[/] {_fmt_dollars(total_ale)}"
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] select  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Esc[/] back"
        )

        lv = self.query_one("#risk-list", ListView)
        lv.clear()
        for item in items:
            lv.append(RiskRow(item))

        if items:
            lv.index = 0
            lv.focus()
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading risk analyses:[/] {escape(error)}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, RiskRow):
            self._update_detail(event.item.data)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, RiskRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", RiskDetailPane)
        detail.item = item

    def action_select_item(self) -> None:
        lv = self.query_one("#risk-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, RiskRow):
            self._update_detail(lv.highlighted_child.data)

    def action_go_back(self) -> None:
        pass

    def action_cursor_down(self) -> None:
        self.query_one("#risk-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#risk-list", ListView).action_cursor_up()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
