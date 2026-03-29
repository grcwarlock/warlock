"""Dashboard view — KRI tiles, compliance gauges, alerts, pipeline status.

This is the default home screen.
"""

from __future__ import annotations

from typing import Any

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import Static


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #


def _posture_color(pct: float) -> str:
    if pct >= 80:
        return "green"
    if pct >= 50:
        return "yellow"
    return "red"


def _posture_bar(pct: float, width: int = 20) -> str:
    filled = int(pct / 100 * width)
    empty = width - filled
    color = _posture_color(pct)
    return f"[{color}]{'\u2588' * filled}[/][dim]{'\u2591' * empty}[/]"


def _sev_style(s: str) -> str:
    styles = {
        "critical": "bold red",
        "high": "dark_orange",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }
    return styles.get(s, "white")


# ------------------------------------------------------------------ #
# Dashboard content widget                                             #
# ------------------------------------------------------------------ #


class DashboardContent(Static):
    """Renders the full dashboard as Rich markup."""

    data: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.data is None:
            return "[dim]Loading dashboard...[/]"

        d = self.data
        lines: list[str] = []

        # Big compliance number
        pct = d["overall_pct"]
        color = _posture_color(pct)
        lines.append("")
        lines.append(
            f"  [{color} bold]{pct:.1f}%[/]  "
            f"[dim]overall compliance "
            f"({d['compliant_controls']:,} / {d['total_controls']:,} controls)[/]"
        )
        lines.append(f"  {_posture_bar(pct, width=40)}")
        lines.append("")

        # KRI tiles row
        lines.append("[bold #a78bfa]\u25c6 KEY RISK INDICATORS[/]")
        lines.append("")

        open_alerts = d.get("open_alerts", 0)
        alert_color = "bold red" if open_alerts > 0 else "green"
        lines.append(
            f"  [{alert_color}]{open_alerts:>4}[/]  Open Alerts          "
            f"  [bold red]{d.get('critical_findings', 0):>4}[/]  Critical Findings"
        )
        overdue = d.get("overdue_poams", 0)
        overdue_color = "bold red" if overdue > 0 else "green"
        lines.append(
            f"  [{overdue_color}]{overdue:>4}[/]  Overdue POA&Ms       "
            f"  [dim]{d.get('total_findings', 0):>4}[/]  Total Findings"
        )
        lines.append("")

        # Pipeline status
        pipe = d.get("pipeline")
        if pipe:
            p_status = pipe["status"]
            p_color = "green" if p_status == "completed" else "yellow"
            ts = pipe.get("started_at")
            ts_label = f"{ts:%Y-%m-%d %H:%M}" if ts else "--"
            lines.append("[bold #a78bfa]\u25c6 PIPELINE[/]")
            lines.append(
                f"  Last run  [{p_color}]{p_status}[/]  "
                f"[dim]{ts_label}[/]  "
                f"connectors [green]{pipe.get('connectors_ok', 0)}[/]"
                f"[dim]/[/][red]{pipe.get('connectors_failed', 0)}[/]  "
                f"findings [bold]{pipe.get('findings', 0):,}[/]"
            )
            lines.append("")

        # Framework tiles
        frameworks = d.get("frameworks", [])
        if frameworks:
            lines.append("[bold #a78bfa]\u25c6 FRAMEWORK POSTURE[/]")
            lines.append("")
            for fw in frameworks:
                name = escape(fw["framework"])
                if len(name) > 20:
                    name = name[:17] + "..."
                fp = fw["posture_pct"]
                fc = _posture_color(fp)
                nc = fw["non_compliant"]
                nc_label = f"[red]{nc}[/]" if nc else "[dim]0[/]"
                lines.append(
                    f"  {name:<20}  [{fc}]{fp:>5.1f}%[/]  {_posture_bar(fp, 16)}  nc {nc_label}"
                )
            lines.append("")

        # Recent alerts
        alerts = d.get("recent_alerts", [])
        if alerts:
            lines.append("[bold #a78bfa]\u25c6 RECENT ALERTS[/]")
            for a in alerts[:5]:
                sev = a["severity"]
                style = _sev_style(sev)
                title = escape(a["title"])
                if len(title) > 60:
                    title = title[:57] + "..."
                ts = a.get("triggered_at")
                ts_label = f"{ts:%H:%M}" if ts else ""
                lines.append(f"  [{style}]{sev:<8}[/]  {title:<60}  [dim]{ts_label}[/]")
            lines.append("")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class DashboardView(Vertical):
    """Dashboard home screen with KRI tiles and compliance gauges."""

    can_focus = True

    BINDINGS = [
        Binding("r", "refresh_data", "Refresh", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield Static(
            " [bold]Dashboard[/]  [dim]loading...[/]",
            id="header-bar",
        )
        yield VerticalScroll(DashboardContent(id="dashboard-content"))
        yield Static(
            " [#a78bfa]r[/] refresh  [#a78bfa]1-9[/] screens  [#a78bfa]Ctrl+K[/] commands",
            id="footer-bar",
        )

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_dashboard_data

            data = get_dashboard_data()
            self.app.call_from_thread(self._set_data, data)
        except Exception as e:
            try:
                self.app.call_from_thread(self._set_error, str(e))
            except Exception:
                pass

    def _set_data(self, data: dict[str, Any]) -> None:
        header = self.query_one("#header-bar", Static)
        pct = data["overall_pct"]
        color = _posture_color(pct)
        header.update(
            f" [bold]Dashboard[/]  [{color}]{pct:.1f}% compliant[/]"
            f"    [dim]{data['total_controls']:,} controls[/]"
        )

        content = self.query_one("#dashboard-content", DashboardContent)
        content.data = data

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading dashboard:[/] {escape(error)}")

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
