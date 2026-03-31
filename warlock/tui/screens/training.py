"""Training view — training campaigns, completion rates by department."""

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


def _posture_bar(pct: float, width: int = 20) -> str:
    filled = int(pct / 100 * width)
    empty = width - filled
    color = "green" if pct >= 80 else "yellow" if pct >= 50 else "red"
    return f"[{color}]{'\u2588' * filled}[/][dim]{'\u2591' * empty}[/]"


# ------------------------------------------------------------------ #
# Content widget                                                       #
# ------------------------------------------------------------------ #


class TrainingContent(Static):
    """Renders training summary as Rich markup."""

    data: reactive[dict | None] = reactive(None, layout=True)

    def render(self) -> str:
        if self.data is None:
            return "[dim]Loading training data...[/]"

        d = self.data
        lines: list[str] = []
        total = d.get("total", 0)
        current = d.get("current", 0)
        overdue = d.get("overdue", 0)
        not_enrolled = d.get("not_enrolled", 0)

        pct = round(100 * current / total, 1) if total else 0.0
        color = "green" if pct >= 80 else "yellow" if pct >= 50 else "red"

        lines.append("")
        lines.append(
            f"  [{color} bold]{pct:.1f}%[/]  "
            f"[dim]training compliance "
            f"({current} / {total} personnel current)[/]"
        )
        lines.append(f"  {_posture_bar(pct, 40)}")
        lines.append("")

        lines.append("[bold #a78bfa]\u25c6 SUMMARY[/]")
        lines.append(f"  [green]{current:>4}[/]  Current")
        overdue_color = "bold red" if overdue > 0 else "dim"
        lines.append(f"  [{overdue_color}]{overdue:>4}[/]  Overdue")
        lines.append(f"  [dim]{not_enrolled:>4}[/]  Not Enrolled")
        lines.append("")

        # Department breakdown
        depts = d.get("departments", [])
        if depts:
            lines.append("[bold #a78bfa]\u25c6 BY DEPARTMENT[/]")
            lines.append("")
            for dept in depts:
                name = escape(dept["name"])
                if len(name) > 20:
                    name = name[:17] + "..."
                dp = dept["completion_pct"]
                dc = "green" if dp >= 80 else "yellow" if dp >= 50 else "red"
                lines.append(
                    f"  {name:<20}  [{dc}]{dp:>5.1f}%[/]  "
                    f"{_posture_bar(dp, 16)}  "
                    f"[dim]{dept['total']} people[/]"
                )
            lines.append("")

        # Top risk personnel
        risky = d.get("high_risk", [])
        if risky:
            lines.append("[bold #a78bfa]\u25c6 ATTENTION REQUIRED[/]")
            for p in risky[:10]:
                name = escape(p["full_name"])
                if len(name) > 24:
                    name = name[:21] + "..."
                dept = escape(p.get("department", "") or "")
                status = p.get("training_status", "")
                s_color = "bold red" if status == "overdue" else "dim"
                phish = p.get("phishing_score")
                phish_label = ""
                if phish is not None:
                    p_color = "red" if phish > 50 else "yellow" if phish > 20 else "green"
                    phish_label = f"  phish [{p_color}]{phish:.0f}%[/]"
                lines.append(f"  {name:<24}  {dept:<14}  [{s_color}]{status:<12}[/]{phish_label}")
            lines.append("")

        return "\n".join(lines)


# ------------------------------------------------------------------ #
# View                                                                 #
# ------------------------------------------------------------------ #


class TrainingView(Vertical):
    """Training compliance dashboard."""

    can_focus = True

    BINDINGS = [
        Binding("r", "refresh_data", "Refresh", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield Static(
            " [bold]Training[/]  [dim]loading...[/]",
            id="header-bar",
        )
        yield VerticalScroll(TrainingContent(id="training-content"))
        yield Static(
            " [#a78bfa]r[/] refresh  [#a78bfa]Ctrl+K[/] commands",
            id="footer-bar",
        )

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_personnel

            people = get_personnel(limit=2000)

            total = len(people)
            current = sum(1 for p in people if p["training_status"] == "current")
            overdue = sum(1 for p in people if p["training_status"] == "overdue")
            not_enrolled = sum(1 for p in people if p["training_status"] == "not_enrolled")

            # Department breakdown
            dept_map: dict[str, dict[str, Any]] = {}
            for p in people:
                dept = p.get("department") or "Unknown"
                if dept not in dept_map:
                    dept_map[dept] = {"name": dept, "total": 0, "current": 0}
                dept_map[dept]["total"] += 1
                if p["training_status"] == "current":
                    dept_map[dept]["current"] += 1

            departments = []
            for d in dept_map.values():
                pct = round(100 * d["current"] / d["total"], 1) if d["total"] else 0.0
                departments.append({**d, "completion_pct": pct})
            departments.sort(key=lambda x: x["completion_pct"])

            # High risk people (overdue or high phishing score)
            high_risk = [
                p
                for p in people
                if p["training_status"] == "overdue" or (p.get("phishing_score") or 0) > 50
            ]
            high_risk.sort(key=lambda p: -(p.get("phishing_score") or 0))

            data = {
                "total": total,
                "current": current,
                "overdue": overdue,
                "not_enrolled": not_enrolled,
                "departments": departments,
                "high_risk": high_risk[:10],
            }
            self.app.call_from_thread(self._set_data, data)
        except Exception as e:
            try:
                self.app.call_from_thread(self._set_error, str(e))
            except Exception:
                pass

    def _set_data(self, data: dict) -> None:
        total = data["total"]
        current = data["current"]
        pct = round(100 * current / total, 1) if total else 0.0
        color = "green" if pct >= 80 else "yellow" if pct >= 50 else "red"

        header = self.query_one("#header-bar", Static)
        header.update(
            f" [bold]Training[/]  [{color}]{pct:.1f}% compliant[/]    [dim]{total} personnel[/]"
        )

        content = self.query_one("#training-content", TrainingContent)
        content.data = data

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading training:[/] {escape(error)}")

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
