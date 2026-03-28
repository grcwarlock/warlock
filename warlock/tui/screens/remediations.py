"""Remediations view — the home dashboard.

Three states:
1. List view — all remediations with summary detail pane
2. Drill-in — expanded detail with impacted systems and CLI commands
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static, ListView, ListItem


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

SEV_STYLE = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "dim",
}

STATUS_STYLE = {
    "open": "yellow",
    "assigned": "cyan",
    "in_progress": "dodger_blue2",
    "verification": "medium_purple",
    "closed": "green",
}


def _sev(s: str) -> str:
    style = SEV_STYLE.get(s, "white")
    return f"[{style}]{s:<8}[/]"


def _status(s: str) -> str:
    style = STATUS_STYLE.get(s, "white")
    return f"[{style}]{s:<12}[/]"


def _due_label(item: dict) -> str:
    days = item.get("days_until_due")
    if days is None:
        return "[dim]\u2014[/]"
    if item.get("overdue"):
        return f"[bold red]{abs(days)}d overdue[/]"
    if days <= 7:
        return f"[yellow]due {days}d[/]"
    return f"[dim]due {days}d[/]"


def _step_icon(step: dict) -> str:
    if step.get("completed"):
        return "[green]\u2713[/]"
    return "[dim]\u25cb[/]"


# ------------------------------------------------------------------ #
# List row                                                             #
# ------------------------------------------------------------------ #


class RemediationRow(ListItem):
    """A single remediation in the list."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        super().__init__()

    def compose(self) -> ComposeResult:
        d = self.data
        assignee = d["assigned_to"][:10] if d["assigned_to"] else "[dim]\u2014[/]"
        title = d["title"]
        if len(title) > 60:
            title = title[:57] + "..."
        line = f"{_sev(d['severity'])} {_status(d['status'])} {title:<60} {_due_label(d):<14} {assignee}"
        yield Static(line)


# ------------------------------------------------------------------ #
# Detail pane (right side)                                             #
# ------------------------------------------------------------------ #


class DetailPane(Widget):
    """Right-side detail pane showing selected remediation info."""

    item: reactive[dict | None] = reactive(None, layout=True)
    expanded: reactive[bool] = reactive(False)

    def render(self) -> str:
        if self.item is None:
            return "[dim]Select a remediation[/]"
        d = self.item
        lines: list[str] = []

        # Header
        lines.append(f"[bold #a78bfa]{d['title']}[/]")
        lines.append("")
        lines.append(f"  Severity   {_sev(d['severity'])}")
        lines.append(f"  Status     {_status(d['status'])}")
        lines.append(f"  Assigned   {d['assigned_to'] or '[dim]unassigned[/]'}")
        lines.append(f"  Due        {_due_label(d)}")
        if d.get("framework"):
            lines.append(f"  Framework  [#a78bfa]{d['framework']} {d.get('control_id', '')}[/]")
        lines.append("")

        # Steps
        steps = d.get("steps") or []
        if steps:
            lines.append("[bold #a78bfa]\u25c6 REMEDIATION STEPS[/]")
            for i, step in enumerate(steps):
                icon = _step_icon(step)
                desc = step.get("description", step.get("step", f"Step {i + 1}"))
                lines.append(f"  {icon} {desc}")
            lines.append("")

        if self.expanded:
            lines.extend(self._render_expanded(d))

        # Evidence
        evidence = d.get("evidence") or []
        if evidence:
            lines.append(f"[bold #a78bfa]\u25c6 EVIDENCE ({len(evidence)})[/]")
            for ev in evidence[:5]:
                desc = ev.get("description", "attachment")
                lines.append(f"  \U0001f4ce {desc}")
            lines.append("")

        if not self.expanded:
            lines.append("[dim]Press Enter to expand \u2192 systems, commands, controls[/]")

        return "\n".join(lines)

    def _render_expanded(self, d: dict) -> list[str]:
        lines: list[str] = []

        # Impacted systems
        systems = d.get("impacted_systems") or []
        if systems:
            lines.append("[bold #a78bfa]\u25c6 IMPACTED SYSTEMS[/]")
            for sys in systems:
                ato = sys.get("ato_status", "Active")
                ato_color = "green" if ato == "Active" else "yellow"
                lines.append(
                    f"  {sys['name']:<24} "
                    f"{sys.get('environment', ''):<12} "
                    f"ATO: [{ato_color}]{ato}[/]"
                )
            lines.append("")

        # CLI commands
        fix_cmds = self._get_fix_commands(d)
        if fix_cmds:
            lines.append("[bold #a78bfa]\u25c6 REMEDIATION COMMANDS[/]")
            lines.append("[dim]  Copy-paste to fix. Run in order.[/]")
            lines.append("")
            for step in fix_cmds:
                step_num = step.get("step", "?")
                desc = step.get("description", "")
                lines.append(f"  [bold]Step {step_num}[/] \u2014 {desc}")
                for cmd in step.get("commands", []):
                    if cmd.startswith("#"):
                        lines.append(f"    [dim]{cmd}[/]")
                    else:
                        lines.append(f"    [#e0e0e0]{cmd}[/]")
                lines.append("")

            # Terraform alternative
            tf = self._get_terraform_alt(d)
            if tf:
                lines.append("  [bold #a78bfa]\u25c6 Terraform Alternative[/]")
                for cmd in tf:
                    lines.append(f"    [#e0e0e0]{cmd}[/]")
                lines.append("")
        elif d.get("remediation_plan"):
            lines.append("[bold #a78bfa]\u25c6 REMEDIATION PLAN[/]")
            lines.append(f"  {d['remediation_plan']}")
            lines.append("")

        # Control impact
        controls = d.get("control_impact") or []
        if controls:
            lines.append("[bold #a78bfa]\u25c6 CONTROL IMPACT[/]")
            for cr in controls[:10]:
                st = cr["status"]
                st_style = STATUS_STYLE.get(st, "white")
                lines.append(
                    f"  {cr['framework']:<14} "
                    f"[#a78bfa]{cr['control_id']:<10}[/] "
                    f"{cr.get('control_title', '')[:30]:<30} "
                    f"[{st_style}]{st}[/]"
                )
            lines.append("")

        return lines

    def _get_fix_commands(self, d: dict) -> list[dict] | None:
        steps = d.get("steps") or []
        if steps and any(s.get("commands") for s in steps):
            return steps
        source = d.get("finding_source", "")
        if source:
            try:
                from warlock.tui.data.fix_templates import get_fix_commands

                return get_fix_commands(source)
            except Exception:
                pass
        return None

    def _get_terraform_alt(self, d: dict) -> list[str] | None:
        control_id = d.get("control_id", "")
        framework = d.get("framework", "")
        if control_id:
            try:
                from warlock.tui.data.fix_templates import get_terraform_alternative

                return get_terraform_alternative(control_id, framework)
            except Exception:
                pass
        return None


# ------------------------------------------------------------------ #
# View (mounted inside the app, not a Screen)                          #
# ------------------------------------------------------------------ #


class RemediationsView(Vertical):
    """Home view — remediation list with detail pane."""

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("enter", "toggle_expand", "Expand", show=False),
        Binding("escape", "collapse", "Back", show=False),
        Binding("t", "transition", "Transition", show=False),
        Binding("a", "assign", "Assign", show=False),
        Binding("slash", "focus_search", "Search", show=False),
        Binding("f", "filter", "Filter", show=False),
        Binding("r", "refresh_data", "Refresh", show=False),
    ]

    can_focus = True

    _items: reactive[list[dict]] = reactive(list, layout=True)

    def compose(self) -> ComposeResult:
        yield Static("", id="header-bar")
        yield Static("", id="filter-bar")
        with Horizontal(id="main-content"):
            yield ListView(id="rem-list")
            yield VerticalScroll(DetailPane(id="detail-view"), id="detail-pane")
        yield Static("", id="footer-bar")

    def on_mount(self) -> None:
        self.focus()
        self._load_data()

    def _load_data(self) -> None:
        self.run_worker(self._fetch_data, thread=True)

    def _fetch_data(self) -> None:
        try:
            from warlock.tui.data.queries import get_remediations, get_remediation_counts

            items = get_remediations()
            counts = get_remediation_counts()
            try:
                self.app.call_from_thread(self._set_data, items, counts)
            except Exception:
                pass
        except Exception as e:
            try:
                self.app.call_from_thread(self._set_error, str(e))
            except Exception:
                pass

    def _set_data(self, items: list[dict], counts: dict) -> None:
        self._items = items

        header = self.query_one("#header-bar", Static)
        c = counts
        header.update(
            f" [bold]Remediations[/]  [dim]{c['total']} items[/]"
            f"    [on dark_red] {c['critical']} critical [/]"
            f"  [on #442200] {c['overdue']} overdue [/]"
            f"  [on #003300] {c['closed']} closed [/]"
        )

        footer = self.query_one("#footer-bar", Static)
        footer.update(
            " [#a78bfa]j[/]/[#a78bfa]k[/] move  "
            "[#a78bfa]Enter[/] expand  "
            "[#a78bfa]t[/] transition  "
            "[#a78bfa]a[/] assign  "
            "[#a78bfa]r[/] refresh  "
            "[#a78bfa]Ctrl+K[/] commands"
        )

        lv = self.query_one("#rem-list", ListView)
        lv.clear()
        for item in items:
            lv.append(RemediationRow(item))

        if items:
            self._update_detail(items[0])

    def _set_error(self, error: str) -> None:
        header = self.query_one("#header-bar", Static)
        header.update(f" [bold red]Error loading remediations:[/] {error}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Enter key pressed on a list item — expand detail."""
        if isinstance(event.item, RemediationRow):
            self._update_detail(event.item.data)
            self._do_expand(event.item.data["id"])

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item and isinstance(event.item, RemediationRow):
            self._update_detail(event.item.data)

    def _update_detail(self, item: dict) -> None:
        detail = self.query_one("#detail-view", DetailPane)
        detail.item = item
        detail.expanded = False

    def _do_expand(self, rem_id: str) -> None:
        """Fetch full detail and expand the pane."""
        self.run_worker(
            lambda: self._fetch_detail(rem_id),
            thread=True,
        )

    def _fetch_detail(self, rem_id: str) -> None:
        try:
            from warlock.tui.data.queries import get_remediation_detail

            full = get_remediation_detail(rem_id)
            if full:
                try:
                    self.app.call_from_thread(self._expand_detail, full)
                except Exception:
                    pass
        except Exception:
            pass

    def _expand_detail(self, full_data: dict) -> None:
        detail = self.query_one("#detail-view", DetailPane)
        detail.item = full_data
        detail.expanded = True
        pane = self.query_one("#detail-pane")
        pane.add_class("--expanded")

    def action_toggle_expand(self) -> None:
        """Manual Enter binding — expand the currently highlighted item."""
        lv = self.query_one("#rem-list", ListView)
        if lv.highlighted_child and isinstance(lv.highlighted_child, RemediationRow):
            self._do_expand(lv.highlighted_child.data["id"])

    def action_collapse(self) -> None:
        detail = self.query_one("#detail-view", DetailPane)
        if detail.expanded:
            detail.expanded = False
            pane = self.query_one("#detail-pane")
            pane.remove_class("--expanded")

    def action_cursor_down(self) -> None:
        self.query_one("#rem-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#rem-list", ListView).action_cursor_up()

    def action_transition(self) -> None:
        detail = self.query_one("#detail-view", DetailPane)
        if not detail.item:
            return
        current = detail.item["status"]
        valid = {
            "open": ["assigned"],
            "assigned": ["in_progress", "open"],
            "in_progress": ["verification", "assigned"],
            "verification": ["closed", "in_progress"],
            "closed": [],
        }
        transitions = valid.get(current, [])
        if not transitions:
            self.notify(f"No transitions from {current}", severity="warning")
            return
        new_status = transitions[0]
        self.run_worker(
            lambda: self._do_transition(detail.item["id"], new_status),
            thread=True,
        )

    def _do_transition(self, rem_id: str, new_status: str) -> None:
        from warlock.tui.data.actions import transition_remediation

        error = transition_remediation(rem_id, new_status, "cli@warlock")
        if error:
            try:
                self.app.call_from_thread(self.notify, error, severity="error")
            except Exception:
                pass
        else:
            try:
                self.app.call_from_thread(self.notify, f"Transitioned to {new_status}")
            except Exception:
                pass
            self._fetch_data()

    def action_assign(self) -> None:
        self.notify("Assignment via input coming soon", severity="information")

    def action_filter(self) -> None:
        self.notify("Filters coming soon", severity="information")

    def action_focus_search(self) -> None:
        self.app.action_command_palette()

    def action_refresh_data(self) -> None:
        self._load_data()
        self.notify("Refreshed")
