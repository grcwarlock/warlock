"""Issues and POA&M management screen for the Warlock TUI.

Combined tabbed view covering Issues, POA&Ms, Risk Acceptances,
and Compensating Controls with full detail panels.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any

from textual import on, work
from textual.app import ComposeResult
from textual.reactive import reactive
from textual.containers import VerticalScroll
from textual.widgets import (
    DataTable,
    Static,
    TabbedContent,
    TabPane,
)


from warlock.db.engine import get_session, init_db
from warlock.db.models import (
    CompensatingControl,
    Issue,
    IssueComment,
    POAM,
    RiskAcceptance,
)

# ---------------------------------------------------------------------------
# Styling helpers
# ---------------------------------------------------------------------------

_PRIORITY_COLORS = {
    "critical": "bold red",
    "high": "#ff8c00",
    "medium": "yellow",
    "low": "dim",
}

_STATUS_COLORS = {
    "open": "bold white",
    "assigned": "cyan",
    "in_progress": "blue",
    "remediated": "green",
    "verified": "green bold",
    "closed": "dim",
    "risk_accepted": "#ff8c00",
    # POAM statuses
    "draft": "dim italic",
    "completed": "green",
    # Risk acceptance / compensating control
    "requested": "yellow",
    "reviewed": "cyan",
    "approved": "green",
    "active": "green bold",
    "expired": "red dim",
    "revoked": "red",
    "proposed": "yellow",
}


def _styled(value: str, color_map: dict[str, str]) -> str:
    style = color_map.get(value, "")
    if style:
        return f"[{style}]{value}[/]"
    return value


def _ts_short(dt: datetime | None) -> str:
    if dt is None:
        return "---"
    return dt.strftime("%Y-%m-%d")


def _is_overdue(dt: datetime | None) -> bool:
    if dt is None:
        return False
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        # Treat naive as UTC for comparison safety.
        return dt < datetime.utcnow()
    return dt < now


def _is_expiring_soon(dt: datetime | None, days: int = 30) -> bool:
    if dt is None:
        return False
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        cutoff = datetime.utcnow() + timedelta(days=days)
        return dt < cutoff
    return dt < now + timedelta(days=days)


def _truncate(text: str, length: int) -> str:
    if not text:
        return ""
    if len(text) <= length:
        return text
    return text[: length - 1] + "\u2026"


# ---------------------------------------------------------------------------
# Stats widgets
# ---------------------------------------------------------------------------


class IssuesStats(Static):
    """Stats bar for the Issues tab."""

    stats_text: reactive[str] = reactive("Loading issues...")

    def render(self) -> str:
        return self.stats_text


class POAMStats(Static):
    """Stats bar for the POA&Ms tab."""

    stats_text: reactive[str] = reactive("Loading POA&Ms...")

    def render(self) -> str:
        return self.stats_text


# ---------------------------------------------------------------------------
# Detail panel
# ---------------------------------------------------------------------------


class DetailPanel(Static):
    """Generic detail panel for any selected row."""

    DEFAULT_CSS = """
    DetailPanel {
        height: auto;
        max-height: 50%;
        overflow-y: auto;
        border-top: solid $accent;
        padding: 1 2;
    }
    """

    detail_text: reactive[str] = reactive("")

    def render(self) -> str:
        return self.detail_text or "[dim]Select a row to view details.[/dim]"


# ---------------------------------------------------------------------------
# Issues screen
# ---------------------------------------------------------------------------


class IssuesScreen(VerticalScroll):
    """Combined Issues, POA&Ms, Risk Acceptances, and Compensating Controls."""

    DEFAULT_CSS = """
    IssuesScreen {
        padding: 1 1;
    }

    .stats-bar {
        height: 3;
        padding: 0 2;
        background: $surface;
    }

    .tab-table {
        height: 1fr;
    }

    #issues-detail, #poams-detail, #ra-detail, #cc-detail {
        dock: bottom;
    }
    """

    # Internal state ---------------------------------------------------------

    _issues: list[Any] = []
    _poams: list[Any] = []
    _risk_acceptances: list[Any] = []
    _compensating_controls: list[Any] = []
    _issue_comments: dict[str, list[Any]] = {}

    # Compose ----------------------------------------------------------------

    def compose(self) -> ComposeResult:
        with TabbedContent("Issues", "POA&Ms", "Risk Acceptances", "Compensating Controls"):
            with TabPane("Issues", id="issues-sub-issues"):
                yield IssuesStats(id="issues-stats", classes="stats-bar")
                yield DataTable(
                    id="issues-table", cursor_type="row", zebra_stripes=True, classes="tab-table"
                )
                yield DetailPanel(id="issues-detail")
            with TabPane("POA&Ms", id="issues-sub-poams"):
                yield POAMStats(id="poams-stats", classes="stats-bar")
                yield DataTable(
                    id="poams-table", cursor_type="row", zebra_stripes=True, classes="tab-table"
                )
                yield DetailPanel(id="poams-detail")
            with TabPane("Risk Acceptances", id="issues-sub-ra"):
                yield DataTable(
                    id="ra-table", cursor_type="row", zebra_stripes=True, classes="tab-table"
                )
                yield DetailPanel(id="ra-detail")
            with TabPane("Compensating Controls", id="issues-sub-cc"):
                yield DataTable(
                    id="cc-table", cursor_type="row", zebra_stripes=True, classes="tab-table"
                )
                yield DetailPanel(id="cc-detail")

    # Lifecycle --------------------------------------------------------------

    def on_mount(self) -> None:
        # Issues table
        issues_t = self.query_one("#issues-table", DataTable)
        issues_t.add_columns(
            "Priority",
            "Status",
            "Framework",
            "Control",
            "Title",
            "Assigned To",
            "Created",
        )

        # POA&Ms table
        poams_t = self.query_one("#poams-table", DataTable)
        poams_t.add_columns(
            "Severity",
            "Status",
            "Framework",
            "Control",
            "Weakness",
            "Scheduled",
            "Delays",
        )

        # Risk Acceptances table
        ra_t = self.query_one("#ra-table", DataTable)
        ra_t.add_columns(
            "Framework",
            "Control",
            "Risk Level",
            "Approver",
            "Expiry",
            "Status",
        )

        # Compensating Controls table
        cc_t = self.query_one("#cc-table", DataTable)
        cc_t.add_columns(
            "Framework",
            "Control",
            "Title",
            "Effectiveness",
            "Expiry",
            "Status",
        )

        self._load_all_data()

    # Data loading -----------------------------------------------------------

    @work(thread=True)
    def _load_all_data(self) -> None:
        """Load all tab data in a single worker thread."""
        init_db()

        with get_session() as session:
            # Issues
            issues = session.query(Issue).order_by(Issue.created_at.desc()).all()
            session.expunge_all()

        with get_session() as session:
            # Issue comments keyed by issue_id
            comments = session.query(IssueComment).all()
            comments_map: dict[str, list[Any]] = {}
            for c in comments:
                comments_map.setdefault(c.issue_id, []).append(c)
            session.expunge_all()

        with get_session() as session:
            poams = session.query(POAM).order_by(POAM.created_at.desc()).all()
            session.expunge_all()

        with get_session() as session:
            risk_acceptances = (
                session.query(RiskAcceptance).order_by(RiskAcceptance.created_at.desc()).all()
            )
            session.expunge_all()

        with get_session() as session:
            compensating = (
                session.query(CompensatingControl)
                .order_by(CompensatingControl.created_at.desc())
                .all()
            )
            session.expunge_all()

        # Build stats strings
        issue_stats = self._build_issue_stats(issues)
        poam_stats = self._build_poam_stats(poams)

        self.app.call_from_thread(
            self._apply_all_data,
            issues,
            comments_map,
            poams,
            risk_acceptances,
            compensating,
            issue_stats,
            poam_stats,
        )

    @staticmethod
    def _build_issue_stats(issues: list[Any]) -> str:
        total = len(issues)
        by_status: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        for i in issues:
            by_status[i.status] = by_status.get(i.status, 0) + 1
            by_priority[i.priority] = by_priority.get(i.priority, 0) + 1

        parts = [f"[bold]Total:[/bold] {total}"]
        for st in ("open", "assigned", "in_progress", "remediated", "verified", "closed"):
            cnt = by_status.get(st, 0)
            if cnt:
                parts.append(f"{_styled(st, _STATUS_COLORS)}: {cnt}")
        for pr in ("critical", "high", "medium", "low"):
            cnt = by_priority.get(pr, 0)
            if cnt:
                parts.append(f"{_styled(pr, _PRIORITY_COLORS)}: {cnt}")
        return "  |  ".join(parts)

    @staticmethod
    def _build_poam_stats(poams: list[Any]) -> str:
        total = len(poams)
        overdue = sum(
            1
            for p in poams
            if p.status not in ("completed", "verified", "closed")
            and _is_overdue(p.scheduled_completion)
        )
        by_status: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        for p in poams:
            by_status[p.status] = by_status.get(p.status, 0) + 1
            by_sev[p.severity] = by_sev.get(p.severity, 0) + 1

        parts = [f"[bold]Total:[/bold] {total}"]
        if overdue:
            parts.append(f"[bold red]Overdue: {overdue}[/]")
        for st in ("draft", "open", "in_progress", "completed", "verified", "closed"):
            cnt = by_status.get(st, 0)
            if cnt:
                parts.append(f"{_styled(st, _STATUS_COLORS)}: {cnt}")
        return "  |  ".join(parts)

    def _apply_all_data(
        self,
        issues: list[Any],
        comments_map: dict[str, list[Any]],
        poams: list[Any],
        risk_acceptances: list[Any],
        compensating: list[Any],
        issue_stats: str,
        poam_stats: str,
    ) -> None:
        """Apply loaded data to all tabs (main thread)."""
        self._issues = issues
        self._issue_comments = comments_map
        self._poams = poams
        self._risk_acceptances = risk_acceptances
        self._compensating_controls = compensating

        self.query_one("#issues-stats", IssuesStats).stats_text = issue_stats
        self.query_one("#poams-stats", POAMStats).stats_text = poam_stats

        self._populate_issues_table()
        self._populate_poams_table()
        self._populate_ra_table()
        self._populate_cc_table()

    # Table population -------------------------------------------------------

    def _populate_issues_table(self) -> None:
        table = self.query_one("#issues-table", DataTable)
        table.clear()
        for issue in self._issues:
            table.add_row(
                _styled(issue.priority, _PRIORITY_COLORS),
                _styled(issue.status, _STATUS_COLORS),
                issue.framework or "---",
                issue.control_id or "---",
                _truncate(issue.title, 50),
                issue.assigned_to or "[dim]unassigned[/dim]",
                _ts_short(issue.created_at),
                key=issue.id,
            )

    def _populate_poams_table(self) -> None:
        table = self.query_one("#poams-table", DataTable)
        table.clear()
        for p in self._poams:
            overdue = p.status not in ("completed", "verified", "closed") and _is_overdue(
                p.scheduled_completion
            )
            sev_display = _styled(p.severity, _PRIORITY_COLORS)
            status_display = _styled(p.status, _STATUS_COLORS)
            sched = _ts_short(p.scheduled_completion)
            if overdue:
                sched = f"[bold red]{sched} OVERDUE[/]"
            table.add_row(
                sev_display,
                status_display,
                p.framework or "---",
                p.control_id or "---",
                _truncate(p.weakness_description, 40),
                sched,
                str(p.delay_count or 0),
                key=p.id,
            )

    def _populate_ra_table(self) -> None:
        table = self.query_one("#ra-table", DataTable)
        table.clear()
        for ra in self._risk_acceptances:
            expiry = _ts_short(ra.expiry_date)
            expiring_soon = _is_expiring_soon(ra.expiry_date)
            expired = _is_overdue(ra.expiry_date)
            if expired:
                expiry = f"[bold red]{expiry} EXPIRED[/]"
            elif expiring_soon:
                expiry = f"[yellow]{expiry}[/]"
            table.add_row(
                ra.framework or "---",
                ra.control_id or "---",
                _styled(ra.risk_level, _PRIORITY_COLORS),
                ra.approved_by or ra.requested_by or "---",
                expiry,
                _styled(ra.status, _STATUS_COLORS),
                key=ra.id,
            )

    def _populate_cc_table(self) -> None:
        table = self.query_one("#cc-table", DataTable)
        table.clear()
        for cc in self._compensating_controls:
            eff = f"{cc.effectiveness_score:.0f}%" if cc.effectiveness_score is not None else "---"
            expiry = _ts_short(cc.expiry_date)
            expired = _is_overdue(cc.expiry_date)
            expiring_soon = _is_expiring_soon(cc.expiry_date)
            if expired:
                expiry = f"[bold red]{expiry} EXPIRED[/]"
            elif expiring_soon:
                expiry = f"[yellow]{expiry}[/]"
            table.add_row(
                cc.original_framework or "---",
                cc.original_control_id or "---",
                _truncate(cc.title, 40),
                eff,
                expiry,
                _styled(cc.status, _STATUS_COLORS),
                key=cc.id,
            )

    # Row selection handlers -------------------------------------------------

    @on(DataTable.RowHighlighted, "#issues-table")
    def _on_issue_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        self._show_issue_detail(str(event.row_key.value))

    @on(DataTable.RowSelected, "#issues-table")
    def _on_issue_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None:
            return
        self._show_issue_detail(str(event.row_key.value))

    @on(DataTable.RowHighlighted, "#poams-table")
    def _on_poam_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        self._show_poam_detail(str(event.row_key.value))

    @on(DataTable.RowSelected, "#poams-table")
    def _on_poam_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None:
            return
        self._show_poam_detail(str(event.row_key.value))

    @on(DataTable.RowHighlighted, "#ra-table")
    def _on_ra_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        self._show_ra_detail(str(event.row_key.value))

    @on(DataTable.RowSelected, "#ra-table")
    def _on_ra_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None:
            return
        self._show_ra_detail(str(event.row_key.value))

    @on(DataTable.RowHighlighted, "#cc-table")
    def _on_cc_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        self._show_cc_detail(str(event.row_key.value))

    @on(DataTable.RowSelected, "#cc-table")
    def _on_cc_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None:
            return
        self._show_cc_detail(str(event.row_key.value))

    # Detail renderers -------------------------------------------------------

    def _show_issue_detail(self, issue_id: str) -> None:
        issue = next((i for i in self._issues if i.id == issue_id), None)
        if issue is None:
            return

        lines: list[str] = []
        lines.append(f"[bold]{issue.title}[/bold]")
        lines.append("")
        lines.append(f"  [bold]ID:[/bold]          {issue.id}")
        lines.append(f"  [bold]Priority:[/bold]    {_styled(issue.priority, _PRIORITY_COLORS)}")
        lines.append(f"  [bold]Status:[/bold]      {_styled(issue.status, _STATUS_COLORS)}")
        lines.append(f"  [bold]Framework:[/bold]   {issue.framework or '---'}")
        lines.append(f"  [bold]Control:[/bold]     {issue.control_id or '---'}")
        lines.append(f"  [bold]Source:[/bold]      {issue.source or '---'}")
        lines.append(f"  [bold]Assigned To:[/bold] {issue.assigned_to or 'unassigned'}")
        lines.append(f"  [bold]Assigned By:[/bold] {issue.assigned_by or '---'}")
        lines.append(f"  [bold]Due Date:[/bold]    {_ts_short(issue.due_date)}")
        lines.append(f"  [bold]Created:[/bold]     {_ts_short(issue.created_at)}")
        lines.append(f"  [bold]Created By:[/bold]  {issue.created_by or '---'}")
        lines.append("")

        if issue.description:
            lines.append("  [bold]Description:[/bold]")
            for dl in issue.description.split("\n")[:10]:
                lines.append(f"    {dl}")
            lines.append("")

        if issue.remediation_plan:
            lines.append("  [bold]Remediation Plan:[/bold]")
            for dl in issue.remediation_plan.split("\n")[:10]:
                lines.append(f"    {dl}")
            lines.append("")

        if issue.risk_accepted:
            lines.append("  [bold #ff8c00]Risk Accepted[/bold #ff8c00]")
            lines.append(f"    Owner:         {issue.risk_acceptance_owner or '---'}")
            lines.append(f"    Expiry:        {_ts_short(issue.risk_acceptance_expiry)}")
            lines.append(
                f"    Justification: {_truncate(issue.risk_acceptance_justification or '', 60)}"
            )
            lines.append("")

        # Comments
        comments = self._issue_comments.get(issue_id, [])
        if comments:
            lines.append(f"  [bold]Comments ({len(comments)}):[/bold]")
            for c in sorted(comments, key=lambda x: x.created_at or datetime.min):
                ts = _ts_short(c.created_at)
                lines.append(
                    f"    [{c.comment_type}] {c.author} ({ts}): {_truncate(c.content, 60)}"
                )
            lines.append("")

        # Action hints
        lines.append("  [dim]CLI actions:[/dim]")
        lines.append(f"    warlock issues assign {issue.id[:8]} --to <email>")
        lines.append(f"    warlock issues transition {issue.id[:8]} --status in_progress")
        lines.append(f"    warlock issues accept-risk {issue.id[:8]} --justification '...'")

        self.query_one("#issues-detail", DetailPanel).detail_text = "\n".join(lines)

    def _show_poam_detail(self, poam_id: str) -> None:
        poam = next((p for p in self._poams if p.id == poam_id), None)
        if poam is None:
            return

        overdue = poam.status not in ("completed", "verified", "closed") and _is_overdue(
            poam.scheduled_completion
        )

        lines: list[str] = []
        header = f"[bold]{poam.weakness_description}[/bold]"
        if overdue:
            header += "  [bold red][OVERDUE][/bold red]"
        lines.append(header)
        lines.append("")
        lines.append(f"  [bold]ID:[/bold]             {poam.id}")
        lines.append(f"  [bold]Severity:[/bold]       {_styled(poam.severity, _PRIORITY_COLORS)}")
        lines.append(f"  [bold]Risk Level:[/bold]     {poam.risk_level or '---'}")
        lines.append(f"  [bold]Status:[/bold]         {_styled(poam.status, _STATUS_COLORS)}")
        lines.append(f"  [bold]Framework:[/bold]      {poam.framework}")
        lines.append(f"  [bold]Control:[/bold]        {poam.control_id}")
        lines.append(f"  [bold]Scheduled:[/bold]      {_ts_short(poam.scheduled_completion)}")
        lines.append(f"  [bold]Actual:[/bold]         {_ts_short(poam.actual_completion)}")
        lines.append(f"  [bold]Delay Count:[/bold]    {poam.delay_count or 0}")
        lines.append(f"  [bold]Created By:[/bold]     {poam.created_by or '---'}")
        lines.append(f"  [bold]Approved By:[/bold]    {poam.approved_by or '---'}")
        lines.append(f"  [bold]Vendor Dep:[/bold]     {poam.vendor_dependency or '---'}")
        lines.append("")

        if poam.resources_required:
            lines.append("  [bold]Resources Required:[/bold]")
            lines.append(f"    {poam.resources_required}")
            lines.append("")

        # Milestones
        milestones = poam.milestones or []
        if milestones:
            lines.append(f"  [bold]Milestones ({len(milestones)}):[/bold]")
            for ms in milestones:
                if isinstance(ms, dict):
                    status_icon = (
                        "[green]done[/green]"
                        if ms.get("status") == "completed"
                        else "[yellow]pending[/yellow]"
                    )
                    lines.append(
                        f"    {status_icon} {ms.get('description', '---')} (due: {ms.get('due_date', '---')})"
                    )
            lines.append("")

        # Delay justifications
        delays = poam.delay_justifications or []
        if delays:
            lines.append("  [bold]Delay Justifications:[/bold]")
            for d in delays:
                if isinstance(d, dict):
                    lines.append(f"    [{d.get('date', '---')}] {d.get('justification', '---')}")
            lines.append("")

        self.query_one("#poams-detail", DetailPanel).detail_text = "\n".join(lines)

    def _show_ra_detail(self, ra_id: str) -> None:
        ra = next((r for r in self._risk_acceptances if r.id == ra_id), None)
        if ra is None:
            return

        lines: list[str] = []
        lines.append(f"[bold]Risk Acceptance: {ra.framework} / {ra.control_id}[/bold]")
        lines.append("")
        lines.append(f"  [bold]ID:[/bold]              {ra.id}")
        lines.append(f"  [bold]Risk Level:[/bold]      {_styled(ra.risk_level, _PRIORITY_COLORS)}")
        lines.append(f"  [bold]Residual Risk:[/bold]   {ra.residual_risk_level or '---'}")
        lines.append(f"  [bold]Status:[/bold]          {_styled(ra.status, _STATUS_COLORS)}")
        lines.append(f"  [bold]Requested By:[/bold]    {ra.requested_by}")
        lines.append(f"  [bold]Reviewed By:[/bold]     {ra.reviewed_by or '---'}")
        lines.append(f"  [bold]Approved By:[/bold]     {ra.approved_by or '---'}")
        lines.append(f"  [bold]Expiry:[/bold]          {_ts_short(ra.expiry_date)}")
        lines.append("")

        if ra.risk_description:
            lines.append("  [bold]Risk Description:[/bold]")
            for dl in ra.risk_description.split("\n")[:10]:
                lines.append(f"    {dl}")
            lines.append("")

        conditions = ra.conditions or []
        if conditions:
            lines.append("  [bold]Conditions:[/bold]")
            for cond in conditions:
                if isinstance(cond, dict):
                    met = "[green]met[/green]" if cond.get("met") else "[red]not met[/red]"
                    lines.append(f"    {met} {cond.get('condition', '---')}")
            lines.append("")

        triggers = ra.auto_reeval_triggers or {}
        if triggers:
            lines.append("  [bold]Auto Re-eval Triggers:[/bold]")
            for k, v in triggers.items():
                lines.append(f"    {k}: {'enabled' if v else 'disabled'}")

        self.query_one("#ra-detail", DetailPanel).detail_text = "\n".join(lines)

    def _show_cc_detail(self, cc_id: str) -> None:
        cc = next((c for c in self._compensating_controls if c.id == cc_id), None)
        if cc is None:
            return

        lines: list[str] = []
        lines.append(f"[bold]{cc.title}[/bold]")
        lines.append("")
        lines.append(f"  [bold]ID:[/bold]              {cc.id}")
        lines.append(f"  [bold]Framework:[/bold]       {cc.original_framework}")
        lines.append(f"  [bold]Control:[/bold]         {cc.original_control_id}")
        lines.append(f"  [bold]Status:[/bold]          {_styled(cc.status, _STATUS_COLORS)}")
        eff = f"{cc.effectiveness_score:.0f}%" if cc.effectiveness_score is not None else "---"
        lines.append(f"  [bold]Effectiveness:[/bold]   {eff}")
        lines.append(f"  [bold]Review Freq:[/bold]     {cc.review_frequency or '---'}")
        lines.append(f"  [bold]Last Reviewed:[/bold]   {_ts_short(cc.last_reviewed)}")
        lines.append(f"  [bold]Expiry:[/bold]          {_ts_short(cc.expiry_date)}")
        lines.append(f"  [bold]Approved By:[/bold]     {cc.approved_by or '---'}")
        lines.append(f"  [bold]Created By:[/bold]      {cc.created_by or '---'}")
        lines.append("")

        if cc.description:
            lines.append("  [bold]Description:[/bold]")
            for dl in cc.description.split("\n")[:10]:
                lines.append(f"    {dl}")
            lines.append("")

        if cc.implementation_details:
            lines.append("  [bold]Implementation Details:[/bold]")
            for dl in cc.implementation_details.split("\n")[:10]:
                lines.append(f"    {dl}")
            lines.append("")

        evidence = cc.evidence_references or []
        if evidence:
            lines.append(f"  [bold]Evidence ({len(evidence)}):[/bold]")
            for ev in evidence:
                if isinstance(ev, dict):
                    lines.append(f"    [{ev.get('type', '---')}] {ev.get('description', '---')}")

        self.query_one("#cc-detail", DetailPanel).detail_text = "\n".join(lines)

    # Actions ----------------------------------------------------------------

    def action_refresh(self) -> None:
        """Reload all data from the database."""
        self.query_one("#issues-stats", IssuesStats).stats_text = "Reloading..."
        self.query_one("#poams-stats", POAMStats).stats_text = "Reloading..."
        for panel_id in ("#issues-detail", "#poams-detail", "#ra-detail", "#cc-detail"):
            self.query_one(panel_id, DetailPanel).detail_text = ""
        self._load_all_data()
