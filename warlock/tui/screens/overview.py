"""Executive dashboard overview screen."""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import DataTable, Label, Static

from sqlalchemy import case, func


# ---------------------------------------------------------------------------
# Data access helpers — all queries run synchronously via get_session()
# ---------------------------------------------------------------------------


def _query_framework_coverage() -> list[dict[str, Any]]:
    """Return per-framework compliance rates."""
    from warlock.db.engine import get_session
    from warlock.db.models import ControlResult

    with get_session() as session:
        rows = (
            session.query(
                ControlResult.framework,
                ControlResult.status,
                func.count(ControlResult.id),
            )
            .group_by(ControlResult.framework, ControlResult.status)
            .all()
        )

    data: dict[str, dict[str, int]] = {}
    for fw, status, count in rows:
        data.setdefault(fw, {})
        data[fw][status] = count

    results: list[dict[str, Any]] = []
    for fw, counts in sorted(data.items()):
        total = sum(counts.values())
        compliant = counts.get("compliant", 0)
        rate = (compliant / total * 100) if total else 0.0
        results.append(
            {
                "framework": fw,
                "compliant": compliant,
                "non_compliant": counts.get("non_compliant", 0),
                "partial": counts.get("partial", 0),
                "not_assessed": counts.get("not_assessed", 0),
                "total": total,
                "rate": round(rate, 1),
            }
        )
    return results


def _query_top_findings(limit: int = 5) -> list[dict[str, Any]]:
    """Return the most severe recent findings."""
    from warlock.db.engine import get_session
    from warlock.db.models import Finding

    severity_order = case(
        (Finding.severity == "critical", 0),
        (Finding.severity == "high", 1),
        (Finding.severity == "medium", 2),
        (Finding.severity == "low", 3),
        else_=4,
    )

    with get_session() as session:
        rows = (
            session.query(Finding)
            .order_by(severity_order, Finding.ingested_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "severity": r.severity,
                "title": r.title[:90] if r.title else "",
                "observation_type": r.observation_type,
                "resource_type": r.resource_type or "",
                "provider": r.provider,
            }
            for r in rows
        ]


def _query_issue_counts() -> dict[str, int]:
    """Return open issue counts by priority."""
    from warlock.db.engine import get_session
    from warlock.db.models import Issue

    with get_session() as session:
        rows = (
            session.query(Issue.priority, func.count(Issue.id))
            .filter(Issue.status.notin_(["closed", "verified"]))
            .group_by(Issue.priority)
            .all()
        )
    return {priority: count for priority, count in rows}


def _query_risk_summary() -> dict[str, Any]:
    """Return latest risk analysis totals."""
    from warlock.db.engine import get_session
    from warlock.db.models import RiskAnalysis

    with get_session() as session:
        rows = session.query(RiskAnalysis).order_by(RiskAnalysis.created_at.desc()).limit(50).all()

    if not rows:
        return {"total_ale": 0.0, "total_var95": 0.0, "scenario_count": 0}

    total_ale = sum(r.mean_ale for r in rows)
    total_var95 = sum(r.var_95 for r in rows)
    return {
        "total_ale": total_ale,
        "total_var95": total_var95,
        "scenario_count": len(rows),
    }


def _query_pipeline_status() -> dict[str, Any]:
    """Return latest pipeline run info."""
    from warlock.db.engine import get_session
    from warlock.db.models import ConnectorRun

    with get_session() as session:
        total = session.query(func.count(ConnectorRun.id)).scalar() or 0
        succeeded = (
            session.query(func.count(ConnectorRun.id))
            .filter(ConnectorRun.status == "success")
            .scalar()
            or 0
        )
        failed = (
            session.query(func.count(ConnectorRun.id))
            .filter(ConnectorRun.status == "error")
            .scalar()
            or 0
        )
        latest = session.query(ConnectorRun).order_by(ConnectorRun.completed_at.desc()).first()
        last_run = ""
        if latest and latest.completed_at:
            last_run = latest.completed_at.strftime("%Y-%m-%d %H:%M UTC")

    return {
        "total": total,
        "succeeded": succeeded,
        "failed": failed,
        "last_run": last_run,
    }


def _query_ai_status() -> dict[str, str]:
    """Return AI configuration status."""
    try:
        from warlock.config import get_settings

        settings = get_settings()
        enabled = getattr(settings, "ai_enabled", False)
        provider = getattr(settings, "ai_provider", "none")
        model = getattr(settings, "ai_model", "none")
        return {
            "enabled": "Enabled" if enabled else "Disabled",
            "provider": provider,
            "model": model,
        }
    except Exception:
        return {"enabled": "Disabled", "provider": "n/a", "model": "n/a"}


# ---------------------------------------------------------------------------
# Helper: severity / rate color
# ---------------------------------------------------------------------------


def _rate_color(rate: float) -> str:
    if rate >= 80:
        return "green"
    if rate >= 50:
        return "yellow"
    return "red"


def _severity_color(sev: str) -> str:
    return {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }.get(sev, "")


def _priority_color(priority: str) -> str:
    return {
        "critical": "white on dark_red",
        "high": "white on red",
        "medium": "black on yellow",
        "low": "white on #444444",
    }.get(priority, "")


# ---------------------------------------------------------------------------
# Widgets
# ---------------------------------------------------------------------------


class PostureSummary(Static):
    """Big aggregate compliance number."""

    DEFAULT_CSS = """
    PostureSummary {
        width: 100%;
        height: 5;
        content-align: center middle;
        text-align: center;
        border: solid $primary;
        margin-bottom: 1;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._rate: float = 0.0

    def set_rate(self, rate: float) -> None:
        self._rate = rate
        color = _rate_color(rate)
        self.update(f"[bold {color}]{rate:.1f}%[/]\n[dim]Aggregate Compliance Posture[/dim]")


class FrameworkCard(Static):
    """Single framework in the overview grid."""

    DEFAULT_CSS = """
    FrameworkCard {
        width: 1fr;
        height: 3;
        padding: 0 1;
        border: solid $surface;
        margin: 0 0 0 0;
    }
    """

    def __init__(self, fw_data: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._fw = fw_data

    def on_mount(self) -> None:
        fw = self._fw
        rate = fw["rate"]
        color = _rate_color(rate)
        bar_width = 20
        filled = int(rate / 100 * bar_width)
        bar = f"[{color}]{'█' * filled}[/][#444444]{'░' * (bar_width - filled)}[/]"
        name = fw["framework"].replace("_", " ").upper()
        if len(name) > 18:
            name = name[:18]
        self.update(
            f"[bold]{name:<18}[/] [{color}]{rate:>5.1f}%[/]\n"
            f"{bar} [dim]{fw['compliant']}/{fw['total']}[/dim]"
        )


class IssueBox(Static):
    """Colored box showing issue count for a priority level."""

    DEFAULT_CSS = """
    IssueBox {
        width: 1fr;
        height: 3;
        content-align: center middle;
        text-align: center;
        margin: 0 1 0 0;
    }
    """

    def __init__(self, priority: str, count: int, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._priority = priority
        self._count = count

    def on_mount(self) -> None:
        color = _priority_color(self._priority)
        self.update(f"[{color}] {self._priority.upper()} [/]\n[bold]{self._count}[/bold]")


class RiskPanel(Static):
    """Risk exposure summary."""

    DEFAULT_CSS = """
    RiskPanel {
        width: 100%;
        height: auto;
        padding: 1 2;
        border: solid $surface;
        margin-bottom: 1;
    }
    """

    def set_data(self, data: dict[str, Any]) -> None:
        ale = data.get("total_ale", 0)
        var95 = data.get("total_var95", 0)
        scenarios = data.get("scenario_count", 0)
        ale_color = "red" if ale > 500_000 else "yellow" if ale > 100_000 else "green"
        self.update(
            f"[bold]Risk Exposure[/bold]\n"
            f"[{ale_color}]Total ALE:  ${ale:>12,.0f}[/]\n"
            f"[{ale_color}]VaR-95:     ${var95:>12,.0f}[/]\n"
            f"[dim]Scenarios:  {scenarios}[/dim]"
        )


class PipelinePanel(Static):
    """Pipeline status summary."""

    DEFAULT_CSS = """
    PipelinePanel {
        width: 100%;
        height: auto;
        padding: 1 2;
        border: solid $surface;
        margin-bottom: 1;
    }
    """

    def set_data(self, data: dict[str, Any]) -> None:
        total = data.get("total", 0)
        succeeded = data.get("succeeded", 0)
        failed = data.get("failed", 0)
        last_run = data.get("last_run", "Never")
        fail_color = "red" if failed > 0 else "green"
        self.update(
            f"[bold]Pipeline[/bold]\n"
            f"Connectors:  [green]{succeeded}[/] up  [{fail_color}]{failed}[/] failed  [dim]{total} total[/dim]\n"
            f"Last run:    [dim]{last_run or 'Never'}[/dim]"
        )


class AIPanel(Static):
    """AI configuration status."""

    DEFAULT_CSS = """
    AIPanel {
        width: 100%;
        height: auto;
        padding: 1 2;
        border: solid $surface;
        margin-bottom: 1;
    }
    """

    def set_data(self, data: dict[str, str]) -> None:
        enabled = data.get("enabled", "Disabled")
        color = "green" if enabled == "Enabled" else "dim"
        self.update(
            f"[bold]AI Status[/bold]\n"
            f"Status:    [{color}]{enabled}[/]\n"
            f"Provider:  [dim]{data.get('provider', 'n/a')}[/dim]\n"
            f"Model:     [dim]{data.get('model', 'n/a')}[/dim]"
        )


# ---------------------------------------------------------------------------
# Main overview screen (composed as a widget, not a Screen)
# ---------------------------------------------------------------------------


class OverviewScreen(VerticalScroll):
    """Executive overview dashboard."""

    DEFAULT_CSS = """
    OverviewScreen {
        padding: 1 2;
    }

    #posture-summary {
        margin-bottom: 1;
    }

    .section-title {
        text-style: bold;
        color: $text;
        margin: 1 0 0 0;
        padding: 0 0 0 0;
    }

    #framework-grid {
        layout: grid;
        grid-size: 2;
        grid-gutter: 1;
        margin-bottom: 1;
        height: auto;
    }

    #issues-row {
        height: 3;
        margin-bottom: 1;
    }

    #findings-table {
        height: 10;
        margin-bottom: 1;
    }

    #bottom-panels {
        height: auto;
        margin-bottom: 1;
    }

    #bottom-panels > * {
        width: 1fr;
    }
    """

    def compose(self) -> ComposeResult:
        yield PostureSummary(id="posture-summary")
        yield Label("[bold]Framework Coverage[/bold]", classes="section-title")
        yield Container(id="framework-grid")
        yield Label("[bold]Open Issues[/bold]", classes="section-title")
        yield Horizontal(id="issues-row")
        yield Label("[bold]Top Findings by Severity[/bold]", classes="section-title")
        yield DataTable(id="findings-table")
        with Horizontal(id="bottom-panels"):
            yield RiskPanel(id="risk-panel")
            yield PipelinePanel(id="pipeline-panel")
            yield AIPanel(id="ai-panel")

    def on_mount(self) -> None:
        self._load_data()

    def _load_data(self) -> None:
        """Query all data sources and populate widgets."""
        try:
            from warlock.db.engine import init_db

            init_db()
        except Exception:
            pass

        # Framework coverage
        try:
            frameworks = _query_framework_coverage()
        except Exception:
            frameworks = []

        # Aggregate posture
        posture = self.query_one("#posture-summary", PostureSummary)
        if frameworks:
            total_compliant = sum(f["compliant"] for f in frameworks)
            total_all = sum(f["total"] for f in frameworks)
            aggregate = (total_compliant / total_all * 100) if total_all else 0.0
            posture.set_rate(aggregate)
        else:
            posture.set_rate(0.0)

        # Framework grid
        grid = self.query_one("#framework-grid", Container)
        grid.remove_children()
        for fw in frameworks:
            grid.mount(FrameworkCard(fw))

        # Issues
        try:
            issue_counts = _query_issue_counts()
        except Exception:
            issue_counts = {}

        issues_row = self.query_one("#issues-row", Horizontal)
        issues_row.remove_children()
        for priority in ("critical", "high", "medium", "low"):
            count = issue_counts.get(priority, 0)
            issues_row.mount(IssueBox(priority, count))

        # Top findings
        try:
            findings = _query_top_findings(5)
        except Exception:
            findings = []

        table = self.query_one("#findings-table", DataTable)
        table.clear(columns=True)
        table.add_columns("Severity", "Type", "Title", "Resource", "Source")
        for f in findings:
            sev = f["severity"]
            table.add_row(
                sev.upper(),
                f["observation_type"],
                f["title"],
                f["resource_type"],
                f["provider"],
            )

        # Risk
        try:
            risk_data = _query_risk_summary()
        except Exception:
            risk_data = {"total_ale": 0, "total_var95": 0, "scenario_count": 0}

        self.query_one("#risk-panel", RiskPanel).set_data(risk_data)

        # Pipeline
        try:
            pipeline_data = _query_pipeline_status()
        except Exception:
            pipeline_data = {}

        self.query_one("#pipeline-panel", PipelinePanel).set_data(pipeline_data)

        # AI
        ai_data = _query_ai_status()
        self.query_one("#ai-panel", AIPanel).set_data(ai_data)

    def refresh_data(self) -> None:
        """Public method for the app to trigger a data reload."""
        self._load_data()
