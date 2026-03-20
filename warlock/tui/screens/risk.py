"""FAIR Monte Carlo risk analysis viewer.

Displays quantified risk results from the FAIR engine: portfolio totals,
per-scenario breakdowns, loss exceedance curves (via plotext), and
optional AI-generated risk narratives for multiple audiences.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    LoadingIndicator,
    Markdown,
    Select,
    Static,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Framework choices for the selector
# ---------------------------------------------------------------------------

_FRAMEWORKS_DIR = Path(__file__).resolve().parent.parent.parent / "frameworks"

_FRAMEWORK_LABELS: dict[str, str] = {
    "nist_800_53": "NIST 800-53",
    "iso_27001": "ISO 27001",
    "iso_27701": "ISO 27701",
    "iso_42001": "ISO 42001",
    "soc2": "SOC 2",
    "ucf": "UCF",
    "fedramp": "FedRAMP",
    "hipaa": "HIPAA",
    "cmmc_l2": "CMMC L2",
    "gdpr": "GDPR",
    "pci_dss": "PCI DSS v4.0",
    "nist_csf": "NIST CSF 2.0",
    "eu_ai_act": "EU AI Act",
    "sec_cyber": "SEC Cyber",
}


def _discover_frameworks() -> list[tuple[str, str]]:
    """Return (label, value) pairs for frameworks that have YAML on disk."""
    choices: list[tuple[str, str]] = []
    for yaml_path in sorted(_FRAMEWORKS_DIR.glob("*.yaml")):
        stem = yaml_path.stem
        if stem.startswith("crosswalk"):
            continue
        label = _FRAMEWORK_LABELS.get(stem, stem.replace("_", " ").title())
        choices.append((label, stem))
    return choices


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fmt_dollar(value: float) -> str:
    """Format a dollar amount with commas and 2 decimal places."""
    if abs(value) >= 1_000_000:
        return f"${value:,.0f}"
    return f"${value:,.2f}"


def _severity_class(ale: float) -> str:
    """Return a Rich markup color tag based on ALE magnitude."""
    if ale > 1_000_000:
        return "red"
    if ale > 100_000:
        return "yellow"
    return "green"


def _render_exceedance_chart(scenarios: list[dict[str, Any]]) -> str:
    """Build a plotext loss exceedance curve as a string.

    Aggregates exceedance curves across all scenarios.  If plotext is not
    installed or there is no curve data, returns a placeholder message.
    """
    try:
        import plotext as plt
    except ImportError:
        return "(plotext not installed -- run 'pip install plotext' for charts)"

    # Collect the first scenario with curve data, or aggregate
    combined: dict[float, float] = {}
    for sc in scenarios:
        curve = sc.get("exceedance_curve", [])
        for prob, loss in curve:
            combined[prob] = combined.get(prob, 0.0) + loss

    if not combined:
        return "(No exceedance curve data available)"

    sorted_probs = sorted(combined.keys(), reverse=True)
    probabilities = sorted_probs
    loss_values = [combined[p] for p in probabilities]

    plt.clear_data()
    plt.clear_figure()
    plt.plot(probabilities, loss_values)
    plt.title("Loss Exceedance Curve")
    plt.xlabel("Probability of Exceedance")
    plt.ylabel("Annual Loss ($)")
    plt.theme("dark")
    plt.plot_size(80, 20)
    canvas = plt.build()
    return canvas


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

RISK_SCREEN_CSS = """\
#risk-screen {
    layout: vertical;
}

#controls-bar {
    height: 5;
    padding: 1 2;
}

#controls-bar Select {
    width: 40;
    margin-right: 2;
}

#controls-bar Button {
    margin-right: 1;
}

#portfolio-panel {
    height: auto;
    max-height: 8;
    padding: 1 2;
    border: solid $accent;
}

#portfolio-panel .metric-value {
    text-style: bold;
}

#results-area {
    height: 1fr;
    padding: 0 1;
}

#scenario-table {
    height: 1fr;
    min-height: 10;
}

#chart-panel {
    height: 24;
    padding: 1;
    border: solid $accent;
}

#narrative-panel {
    height: auto;
    max-height: 20;
    padding: 1 2;
    border: solid $accent;
}

#no-data-label {
    text-align: center;
    padding: 4;
    color: $text-muted;
}

#loading-area {
    height: 6;
    content-align: center middle;
}
"""


# ---------------------------------------------------------------------------
# Screen
# ---------------------------------------------------------------------------


class RiskScreen(Screen):
    """FAIR Monte Carlo risk dashboard."""

    CSS = RISK_SCREEN_CSS
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("r", "run_analysis", "Run Analysis"),
        ("n", "ai_narrative", "AI Narrative"),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._portfolio: dict[str, Any] | None = None
        self._scenarios: list[dict[str, Any]] = []
        self._selected_framework: str = ""

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="risk-screen"):
            # Top bar: framework selector + action buttons
            with Horizontal(id="controls-bar"):
                frameworks = _discover_frameworks()
                yield Select(
                    [(label, value) for label, value in frameworks],
                    prompt="Select framework",
                    id="framework-select",
                )
                yield Button("Run Analysis", variant="primary", id="run-btn")
                yield Button("AI Narrative", variant="default", id="narrative-btn")

            # Portfolio summary (hidden until results)
            yield Container(
                Label("", id="portfolio-summary"),
                id="portfolio-panel",
            )

            # Loading indicator
            yield Container(
                LoadingIndicator(),
                Label("Running Monte Carlo simulation...", id="loading-label"),
                id="loading-area",
            )

            # Results area
            with VerticalScroll(id="results-area"):
                yield DataTable(id="scenario-table")
                yield Static("", id="chart-panel")
                yield Markdown("", id="narrative-panel")

            # Fallback for no data
            yield Label(
                "No risk data. Select a framework and click 'Run Analysis' "
                "to start a FAIR Monte Carlo simulation.",
                id="no-data-label",
            )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#loading-area").display = False
        self.query_one("#portfolio-panel").display = False
        self.query_one("#results-area").display = False
        self.query_one("#narrative-panel").display = False

        table = self.query_one("#scenario-table", DataTable)
        table.add_columns(
            "Scenario",
            "Mean ALE",
            "VaR-95",
            "VaR-99",
            "Control Eff.",
        )

        # If DB already has results, load the most recent
        self._load_existing_results()

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "framework-select" and event.value is not Select.BLANK:
            self._selected_framework = str(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-btn":
            self.action_run_analysis()
        elif event.button.id == "narrative-btn":
            self.action_ai_narrative()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_run_analysis(self) -> None:
        if not self._selected_framework:
            self.notify("Select a framework first.", severity="warning")
            return
        self._run_analysis_worker(self._selected_framework)

    def action_ai_narrative(self) -> None:
        if not self._portfolio:
            self.notify("Run an analysis first.", severity="warning")
            return
        self._generate_narrative_worker()

    # ------------------------------------------------------------------
    # Workers (non-blocking)
    # ------------------------------------------------------------------

    @work(thread=True, exclusive=True, group="risk-analysis")
    def _run_analysis_worker(self, framework: str) -> None:
        """Run FAIR simulation in a background thread."""
        self.call_from_thread(self._show_loading, True)

        try:
            from warlock.assessors.risk_engine import RiskEngine
            from warlock.db.engine import get_session

            engine = RiskEngine()
            session_gen = get_session()
            session = next(session_gen)
            try:
                portfolio = engine.analyze_framework_risk(session, framework)
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                try:
                    next(session_gen)
                except StopIteration:
                    pass

            self.call_from_thread(self._display_results, portfolio)
        except Exception as exc:
            log.exception("Risk analysis failed")
            self.call_from_thread(
                self.notify,
                f"Analysis failed: {exc}",
                severity="error",
            )
        finally:
            self.call_from_thread(self._show_loading, False)

    @work(thread=True, exclusive=True, group="ai-narrative")
    def _generate_narrative_worker(self) -> None:
        """Call AI for risk narrative in background thread."""
        if not self._portfolio:
            return

        self.call_from_thread(
            self.notify, "Generating AI risk narrative...", severity="information"
        )

        try:
            from warlock.ai.service import get_ai_service
            from warlock.ai.types import AITask

            svc = get_ai_service()
            result = svc.reason(
                task=AITask.RISK_NARRATIVE,
                context={"risk_data": self._portfolio},
            )

            if result.ai_used and result.value:
                self.call_from_thread(self._display_narrative, result.value)
            else:
                reason = result.fallback_reason or "AI not available"
                self.call_from_thread(
                    self.notify,
                    f"AI narrative unavailable: {reason}",
                    severity="warning",
                )
        except Exception as exc:
            log.exception("AI narrative generation failed")
            self.call_from_thread(
                self.notify,
                f"Narrative failed: {exc}",
                severity="error",
            )

    # ------------------------------------------------------------------
    # UI update helpers (must run on main thread)
    # ------------------------------------------------------------------

    def _show_loading(self, visible: bool) -> None:
        self.query_one("#loading-area").display = visible
        self.query_one("#no-data-label").display = False

    def _display_results(self, portfolio: dict[str, Any]) -> None:
        self._portfolio = portfolio
        self._scenarios = portfolio.get("scenarios", [])
        totals = portfolio.get("portfolio", {})

        # -- Portfolio summary --
        mean_ale = totals.get("total_mean_ale", 0.0)
        var_95 = totals.get("total_var_95", 0.0)
        var_99 = totals.get("total_var_99", 0.0)
        count = totals.get("scenario_count", 0)
        iters = totals.get("iterations", 0)

        mean_color = _severity_class(mean_ale)
        v95_color = _severity_class(var_95)
        v99_color = _severity_class(var_99)

        summary = (
            f"[bold]Portfolio Risk Summary[/bold]  "
            f"({count} scenarios, {iters:,} iterations)\n"
            f"  Mean ALE: [{mean_color} bold]{_fmt_dollar(mean_ale)}[/]  |  "
            f"  VaR-95: [{v95_color} bold]{_fmt_dollar(var_95)}[/]  |  "
            f"  VaR-99: [{v99_color} bold]{_fmt_dollar(var_99)}[/]"
        )
        self.query_one("#portfolio-summary", Label).update(summary)
        self.query_one("#portfolio-panel").display = True

        # -- Scenario table --
        table = self.query_one("#scenario-table", DataTable)
        table.clear()

        for sc in self._scenarios:
            ale = sc.get("mean_ale", 0.0)
            color = _severity_class(ale)
            table.add_row(
                sc.get("name", "Unknown"),
                f"[{color}]{_fmt_dollar(ale)}[/]",
                f"[{color}]{_fmt_dollar(sc.get('var_95', 0.0))}[/]",
                f"[{color}]{_fmt_dollar(sc.get('var_99', 0.0))}[/]",
                f"{sc.get('control_effectiveness', 0.0):.1%}",
            )

        # -- Exceedance chart --
        chart_text = _render_exceedance_chart(self._scenarios)
        self.query_one("#chart-panel", Static).update(chart_text)

        self.query_one("#results-area").display = True
        self.query_one("#no-data-label").display = False
        self.query_one("#loading-area").display = False

    def _display_narrative(self, narrative: Any) -> None:
        """Render AI narrative in the Markdown panel."""
        panel = self.query_one("#narrative-panel", Markdown)

        if isinstance(narrative, dict):
            # Expected format: {technical: ..., insurance: ..., board: ...}
            parts: list[str] = []
            for audience in ("technical", "insurance", "board"):
                text = narrative.get(audience, "")
                if text:
                    parts.append(f"## {audience.title()} Narrative\n\n{text}")
            md_text = "\n\n---\n\n".join(parts) if parts else str(narrative)
        elif isinstance(narrative, str):
            md_text = narrative
        else:
            md_text = str(narrative)

        panel.update(md_text)
        panel.display = True

    # ------------------------------------------------------------------
    # Load cached results from DB on mount
    # ------------------------------------------------------------------

    def _load_existing_results(self) -> None:
        """Check the DB for the most recent risk analysis and display it."""
        try:
            from warlock.db.engine import get_session
            from warlock.db.models import RiskAnalysis

            session_gen = get_session()
            session = next(session_gen)
            try:
                latest = (
                    session.query(RiskAnalysis)
                    .filter(RiskAnalysis.details.isnot(None))
                    .order_by(RiskAnalysis.created_at.desc())
                    .first()
                )
                if latest and isinstance(latest.details, dict):
                    portfolio = latest.details.get("portfolio_result")
                    if portfolio:
                        self._selected_framework = portfolio.get("framework", "")
                        self._display_results(portfolio)
                        return
            finally:
                try:
                    next(session_gen)
                except StopIteration:
                    pass
        except Exception:
            log.debug("No existing risk data found", exc_info=True)
