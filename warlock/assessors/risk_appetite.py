"""Risk appetite and tolerance framework.

Defines configurable risk appetite thresholds per compliance framework
and evaluates whether current risk posture exceeds organizational
tolerance. Integrates with FAIR Monte Carlo results from the risk engine.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.models import RiskAnalysis

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Default risk appetite thresholds per framework
# ---------------------------------------------------------------------------

risk_appetite_defaults: dict[str, dict[str, float]] = {
    "nist_800_53": {
        "max_ale": 2_000_000.0,
        "max_var95": 5_000_000.0,
        "max_high_findings": 10,
    },
    "soc2": {
        "max_ale": 1_500_000.0,
        "max_var95": 3_500_000.0,
        "max_high_findings": 5,
    },
    "iso_27001": {
        "max_ale": 1_500_000.0,
        "max_var95": 4_000_000.0,
        "max_high_findings": 8,
    },
    "fedramp": {
        "max_ale": 1_000_000.0,
        "max_var95": 3_000_000.0,
        "max_high_findings": 3,
    },
    "hipaa": {
        "max_ale": 1_000_000.0,
        "max_var95": 3_000_000.0,
        "max_high_findings": 5,
    },
    "cmmc_l2": {
        "max_ale": 1_500_000.0,
        "max_var95": 4_000_000.0,
        "max_high_findings": 5,
    },
    "gdpr": {
        "max_ale": 2_000_000.0,
        "max_var95": 5_000_000.0,
        "max_high_findings": 5,
    },
    "ucf": {
        "max_ale": 1_500_000.0,
        "max_var95": 4_000_000.0,
        "max_high_findings": 8,
    },
    "iso_27701": {
        "max_ale": 1_500_000.0,
        "max_var95": 4_000_000.0,
        "max_high_findings": 5,
    },
    "iso_42001": {
        "max_ale": 1_500_000.0,
        "max_var95": 4_000_000.0,
        "max_high_findings": 5,
    },
}


@dataclass
class AppetiteBreach:
    """Describes a single appetite threshold breach."""

    framework: str
    metric: str  # "ale", "var95", "high_findings"
    threshold: float
    actual: float
    exceeded_by_pct: float  # how much over threshold as percentage


@dataclass
class AppetiteCheckResult:
    """Result of checking risk appetite for a framework."""

    framework: str
    within_appetite: bool
    breaches: list[AppetiteBreach]
    thresholds: dict[str, float]
    actuals: dict[str, float]


class RiskAppetiteFramework:
    """Configurable risk appetite thresholds per compliance framework.

    Defines maximum acceptable risk levels and evaluates whether
    current FAIR simulation results exceed organizational tolerance.
    """

    def __init__(
        self,
        defaults: dict[str, dict[str, float]] | None = None,
    ) -> None:
        self._appetites: dict[str, dict[str, float]] = dict(defaults or risk_appetite_defaults)

    def define_appetite(
        self,
        framework: str,
        max_ale: float,
        max_var95: float,
        max_high_findings: float,
    ) -> None:
        """Set risk appetite thresholds for a framework.

        Args:
            framework: Framework identifier (e.g. "nist_800_53").
            max_ale: Maximum tolerable annualized loss expectancy.
            max_var95: Maximum tolerable 95th-percentile Value at Risk.
            max_high_findings: Maximum count of high/critical risk scenarios.
        """
        self._appetites[framework] = {
            "max_ale": max_ale,
            "max_var95": max_var95,
            "max_high_findings": max_high_findings,
        }
        log.info(
            "Risk appetite defined for %s: ALE<=%.0f, VaR95<=%.0f, high<=%.0f",
            framework,
            max_ale,
            max_var95,
            max_high_findings,
        )

    def get_appetite(self, framework: str) -> dict[str, float] | None:
        """Return current appetite thresholds for a framework, or None."""
        return self._appetites.get(framework)

    def check_appetite(
        self,
        framework: str,
        risk_analysis_result: dict[str, Any],
    ) -> AppetiteCheckResult:
        """Check whether a risk analysis result exceeds appetite.

        Args:
            framework: Framework identifier.
            risk_analysis_result: Dict from RiskEngine.analyze_framework_risk()
                or simulate_portfolio() containing a "portfolio" key with
                total_mean_ale and total_var_95, and a "scenarios" list.

        Returns:
            AppetiteCheckResult indicating whether appetite is exceeded.
        """
        thresholds = self._appetites.get(framework)
        if thresholds is None:
            log.warning(
                "No risk appetite defined for framework %s; defaulting to within appetite",
                framework,
            )
            return AppetiteCheckResult(
                framework=framework,
                within_appetite=True,
                breaches=[],
                thresholds={},
                actuals={},
            )

        portfolio = risk_analysis_result.get("portfolio", {})
        scenarios = risk_analysis_result.get("scenarios", [])

        actual_ale = portfolio.get("total_mean_ale", 0.0)
        actual_var95 = portfolio.get("total_var_95", 0.0)

        # Count high-risk scenarios: control effectiveness < 0.5
        actual_high = sum(1 for s in scenarios if s.get("control_effectiveness", 1.0) < 0.5)

        actuals = {
            "ale": actual_ale,
            "var95": actual_var95,
            "high_findings": float(actual_high),
        }

        breaches: list[AppetiteBreach] = []

        max_ale = thresholds["max_ale"]
        if actual_ale > max_ale:
            breaches.append(
                AppetiteBreach(
                    framework=framework,
                    metric="ale",
                    threshold=max_ale,
                    actual=actual_ale,
                    exceeded_by_pct=round((actual_ale - max_ale) / max_ale * 100, 2),
                )
            )

        max_var95 = thresholds["max_var95"]
        if actual_var95 > max_var95:
            breaches.append(
                AppetiteBreach(
                    framework=framework,
                    metric="var95",
                    threshold=max_var95,
                    actual=actual_var95,
                    exceeded_by_pct=round((actual_var95 - max_var95) / max_var95 * 100, 2),
                )
            )

        max_high = thresholds["max_high_findings"]
        if actual_high > max_high:
            breaches.append(
                AppetiteBreach(
                    framework=framework,
                    metric="high_findings",
                    threshold=max_high,
                    actual=float(actual_high),
                    exceeded_by_pct=round((actual_high - max_high) / max_high * 100, 2)
                    if max_high > 0
                    else 100.0,
                )
            )

        return AppetiteCheckResult(
            framework=framework,
            within_appetite=len(breaches) == 0,
            breaches=breaches,
            thresholds={
                "max_ale": max_ale,
                "max_var95": max_var95,
                "max_high_findings": max_high,
            },
            actuals=actuals,
        )

    def get_breaches(self, session: Session) -> list[AppetiteCheckResult]:
        """Scan all frameworks with defined appetites against latest risk data.

        Queries the most recent RiskAnalysis rows per framework, aggregates
        them into portfolio-level metrics, and checks against appetite.

        Returns:
            List of AppetiteCheckResult for frameworks that exceed appetite.
        """
        from sqlalchemy import func

        breached: list[AppetiteCheckResult] = []

        for framework in self._appetites:
            # Get the latest analysis batch: most recent created_at per framework
            latest_ts = (
                session.query(func.max(RiskAnalysis.created_at))
                .filter(RiskAnalysis.framework == framework)
                .scalar()
            )
            if latest_ts is None:
                continue

            analyses = (
                session.query(RiskAnalysis)
                .filter(
                    RiskAnalysis.framework == framework,
                    RiskAnalysis.created_at == latest_ts,
                )
                .all()
            )
            if not analyses:
                continue

            # Reconstruct portfolio-level metrics from individual scenario rows
            total_ale = sum(a.mean_ale for a in analyses)
            total_var95 = sum(a.var_95 for a in analyses)
            scenarios = [
                {
                    "name": a.scenario_name,
                    "mean_ale": a.mean_ale,
                    "var_95": a.var_95,
                    "control_effectiveness": a.control_effectiveness or 0.0,
                }
                for a in analyses
            ]

            result_dict: dict[str, Any] = {
                "portfolio": {
                    "total_mean_ale": total_ale,
                    "total_var_95": total_var95,
                },
                "scenarios": scenarios,
            }

            check = self.check_appetite(framework, result_dict)
            if not check.within_appetite:
                breached.append(check)
                log.warning(
                    "Risk appetite breach for %s: %d threshold(s) exceeded",
                    framework,
                    len(check.breaches),
                )

        return breached
