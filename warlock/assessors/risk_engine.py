"""FAIR Monte Carlo risk quantification engine.

Translates control posture data into quantified risk using the FAIR
(Factor Analysis of Information Risk) methodology. Runs Monte Carlo
simulations with PERT distributions for threat event frequency and
loss magnitude, modulated by control effectiveness derived from posture
scores.

Works with or without numpy — falls back to stdlib random module with
triangular distributions when numpy is unavailable.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import logging
import math
import random
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.assessors.posture import ControlPosture, PostureAggregator
from warlock.db.models import (
    RiskAnalysis,
)

log = logging.getLogger(__name__)

# Try numpy for PERT distribution; fall back to stdlib
try:
    import numpy as np

    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False
    log.info("numpy not available — using stdlib triangular distribution fallback")


# ---------------------------------------------------------------------------
# Default scenario catalog — maps control families to threat scenarios
# ---------------------------------------------------------------------------

DEFAULT_SCENARIO_CATALOG: dict[str, dict[str, Any]] = {
    "AC": {
        "name": "unauthorized_access",
        "description": "Unauthorized access to information systems",
        "frequency_min": 1, "frequency_mode": 5, "frequency_max": 20,
        "impact_min": 50_000, "impact_mode": 250_000, "impact_max": 2_000_000,
    },
    "SI": {
        "name": "malware",
        "description": "Malware infection and propagation",
        "frequency_min": 2, "frequency_mode": 8, "frequency_max": 30,
        "impact_min": 25_000, "impact_mode": 150_000, "impact_max": 1_500_000,
    },
    "CP": {
        "name": "service_disruption",
        "description": "Business continuity and disaster recovery failure",
        "frequency_min": 0.5, "frequency_mode": 2, "frequency_max": 8,
        "impact_min": 100_000, "impact_mode": 500_000, "impact_max": 5_000_000,
    },
    "AU": {
        "name": "audit_failure",
        "description": "Insufficient audit logging leading to undetected breach",
        "frequency_min": 1, "frequency_mode": 4, "frequency_max": 15,
        "impact_min": 30_000, "impact_mode": 200_000, "impact_max": 1_000_000,
    },
    "IA": {
        "name": "identity_compromise",
        "description": "Identity and authentication system compromise",
        "frequency_min": 2, "frequency_mode": 10, "frequency_max": 40,
        "impact_min": 50_000, "impact_mode": 300_000, "impact_max": 3_000_000,
    },
    "SC": {
        "name": "data_exfiltration",
        "description": "Data exfiltration through communication channels",
        "frequency_min": 1, "frequency_mode": 3, "frequency_max": 12,
        "impact_min": 100_000, "impact_mode": 500_000, "impact_max": 10_000_000,
    },
    "CM": {
        "name": "configuration_drift",
        "description": "Configuration management failure leading to exposure",
        "frequency_min": 3, "frequency_mode": 10, "frequency_max": 50,
        "impact_min": 10_000, "impact_mode": 75_000, "impact_max": 500_000,
    },
    "RA": {
        "name": "unassessed_risk",
        "description": "Unidentified or unassessed risks materializing",
        "frequency_min": 1, "frequency_mode": 3, "frequency_max": 10,
        "impact_min": 50_000, "impact_mode": 250_000, "impact_max": 2_000_000,
    },
    "SA": {
        "name": "supply_chain_compromise",
        "description": "Third-party or supply chain security compromise",
        "frequency_min": 0.5, "frequency_mode": 2, "frequency_max": 8,
        "impact_min": 75_000, "impact_mode": 400_000, "impact_max": 5_000_000,
    },
    "SR": {
        "name": "supply_chain_compromise",
        "description": "Supply chain risk management failure",
        "frequency_min": 0.5, "frequency_mode": 2, "frequency_max": 8,
        "impact_min": 75_000, "impact_mode": 400_000, "impact_max": 5_000_000,
    },
    "IR": {
        "name": "incident_response_failure",
        "description": "Inadequate incident response extending breach impact",
        "frequency_min": 1, "frequency_mode": 4, "frequency_max": 15,
        "impact_min": 50_000, "impact_mode": 300_000, "impact_max": 3_000_000,
    },
    "PE": {
        "name": "physical_breach",
        "description": "Physical security breach or environmental failure",
        "frequency_min": 0.2, "frequency_mode": 1, "frequency_max": 5,
        "impact_min": 25_000, "impact_mode": 200_000, "impact_max": 2_000_000,
    },
    "UCF-TPM": {
        "name": "vendor_breach",
        "description": "Third-party vendor security breach or data exposure",
        "frequency_min": 0.5, "frequency_mode": 3, "frequency_max": 10,
        "impact_min": 100_000, "impact_mode": 500_000, "impact_max": 5_000_000,
    },
    # SOC 2 TSC family mappings — alias to equivalent NIST families
    "CC": {  # Common Criteria -> Access Control
        "name": "unauthorized_access",
        "description": "Unauthorized access to information systems",
        "frequency_min": 1, "frequency_mode": 5, "frequency_max": 20,
        "impact_min": 50_000, "impact_mode": 250_000, "impact_max": 2_000_000,
    },
    "A": {  # Availability -> Continuity Planning
        "name": "service_disruption",
        "description": "Business continuity and disaster recovery failure",
        "frequency_min": 0.5, "frequency_mode": 2, "frequency_max": 8,
        "impact_min": 100_000, "impact_mode": 500_000, "impact_max": 5_000_000,
    },
    "PI": {  # Processing Integrity -> System and Information Integrity
        "name": "malware",
        "description": "Malware infection and propagation",
        "frequency_min": 2, "frequency_mode": 8, "frequency_max": 30,
        "impact_min": 25_000, "impact_mode": 150_000, "impact_max": 1_500_000,
    },
    "C": {  # Confidentiality -> System and Communications Protection
        "name": "data_exfiltration",
        "description": "Data exfiltration through communication channels",
        "frequency_min": 1, "frequency_mode": 3, "frequency_max": 12,
        "impact_min": 100_000, "impact_mode": 500_000, "impact_max": 10_000_000,
    },
    "P": {  # Privacy -> Program Management
        "name": "unassessed_risk",
        "description": "Unidentified or unassessed privacy risks materializing",
        "frequency_min": 1, "frequency_mode": 3, "frequency_max": 10,
        "impact_min": 50_000, "impact_mode": 250_000, "impact_max": 2_000_000,
    },
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ThreatScenario:
    """A single threat scenario with PERT distribution parameters."""

    name: str
    description: str = ""
    frequency_min: float = 1.0
    frequency_mode: float = 5.0
    frequency_max: float = 20.0
    impact_min: float = 10_000
    impact_mode: float = 100_000
    impact_max: float = 1_000_000
    control_effectiveness: float = 0.5  # 0.0 = no controls, 1.0 = perfect controls
    control_id: str | None = None
    framework: str | None = None

    @staticmethod
    def from_posture(
        posture: ControlPosture,
        scenario_catalog: dict[str, dict[str, Any]] | None = None,
    ) -> ThreatScenario | None:
        """Auto-generate a threat scenario from posture data.

        Maps control families to scenario categories:
          AC -> unauthorized_access
          SI -> malware
          CP -> service_disruption
          etc.

        Uses posture_score as control_effectiveness (0-100 mapped to 0.0-1.0).

        Returns None if no matching scenario category is found.
        """
        catalog = scenario_catalog or DEFAULT_SCENARIO_CATALOG

        # Extract the control family prefix from the control_id
        # Handles formats like: AC-2, AC-2(1), CC6.1, UCF-TPM-01
        control_id = posture.control_id
        family = _extract_family(control_id)

        scenario_template = catalog.get(family)
        if scenario_template is None:
            return None

        effectiveness = posture.posture_score / 100.0

        return ThreatScenario(
            name=f"{scenario_template['name']}:{control_id}",
            description=scenario_template.get("description", ""),
            frequency_min=scenario_template["frequency_min"],
            frequency_mode=scenario_template["frequency_mode"],
            frequency_max=scenario_template["frequency_max"],
            impact_min=scenario_template["impact_min"],
            impact_mode=scenario_template["impact_mode"],
            impact_max=scenario_template["impact_max"],
            control_effectiveness=effectiveness,
            control_id=control_id,
            framework=posture.framework,
        )


@dataclass
class SimulationResult:
    """Results from a Monte Carlo simulation of a single scenario."""

    scenario_name: str
    iterations: int
    mean_ale: float  # Annualized Loss Expectancy
    var_90: float    # Value at Risk, 90th percentile
    var_95: float    # Value at Risk, 95th percentile
    var_99: float    # Value at Risk, 99th percentile
    median_ale: float = 0.0
    min_ale: float = 0.0
    max_ale: float = 0.0
    std_dev: float = 0.0
    percentiles: dict[int, float] = field(default_factory=dict)
    control_effectiveness: float = 0.0
    exceedance_curve: list[tuple[float, float]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _posture_hash(postures: list[ControlPosture]) -> str:
    """Stable SHA-256 fingerprint of a posture list.

    Sorted by control_id so the hash is order-independent.  Only the fields
    that affect simulation inputs are included (control_id, posture_score,
    framework) so that irrelevant DB columns don't bust the cache.
    """
    payload = sorted(
        [
            {"c": p.control_id, "f": p.framework, "s": round(p.posture_score, 4)}
            for p in postures
        ],
        key=lambda x: x["c"],
    )
    return hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()


def _extract_family(control_id: str) -> str:
    """Extract the control family prefix from a control ID.

    Examples:
        AC-2       -> AC
        AC-2(1)    -> AC
        CC6.1      -> CC
        UCF-TPM-01 -> UCF-TPM
        SA-9       -> SA
        SR-3       -> SR
    """
    # Handle UCF-prefixed controls specially
    if control_id.startswith("UCF-"):
        parts = control_id.split("-")
        if len(parts) >= 3:
            return f"{parts[0]}-{parts[1]}"
        return control_id

    # Handle standard NIST-style: letters followed by dash/dot/digit
    family = ""
    for ch in control_id:
        if ch.isalpha():
            family += ch
        else:
            break
    return family or control_id


def _pert_sample(
    minimum: float, mode: float, maximum: float, lam: float = 4.0,
    rng: Any = None,
) -> float:
    """Generate a single sample from a PERT distribution.

    Uses Beta distribution parameterization when numpy is available,
    falls back to triangular distribution otherwise.
    """
    if minimum >= maximum:
        return mode

    if _HAS_NUMPY:
        gen = rng if rng is not None else np.random.default_rng()
        # PERT via Beta distribution
        mu = (minimum + lam * mode + maximum) / (lam + 2)
        if maximum == minimum:
            return mode
        if abs(mode - mu) < 1e-10:
            return float(gen.triangular(minimum, mode, maximum))
        # Avoid division by zero in alpha/beta calculation
        a1 = ((mu - minimum) * (2 * mode - minimum - maximum)) / (
            (mode - mu) * (maximum - minimum)
        )
        if a1 <= 0:
            a1 = 1.0
        a2 = a1 * (maximum - mu) / (mu - minimum) if (mu - minimum) > 0 else 1.0
        if a2 <= 0:
            a2 = 1.0
        sample = gen.beta(a1, a2)
        return minimum + sample * (maximum - minimum)
    else:
        # Triangular fallback
        return random.triangular(minimum, maximum, mode)


def _pert_samples(
    minimum: float, mode: float, maximum: float, n: int, lam: float = 4.0,
    rng: Any = None,
) -> list[float]:
    """Generate n samples from a PERT distribution."""
    if minimum >= maximum:
        return [mode] * n

    if _HAS_NUMPY:
        gen = rng if rng is not None else np.random.default_rng()
        mu = (minimum + lam * mode + maximum) / (lam + 2)
        if abs(mode - mu) < 1e-10:
            return list(gen.triangular(minimum, mode, maximum, size=n))
        a1 = ((mu - minimum) * (2 * mode - minimum - maximum)) / (
            (mode - mu) * (maximum - minimum)
        )
        if a1 <= 0:
            a1 = 1.0
        a2 = a1 * (maximum - mu) / (mu - minimum) if (mu - minimum) > 0 else 1.0
        if a2 <= 0:
            a2 = 1.0
        samples = gen.beta(a1, a2, size=n)
        return (minimum + samples * (maximum - minimum)).tolist()
    else:
        return [random.triangular(minimum, maximum, mode) for _ in range(n)]


# ---------------------------------------------------------------------------
# RiskEngine
# ---------------------------------------------------------------------------

class RiskEngine:
    """FAIR-based Monte Carlo risk simulation engine."""

    def __init__(self, default_iterations: int = 10_000, seed: int | None = None):
        self.default_iterations = default_iterations
        self._rng: Any = None
        if seed is not None:
            random.seed(seed)
            if _HAS_NUMPY:
                self._rng = np.random.default_rng(seed)
        elif _HAS_NUMPY:
            self._rng = np.random.default_rng()

    def simulate_scenario(
        self,
        scenario: ThreatScenario,
        iterations: int | None = None,
    ) -> SimulationResult:
        """Run Monte Carlo simulation for a single threat scenario.

        For each iteration:
          1. Sample threat event frequency from PERT distribution
          2. For each event, sample loss magnitude from PERT distribution
          3. Apply control effectiveness as a reduction factor
          4. Sum annual losses

        Returns:
            SimulationResult with statistical summary.
        """
        n = iterations or self.default_iterations
        annual_losses: list[float] = []

        rng = self._rng

        # Sample frequencies for all iterations
        frequencies = _pert_samples(
            scenario.frequency_min, scenario.frequency_mode, scenario.frequency_max, n,
            rng=rng,
        )

        if _HAS_NUMPY:
            # --- Fully vectorized path (#24 fix) ---
            gen = rng if rng is not None else np.random.default_rng()
            freq_arr = np.maximum(0, np.asarray(frequencies, dtype=np.float64))

            # Draw all event counts in one call — shape (n,)
            event_counts = gen.poisson(freq_arr)

            reduction = scenario.control_effectiveness
            loss_scale = 1.0 - reduction

            # Total events across all iterations
            total_events = int(event_counts.sum())
            if total_events > 0:
                # Generate all PERT samples at once instead of per-iteration
                all_losses = _pert_samples(
                    scenario.impact_min, scenario.impact_mode, scenario.impact_max,
                    total_events, rng=gen,
                )
                loss_arr = np.asarray(all_losses, dtype=np.float64)
                # Fully vectorized: use cumsum + split-by-offset to sum
                # losses per iteration without a Python loop
                cumsum = np.cumsum(loss_arr)
                offsets = np.cumsum(event_counts)
                # Per-iteration sums via cumsum differences
                per_iter_sums = np.empty(n, dtype=np.float64)
                per_iter_sums[0] = cumsum[offsets[0] - 1] if event_counts[0] > 0 else 0.0
                mask_nonzero = event_counts > 0
                # For iterations 1..n-1, sum = cumsum[end] - cumsum[start-1]
                per_iter_sums[1:] = np.where(
                    mask_nonzero[1:],
                    cumsum[np.clip(offsets[1:] - 1, 0, total_events - 1)]
                    - cumsum[np.clip(offsets[:-1] - 1, 0, total_events - 1)],
                    0.0,
                )
                # Zero out iterations with no events
                per_iter_sums[~mask_nonzero] = 0.0
                per_iter_sums *= loss_scale
                annual_losses = per_iter_sums.tolist()
            else:
                annual_losses = [0.0] * n
        else:
            # --- Pure-Python fallback ---
            for freq in frequencies:
                event_count = _poisson_pure(max(0, freq))
                if event_count == 0:
                    annual_losses.append(0.0)
                    continue
                losses = _pert_samples(
                    scenario.impact_min, scenario.impact_mode, scenario.impact_max, event_count,
                    rng=rng,
                )
                reduction = scenario.control_effectiveness
                total_loss = sum(loss * (1.0 - reduction) for loss in losses)
                annual_losses.append(total_loss)

        # Compute statistics
        annual_losses.sort()
        n_actual = len(annual_losses)
        mean_ale = sum(annual_losses) / n_actual if n_actual else 0.0
        median_ale = annual_losses[n_actual // 2] if n_actual else 0.0
        min_ale = annual_losses[0] if n_actual else 0.0
        max_ale = annual_losses[-1] if n_actual else 0.0

        # Standard deviation
        variance = sum((x - mean_ale) ** 2 for x in annual_losses) / n_actual if n_actual else 0.0
        std_dev = math.sqrt(variance)

        # Percentiles
        def _pct(p: int) -> float:
            idx = int(n_actual * p / 100)
            return annual_losses[min(idx, n_actual - 1)] if n_actual else 0.0

        percentiles = {p: round(_pct(p), 2) for p in [5, 10, 25, 50, 75, 90, 95, 99]}

        # Loss exceedance curve
        exceedance_curve = self.generate_exceedance_curve(annual_losses)

        return SimulationResult(
            scenario_name=scenario.name,
            iterations=n,
            mean_ale=round(mean_ale, 2),
            var_90=round(_pct(90), 2),
            var_95=round(_pct(95), 2),
            var_99=round(_pct(99), 2),
            median_ale=round(median_ale, 2),
            min_ale=round(min_ale, 2),
            max_ale=round(max_ale, 2),
            std_dev=round(std_dev, 2),
            percentiles=percentiles,
            control_effectiveness=scenario.control_effectiveness,
            exceedance_curve=exceedance_curve,
        )

    @staticmethod
    def generate_exceedance_curve(
        annual_losses: list[float],
        points: int = 100,
    ) -> list[tuple[float, float]]:
        """Compute a loss exceedance curve from Monte Carlo results.

        For each of ``points`` evenly-spaced loss thresholds between the
        minimum and maximum simulated loss, computes the probability that
        annual losses exceed that threshold.

        Args:
            annual_losses: Sorted list of simulated annual loss values.
            points: Number of threshold points to compute (default 100).

        Returns:
            List of ``(loss_amount, probability_of_exceedance)`` tuples
            sorted by ascending loss_amount.
        """
        n = len(annual_losses)
        if n == 0:
            return []

        # annual_losses is expected sorted; ensure it
        losses = sorted(annual_losses)
        lo = losses[0]
        hi = losses[-1]

        if hi <= lo:
            return [(round(lo, 2), 1.0)]

        step = (hi - lo) / points
        curve: list[tuple[float, float]] = []

        for i in range(points + 1):
            threshold = lo + step * i
            # Count how many losses exceed this threshold
            # Since losses is sorted, use bisect for efficiency
            idx = bisect.bisect_right(losses, threshold)
            prob = (n - idx) / n
            curve.append((round(threshold, 2), round(prob, 6)))

        return curve

    def simulate_portfolio(
        self,
        scenarios: list[ThreatScenario],
        iterations: int | None = None,
    ) -> dict[str, Any]:
        """Run simulation across all scenarios and aggregate.

        Returns:
            Dict with per-scenario results and portfolio-level aggregates.
        """
        n = iterations or self.default_iterations
        results: list[SimulationResult] = []
        for scenario in scenarios:
            result = self.simulate_scenario(scenario, iterations=n)
            results.append(result)

        total_mean = sum(r.mean_ale for r in results)
        # VaR is summed across scenarios assuming perfect positive correlation.
        # This is a conservative upper bound; in practice, diversification
        # effects would reduce portfolio VaR. A copula-based approach would
        # provide a more accurate estimate but requires correlation data.
        total_var_95 = sum(r.var_95 for r in results)
        total_var_99 = sum(r.var_99 for r in results)

        return {
            "scenarios": [
                {
                    "name": r.scenario_name,
                    "mean_ale": r.mean_ale,
                    "var_95": r.var_95,
                    "var_99": r.var_99,
                    "control_effectiveness": r.control_effectiveness,
                    "exceedance_curve": r.exceedance_curve,
                }
                for r in results
            ],
            "portfolio": {
                "total_mean_ale": round(total_mean, 2),
                "total_var_95": round(total_var_95, 2),
                "total_var_99": round(total_var_99, 2),
                "scenario_count": len(results),
                "iterations": n,
                "portfolio_note": (
                    "VaR summed assuming perfect correlation "
                    "(conservative upper bound)"
                ),
            },
        }

    def compare_treatments(
        self,
        scenario: ThreatScenario,
        treatments: list[dict[str, Any]],
        iterations: int | None = None,
    ) -> list[dict[str, Any]]:
        """Compare risk treatment options for a scenario.

        Each treatment is a dict with:
          - name: str
          - effectiveness_delta: float (added to control_effectiveness, capped at 1.0)
          - cost: float (annual cost of the treatment)

        Returns:
            List of dicts with treatment analysis including ROI.
        """
        n = iterations or self.default_iterations

        # Baseline
        baseline = self.simulate_scenario(scenario, iterations=n)

        comparisons: list[dict[str, Any]] = []
        for treatment in treatments:
            # Create modified scenario
            new_effectiveness = min(
                1.0,
                scenario.control_effectiveness + treatment.get("effectiveness_delta", 0.0),
            )
            treated = ThreatScenario(
                name=scenario.name,
                description=scenario.description,
                frequency_min=scenario.frequency_min,
                frequency_mode=scenario.frequency_mode,
                frequency_max=scenario.frequency_max,
                impact_min=scenario.impact_min,
                impact_mode=scenario.impact_mode,
                impact_max=scenario.impact_max,
                control_effectiveness=new_effectiveness,
                control_id=scenario.control_id,
                framework=scenario.framework,
            )
            treated_result = self.simulate_scenario(treated, iterations=n)

            risk_reduction = baseline.mean_ale - treated_result.mean_ale
            treatment_cost = treatment.get("cost", 0.0)
            roi = (
                (risk_reduction - treatment_cost) / treatment_cost
                if treatment_cost > 0
                else float("inf") if risk_reduction > 0 else 0.0
            )

            comparisons.append({
                "treatment": treatment.get("name", "unnamed"),
                "baseline_mean_ale": baseline.mean_ale,
                "treated_mean_ale": treated_result.mean_ale,
                "risk_reduction": round(risk_reduction, 2),
                "treatment_cost": treatment_cost,
                "roi": round(roi, 4),
                "new_effectiveness": new_effectiveness,
                "var_95_reduction": round(baseline.var_95 - treated_result.var_95, 2),
            })

        return comparisons

    def analyze_framework_risk(
        self,
        session: Session,
        framework: str,
        iterations: int | None = None,
        scenario_catalog: dict[str, dict[str, Any]] | None = None,
        cache_ttl_hours: float = 4.0,
    ) -> dict[str, Any]:
        """Run risk simulation across all controls in a framework.

        Uses PostureAggregator to get current posture scores, converts them
        to ThreatScenarios via from_posture, and runs portfolio simulation.

        Results are persisted as RiskAnalysis rows.  Before running, checks
        whether a cached result exists whose posture hash matches the current
        posture and whose age is within *cache_ttl_hours* (default 4).  If a
        cache hit is found the simulation is skipped and the cached portfolio
        totals are returned immediately.

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier (e.g. ``"nist_800_53"``).
            iterations: Monte Carlo iteration count; defaults to
                ``self.default_iterations``.
            scenario_catalog: Override the default scenario catalog.
            cache_ttl_hours: How many hours a cached result stays valid.
                Set to 0 to disable caching.

        Returns:
            Portfolio-level risk analysis dict.
        """
        n = iterations or self.default_iterations
        catalog = scenario_catalog or DEFAULT_SCENARIO_CATALOG

        aggregator = PostureAggregator()
        postures = aggregator.aggregate_framework(session, framework)

        if not postures:
            log.warning("No posture data for framework %s", framework)
            return {
                "framework": framework,
                "scenarios": [],
                "portfolio": {
                    "total_mean_ale": 0.0,
                    "total_var_95": 0.0,
                    "total_var_99": 0.0,
                    "scenario_count": 0,
                    "iterations": n,
                },
            }

        # --- Cache check (#53) ---
        if cache_ttl_hours > 0:
            current_hash = _posture_hash(postures)
            cutoff = datetime.now(timezone.utc) - timedelta(hours=cache_ttl_hours)
            cached = (
                session.query(RiskAnalysis)
                .filter(
                    RiskAnalysis.framework == framework,
                    RiskAnalysis.created_at >= cutoff,
                )
                .filter(
                    RiskAnalysis.details.isnot(None),
                )
                .order_by(RiskAnalysis.created_at.desc())
                .first()
            )
            if cached and isinstance(cached.details, dict):
                cached_hash = cached.details.get("posture_hash")
                if cached_hash == current_hash:
                    log.info(
                        "Cache hit for %s (hash=%s, age<%.1fh) — skipping simulation",
                        framework,
                        current_hash[:8],
                        cache_ttl_hours,
                    )
                    self._record_hit()
                    return cached.details.get("portfolio_result", {})

        # --- Convert postures to scenarios ---
        scenarios: list[ThreatScenario] = []
        for posture in postures:
            scenario = ThreatScenario.from_posture(posture, catalog)
            if scenario is not None:
                scenarios.append(scenario)

        if not scenarios:
            log.warning(
                "No threat scenarios generated for framework %s "
                "(no control families matched the scenario catalog)",
                framework,
            )
            return {
                "framework": framework,
                "scenarios": [],
                "portfolio": {
                    "total_mean_ale": 0.0,
                    "total_var_95": 0.0,
                    "total_var_99": 0.0,
                    "scenario_count": 0,
                    "iterations": n,
                },
            }

        # Run portfolio simulation (cache miss — record before simulation)
        self._record_miss()
        portfolio = self.simulate_portfolio(scenarios, iterations=n)
        portfolio["framework"] = framework

        # Persist results — first row carries the full portfolio payload and
        # posture hash for cache retrieval; subsequent rows carry scenario detail.
        now = datetime.now(timezone.utc)
        posture_hash = _posture_hash(postures) if cache_ttl_hours > 0 else ""
        for idx, scenario_result in enumerate(portfolio["scenarios"]):
            details: dict[str, Any] = {
                "portfolio_total_mean_ale": portfolio["portfolio"]["total_mean_ale"],
                "portfolio_total_var_95": portfolio["portfolio"]["total_var_95"],
            }
            if idx == 0:
                # Embed cache artefacts only on the first (representative) row
                details["posture_hash"] = posture_hash
                details["portfolio_result"] = portfolio
            analysis = RiskAnalysis(
                framework=framework,
                scenario_name=scenario_result["name"],
                mean_ale=scenario_result["mean_ale"],
                var_95=scenario_result["var_95"],
                var_99=scenario_result["var_99"],
                control_effectiveness=scenario_result["control_effectiveness"],
                iterations=n,
                details=details,
                created_at=now,
            )
            session.add(analysis)

        session.flush()
        log.info(
            "Risk analysis complete for %s: %d scenarios, total mean ALE $%.2f",
            framework,
            len(scenarios),
            portfolio["portfolio"]["total_mean_ale"],
        )
        return portfolio

    def precompute_all_frameworks(
        self,
        session: Session,
        cache_ttl_hours: float = 4.0,
    ) -> dict[str, dict[str, Any]]:
        """Pre-warm the Monte Carlo cache for every active framework.

        Discovers active frameworks by querying the distinct set of framework
        values present in ``ControlResult``.  For each framework, calls
        ``analyze_framework_risk()`` which populates the DB-backed cache when a
        valid cached entry does not already exist.

        Args:
            session: SQLAlchemy session.
            cache_ttl_hours: TTL forwarded to ``analyze_framework_risk``.

        Returns:
            Summary dict keyed by framework name::

                {
                    "nist_800_53": {"cached": False, "duration_ms": 4312},
                    "soc2":        {"cached": True,  "duration_ms": 3},
                }

            ``cached=True`` means a fresh cache entry was found and the
            simulation was skipped; ``cached=False`` means the simulation ran
            and results were written to the DB.
        """
        from sqlalchemy import distinct as sa_distinct
        from warlock.db.models import ControlResult

        frameworks: list[str] = [
            row[0]
            for row in session.query(sa_distinct(ControlResult.framework)).all()
            if row[0]
        ]

        if not frameworks:
            log.warning("precompute_all_frameworks: no active frameworks found in ControlResult")
            return {}

        log.info("precompute_all_frameworks: warming cache for %d frameworks", len(frameworks))
        summary: dict[str, dict[str, Any]] = {}

        for framework in sorted(frameworks):
            # Record hit/miss counters before the call so we can detect
            # whether analyze_framework_risk found a cache hit, without
            # duplicating the posture aggregation that _cache_hit performs.
            with self._stats_lock:
                hits_before = self._cache_hits

            t0 = datetime.now(timezone.utc)
            try:
                self.analyze_framework_risk(
                    session,
                    framework,
                    cache_ttl_hours=cache_ttl_hours,
                )
            except Exception as exc:  # pragma: no cover
                log.exception("precompute_all_frameworks: error processing %s", framework)
                summary[framework] = {"cached": False, "duration_ms": 0, "error": str(exc)}
                continue

            with self._stats_lock:
                hit = self._cache_hits > hits_before

            duration_ms = int(
                (datetime.now(timezone.utc) - t0).total_seconds() * 1000
            )
            summary[framework] = {"cached": hit, "duration_ms": duration_ms}
            log.info(
                "precompute_all_frameworks: %s — %s in %d ms",
                framework,
                "cache hit" if hit else "simulation ran",
                duration_ms,
            )

        return summary

    def _cache_hit(
        self,
        session: Session,
        framework: str,
        cache_ttl_hours: float,
    ) -> bool:
        """Return True if a valid, hash-matching cache entry exists.

        This is a lightweight pre-check used by ``precompute_all_frameworks``
        to distinguish cache hits from misses without duplicating the logic
        embedded inside ``analyze_framework_risk``.
        """
        if cache_ttl_hours <= 0:
            return False

        aggregator = PostureAggregator()
        postures = aggregator.aggregate_framework(session, framework)
        if not postures:
            return False

        current_hash = _posture_hash(postures)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=cache_ttl_hours)
        cached = (
            session.query(RiskAnalysis)
            .filter(
                RiskAnalysis.framework == framework,
                RiskAnalysis.created_at >= cutoff,
                RiskAnalysis.details.isnot(None),
            )
            .order_by(RiskAnalysis.created_at.desc())
            .first()
        )
        if cached and isinstance(cached.details, dict):
            return cached.details.get("posture_hash") == current_hash
        return False

    # -------------------------------------------------------------------------
    # Cache stats
    # -------------------------------------------------------------------------

    # Module-level hit/miss counters shared across all RiskEngine instances.
    # Protected by _stats_lock; updated by analyze_framework_risk via the
    # internal tracking hooks below.
    _cache_hits: int = 0
    _cache_misses: int = 0
    _stats_lock: threading.Lock = threading.Lock()

    @classmethod
    def _record_hit(cls) -> None:
        """Increment the in-process cache hit counter."""
        with cls._stats_lock:
            cls._cache_hits += 1

    @classmethod
    def _record_miss(cls) -> None:
        """Increment the in-process cache miss counter."""
        with cls._stats_lock:
            cls._cache_misses += 1

    def get_cache_stats(self, session: Session) -> dict[str, Any]:
        """Return runtime statistics about the Monte Carlo DB cache.

        Queries the ``RiskAnalysis`` table for aggregate information and
        combines it with the in-process hit/miss counters that are incremented
        each time ``analyze_framework_risk`` is called.

        Returns:
            Dict with the following keys:

            * ``total_entries``       — total RiskAnalysis rows in the DB.
            * ``oldest_entry_age_hours`` — age of the oldest entry in hours,
              or ``None`` when the table is empty.
            * ``entries_per_framework`` — ``{framework: count}`` dict.
            * ``cache_hits``          — cumulative in-process hit count.
            * ``cache_misses``        — cumulative in-process miss count.
            * ``hit_rate``            — float 0.0-1.0, or ``None`` when no
              calls have been recorded yet.
        """
        from sqlalchemy import func as sa_func

        # Total rows
        total: int = session.query(sa_func.count(RiskAnalysis.id)).scalar() or 0

        # Oldest created_at
        oldest = session.query(sa_func.min(RiskAnalysis.created_at)).scalar()
        if oldest is not None:
            # Ensure timezone-aware before subtraction
            if oldest.tzinfo is None:
                oldest = oldest.replace(tzinfo=timezone.utc)
            age_hours: float | None = (
                datetime.now(timezone.utc) - oldest
            ).total_seconds() / 3600.0
        else:
            age_hours = None

        # Per-framework counts
        rows = (
            session.query(RiskAnalysis.framework, sa_func.count(RiskAnalysis.id))
            .group_by(RiskAnalysis.framework)
            .all()
        )
        per_framework: dict[str, int] = {fw: cnt for fw, cnt in rows if fw}

        # In-process counters
        with self._stats_lock:
            hits = self._cache_hits
            misses = self._cache_misses

        total_calls = hits + misses
        hit_rate: float | None = (hits / total_calls) if total_calls > 0 else None

        return {
            "total_entries": total,
            "oldest_entry_age_hours": round(age_hours, 2) if age_hours is not None else None,
            "entries_per_framework": per_framework,
            "cache_hits": hits,
            "cache_misses": misses,
            "hit_rate": round(hit_rate, 4) if hit_rate is not None else None,
        }

    # -------------------------------------------------------------------------
    # Cache invalidation
    # -------------------------------------------------------------------------

    def generate_narrative(
        self,
        session: Session,
        framework: str,
        portfolio_result: dict[str, Any],
    ) -> dict[str, str | None] | None:
        """Generate AI-written risk narratives from portfolio simulation results.

        Calls ``AIService.reason(AITask.RISK_NARRATIVE, ...)`` with the
        portfolio result data, scenario details, and posture data to
        produce audience-targeted summaries.

        When AI is off or unavailable, returns ``None`` so that the
        caller can fall back to showing raw numbers directly.

        Args:
            session: SQLAlchemy database session (used for posture lookup).
            framework: Framework identifier (e.g. ``"nist_800_53"``).
            portfolio_result: The dict returned by ``analyze_framework_risk()``
                or ``simulate_portfolio()`` -- must contain ``portfolio`` and
                ``scenarios`` keys.

        Returns:
            A dict with three audience-targeted narrative strings when AI
            succeeds::

                {
                    "technical_summary": "...",
                    "insurance_summary": "...",
                    "board_summary": "...",
                }

            Returns ``None`` when AI is off or the call fails, signaling
            the caller to present raw quantitative data instead.
        """
        from warlock.ai import get_ai_service, AITask

        ai = get_ai_service()

        # Gather posture data for additional context
        aggregator = PostureAggregator()
        postures = aggregator.aggregate_framework(session, framework)
        posture_data = [
            {
                "control_id": p.control_id,
                "posture_score": p.posture_score,
                "framework": p.framework,
            }
            for p in postures[:50]  # Cap to avoid prompt bloat
        ]

        context: dict[str, Any] = {
            "framework": framework,
            "portfolio_result": portfolio_result,
            "scenarios": portfolio_result.get("scenarios", []),
            "posture_data": posture_data,
        }

        result = ai.reason(
            task=AITask.RISK_NARRATIVE,
            context=context,
            fallback=lambda: None,
        )

        if not result.ai_used or result.value is None:
            log.debug(
                "generate_narrative for %s: AI not used (reason=%s)",
                framework,
                result.fallback_reason,
            )
            return None

        # Parse the AI response into the expected structure
        value = result.value
        if isinstance(value, dict):
            narrative_text = value.get("narrative", "")
            return {
                "technical_summary": value.get("technical_summary", narrative_text),
                "insurance_summary": value.get("insurance_summary", narrative_text),
                "board_summary": value.get("board_summary", narrative_text),
            }

        # Raw string response -- use for all three summaries
        text = str(value)
        return {
            "technical_summary": text,
            "insurance_summary": text,
            "board_summary": text,
        }

    def invalidate_cache(
        self,
        session: Session,
        framework: str | None = None,
    ) -> dict[str, Any]:
        """Delete cached RiskAnalysis entries from the database.

        Args:
            session: SQLAlchemy session.  The caller is responsible for
                committing the transaction after this method returns.
            framework: If given, only entries for that framework are deleted.
                Pass ``None`` to clear **all** cached entries.

        Returns:
            Dict with ``{"deleted": int, "framework": str | None}``.
        """
        q = session.query(RiskAnalysis)
        if framework is not None:
            q = q.filter(RiskAnalysis.framework == framework)

        # Count before delete for the summary
        count = q.count()
        q.delete(synchronize_session="fetch")

        if framework is not None:
            log.info(
                "invalidate_cache: deleted %d entries for framework '%s'",
                count,
                framework,
            )
        else:
            log.info("invalidate_cache: deleted %d entries (all frameworks)", count)

        return {"deleted": count, "framework": framework}


# ---------------------------------------------------------------------------
# Pure-Python Poisson sampling (no numpy needed)
# ---------------------------------------------------------------------------

def _poisson_pure(lam: float) -> int:
    """Generate a Poisson-distributed random integer using Knuth's algorithm."""
    if lam <= 0:
        return 0
    if lam > 30:
        # Normal approximation for large lambda
        return max(0, int(random.gauss(lam, math.sqrt(lam))))
    L = math.exp(-lam)
    k = 0
    p = 1.0
    while True:
        k += 1
        p *= random.random()
        if p <= L:
            return k - 1
