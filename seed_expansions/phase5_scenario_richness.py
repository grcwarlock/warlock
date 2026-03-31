"""Compatibility shim for phase-5 seed expansion.

The canonical implementation lives in ``scripts.seed_expansions``.
Keep this module as a thin delegate to avoid drift between duplicate
package paths used by different entry points.
"""

from __future__ import annotations

from scripts.seed_expansions.phase5_scenario_richness import seed_phase5  # noqa: F401
