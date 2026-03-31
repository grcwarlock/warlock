"""Compatibility shim for phase-3 seed expansion.

The canonical implementation lives in ``scripts.seed_expansions``.
Keep this module as a thin delegate to avoid drift between duplicate
package paths used by different entry points.
"""

from __future__ import annotations

from scripts.seed_expansions.phase3_time_depth import seed_phase3  # noqa: F401
