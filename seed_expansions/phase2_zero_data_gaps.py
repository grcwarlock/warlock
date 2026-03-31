"""Compatibility shim for phase-2 seed expansion.

The canonical implementation lives in ``scripts.seed_expansions``.
Keep this module as a thin delegate to avoid drift between duplicate
package paths used by different entry points.
"""

from __future__ import annotations

from scripts.seed_expansions.phase2_zero_data_gaps import seed_phase2  # noqa: F401
