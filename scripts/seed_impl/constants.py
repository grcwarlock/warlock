"""Demo seed clock anchor (single module load)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

NOW = datetime.now(timezone.utc)

# scripts/seed_impl/*.py -> parents[2] == repository root (same as scripts/demo_seed.py parent.parent)
REPO_ROOT = Path(__file__).resolve().parents[2]
