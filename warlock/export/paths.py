"""Export path management for Warlock GRC.

Organises export files into ``exports/<report_type>/`` under the project
root so they don't litter the top-level directory.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[2]  # warlock repo root
EXPORTS_DIR = _PROJECT_ROOT / "exports"

# Mapping of export format keys → subfolder names
REPORT_TYPE_DIRS: dict[str, str] = {
    "ar": "oscal-ar",
    "ssp": "oscal-ssp",
    "poam": "oscal-poam",
    "sap": "oscal-sap",
    "comp-def": "oscal-comp-def",
    "ssp-narrative": "ssp-narrative",
    "board-pdf": "board-pdf",
    "soc2": "soc2",
    "iso_soa": "iso-soa",
    "markdown": "markdown",
    "html": "html",
    "pdf": "pdf",
    "evidence_json": "evidence-json",
    "evidence_csv": "evidence-csv",
    "audit_package": "audit-package",
}


def export_path(
    report_type: str,
    *,
    framework: str | None = None,
    extension: str = "json",
    base_dir: Path | None = None,
) -> Path:
    """Build an organised export file path.

    Returns something like::

        exports/oscal-ar/nist_800_53_2026-03-18T14-30-00Z.json

    Args:
        report_type: Key into ``REPORT_TYPE_DIRS`` (e.g. ``"ar"``, ``"pdf"``).
        framework: Optional framework slug appended to the filename.
        extension: File extension (without dot).
        base_dir: Override the default ``exports/`` root.
    """
    root = base_dir or EXPORTS_DIR
    subdir = REPORT_TYPE_DIRS.get(report_type, report_type)
    dest = root / subdir

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    name_parts = [report_type]
    if framework:
        name_parts.append(framework)
    name_parts.append(timestamp)
    filename = f"{'_'.join(name_parts)}.{extension}"

    dest.mkdir(parents=True, exist_ok=True)
    return dest / filename
