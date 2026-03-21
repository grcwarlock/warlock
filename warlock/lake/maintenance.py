"""Lake maintenance jobs — compaction, snapshot expiry, orphan cleanup.

These jobs keep the lake performant by:
1. Compacting small Parquet files into larger ones (~256MB target)
2. Expiring old snapshot files (time-travel data beyond retention window)
3. Removing orphaned files not referenced by any table
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def compact(lake_path: str, target_size_mb: int = 256) -> dict[str, int]:
    """Compact small Parquet files into larger ones.

    Scans each zone for directories with multiple small files and
    rewrites them as fewer, larger files.

    Returns dict of {zone: files_compacted}.
    """
    import pyarrow as pa
    import pyarrow.parquet as pq

    base = Path(lake_path)
    stats = {}

    for zone_dir in _iter_leaf_dirs(base):
        parquet_files = sorted(zone_dir.glob("*.parquet"))
        if len(parquet_files) <= 1:
            continue

        # Check total size
        total_size = sum(f.stat().st_size for f in parquet_files)
        target_bytes = target_size_mb * 1024 * 1024

        if total_size < target_bytes and len(parquet_files) > 1:
            # Small enough to merge into one file
            try:
                tables = [pq.read_table(str(f)) for f in parquet_files]
                merged = pa.concat_tables(tables)

                # Write merged file
                merged_path = zone_dir / "compacted.parquet"
                pq.write_table(merged, str(merged_path))

                # Remove originals
                for f in parquet_files:
                    f.unlink()

                zone_key = str(zone_dir.relative_to(base))
                stats[zone_key] = len(parquet_files)
                log.info("Compacted %d files in %s", len(parquet_files), zone_key)
            except Exception as exc:
                log.warning("Compaction failed for %s: %s", zone_dir, exc)

    return stats


def expire_snapshots(
    lake_path: str,
    raw_days: int = 7,
    enrichment_days: int = 30,
    curated_days: int = 365,
) -> dict[str, int]:
    """Remove files older than retention window per zone.

    Returns dict of {zone: files_removed}.
    """
    base = Path(lake_path)
    stats = {}
    now = datetime.now(timezone.utc)

    zone_retention = {
        "raw": timedelta(days=raw_days),
        "enrichment": timedelta(days=enrichment_days),
        "curated": timedelta(days=curated_days),
    }

    for zone_name, max_age in zone_retention.items():
        zone_dir = base / zone_name
        if not zone_dir.exists():
            continue

        cutoff = now - max_age
        removed = 0

        for parquet_file in zone_dir.rglob("*.parquet"):
            file_mtime = datetime.fromtimestamp(
                parquet_file.stat().st_mtime, tz=timezone.utc
            )
            if file_mtime < cutoff:
                parquet_file.unlink()
                removed += 1

        if removed:
            stats[zone_name] = removed
            log.info(
                "Expired %d files in %s (older than %d days)",
                removed,
                zone_name,
                max_age.days,
            )

    return stats


def cleanup_orphans(lake_path: str) -> dict[str, int]:
    """Remove empty directories left after compaction or expiry.

    Returns dict of {zone: dirs_removed}.
    """
    base = Path(lake_path)
    stats = {}

    for zone_name in ["raw", "enrichment", "curated"]:
        zone_dir = base / zone_name
        if not zone_dir.exists():
            continue

        removed = 0
        # Walk bottom-up to remove empty dirs
        for dirpath, dirnames, filenames in os.walk(str(zone_dir), topdown=False):
            p = Path(dirpath)
            if p == zone_dir:
                continue
            if not any(p.iterdir()):
                p.rmdir()
                removed += 1

        if removed:
            stats[zone_name] = removed
            log.info("Cleaned up %d empty directories in %s", removed, zone_name)

    return stats


def run_all_maintenance(lake_path: str) -> dict[str, Any]:
    """Run all maintenance jobs in order."""
    results = {
        "compaction": compact(lake_path),
        "expiry": expire_snapshots(lake_path),
        "orphan_cleanup": cleanup_orphans(lake_path),
    }
    return results


def expire_snapshots_safe(session, lake_path: str, **kwargs) -> dict:
    """expire_snapshots with legal hold checking.

    Checks for active legal holds before expiring any files.
    If any hold is active, returns immediately without deleting.
    """
    from warlock.db.models import LegalHold
    active_holds = session.query(LegalHold).filter(LegalHold.is_active == True).count()
    if active_holds > 0:
        log.warning("Snapshot expiry blocked: %d active legal hold(s)", active_holds)
        return {"blocked_by_hold": True, "active_holds": active_holds}
    return expire_snapshots(lake_path, **kwargs)


def _iter_leaf_dirs(base: Path):
    """Iterate leaf directories (dirs with parquet files, no subdirs with parquets)."""
    for dirpath, dirnames, filenames in os.walk(str(base)):
        p = Path(dirpath)
        if any(f.endswith(".parquet") for f in filenames):
            yield p
