"""ARCH-008: PostgreSQL table partitioning strategy.

Generates and applies ``PARTITION BY RANGE`` DDL for high-volume tables
(``findings``, ``control_results``, ``audit_entries``).  SQLite does not
support partitioning — all functions are safe no-ops on non-PostgreSQL
engines.

Usage (CLI)::

    warlock db partition --table findings --interval monthly

Usage (programmatic)::

    from warlock.db.partitioning import setup_partitioning
    from warlock.db.engine import get_engine

    setup_partitioning(get_engine(), "findings", interval="monthly")
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

log = logging.getLogger(__name__)

# Tables eligible for partitioning and their default partition column.
PARTITIONABLE_TABLES: dict[str, str] = {
    "findings": "ingested_at",
    "control_results": "assessed_at",
    "audit_entries": "created_at",
}


def _is_postgresql(engine: Engine) -> bool:
    """Return ``True`` if *engine* is connected to PostgreSQL."""
    return str(engine.url).startswith("postgresql")


def _partition_bounds(interval: str, periods: int = 6) -> list[tuple[str, str, str]]:
    """Generate partition name and boundary pairs.

    Returns a list of ``(partition_name_suffix, start_bound, end_bound)``
    tuples covering *periods* intervals from the current date.

    Parameters
    ----------
    interval:
        ``"monthly"`` or ``"quarterly"``.
    periods:
        Number of partitions to create ahead of the current date.
    """
    from dateutil.relativedelta import relativedelta

    now = datetime.now(timezone.utc)
    if interval == "quarterly":
        # Align to quarter start.
        quarter_month = ((now.month - 1) // 3) * 3 + 1
        start = now.replace(month=quarter_month, day=1, hour=0, minute=0, second=0, microsecond=0)
        delta = relativedelta(months=3)
        fmt = "q%Y_%m"
    else:
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        delta = relativedelta(months=1)
        fmt = "p%Y_%m"

    bounds: list[tuple[str, str, str]] = []
    for i in range(-1, periods):
        lo = start + delta * i
        hi = lo + delta
        suffix = lo.strftime(fmt)
        bounds.append((suffix, lo.strftime("%Y-%m-%d"), hi.strftime("%Y-%m-%d")))

    return bounds


def setup_partitioning(
    engine: Engine,
    table_name: str,
    partition_column: str | None = None,
    interval: str = "monthly",
    periods: int = 6,
    dry_run: bool = False,
) -> list[str]:
    """Create range partitions for a high-volume table.

    Only applies to PostgreSQL.  Returns the DDL statements generated
    (executed unless *dry_run* is ``True``).  On SQLite this is a no-op
    that returns an empty list.

    Parameters
    ----------
    engine:
        SQLAlchemy engine.
    table_name:
        Target table (must be in :data:`PARTITIONABLE_TABLES`).
    partition_column:
        Column to partition on.  Defaults to the table's standard column.
    interval:
        ``"monthly"`` or ``"quarterly"``.
    periods:
        How many future partitions to pre-create.
    dry_run:
        If ``True``, return DDL without executing.
    """
    if not _is_postgresql(engine):
        log.info("Partitioning skipped — engine is not PostgreSQL")
        return []

    if table_name not in PARTITIONABLE_TABLES:
        raise ValueError(
            f"Table '{table_name}' is not eligible for partitioning. "
            f"Allowed: {', '.join(sorted(PARTITIONABLE_TABLES))}"
        )

    try:
        bounds = _partition_bounds(interval, periods)
    except ImportError:
        log.error(
            "python-dateutil is required for partition generation — "
            "install with: pip install python-dateutil"
        )
        return []

    statements: list[str] = []
    for suffix, lo, hi in bounds:
        part_name = f"{table_name}_{suffix}"
        stmt = (
            f"CREATE TABLE IF NOT EXISTS {part_name} "
            f"PARTITION OF {table_name} "
            f"FOR VALUES FROM ('{lo}') TO ('{hi}')"
        )
        statements.append(stmt)

    if dry_run:
        for s in statements:
            log.info("DRY RUN: %s", s)
        return statements

    from sqlalchemy import text

    with engine.begin() as conn:
        for stmt in statements:
            try:
                conn.execute(text(stmt))
                log.info("Created partition: %s", stmt.split("IF NOT EXISTS ")[1].split(" ")[0])
            except Exception:
                # Partition may already exist or table isn't partitioned yet.
                log.debug("Partition DDL skipped (may already exist): %s", stmt, exc_info=True)

    return statements


def get_partition_ddl(table_name: str, partition_column: str | None = None) -> str:
    """Return the ``ALTER TABLE ... PARTITION BY RANGE`` DDL hint.

    This is informational — partitioning must be set up *before* data
    exists in the table (typically during initial migration).
    """
    col = partition_column or PARTITIONABLE_TABLES.get(table_name, "created_at")
    return f"-- Convert to partitioned table:\n-- CREATE TABLE {table_name} (...) PARTITION BY RANGE ({col});"
