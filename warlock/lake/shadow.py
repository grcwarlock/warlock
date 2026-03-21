"""Shadow query comparator — validates lake reads against OLTP.

During Phase 2 migration, shadow queries run both OLTP and lake
paths for the same query. Results are compared and discrepancies
are logged. This is the safety net that proves the lake is correct.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

log = logging.getLogger(__name__)


@dataclass
class ComparisonResult:
    query_name: str
    match: bool
    oltp_count: int = 0
    lake_count: int = 0
    oltp_ms: float = 0.0
    lake_ms: float = 0.0
    discrepancies: list[str] = field(default_factory=list)


def compare_results(query_name: str, oltp_result: Any, lake_result: Any) -> ComparisonResult:
    """Compare OLTP and lake query results."""
    result = ComparisonResult(query_name=query_name, match=True)

    oltp_list = list(oltp_result) if oltp_result else []
    lake_list = list(lake_result) if lake_result else []

    result.oltp_count = len(oltp_list)
    result.lake_count = len(lake_list)

    if result.oltp_count != result.lake_count:
        result.match = False
        result.discrepancies.append(
            f"Row count mismatch: OLTP={result.oltp_count}, Lake={result.lake_count}"
        )
        return result

    for i, (o, lake_val) in enumerate(zip(oltp_list, lake_list)):
        if o != lake_val:
            result.match = False
            result.discrepancies.append(f"Row {i} differs: OLTP={o!r}, Lake={lake_val!r}")
            if len(result.discrepancies) > 10:
                result.discrepancies.append("... (truncated)")
                break

    return result


class ShadowQueryRunner:
    """Runs both OLTP and lake queries, compares, logs results."""

    def __init__(self) -> None:
        self._results: list[ComparisonResult] = []

    def compare(
        self,
        query_name: str,
        oltp_fn: Callable[[], Any],
        lake_fn: Callable[[], Any],
    ) -> ComparisonResult:
        """Run both queries and compare results."""
        start = time.perf_counter()
        oltp_result = oltp_fn()
        oltp_ms = (time.perf_counter() - start) * 1000

        start = time.perf_counter()
        try:
            lake_result = lake_fn()
        except Exception as exc:
            lake_ms = (time.perf_counter() - start) * 1000
            log.warning("Shadow lake query %s failed: %s — using OLTP result", query_name, exc)
            result = ComparisonResult(
                query_name=query_name, match=False,
                oltp_count=len(list(oltp_result)) if oltp_result else 0,
                oltp_ms=oltp_ms, lake_ms=lake_ms,
            )
            result.discrepancies.append(f"Lake query failed: {exc}")
            self._results.append(result)
            return result
        lake_ms = (time.perf_counter() - start) * 1000

        result = compare_results(query_name, oltp_result, lake_result)
        result.oltp_ms = oltp_ms
        result.lake_ms = lake_ms

        if result.match:
            log.debug(
                "Shadow OK: %s (OLTP=%.1fms, Lake=%.1fms, %d rows)",
                query_name, oltp_ms, lake_ms, result.oltp_count,
            )
        else:
            log.warning(
                "Shadow MISMATCH: %s — %s",
                query_name, "; ".join(result.discrepancies[:3]),
            )

        self._results.append(result)
        return result

    @property
    def all_match(self) -> bool:
        return all(r.match for r in self._results)

    @property
    def mismatches(self) -> list[ComparisonResult]:
        return [r for r in self._results if not r.match]
