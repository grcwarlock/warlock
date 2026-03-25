# 686-Command Test Sweep — 2026-03-24

Full test of every leaf CLI command against seeded demo database.
686 commands tested across 6 parallel agents.

## Results: 681 PASS, 5 EXPECTED FAIL (optional deps)

All 24 real bugs found and fixed in commit `1ce5af4`.

## Bugs Found and Fixed

### Naive-vs-Aware Datetime (11 fixes)
All caused by SQLite returning naive datetimes compared with `datetime.now(timezone.utc)`.
Fix: wrap DB values with `ensure_aware()`.

| # | Command | File | Line |
|---|---------|------|------|
| 1 | `warlock poam list` | poam_cmd.py | 252 |
| 2 | `warlock risk-review quarterly` | risk_workflow_cmd.py | 728 |
| 3 | `warlock monthly-review` | ops_workflow_cmd.py | 943 |
| 4 | `warlock weekly` | ops_workflow_cmd.py | 538 |
| 5 | `warlock comply debt` | comply_cmd.py | 1045 |
| 6 | `warlock comply pre-audit` | comply_cmd.py | 449 |
| 7 | `warlock control-tests due` | control_tests_cmd.py | 416 |
| 8 | `warlock control-tests gaps` | control_tests_cmd.py | 707 |
| 9 | `warlock vendor-review reassess` | vendor_workflow_cmd.py | 486 |
| 10 | `warlock vulns aging` | vulns_cmd.py | 364 |
| 11 | `warlock vulns sla-breach` | vulns_cmd.py | 161 |
| 12 | `warlock attestations overdue` | attestations_cmd.py | 329 |
| 13 | `warlock attestations expiring` | attestations_cmd.py | 373 |

### SQLAlchemy .cast(int) Bug (3 fixes)
`.cast(int)` returns Python int, not SA expression. Fix: use `case()`.

| # | Command | File |
|---|---------|------|
| 14 | `warlock ai-ops predict-risk` | ai_ops_cmd.py |
| 15 | `warlock ai-ops horizon-scan` | horizon_scanning.py |
| 16 | (also horizon_scanning gap_clusters) | horizon_scanning.py |

### Lake Analytics fromisoformat (4 fixes)
`cast(Finding.ingested_at, Date)` fails on SQLite. Fix: use `func.strftime()`.

| # | Command | File |
|---|---------|------|
| 17 | `warlock lake-analytics anomaly detect` | lake_analytics_cmd.py |
| 18 | `warlock lake-analytics anomaly list` | lake_analytics_cmd.py |
| 19 | `warlock lake-analytics trends findings` | lake_analytics_cmd.py |
| 20 | `warlock lake-analytics trends risk` | lake_analytics_cmd.py |

### Other Bugs (4 fixes)

| # | Command | File | Issue |
|---|---------|------|-------|
| 21 | `warlock bulk link-findings-to-issues` | bulk_cmd.py | `Finding.created_at` → `Finding.ingested_at` |
| 22 | `warlock control-tests import` | control_tests_cmd.py | Unhandled `JSONDecodeError` |
| 23 | `warlock vulns remediation-rate` | vulns_cmd.py | Self-join cartesian product (hang) |
| 24 | `warlock poam overdue` | poam_cmd.py | Rich markup empty style tag `[/]` |

## Remaining: Expected Failures (optional lake deps not installed)

These 5 commands require `pip install -e ".[lake]"` (pyarrow, duckdb, pyiceberg):

| Command | Missing Dep |
|---------|-------------|
| `warlock lake aggregate` | pyarrow |
| `warlock lake assess` | duckdb |
| `warlock lake compact` | pyarrow |
| `warlock lake maintenance` | pyarrow |
| `warlock lake register` | pyiceberg |

**DONE (2026-03-25):** Graceful `ModuleNotFoundError` handling added. All 5 commands now print "Install with: pip install -e '.[lake]'" instead of crashing.

## Test Coverage by Batch

| Batch | Commands | PASS | FAIL | Fixed |
|-------|----------|------|------|-------|
| 1 (access-review → automation) | 115 | 112 | 3 | 3 |
| 2 (bcp → control-tests) | 115 | 109 | 6 | 6 |
| 3 (correlate → incidents) | 115 | 115 | 0 | — |
| 4 (incidents → pipeline) | 119 | 109 | 10 | 5 real + 5 lake deps |
| 5 (poam → scheduler) | 115 | 113 | 2 | 2 |
| 6 (search → weekly) | 111 | 107 | 4 | 4 |
| **Total** | **690** | **665** | **25** | **24 fixed** |
