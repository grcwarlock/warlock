# Run 1: Pipeline & Demo Audit Findings

Audited: 2026-03-29
Seed counts verified: 351 connectors, 0 failed, 1071 raw events, 7324 findings, 373852 controls mapped

---

## Section 1: What Works (Verified)

### Pipeline Core
- **Pipeline seed runs correctly** -- all 351 connectors succeed, counts match CLAUDE.md expectations
- **Pipeline status/history/stats** -- all display correctly with Rich tables, proper counts
- **Pipeline errors** -- shows 5 simulated connector failures (crowdstrike, splunk, tenable, okta, wiz) with timestamps
- **Pipeline DLQ** -- subcommand group works (list/purge/retry); list correctly shows empty after fresh seed
- **Pipeline schedule show** -- correctly reports scheduler not running, default 60m interval
- **Pipeline compare** -- accepts two run IDs (not tested with valid pair, but arg parsing works)
- **Pipeline replay** -- accepts run ID argument, help text correct
- **Pipeline hash-verify** -- accepts run ID to verify per-connector event integrity

### Data Lake
- **Lake init** -- creates zone directories (raw/enrichment/curated)
- **Lake status** -- shows 8117 files, 119.8 MB across zones after seed
- **Lake backfill** -- successfully writes 1,513,803 rows in ~20s from OLTP to lake
- **Lake aggregate** -- refreshes agg_framework_posture (14 rows) and agg_control_family_posture (159 rows)
- **Lake assess** -- computes 2084 aggregate control assessments across 14 frameworks
- **Lake compact** -- compacts small Parquet files into larger ones
- **Lake register** -- registers tables with Iceberg catalog (19 tables)
- **Lake maintenance** -- runs all maintenance jobs (compact, expire, orphan cleanup)
- **Lake analytics trends** -- shows compliance posture trends per framework from lake data
- **Lake analytics heatmap** -- shows control family compliance heatmap across all 14 frameworks
- **Lake health runs** -- shows recent pipeline runs from DuckDB

### Audit Trail
- **audit-trail verify** -- hash chain INTACT (93 entries verified)
- **audit-trail integrity-report** -- 0 chain breaks, 0 hash mismatches
- **audit-trail tamper-detect** -- no tamper evidence detected
- **audit-trail list/show/search/export/stats/timeline/user-activity** -- all subcommands registered

### Assessments & Compliance
- **assertions** -- shows 103 assertions with control bindings
- **coverage** -- shows compliance rates across 14 frameworks
- **effectiveness** -- shows control uptime %, MTTR, drift counts
- **cadence** -- shows monitoring cadence per control (OK/overdue status)
- **sufficiency** -- shows evidence sufficiency scores with gap analysis
- **drift** -- shows compliance drift events with direction (improved/degraded)
- **posture-history** -- shows trend data for individual controls (slope, points)
- **simulate-audit** -- projects audit readiness at future date with stale/overdue counts

### Risk & Governance
- **risk analyze** -- Monte Carlo FAIR simulation with ALE, VaR 95/99, control effectiveness
- **risk cache-stats/invalidate/precompute** -- cache management subcommands exist
- **poams** -- shows POA&Ms with severity, status, weakness details
- **compensating-controls** -- shows 20+ compensating controls with effectiveness scores
- **risk-acceptances** -- shows 14 risk acceptances with status/expiry
- **briefing** -- comprehensive daily briefing with prioritized CRIT/HIGH items and suggested actions

### Dashboards
- **dashboard executive** -- board-level summary: overall score, framework compliance, POA&M counts
- **dashboard operations** -- connector health, pipeline status, event counts
- **dashboard security** -- vulnerability counts by severity, misconfigurations, top sources

### Exports
- **OSCAL SSP** -- generates valid OSCAL SSP JSON for any framework
- **OSCAL assessment-results** -- generates valid OSCAL AR JSON for any framework
- **automation gate** -- CI/CD compliance gate with pass/fail threshold

### Correlation
- **correlate** -- extensive subcommand tree: blast-radius, coverage-matrix, gap-analysis, trace, orphan-findings, orphan-controls, finding-to-controls, control-to-findings, etc.
- **correlate orphan-findings** -- correctly shows findings with no control mapping
- **correlate orphan-controls** -- correctly reports "no orphan controls" for soc2

---

## Section 2: What's Broken (Bugs)

### P0 -- Critical

1. **`pipeline verify-chain` uses wrong hash algorithm** -- P0 / S
   - The `pipeline verify-chain` command (pipeline_ext_cmd.py line 222-232) computes entry_hash using string concatenation (`f"{seq}:{prev_hash}:{action}:{entity_type}:{entity_id}:{actor}"`), but the actual `AuditTrail.record()` method uses JSON serialization with `sort_keys=True`. This causes it to report "Chain broken at 93 point(s)" when the chain is actually intact (confirmed by `audit-trail verify` and `audit-trail integrity-report` which use the correct algorithm).
   - Fix: Replace the hash computation in `pipeline verify-chain` with the same JSON-based serialization used in `_recompute_hash()` from audit_trail_cmd.py.

2. **Lake reconciliation always fails after `make reset`** -- P0 / M
   - Running `make reset` (which deletes warlock.db) does NOT delete the `lake/` directory. The lake accumulates data across multiple resets. After a single `make reset` + `lake backfill`, reconciliation shows 577% drift for raw_events and 515% drift for findings because the lake has stale data from prior runs.
   - `make reset` must also `rm -rf lake/` to ensure OLTP and lake are in sync.
   - Even without reset, multiple `lake backfill` calls append duplicates rather than upsert. The backfill is not idempotent.

3. **Demo seed throws IntegrityError on external_auditors.email** -- P0 / S
   - `sqlite3.IntegrityError: UNIQUE constraint failed: external_auditors.email` appears during seed. The seed is not idempotent for external_auditors when run multiple times (even after DB reset, if the seed creates them twice within one run).

### P1 -- High

4. **Lake health freshness/coverage return "No data found"** -- P1 / M
   - `warlock lake health freshness` and `warlock lake health coverage` both return "No data found. Run pipeline with WLK_LAKE_ENABLED=true first." even though the lake has 119.8 MB of data and other lake commands (analytics, reconcile) work fine. These commands likely query tables/zones that the demo seed doesn't populate, or they check a flag that isn't set during seed.

5. **Lake evidence, incidents, privacy, supply-chain all return "No data found"** -- P1 / L
   - `warlock lake evidence list` -- "No data found"
   - `warlock lake evidence freshness` -- "No data found"
   - `warlock lake incidents list` -- "No data found"
   - `warlock lake incidents events` -- "No data found"
   - `warlock lake privacy dsars` -- "No data found"
   - `warlock lake privacy processing` -- "No data found"
   - `warlock lake privacy transfers` -- "No data found"
   - `warlock lake supply-chain sbom` -- "No data found"
   - `warlock lake supply-chain suppliers` -- "No data found"
   - `warlock lake supply-chain concentration` -- "No data found"
   - These are all Rule 8 violations ("No data = failed demo"). The demo seed must be extended to populate these lake domain tables, or the backfill must extract this data from OLTP.

6. **`ask` and `lake query` return generic response regardless of question** -- P1 / M
   - `warlock ask "which controls are failing for HIPAA"` returns only "Tracking 14 frameworks: cmmc_l2, eu_ai_act, ..." -- the same generic summary regardless of the question asked.
   - `warlock lake query "show non-compliant controls for soc2"` returns the same.
   - Without AI enabled, these should at least do keyword/SQL-based queries against the lake. Currently they are useless in the demo without a running LLM.

7. **`coverage` command makes AI call even with WLK_AI_ENABLED=false** -- P1 / S
   - `warlock coverage` shows "HTTP Request: POST https://ollama.com/v1/chat/completions" and "Ollama client error 404" even though WLK_AI_ENABLED=false is set. The command should check the AI flag before attempting the call.
   - Same issue with `simulate-audit`: "AI assessment unavailable: HTTPStatusError"

8. **`embeddings` returns "No embeddings found"** -- P1 / S
   - The demo seed doesn't generate any embeddings. If this is a user-facing feature, it needs seed data. Rule 8 violation.

### P2 -- Medium

9. **`framework-diff` expects file paths, not framework IDs** -- P2 / S
   - `warlock framework-diff --old nist_800_53 --new soc2` fails with "Path 'nist_800_53' does not exist." The command expects file paths to YAML files rather than framework IDs, which is inconsistent with every other command that accepts `-f framework_id`.

10. **`inheritance` requires --system but demo seed may not provide valid system IDs** -- P2 / S
    - `warlock inheritance --system <id>` is required but the demo seed doesn't advertise available system IDs. Users can't discover valid values without querying the DB directly.

11. **`risk` command doesn't accept `-f` flag directly** -- P2 / S
    - DEMO.md suggests `warlock risk -f nist_800_53` but the command is actually `warlock risk analyze -f nist_800_53`. The top-level `risk` is a group, not a command with `-f`.

---

## Section 3: What's Missing (Gaps vs Modern GRC Data Lake Platforms)

### P0 -- Critical Gaps

12. **No pipeline data lineage tracking** -- P0 / L
    - There is no way to trace a specific control_result back through the pipeline to see: which raw event created it, which normalizer processed it, which assertion evaluated it, and which mapper assigned it. The `correlate` commands do some of this but there's no end-to-end lineage graph or lineage metadata stored per record.
    - Modern data platforms (dbt, Amundsen, DataHub, OpenLineage) track column-level lineage. Warlock should at minimum track record-level lineage: finding_id -> raw_event_id -> connector_run_id with assertion_id attached to control_results.

13. **Lake backfill is not idempotent / no deduplication** -- P0 / M
    - Running `lake backfill` multiple times creates duplicate rows in the lake. There's no merge/upsert logic, no dedup on primary keys. This makes reconciliation permanently broken after any re-run.
    - Need: upsert-on-PK or delete-then-write per backfill batch, or track watermarks to avoid re-processing.

14. **No lake cleanup on DB reset** -- P0 / S
    - `make reset` deletes warlock.db but leaves `lake/` intact. This creates permanent OLTP-lake drift. Add `rm -rf lake/` to the reset target.

### P1 -- High Gaps

15. **No pipeline data quality checks / validation layer** -- P1 / L
    - No automated checks for: duplicate findings, null required fields, schema violations in raw events, out-of-range severity values, timestamp sanity (future dates, very old dates), orphaned records.
    - The schema_registry.py exists but is not wired into the pipeline execution path. It's a library that isn't called.
    - Modern GRC platforms run Great Expectations or dbt tests on every pipeline stage.

16. **No pipeline observability / metrics export** -- P1 / L
    - No Prometheus/OpenTelemetry metrics for: pipeline throughput (events/sec), pipeline latency (p50/p95/p99), connector error rates, queue depth, backpressure signals.
    - The scheduler tracks basic counts but doesn't expose metrics in a scrapeable format.
    - `dashboard operations` shows connector health but there's no time-series storage for pipeline performance over time.

17. **No incremental/CDC pipeline mode in practice** -- P1 / M
    - `IncrementalTracker` exists in `warlock/pipeline/incremental.py` but the demo seed runs in full-refresh mode only. There's no CLI flag or demo scenario that exercises incremental collection.
    - `WLK_PIPELINE_MODE` config exists but is never demonstrated or tested in the demo flow.
    - Modern pipelines default to incremental with full-refresh as a fallback.

18. **No pipeline retry with exponential backoff** -- P1 / M
    - The demo shows 5 simulated connector failures (crowdstrike, splunk, etc.) but there's no evidence of automatic retry with backoff. Failed connectors go to error state with no retry scheduling.
    - The DLQ exists but has 0 entries even after failures -- suggesting failed events aren't captured in the DLQ during normal pipeline runs.
    - Need: configurable retry policy (max retries, backoff strategy), circuit breaker pattern for chronically failing connectors.

19. **No pipeline dependency graph / DAG visualization** -- P1 / M
    - The pipeline stages (collect -> normalize -> map -> assess) are implicit. There's no DAG definition, no visualization of stage dependencies, no way to see which stages are blocked or waiting.
    - Modern orchestrators (Dagster, Prefect, Airflow) provide DAG visualization as a core feature.

20. **No real-time streaming / webhook ingestion** -- P1 / L
    - All data ingestion is pull-based (scheduled collection). There's no webhook endpoint to receive real-time events from connectors that support push (CloudTrail via EventBridge, GuardDuty via SNS, etc.).
    - The event bus (`bus.py`) exists but is in-process only -- not a durable message queue.

21. **No pipeline cost/resource tracking** -- P1 / S
    - No tracking of: API call counts per connector (for rate limit budgeting), data volume per connector (for cost allocation), processing time per stage (for capacity planning).
    - `pipeline stats` shows aggregate counts but not per-connector resource consumption.

### P2 -- Medium Gaps

22. **No data lake partitioning strategy exposed to users** -- P2 / M
    - Lake data is partitioned by source/date in the filesystem, but there's no CLI command to show partition statistics, rebalance partitions, or configure partition strategies.
    - `db partition` exists for PostgreSQL but not for the Parquet-based lake.

23. **No SCD (Slowly Changing Dimensions) tracking for compliance state** -- P2 / L
    - `warlock/lake/scd.py` exists but it's unclear if it's wired into the pipeline. Control status changes should maintain Type 2 SCD history (effective_from, effective_to) for regulatory audit trails.
    - Currently compliance drift is tracked in a separate table but not as a proper SCD.

24. **No data lake access controls / row-level security** -- P2 / M
    - The API has ABAC but the lake Parquet files are directly readable by anyone with filesystem access. No tenant isolation in the lake layer.

25. **No pipeline canary / smoke test mode** -- P2 / S
    - No way to run a subset of connectors as a health check without processing the full pipeline. A `pipeline smoke-test` command that runs 3-5 representative connectors would catch infrastructure issues faster.

26. **No pipeline schema evolution handling** -- P2 / M
    - When connector output schemas change (new fields, removed fields, type changes), there's no automated detection or migration. The schema_registry has the capability but isn't exercised.

27. **No lake snapshot / time travel** -- P2 / L
    - Iceberg catalog is registered but time travel queries aren't exposed in the CLI. Users can't query "what was our SOC 2 posture 30 days ago" against lake snapshots.
    - The `posture-history` command uses OLTP data, not lake snapshots.

28. **No pipeline alerting on anomalous data volumes** -- P2 / M
    - No alert when a connector that usually produces 100 findings suddenly produces 0 or 10,000. Volume anomaly detection would catch connector misconfigurations and data source issues early.

### P3 -- Low Gaps

29. **No pipeline warm-up / pre-flight check** -- P3 / S
    - No command to verify all connector credentials are valid and all target APIs are reachable before starting a full pipeline run. Would avoid wasting time on half-completed runs.

30. **No data lake garbage collection reporting** -- P3 / S
    - `lake maintenance` runs but doesn't report what was cleaned up, how much space was reclaimed, or what's still pending.

31. **No pipeline run comparison with semantic diff** -- P3 / M
    - `pipeline compare` exists but likely only shows count differences. A semantic diff (which controls changed status, which findings are new/resolved) would be more useful for continuous monitoring.

32. **No lake data catalog / metadata search** -- P3 / M
    - No command to search for "which lake tables contain PII" or "which zones have data older than 90 days". Lake metadata is managed but not searchable.

33. **No pipeline SLA tracking** -- P3 / M
    - No way to define "connector X must complete within 5 minutes" or "all connectors must run at least once per 24 hours" and alert on violations. The cadence command covers assessment freshness but not pipeline execution SLAs.
