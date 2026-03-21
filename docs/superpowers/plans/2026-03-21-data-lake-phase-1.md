# Data Lake Phase 1: Lake Alongside OLTP — Implementation Plan

**Goal:** Wire the event bus to asynchronously write pipeline data to the lake (Parquet files) alongside the existing OLTP writes. Add backfill CLI, reconciliation, and the 5 existing curated domains.

**Architecture:** Event-sourced materialization — pipeline writes to OLTP as today, a new `LakeWriter` subscriber asynchronously batches and writes Parquet. OLTP never blocked. Eventually consistent.

**Depends on:** Phase 0 complete (storage, query engine, catalog, config, repository pattern)

---

## File Structure

### New Files

| File | Responsibility |
|---|---|
| `warlock/lake/writer.py` | LakeWriter subscriber — batches pipeline events, writes Parquet per zone |
| `warlock/lake/zones.py` | Zone writers — raw, enrichment, curated zone Parquet serialization |
| `warlock/lake/reconciliation.py` | Nightly reconciliation job — row count + SHA-256 comparison |
| `warlock/lake/backfill.py` | Backfill existing OLTP data to lake |
| `warlock/cli/lake.py` | CLI commands: lake init, lake backfill, lake reconcile, lake status |
| `tests/test_lake_writer.py` | Tests for lake writer, zones, reconciliation |

### Modified Files

| File | What Changes |
|---|---|
| `warlock/lake/__init__.py` | Export key classes |
| `warlock/pipeline/orchestrator.py` | Register LakeWriter subscriber when lake_enabled |
| `warlock/cli/__init__.py` | Register lake CLI group |
| `warlock/pipeline/scheduler.py` | Add reconciliation schedule |

---

## Task 1: LakeWriter Event Bus Subscriber

The core of Phase 1. Subscribes to all pipeline events, batches per run, writes Parquet.

## Task 2: Zone Writers (Raw, Enrichment, Curated)

Serialize pipeline data to Parquet in each zone with proper partitioning.

## Task 3: Orchestrator Integration

Register LakeWriter when `lake_enabled=True`. Wire into pipeline run lifecycle.

## Task 4: Backfill CLI Command

`warlock lake backfill` — reads OLTP historical data, writes to lake.

## Task 5: Reconciliation Job

Nightly row count + SHA-256 hash comparison between OLTP and lake.

## Task 6: Lake CLI Commands

`warlock lake init`, `warlock lake status`, `warlock lake reconcile`.

## Task 7: Tests + QA Gate

Full test coverage, demo seed with lake enabled, reconciliation verification.
