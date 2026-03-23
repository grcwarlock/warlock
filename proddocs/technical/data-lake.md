# GRC Data Lake Architecture

The Warlock GRC Data Lake provides an analytical layer alongside the OLTP database. Pipeline data is materialized to Parquet files via the event bus, and DuckDB runs in-process for analytical queries. The lake adds historical analysis, cross-domain joins, and semantic search without burdening the OLTP database.

## Overview

```
Pipeline (OLTP write)
    |
    v
Event Bus -----> LakeWriter (subscriber)
                     |
                     v
              +------+------+
              |  Lake Zones  |
              +------+------+
              |              |
     +--------+     +-------+--------+
     |  Raw   |     | Enrichment     |
     | (immut)|     | (normalized)   |
     +--------+     +----------------+
                          |
                    +-----v------+
                    |  Curated   |
                    | (10 domains|
                    |  + bridges)|
                    +-----+------+
                          |
              +-----------+-----------+
              |           |           |
         DuckDB       Iceberg      RAG
         Readers      Catalog    (TF-IDF)
```

**23 modules** in `warlock/lake/`:

| Module | Purpose |
|---|---|
| `zones.py` | Raw, enrichment, and curated zone writers |
| `domains.py` | 10 curated domain fact table writers |
| `readers.py` | DuckDB analytical query methods |
| `query.py` | DuckDB query engine |
| `writer.py` | Event bus subscriber for lake materialization |
| `reconciliation.py` | OLTP vs lake row count + hash comparison |
| `rag.py` | TF-IDF semantic search over curated zone |
| `catalog.py` | Iceberg catalog integration |
| `bridges.py` | Cross-domain bridge table writers |
| `scd.py` | SCD Type 2 dimension management |
| `shadow.py` | Shadow query comparator (OLTP vs lake) |
| `maintenance.py` | Compaction, snapshot expiry, orphan cleanup |
| `backfill.py` | Populate lake from existing OLTP data |
| `batch_assessor.py` | Post-pipeline AI assessment on lake data |
| `aggregations.py` | Pre-computed aggregation tables |
| `consumption.py` | Consumption layer views |
| `storage.py` | Storage abstraction |
| `schema.py` | Arrow schema definitions |
| `oltp_thin.py` | OLTP thinning (archive old data to lake) |
| `ask.py` | Natural language query interface |
| `mcp_tools.py` | MCP tool integration |
| `demo.py` | Demo data generation for lake |
| `utils.py` | Shared utilities (serialization, partitioning) |

## Three Zones

### Raw Zone (Immutable)

**Path:** `{lake_path}/raw/{source}/{date}/`

Contains verbatim raw events as received from connectors. Files are append-only and never modified. One Parquet file per pipeline run per source.

**Writer:** `write_raw_zone()` in `zones.py`

**Columns:**

| Column | Type | Description |
|---|---|---|
| `id` | string | Event UUID |
| `connector_run_id` | string | Parent connector run |
| `source` | string | Source provider |
| `source_type` | string | SourceType value |
| `provider` | string | Product name |
| `event_type` | string | Event classification |
| `raw_data` | string | JSON-serialized raw payload |
| `sha256` | string | Content hash |
| `ingested_at` | string | ISO-8601 timestamp |
| `run_id` | string | Pipeline run UUID |

**Partitioning:** By `source` (first level), then by date in `YYYY/MM/DD` format.

**Retention:** 7 days default (configurable via `expire_snapshots()`).

### Enrichment Zone (Normalized)

**Path:** `{lake_path}/enrichment/{source}/{date}/`

Contains normalized findings produced by Stage 2 normalizers. One Parquet file per pipeline run per source.

**Writer:** `write_enrichment_zone()` in `zones.py`

**Columns:**

| Column | Type | Description |
|---|---|---|
| `id` | string | Finding UUID |
| `raw_event_id` | string | Parent raw event |
| `observation_type` | string | misconfiguration, vulnerability, etc. |
| `title` | string | Finding title |
| `detail` | string | JSON-serialized finding details |
| `resource_id` | string | Resource identifier |
| `resource_type` | string | Resource classification |
| `source` | string | Source provider |
| `severity` | string | critical, high, medium, low, info |
| `confidence` | float | 0.0-1.0 |
| `sha256` | string | Content hash |
| `run_id` | string | Pipeline run UUID |

**Partitioning:** By `source`, then by date.

**Retention:** 30 days default.

### Curated Zone (10 Domains + Bridges)

**Path:** `{lake_path}/curated/{table_name}/{date}/` or `{lake_path}/curated/{table_name}/{framework}/{date}/`

Contains domain-specific fact and dimension tables. Some tables are partitioned by framework (control results, posture snapshots), others by date only.

**Retention:** 365 days default.

## 10 Curated Domains

All domain writers are in `warlock/lake/domains.py`. Each domain has a top-level writer function that accepts lists of dicts and writes Parquet files.

### Domain 1: Compliance Facts

Written by `write_curated_zone()` in `zones.py`.

| Table | Partitioning | Contents |
|---|---|---|
| `control_results` | framework/date | Assessment results per control |
| `control_mappings` | date | Finding-to-control mappings |
| `connector_runs` | date | Connector execution metadata |

### Domain 2: Temporal Facts

Written by `write_temporal_facts()`.

| Table | Partitioning | Contents |
|---|---|---|
| `posture_snapshots` | framework/date | Point-in-time compliance scores |
| `compliance_drift` | framework/date | Status change records |
| `regulatory_deadlines` | date | Upcoming regulatory dates |

### Domain 3: Risk Facts

Written by `write_risk_facts()`.

| Table | Partitioning | Contents |
|---|---|---|
| `risk_simulations` | framework/date | Monte Carlo simulation results |
| `vulnerability_lifecycle` | date | Vulnerability open/close tracking |
| `control_effectiveness` | framework/date | Uptime %, MTTR, drift counts |

### Domain 4: Entity Facts (SCD Type 2)

Written by `write_entity_facts()`.

| Table | Partitioning | Contents |
|---|---|---|
| `resources` | date | Cloud resources, endpoints |
| `systems` | date | System profiles / boundaries |
| `personnel` | date | HR + IdP + training records |
| `vendors` | date | Third-party vendors |
| `data_silos` | date | Data stores and classification |
| `software_components` | date | SBOM components |

Entity dimension tables use SCD Type 2 versioning (see below).

### Domain 5: Governance Facts

Written by `write_governance_facts()`.

| Table | Partitioning | Contents |
|---|---|---|
| `poams` | framework/date | Plan of Action & Milestones |
| `issues` | framework/date | Remediation tracking |
| `attestations` | framework/date | Sign-off workflows |
| `audit_entries` | date | Audit trail records |
| `policy_documents` | date | Policy metadata |
| `exceptions` | date | Policy exceptions |
| `legal_holds` | date | Data preservation orders |

### Domain 6: Evidence Facts

Written by `write_evidence_facts()`.

| Table | Partitioning | Contents |
|---|---|---|
| `evidence_artifacts` | date | Evidence file metadata |
| `evidence_control_bindings` | date | Evidence-to-control links |
| `evidence_freshness` | date | Staleness metrics |
| `evidence_quality` | date | Quality scoring |

### Domain 7: Privacy Facts

Written by `write_privacy_facts()`.

| Table | Partitioning | Contents |
|---|---|---|
| `processing_activities` | date | GDPR Article 30 register |
| `dsars` | date | Data Subject Access Requests |
| `consent` | date | Consent records |
| `cross_border_transfers` | date | International data transfers |
| `dpias` | date | Data Protection Impact Assessments |
| `breach_register` | date | Breach notification records |

### Domain 8: Incident Facts

Written by `write_incident_facts()`.

| Table | Partitioning | Contents |
|---|---|---|
| `security_events` | date | Raw security events |
| `incidents` | date | Incident records |
| `notifications` | date | Notification history |
| `tabletop_exercises` | date | Exercise results |

### Domain 9: Pipeline Health Facts

Written by `write_pipeline_health_facts()`.

| Table | Partitioning | Contents |
|---|---|---|
| `pipeline_runs` | date | Pipeline execution stats |
| `data_freshness` | date | Per-source data age |
| `coverage_metrics` | date | Framework coverage stats |

### Domain 10: Supply Chain Facts

Written by `write_supply_chain_facts()`.

| Table | Partitioning | Contents |
|---|---|---|
| `sbom_components` | date | Software bill of materials |
| `supplier_assessments` | date | Vendor risk scores |
| `concentration_risk` | date | Single-vendor dependency analysis |
| `provenance_attestations` | date | Software provenance records |

## Bridge Tables

**Source:** `warlock/lake/bridges.py`

Bridge tables connect entities across curated zone domains. Written by `write_bridge_tables()`.

| Bridge Table | Purpose |
|---|---|
| `bridge_control_crosswalk` | Framework-to-framework control mappings |
| `bridge_entity_relationship` | Graph model for blast radius analysis |
| `fact_data_flow` | Data classification and transfer tracking |
| `fact_boundary_membership` | FedRAMP authorization boundary membership |
| `bridge_incident_control` | Which controls were affected by incidents |
| `bridge_incident_entity` | Which entities were affected by incidents |

## SCD Type 2

**Source:** `warlock/lake/scd.py`

Entity dimension tables (Domain 4) use Slowly Changing Dimension Type 2 to maintain history. When a dimension record changes:

1. The previous version is closed: `valid_to` set to change date, `is_current` set to `false`
2. A new version is appended: `valid_from` set to change date, `is_current` set to `true`

```python
merged = apply_scd_type2(
    existing=current_records,
    incoming=new_records,
    key_fields=["id"],           # Which fields identify the same entity
    change_date="2026-03-21",    # Version boundary
    compare_fields=["status", "risk_score"],  # What triggers a new version
)
```

New entities get `valid_from = change_date`, `valid_to = "9999-12-31"`, `is_current = "true"`. Unchanged entities are not modified.

## Event-Sourced Materialization

**Source:** `warlock/lake/writer.py`

The `LakeWriter` subscribes to the event bus as a wildcard handler. During a pipeline run, it accumulates payload IDs by event type. After the OLTP transaction commits, `flush()` reads full records from OLTP and writes them to Parquet.

```python
writer = LakeWriter("/path/to/lake")
bus.subscribe_all(writer.handle_event)

# Pipeline runs, events are published...

stats = writer.flush("run-123", session)
# stats.raw_events_written: 191
# stats.findings_written: 547
# stats.control_results_written: 29207
```

This design avoids synchronous dual-write (OLTP is never blocked), avoids one-Parquet-file-per-record (batched per pipeline run), and preserves SHA-256 hash integrity (same serialization).

## DuckDB Readers

**Source:** `warlock/lake/readers.py`

The `LakeReaders` class provides DuckDB-backed analytical queries that mirror OLTP repository methods. Results use the same format, enabling transparent swapping via feature flags.

### ABAC Scope Filtering

All reader methods accept `allowed_frameworks` and `allowed_system_profiles` parameters. When provided, WHERE clauses are injected using parameterized queries (never string interpolation):

```python
def _abac_clauses(
    allowed_frameworks: list[str] | None,
    allowed_system_profiles: list[str] | None,
) -> tuple[list[str], list[Any]]:
    clauses, params = [], []
    if allowed_frameworks:
        placeholders = ", ".join("?" for _ in allowed_frameworks)
        clauses.append(f"framework IN ({placeholders})")
        params.extend(allowed_frameworks)
    # ...
```

### Available Queries

| Method | Description |
|---|---|
| `dashboard_framework_summary()` | Framework x status counts |
| `coverage_by_status()` | Per-framework status breakdown |
| `distinct_frameworks()` | List of frameworks with data |
| `top_non_compliant_risks()` | Top 20 non-compliant controls |
| `last_assessed_at()` | Most recent assessment timestamp |
| `list_frameworks()` | Frameworks with control counts |
| `list_controls()` | Controls within a framework |
| `total_event_count()` | Total events across all connectors |
| `latest_per_connector()` | Most recent run per connector |
| `latest_per_provider()` | Most recent run per provider |
| `findings_by_severity()` | Findings filtered by severity |
| `findings_by_source()` | Findings filtered by source |
| `latest_snapshot_date()` | Most recent posture snapshot |
| `framework_avg_scores_at()` | Average posture score per framework |
| `effectiveness_latest()` | Control effectiveness data |

### Query Engine

**Source:** `warlock/lake/query.py`

`LakeQueryEngine` wraps an embedded DuckDB connection. It reads Parquet files directly from the filesystem (local or S3 via httpfs extension). No JVM dependency.

```python
engine = LakeQueryEngine("/path/to/lake")
results = engine.query(
    "SELECT framework, COUNT(*) FROM read_parquet('...') GROUP BY framework"
)
# results: [{"framework": "nist_800_53", "count": 1176}, ...]
engine.close()
```

## Reconciliation

**Source:** `warlock/lake/reconciliation.py`

Compares OLTP and lake to detect drift. Intended for nightly or on-demand verification.

### Row Count Comparison

```python
result = reconcile(session, lake_path, threshold=0.001)
# result.passed: True if all tables within 0.1% drift
# result.drifted: list of tables exceeding threshold
```

Compares five pipeline tables: `raw_events`, `findings`, `control_mappings`, `control_results`, `connector_runs`.

### Hash Verification

```python
mismatches = sample_hashes(oltp_hashes, lake_hashes)
# Returns records where SHA-256 differs or is missing from lake
```

The `TableComparison` dataclass reports per-table drift as a percentage:

```python
@dataclass
class TableComparison:
    table: str
    oltp_count: int
    lake_count: int

    @property
    def drift_pct(self) -> float:
        return abs(oltp_count - lake_count) / oltp_count * 100
```

## Shadow Queries

**Source:** `warlock/lake/shadow.py`

During Phase 2 migration, shadow queries run both OLTP and lake paths for the same query. Results are compared and discrepancies are logged. This validates that the lake produces correct results before switching read traffic.

```python
runner = ShadowQueryRunner()
result = compare_results("dashboard_summary", oltp_result, lake_result)
# result.match: True/False
# result.discrepancies: ["Row count mismatch: OLTP=547, Lake=546"]
```

## Semantic Search (RAG)

**Source:** `warlock/lake/rag.py`

The `LakeRAG` class indexes compliance data from Parquet files and provides semantic search using TF-IDF. No external API keys are needed.

### Indexing

```python
rag = LakeRAG(lake_path)
doc_count = rag.index()  # Build index from curated zone
```

Three data sources are indexed:
- **Control results:** "Control AC-2 in nist_800_53: status=compliant, severity=high"
- **Findings:** "Finding: MFA not enabled (severity=high, source=okta)"
- **Control mappings:** "Framework nist_800_53 control AC-2 (family=AC, mapped via explicit)"

### Querying

```python
results = rag.query("access control compliance status", top_k=10)
for r in results:
    print(f"{r.score:.3f} {r.document.content}")
```

Uses TF-IDF cosine similarity. Tokenization strips stopwords and lowercases. Terms shorter than 2 characters are filtered.

## Iceberg Integration

**Source:** `warlock/lake/catalog.py`

The lake supports Iceberg table format registration via PyIceberg. Two catalog types:

| Type | Use Case | Config |
|---|---|---|
| `sqlite` | Development / on-prem | Local SQLite DB file |
| `rest` | Cloud production | Any Iceberg REST catalog service |

```python
catalog = create_catalog("sqlite", "/path/to/catalog.db")
ensure_namespace(catalog, "warlock")
register_table(catalog, "warlock", "control_results", schema, location)
```

`register_pipeline_tables()` registers all pipeline tables with the catalog. If a table already exists, it is returned unchanged.

## Maintenance

**Source:** `warlock/lake/maintenance.py`

Three maintenance jobs keep the lake performant:

### Compaction

Merges small Parquet files into larger ones (~256MB target). Scans leaf directories for multiple small files and rewrites them as a single `compacted.parquet`.

```python
stats = compact(lake_path, target_size_mb=256)
# {"curated/control_results/nist_800_53/2026/03/21": 12}
```

### Snapshot Expiry

Removes Parquet files older than the retention window per zone:

| Zone | Default Retention |
|---|---|
| raw | 7 days |
| enrichment | 30 days |
| curated | 365 days |

**Legal hold protection:** `expire_snapshots_safe()` checks for active `LegalHold` records before deleting. If any hold is active, expiry is blocked entirely.

```python
result = expire_snapshots_safe(session, lake_path)
# {"blocked_by_hold": True, "active_holds": 2}
```

### Orphan Cleanup

Removes empty directories left after compaction or expiry. Walks bottom-up to safely remove nested empty dirs.

### Run All

```python
results = run_all_maintenance(lake_path)
# {"compaction": {...}, "expiry": {...}, "orphan_cleanup": {...}}
```

## CLI Commands

The lake is fully accessible via the CLI:

| Command | Description |
|---|---|
| `warlock lake status` | Show lake size, zone counts, last write |
| `warlock lake reconcile` | Compare OLTP vs lake, report drift |
| `warlock lake query <sql>` | Run arbitrary DuckDB SQL |
| `warlock lake assess` | Batch AI assessment on lake data |
| `warlock lake ask <question>` | Natural language query |
| `warlock lake compact` | Run compaction |
| `warlock lake expire` | Run snapshot expiry |

## Design Decisions

1. **Parquet over Delta Lake / Iceberg-only.** Parquet files are the storage format. Iceberg registration is optional for metadata management. This avoids a hard dependency on heavy table format libraries while preserving the option to adopt them.

2. **DuckDB over Spark / Trino.** DuckDB runs in-process with no server, no JVM, and sub-second query times on single-node datasets. When the lake exceeds single-node capacity, queries can be migrated to Trino/Spark with minimal SQL changes.

3. **Event-sourced over dual-write.** The lake writer subscribes to the event bus rather than intercepting OLTP writes. This means the lake is eventually consistent (not strongly consistent), but OLTP writes are never blocked by lake failures.

4. **ABAC on reads, not writes.** Scope filtering is applied at query time in `LakeReaders`, not at write time. All data is written to the lake regardless of who triggered the pipeline run. This ensures the lake is complete for reconciliation and audit purposes.

5. **Legal holds block all expiry.** When any legal hold is active, the entire expiry job is skipped (not just the scoped data). This is conservative by design for compliance safety.
