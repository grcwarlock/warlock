# STUBS.md -- Warlock Stub & False Confidence Inventory

**Last updated:** 2026-03-26
**Sources merged:** 3 independent codebase audits
**Total unique findings:** 30

This document catalogs every stub, mock, false-confidence output, and in-memory-only module in the Warlock codebase. Each finding has been verified against source code with file:line references.

---

## Category 1: True Stubs

These are features that appear functional in the UI or CLI but have no real implementation behind them.

---

### STUB-001: 84 of 352 Connectors Are Demo Mocks

**Risk:** MODERATE
**Location:** `warlock/connectors/` (84 files), `scripts/demo_seed.py`

84 of the 352 connector files are demo-only mocks that return synthetic data. They follow the `BaseConnector` interface but generate fabricated findings rather than connecting to real systems.

**Breakdown by category:**

| Category | Mock | Real | Total |
|---|---|---|---|
| ASSET_MGMT | 6 | 0 | 6 |
| GRC | 5 | 1 | 6 |
| API_SECURITY | 4 | 0 | 4 |
| COST | 3 | 0 | 3 |
| BACKUP | 6 | 1 | 7 |
| PATCHES | 2 | 0 | 2 |
| Other categories | 58 | 84 | 142 |

**Impact:** Half the connector ecosystem is fabricated. Any demo showing "351 connectors succeeded" is counting mocks as real integrations.

---

### STUB-002: Domain Service Event Handlers Return Empty Lists

**Risk:** HIGH
**Location:** `warlock/domains/`

- `evidence.py:108-109` -- `handle_event()` returns `[]`
- `controls.py:118-119` -- `handle_event()` returns `[]`
- `issues.py:124-125` -- `handle_event()` returns `[]`

The domain event bus dispatches events to these handlers, which accept the event, log it, and return empty lists. No domain logic executes. The event bus architecture is fully wired but every handler is a no-op.

**Evidence:**
```python
# evidence.py:108-109
def handle_event(self, event: DomainEvent) -> list:
    return []
```

---

### STUB-003: Incidents Mobile-Approve -- Display Only

**Risk:** LOW
**Location:** `warlock/cli/incidents.py`

The `mobile-approve` CLI command displays an endpoint description and approval instructions but performs no actual approval action. It prints what would need to happen but never executes it.

---

### STUB-004: Incidents Offline-Collect -- Instructions Only

**Risk:** LOW
**Location:** `warlock/cli/incidents.py`

The `offline-collect` CLI command prints instructions for offline evidence collection but does not implement any collection, packaging, or sync logic.

---

### STUB-005: Lake NL Query Is Keyword Router

**Risk:** HIGH
**Location:** `lake/ask.py:24-33`

The natural language query interface is not NLP-powered. It uses simple string matching with approximately 15 hardcoded patterns:

```python
if "posture" in question_lower:
    # branch 1
elif "trend" in question_lower:
    # branch 2
elif "compliance" in question_lower:
    # branch 3
```

Any question that does not match one of the ~15 keyword patterns silently returns nothing -- no error, no "query not understood" message, just empty results. This creates the false impression that there is no data rather than that the query was not recognized.

---

### STUB-006: Regulatory Filing Templates -- Placeholder Text

**Risk:** MODERATE
**Location:** `lake/consumption.py:230-350`

The regulatory filing template system uses Jinja2 template strings but the actual template content is placeholder text reading "To be determined" in key sections. There is no filing submission logic, no tracking, and no deadline management. The templates render syntactically valid documents with no substantive content.

---

### STUB-007: Questionnaire Automation -- Hardcoded Answers

**Risk:** MODERATE
**Location:** `lake/consumption.py:358-466`

The `QuestionnaireEngine` class implements `create()`, `submit()`, `score()`, and `report()` methods. All state is stored in in-memory dicts. Answers are hardcoded or pattern-matched. No questionnaire data persists to the database. The entire workflow runs in memory and is lost on restart.

---

### STUB-008: Bulk/Legacy Import Parses But Does Not Persist

**Risk:** HIGH
**Location:** `warlock/platform/bulk_import.py` (355 lines), `warlock/platform/legacy_import.py` (372 lines)

Both import modules contain real, functional parsers for CSV, JSON, and XML formats. The parsing logic works correctly. However, `persist_batch()` logs "Batch persisted" and returns a success status without ever calling `session.add()` or writing to the database. Data is parsed, validated, transformed, and then silently discarded.

**Evidence:**
```python
# persist_batch() logs success but never calls session.add()
logger.info("Batch persisted")
return {"status": "success", "count": len(batch)}
```

---

### STUB-009: Workpapers, Evidence Snapshots, and Test Schedules Are Ephemeral

**Risk:** MODERATE
**Location:** `warlock/platform/audit_manager.py:148-276` (workpapers), `warlock/platform/evidence_retention.py:74-184` (snapshots), `warlock/platform/audit_manager.py:282-331` (test schedules)

All three features store their data in instance-level Python dicts. No database models exist for workpapers, evidence snapshots, or test schedules. All data is lost when the process restarts. The APIs accept and return data correctly but nothing survives beyond the current process lifetime.

---

### STUB-010: SCD Type 2 Implemented But Never Called

**Risk:** LOW
**Location:** `lake/scd.py` (104 lines)

A complete Slowly Changing Dimension Type 2 implementation exists with proper effective-date tracking, row versioning, and current-record flagging. However, no code anywhere in the codebase calls any function from this module. It is fully dead code.

---

### STUB-011: 7 of 10 Lake Domain Writers Have No Upstream Producer

**Risk:** MODERATE
**Location:** `warlock/lake/`

The data lake defines 10 domain-specific writer modules. Only 3 of them have upstream pipeline stages that actually produce data for them to write. The remaining 7 writers are wired into the lake architecture but never receive input, so their tables remain permanently empty.

---

### STUB-012: Segregation of Duties (SoD) Engine Never Called

**Risk:** MODERATE
**Location:** `warlock/domains/sod.py`

A complete SoD analysis engine exists with role-conflict detection, duty matrix evaluation, and violation reporting. No code anywhere in the codebase invokes any function from this module. The engine is fully implemented but entirely dead code -- never registered as an event handler, never called from CLI, API, or pipeline.

---

### STUB-013: Compensating Control Evaluation Hardcoded

**Risk:** HIGH
**Location:** `warlock/assessors/`

The `evaluate_effectiveness()` function for compensating controls always returns `{"score": 0.8, "status": "effective"}` regardless of input. Every compensating control is assessed as 80% effective with no actual evaluation logic. This masks the true state of compensating controls in compliance reports.

---

### STUB-014: Queue Backends Defined But Never Selectable

**Risk:** LOW
**Location:** `warlock/pipeline/`

Multiple queue backends (Redis, RabbitMQ, SQS) are implemented alongside the default `EventBus`. However, the orchestrator always instantiates `EventBus()` directly. There is no configuration path or factory method to select an alternative backend. The implementations exist but are unreachable.

---

### STUB-015: Lake RAG Is TF-IDF Only, No Vector Database

**Risk:** MODERATE
**Location:** `warlock/lake/rag.py:44-55`

The RAG (Retrieval-Augmented Generation) module uses a dict-based TF-IDF implementation for document similarity. There is no vector database, no embeddings model, and no semantic search. The "RAG" label implies neural retrieval but the implementation is keyword frequency matching.

---

### STUB-016: Lake Disabled by Default

**Risk:** LOW
**Location:** `warlock/config.py`

`WLK_LAKE_ENABLED` defaults to `false`. The entire data lake subsystem (DuckDB, Parquet, RAG, Iceberg, domain writers) is off unless explicitly enabled. This is by design but means no demo or test exercises the lake code paths unless the flag is set.

---

### STUB-017: Integrations Real Code But Untestable Without Credentials

**Risk:** LOW
**Location:** `warlock/integrations/`

The Jira, ServiceNow, Teams, and STIX/TAXII integration modules contain real HTTP client code with proper error handling. However, they cannot be tested without live service credentials. No mock/stub test harness exists for integration testing.

---

### STUB-018: Terraform Provider Is Read-Only

**Risk:** LOW
**Location:** `terraform/`

The Terraform provider implementation supports `data` sources (reads) but has no `resource` definitions (creates/updates/deletes). It can query Warlock state but cannot manage it. The provider is functional for its limited scope but the label "Terraform provider" implies full CRUD capability.

---

### STUB-019: Forecast Is Linear Extrapolation Only

**Risk:** MODERATE
**Location:** `warlock/assessors/`

The compliance forecast feature is labeled "Monte Carlo simulation" but implements simple linear extrapolation from historical data points. There is no probability distribution sampling, no confidence intervals from simulation, and no random variable modeling. The output format mimics Monte Carlo results but the math is a trend line.

---

### STUB-020: Seed Expansion Phases 2, 3, 5 Broken

**Risk:** HIGH
**Location:** `scripts/demo_seed.py`

Seed expansion phases produce runtime errors:
- **Phase 2:** `'AuditTrail' has no attribute 'append'` -- the model interface changed but seed code was not updated
- **Phase 5:** `'raw_event_count' invalid keyword` -- constructor signature mismatch

These phases are wrapped in try/except blocks so the seed completes without error, but the expanded demo data is silently missing.

---

## Category 2: False Confidence Issues

These are features that actively report healthy/passing/complete status when the underlying data is absent, broken, or fabricated. These are more dangerous than stubs because they create false assurance.

---

### STUB-021: `control-tests gaps` Returns False Negative -- EXTREME RISK

**Risk:** EXTREME
**Location:** `warlock/cli/`

The `control-tests gaps` command reports "No Gaps Found" when no test coverage data exists. It conflates the presence of automated assessment results (from the assertion engine) with manual test execution. A control that has been assessed by assertions but never manually tested shows as "tested." This means:

- A system with zero manual tests reports zero gaps
- The command provides false assurance that testing is complete
- Auditors relying on this output would conclude all controls are tested

**Root cause:** The query checks for `ControlResult` records (produced by automated assertions) rather than a separate test-execution tracking table (which does not exist).

---

### STUB-022: `evidence gaps` Returns False Negative -- HIGH RISK

**Risk:** HIGH
**Location:** `warlock/cli/`

The `evidence gaps` command reports "100% Coverage" when only computed pipeline hashes exist as "evidence." There is no `Evidence` model in the database. The command counts the existence of any `ControlResult` record as "evidence collected," even though:

- No document/artifact was uploaded
- No screenshot or log was attached
- The only "evidence" is the SHA-256 hash from pipeline processing

An auditor would interpret "100% evidence coverage" as meaning artifacts exist for every control.

---

### STUB-023: Dashboard "Hash Chain: Verified" Is Hardcoded Green

**Risk:** EXTREME
**Location:** `frontend/src/components/Dashboard.tsx:143`

The frontend dashboard displays an audit chain health indicator that is hardcoded to show a green/healthy status. It never calls the backend verification API.

**Evidence:**
```jsx
<StatusBadge status="healthy" label="Audit Chain: Valid" />
```

This badge is static JSX. There is no `useEffect`, no `fetch()`, no API call. The chain could be completely broken and the dashboard would still show green.

---

### STUB-024: POA&M Transition Buttons Are Decorative

**Risk:** HIGH
**Location:** `frontend/src/components/POAMDetail.tsx:143-149`

The POA&M detail view renders state-transition buttons (e.g., "Move to In Progress", "Mark Remediated") but the buttons have no `onClick` handlers. Clicking them does nothing. The backend `POAMManager.transition()` API exists and works, but the frontend never calls it.

---

### STUB-025: Settings Page Sliders Are Cosmetic

**Risk:** MODERATE
**Location:** `frontend/src/components/SettingsOverview.tsx:241-278`

The settings page displays sliders for AI confidence threshold, risk tolerance, and other tunable parameters. The `handleSave` function only sends `provider`, `api_key`, and `base_url` to the backend. All slider values are discarded on save. Users can adjust sliders and click save with no error, but nothing changes.

---

### STUB-026: Peer Benchmark Uses Synthetic Data

**Risk:** MODERATE
**Location:** `warlock/cli/`

The peer benchmark feature generates "industry comparison" data by taking the organization's own scores and adding random noise of +/-5-15% via random distributions. The output labels this as "peer data" but it is entirely fabricated from the organization's own metrics. There is no external data source, no anonymized peer database, and no industry dataset.

---

### STUB-027: Audit Trail Hash Chain Broken in Demo -- EXTREME RISK

**Risk:** EXTREME
**Location:** `scripts/demo_seed.py`, `warlock/db/`

The audit trail hash chain passes verification at seed step 31 but breaks during subsequent seed steps. The chain uses SHA-256 with `SELECT FOR UPDATE` serialization and `"genesis"` as the initial previous_hash. After certain seed operations, the chain integrity check fails.

This is distinct from STUB-023 (dashboard showing green) -- the chain is actually broken in the demo database. Even if the dashboard called the verification API, it would report failure. Combined with STUB-023, the demo shows a green badge over a broken chain.

---

### STUB-028: CLI `audit-trail verify` Uses Wrong Hash Algorithm

**Risk:** EXTREME
**Location:** `warlock/cli/`

The `audit-trail verify` CLI command computes verification hashes using pipe-separated field concatenation, while the pipeline writes hashes using `json.dumps(data, sort_keys=True, default=str)`. These two serialization methods will never produce matching hashes. The verify command will ALWAYS report a broken chain, even on a valid one.

This means:
- If the chain is valid, `verify` reports it as broken (false negative)
- If the chain is broken, `verify` reports it as broken (correct but for the wrong reason)
- There is no way to distinguish a real break from the algorithm mismatch

**Relationship to STUB-027:** STUB-027 documents that the chain is actually broken in demo data. STUB-028 documents that even if it were fixed, the verify command would still report failure due to algorithm mismatch.

---

### STUB-029: Pipeline Status Shows Zero Counts

**Risk:** HIGH
**Location:** `warlock/pipeline/pipeline.py:143-144`

The pipeline status reporting hardcodes `finding_count=0` and `result_count=0` regardless of actual pipeline output. After a full pipeline run that processes thousands of findings, the status report shows zero.

**Evidence:**
```python
# pipeline.py:143-144
finding_count=0,
result_count=0,
```

---

## Category 3: In-Memory Only Modules

These modules implement their full advertised feature set but store all state in Python dicts or module-level variables. Everything is lost on process restart. No database models exist for any of them.

---

### STUB-030: Multi-Tenancy -- In-Memory Only

**Risk:** HIGH
**Location:** `warlock/platform/tenancy.py:32`

The multi-tenancy module uses a module-level `_TENANTS: dict = {}` to store tenant configurations. Tenant creation, isolation, and routing all work correctly within a single process lifetime. On restart, all tenants and their configurations vanish. There are no database tables for tenants.

---

### STUB-031: Delegation Records -- In-Memory Only

**Risk:** HIGH
**Location:** `warlock/platform/delegation.py:98`

The delegation module stores authority delegation records (who delegated what to whom, with expiry dates and scope constraints) in an instance-level dict. Delegations are enforced correctly during the process lifetime but are lost on restart. An authority delegation that was valid disappears silently.

---

### STUB-032: Sandbox Environments -- In-Memory Only

**Risk:** MODERATE
**Location:** `warlock/platform/sandbox.py:31`

The sandbox module creates isolated environments for policy testing and what-if analysis. `promote_to_production()` returns a diff showing what would change but explicitly states: "Actual application is the caller's responsibility." Sandbox state is stored in-memory and lost on restart. There is no persistence layer.

---

### STUB-033: White-Label Branding -- In-Memory Only

**Risk:** LOW
**Location:** `warlock/platform/white_label.py:78`

The white-label module stores branding configurations (logos, colors, domain mappings, custom CSS) in an in-memory dict. Branding applies correctly to responses during the process lifetime but resets to defaults on restart.

---

## Summary Table

| ID | Category | Risk | Description |
|---|---|---|---|
| STUB-001 | True Stub | MODERATE | 84 of 352 connectors are demo mocks |
| STUB-002 | True Stub | HIGH | Domain event handlers return empty lists |
| STUB-003 | True Stub | LOW | Incidents mobile-approve is display only |
| STUB-004 | True Stub | LOW | Incidents offline-collect is instructions only |
| STUB-005 | True Stub | HIGH | Lake NL query is keyword router (~15 patterns) |
| STUB-006 | True Stub | MODERATE | Regulatory filing templates are placeholder text |
| STUB-007 | True Stub | MODERATE | Questionnaire automation uses hardcoded in-memory answers |
| STUB-008 | True Stub | HIGH | Bulk/legacy import parses but never persists |
| STUB-009 | True Stub | MODERATE | Workpapers, evidence snapshots, test schedules are ephemeral |
| STUB-010 | True Stub | LOW | SCD Type 2 implemented but never called |
| STUB-011 | True Stub | MODERATE | 7 of 10 lake domain writers have no upstream producer |
| STUB-012 | True Stub | MODERATE | SoD analysis engine is dead code |
| STUB-013 | True Stub | HIGH | Compensating control evaluation hardcoded to 0.8 |
| STUB-014 | True Stub | LOW | Queue backends defined but never selectable |
| STUB-015 | True Stub | MODERATE | Lake RAG is TF-IDF only, no vector database |
| STUB-016 | True Stub | LOW | Lake disabled by default |
| STUB-017 | True Stub | LOW | Integrations untestable without credentials |
| STUB-018 | True Stub | LOW | Terraform provider is read-only |
| STUB-019 | True Stub | MODERATE | Forecast is linear extrapolation, not Monte Carlo |
| STUB-020 | True Stub | HIGH | Seed expansion phases 2, 3, 5 broken silently |
| STUB-021 | False Confidence | EXTREME | control-tests gaps reports no gaps when no tests exist |
| STUB-022 | False Confidence | HIGH | evidence gaps reports 100% when no evidence model exists |
| STUB-023 | False Confidence | EXTREME | Dashboard hash chain badge hardcoded green |
| STUB-024 | False Confidence | HIGH | POA&M transition buttons have no onClick handlers |
| STUB-025 | False Confidence | MODERATE | Settings sliders are cosmetic, values discarded on save |
| STUB-026 | False Confidence | MODERATE | Peer benchmark fabricates data from own scores |
| STUB-027 | False Confidence | EXTREME | Audit trail hash chain broken in demo data |
| STUB-028 | False Confidence | EXTREME | CLI audit-trail verify uses wrong hash algorithm |
| STUB-029 | False Confidence | HIGH | Pipeline status hardcodes finding_count=0, result_count=0 |
| STUB-030 | In-Memory Only | HIGH | Multi-tenancy stored in module-level dict |
| STUB-031 | In-Memory Only | HIGH | Delegation records lost on restart |
| STUB-032 | In-Memory Only | MODERATE | Sandbox environments not persisted |
| STUB-033 | In-Memory Only | LOW | White-label branding resets on restart |

---

## Remediation Priority

### Tier 1 -- Fix Immediately (EXTREME risk, actively misleading)

1. **STUB-028** -- Fix `audit-trail verify` to use `json.dumps(sort_keys=True, default=str)` matching the pipeline's hash algorithm
2. **STUB-027** -- Fix demo seed to produce a valid hash chain end-to-end
3. **STUB-023** -- Wire dashboard badge to call the verification API endpoint
4. **STUB-021** -- Rename command or add prominent disclaimer that it checks assessment coverage, not test coverage

### Tier 2 -- Fix Before Any Demo to Auditors (HIGH risk, false assurance)

5. **STUB-022** -- Rename to `evidence-assessment-coverage` or add disclaimer about what constitutes "evidence"
6. **STUB-029** -- Wire pipeline status to actual counts from `PipelineRunStats`
7. **STUB-024** -- Add onClick handlers to POA&M buttons calling `POAMManager.transition()`
8. **STUB-013** -- Implement actual compensating control scoring or remove the feature
9. **STUB-002** -- Implement at least one domain event handler to prove the architecture
10. **STUB-008** -- Add `session.add()` calls to persist imported data
11. **STUB-020** -- Fix seed expansion phase errors (model attribute mismatch)

### Tier 3 -- Fix Before GA (MODERATE risk, incomplete features)

12. **STUB-005** -- Replace keyword router with proper NL query (even basic intent classification)
13. **STUB-025** -- Wire settings sliders to backend configuration
14. **STUB-019** -- Either implement real Monte Carlo or rename to "Linear Forecast"
15. **STUB-015** -- Either implement vector search or rename from "RAG"
16. **STUB-001** -- Document which connectors are mocks vs real in connector list output
17. **STUB-026** -- Either source real peer data or clearly label as "simulated benchmark"
18. **STUB-030/031** -- Add database models for tenancy and delegation

### Tier 4 -- Backlog (LOW risk, known limitations)

19. **STUB-003/004** -- Implement mobile-approve and offline-collect or remove from CLI
20. **STUB-010/012/014** -- Remove dead code (SCD, SoD, unused queue backends) or wire them in
21. **STUB-016/017/018** -- Document limitations; these are acceptable for current scope
22. **STUB-032/033** -- Add persistence when multi-tenancy is prioritized
