# Warlock Architecture Review

> **Last updated:** 2026-03-26
> **Scope:** Full-stack architecture audit across pipeline, database, security, frontend, deployment, data, and observability domains.
> **Method:** Three independent analysis sessions merged into a single definitive reference. Every unique finding preserved; overlapping findings consolidated using the richest description.

---

## Executive Summary

Warlock's core pipeline is genuinely well-engineered. The five-stage flow (collect, normalize, map, assess, export) has clear input/output contracts, SHA-256 hash chaining for auditability, per-connector transaction isolation, and a queue backend abstraction that already speaks Redis Streams, Kafka, SQS, and NATS JetStream. The 14-framework control mapping with crosswalk propagation, 670 OPA Rego policies, OSCAL export with deterministic UUID5 generation, and FAIR Monte Carlo risk quantification are substantial, production-worthy subsystems rarely seen even in commercial GRC tools.

The gaps cluster in three areas:

1. **Deployment and operationalization** -- no containerization, no structured logging, no metrics, no distributed tracing, no health check depth, and no CI/CD beyond lint-and-test.
2. **Resilience under failure** -- no dead letter queue, no circuit breakers, no retry budgets, single-process scheduling, and per-worker (not distributed) rate limiting.
3. **Scale** -- SQLite as the default database, no caching layer, no query timeouts, no table partitioning, batch-only pipeline processing, and in-memory-only platform modules.

The frontend (Next.js 14) is a read-only dashboard with no authentication UI, no forms, no POST requests, and no integration with the backend build or deployment. Several UI elements (POA&M action buttons, settings sliders) are cosmetic -- they render but have no event handlers.

None of these gaps are architectural dead-ends. The codebase is well-structured for incremental hardening. The findings below are ordered by domain, each with severity, evidence, and recommended remediation.

---

## Table of Contents

1. [Pipeline Domain (ARCH-001 through ARCH-004)](#1-pipeline-domain)
2. [Database Domain (ARCH-005 through ARCH-009)](#2-database-domain)
3. [Security Domain (ARCH-010 through ARCH-014)](#3-security-domain)
4. [Frontend Domain (ARCH-015 through ARCH-017)](#4-frontend-domain)
5. [Deployment Domain (ARCH-018 through ARCH-020)](#5-deployment-domain)
6. [Data Domain (ARCH-021 through ARCH-023)](#6-data-domain)
7. [Observability Domain (ARCH-024 through ARCH-030)](#7-observability-domain)
8. [Additional Findings (ARCH-031 through ARCH-037)](#8-additional-findings)
9. [What Works Well](#9-what-works-well)
10. [Summary Table](#10-summary-table)

---

## 1. Pipeline Domain

### ARCH-001: No Dead Letter Queue

**Severity:** High
**Domain:** Pipeline / Resilience

The pipeline processes connector output in a single pass. When a connector raises an unhandled exception, its events are lost -- there is no dead letter queue (DLQ) to capture failed items for later replay or inspection.

**Evidence:**
- `warlock/pipeline/orchestrator.py` catches exceptions per-connector and logs them, but the failed connector's partial results are discarded.
- `warlock/pipeline/queue.py` (1,008 lines) implements Redis Streams, Kafka, SQS, and NATS JetStream backends. The SQS backend has visibility-timeout handling (a form of retry), but there is no cross-backend DLQ abstraction.
- `PipelineRunStats` tracks `connectors_failed` count but not the individual failed events.

**Impact:** A transient failure (network timeout, API rate limit) during a pipeline run silently drops that connector's findings. The next full run re-collects everything, but any events unique to the failed window are lost.

**Recommendation:** Add a `FailedEvent` table (or DLQ topic in the queue backend) that captures the raw event, the exception, and a retry count. Expose a CLI command (`warlock pipeline replay-dlq`) and an API endpoint to retry or discard failed events.

---

### ARCH-002: No Circuit Breaker Pattern

**Severity:** Medium
**Domain:** Pipeline / Resilience

Connectors call external APIs (AWS, Azure, GCP, GitHub, Jira, etc.) without circuit breaker protection. A degraded upstream service causes the entire pipeline run to block on that connector's timeout.

**Evidence:**
- `warlock/connectors/base.py` defines `BaseConnector` with a `collect()` method. There is no retry budget, backoff, or circuit state.
- The pipeline orchestrator iterates connectors sequentially (or via the queue backend). A single slow connector delays all subsequent connectors.
- No dependency on `tenacity`, `pybreaker`, or any retry/circuit library in `pyproject.toml`.

**Impact:** A 30-second timeout on one connector multiplied by retry attempts can turn a 2-minute pipeline run into a 15-minute run. In production with 352 connectors, this compounds.

**Recommendation:** Implement a circuit breaker per connector (or per upstream API). After N consecutive failures, open the circuit and skip that connector for a configurable cooldown period. Log the circuit state transition. Consider `tenacity` for retry-with-backoff.

---

### ARCH-003: Batch-Only Pipeline Processing

**Severity:** Medium
**Domain:** Pipeline / Scale

The pipeline operates in batch mode only -- every run re-collects all data from every connector. There is no incremental collection, no high-water marks, and no change-detection mechanism.

**Evidence:**
- `warlock/pipeline/orchestrator.py` calls `connector.collect()` on every registered connector, every run.
- No `last_collected_at` or cursor/checkpoint column on the `Connector` model.
- The demo seed creates ~1,071 raw events and ~7,325 findings per run, but a production environment with continuous collection would generate orders of magnitude more.
- Connectors do not implement incremental collection -- there are no high-water mark parameters (e.g., "collect events since timestamp X") passed to `collect()`.

**Impact:** Pipeline runs are O(total data), not O(new data). As the monitored environment grows, run times increase linearly even when nothing has changed.

**Recommendation:** Add a `last_checkpoint` JSON column to the `Connector` model. Pass the checkpoint to `collect()` so connectors can implement incremental fetches (e.g., AWS CloudTrail events since last EventTime, GitHub audit log since last cursor). Fall back to full collection when checkpoint is null or on explicit `--full` flag.

---

### ARCH-004: Synchronous Event Bus

**Severity:** Medium
**Domain:** Pipeline / Scale

The in-process event bus (`warlock/pipeline/events.py`) dispatches events synchronously. All subscribers execute in the caller's thread, blocking the pipeline until every handler completes.

**Evidence:**
- `EventBus.publish()` iterates `self._subscribers[event_type]` and calls each handler sequentially.
- No async dispatch, no thread pool, no fire-and-forget option.
- The event bus is used for pipeline lifecycle events (run started, connector completed, run finished), audit logging hooks, and alert triggers.

**Impact:** A slow subscriber (e.g., an alert handler that calls an external webhook) blocks the pipeline. Adding more subscribers degrades pipeline throughput linearly.

**Recommendation:** Add an async dispatch mode using `asyncio.create_task()` or a thread pool. Critical subscribers (audit trail) remain synchronous; optional subscribers (alerts, webhooks) dispatch asynchronously with error isolation.

---

## 2. Database Domain

### ARCH-005: POA&M CHECK Constraint vs. Model Mismatch

**Severity:** High
**Domain:** Database / Integrity

The `poam_items` table has a CHECK constraint allowing 6 status values, but the application's `POAMManager` state machine defines 9 valid statuses. Three statuses accepted by the application will be rejected by the database.

**Evidence:**
- `warlock/db/models.py` defines the `POAMItem` model. The Alembic migration for `poam_items` includes:
  ```sql
  CHECK (status IN ('draft', 'open', 'in_progress', 'remediated', 'verified', 'completed'))
  ```
- `warlock/workflows/poam.py` (`POAMManager`) defines transitions that include `risk_accepted`, `cancelled`, and `closed` as valid target statuses.
- The three missing statuses (`risk_accepted`, `cancelled`, `closed`) can be set via `POAMManager.transition()` but will raise `IntegrityError` on commit.

**Impact:** Any POA&M workflow that transitions to `risk_accepted`, `cancelled`, or `closed` will fail at the database level. These are common real-world workflow outcomes.

**Recommendation:** Update the CHECK constraint via a new Alembic migration to include all 9 statuses. Verify the constraint matches the `VALID_STATUSES` set in `POAMManager`.

---

### ARCH-006: 9 Models Without Alembic Migrations

**Severity:** High
**Domain:** Database / Schema Management

Nine SQLAlchemy models exist in `warlock/db/models.py` that are created by `Base.metadata.create_all()` but have no corresponding Alembic migration. This means `alembic upgrade head` on a fresh database will not create these tables -- only `create_all()` will.

**Evidence:**
The following models lack migration scripts in `warlock/db/migrations/versions/`:
1. `AuditTrail`
2. `RiskScenario`
3. `CompensatingControl`
4. `GDPRSubjectRequest`
5. `RetentionPolicy`
6. `LakeIngestionRun`
7. `LakeQueryCache`
8. `DelegationRecord`
9. `SandboxEnvironment`

- `warlock/db/migrations/versions/` contains 18 migration files, but none reference these 9 models.
- The `demo.sh` script calls `create_all()` as a safety net, which masks the missing migrations in development.

**Impact:** Production deployments that rely solely on Alembic migrations will have missing tables. The `create_all()` fallback works in development but is not safe for production schema management (it cannot handle ALTER TABLE, column additions, or data migrations).

**Recommendation:** Generate Alembic migrations for all 9 models. Use `alembic revision --autogenerate` to create the initial migration, then verify it matches the model definitions. Remove the `create_all()` fallback from production startup paths.

---

### ARCH-007: Application-Level Sequence Generation

**Severity:** Medium
**Domain:** Database / Concurrency

The audit trail hash chain uses `SELECT ... FOR UPDATE` to serialize sequence number generation at the application level. This works for PostgreSQL but is a no-op for SQLite (which ignores `FOR UPDATE`).

**Evidence:**
- `warlock/db/audit.py` uses `with_for_update()` on the query to get the latest audit entry's sequence number, then increments it in Python.
- SQLite's `with_for_update()` is silently ignored -- concurrent writers will read the same sequence number and produce duplicate sequences.
- The hash chain uses `previous_hash` from the prior entry. Duplicate sequences break the chain's integrity.
- Initial `previous_hash` is `"genesis"` (not empty or None).

**Impact:** Under concurrent API requests with SQLite, audit trail entries can have duplicate sequence numbers, breaking the hash chain. PostgreSQL deployments are safe due to row-level locking.

**Recommendation:** For SQLite, use a mutex or database-level lock (e.g., `BEGIN EXCLUSIVE TRANSACTION`). For PostgreSQL, the current approach is correct. Consider a database sequence (`CREATE SEQUENCE`) for PostgreSQL to avoid the application-level increment entirely.

---

### ARCH-008: No Table Partitioning Strategy

**Severity:** Medium
**Domain:** Database / Scale

High-volume tables (`findings`, `control_results`, `raw_events`, `audit_trail`) grow without bound. There is no partitioning, archival, or retention strategy.

**Evidence:**
- The demo seed creates ~7,325 findings and ~373,852 control results in a single run. Production environments running daily would accumulate millions of rows within months.
- No `created_at` partitioning, no archive tables, no retention policies at the database level.
- `warlock/workflows/retention.py` defines a `RetentionPolicy` model but it operates on document-level retention (OSCAL exports, reports), not on database row retention.
- Query performance will degrade as tables grow, especially for unindexed `created_at` range queries.

**Impact:** Database performance degrades over time. Backup and restore times increase. No way to age out old data without manual intervention.

**Recommendation:** For PostgreSQL, implement table partitioning by month on `findings`, `control_results`, and `audit_trail`. For SQLite (development only), implement a `warlock db archive` CLI command that moves records older than N days to an archive database. Add database-level retention policies to complement the existing document-level retention.

---

### ARCH-009: No Query Timeout Configuration

**Severity:** Medium
**Domain:** Database / Resilience

Neither SQLite nor PostgreSQL connections have query-level timeout configuration. A runaway query (e.g., unindexed JOIN across `control_results` and `findings`) will block the connection pool indefinitely.

**Evidence:**
- `warlock/db/session.py` configures SQLite PRAGMAs (`busy_timeout=5000`, `journal_mode=WAL`, `foreign_keys=ON`) but no statement timeout.
- No PostgreSQL `statement_timeout` setting in the engine configuration.
- The API uses `Depends(get_pagination)` with a hard cap of 1,000 rows, but the underlying query may still scan millions of rows before the LIMIT is applied.

**Impact:** A single expensive query can exhaust the connection pool, causing all subsequent API requests to hang.

**Recommendation:** Set `statement_timeout` for PostgreSQL connections (e.g., 30 seconds). For SQLite, the `busy_timeout` already handles lock contention but not query execution time -- consider a Python-level timeout wrapper using `signal.alarm()` or `asyncio.wait_for()`.

---

## 3. Security Domain

### ARCH-010: Per-Worker Rate Limiting

**Severity:** High
**Domain:** Security / API Protection

Rate limiting is implemented in-process using a dictionary (`_ENDPOINT_LIMITS` in `warlock/api/middleware.py`). Each worker process maintains its own rate limit counters. Behind a load balancer with multiple workers, an attacker gets N times the rate limit (where N is the number of workers).

**Evidence:**
- `warlock/api/middleware.py` stores rate limit state in a module-level dictionary, reset per-process.
- No Redis, Memcached, or other shared state backend for rate limiting.
- Rate limits: login=10/min, register=5/min, AI=30/min, pipeline=5/min.
- With 4 Uvicorn workers, an attacker gets 40 login attempts per minute instead of 10.

**Impact:** Rate limiting is ineffective in any multi-process or multi-instance deployment. Login brute-force protection is proportionally weakened.

**Recommendation:** Move rate limit state to Redis using a sliding window algorithm. Use a library like `slowapi` with a Redis backend, or implement token bucket in Redis with Lua scripts for atomicity.

---

### ARCH-011: OPA Policy Gate Bypassed by Default

**Severity:** High
**Domain:** Security / Authorization

The OPA integration has two distinct fail modes that are easily confused:

1. `opa_fail_mode = "closed"` (default) -- the API-level policy gate in `warlock/api/policy_gate.py`. This correctly blocks requests when OPA is unreachable.
2. `opa_compliance_fail_mode = "open"` (default) -- the compliance evaluation in the assessment pipeline. This intentionally allows assessments to proceed when OPA policies are missing for a specific control.

However, the OPA middleware in `policy_gate.py` has a structural issue: it checks `request.state.user` for ABAC attributes, but `request.state.user` is `None` at middleware execution time (before the auth dependency resolves). The middleware falls through to the default allow/deny based on `opa_fail_mode` without ever evaluating the actual OPA policy with user context.

**Evidence:**
- `warlock/api/policy_gate.py` accesses `request.state.user` which is set by the auth dependency, but middleware runs before dependencies.
- The `_HEALTH_PATHS` set correctly bypasses OPA for health endpoints.
- `warlock/config.py` defaults: `opa_fail_mode="closed"`, `opa_compliance_fail_mode="open"`.

**Impact:** ABAC policies that depend on user attributes (role, tenant, department) are never evaluated at the middleware level. The policy gate effectively becomes a binary allow/deny based on whether OPA is reachable, not on the policy outcome.

**Recommendation:** Move OPA policy evaluation from middleware to a FastAPI dependency that runs after authentication. This ensures `request.state.user` is populated before policy evaluation. Alternatively, use a sub-request to the auth system within the middleware.

---

### ARCH-012: Weak PII Pseudonymization

**Severity:** High
**Domain:** Security / Data Protection

The PII scrubbing utility (`warlock/utils/pii.py`) uses unsalted SHA-256 truncated to 32 bits (8 hex characters) for pseudonymization. This provides only ~4 billion possible values, making rainbow table attacks trivial for structured data like email addresses and IP addresses.

**Evidence:**
- `warlock/utils/pii.py` defines `scrub_finding()` which applies 5 regex patterns:
  1. Email addresses
  2. IPv4 addresses
  3. AWS account IDs (12-digit numbers)
  4. AWS ARNs
  5. Hostnames matching common patterns
- The pseudonymization function: `hashlib.sha256(value.encode()).hexdigest()[:8]`
- No salt, no pepper, no HMAC key. The same input always produces the same 8-character hash.
- Coverage is estimated at ~60% of PII fields. Usernames, phone numbers, physical addresses, and cloud resource names with embedded PII are not caught.

**Impact:** An attacker with access to the findings table can reverse pseudonymized emails by hashing common email patterns. The 32-bit hash space means collisions are frequent (~50% collision probability at ~65,000 unique values by the birthday paradox).

**Recommendation:** Use HMAC-SHA256 with a configurable secret (similar to `gdpr_hmac_secret`) and output the full 256-bit hash (or at least 128 bits). Add regex patterns for phone numbers, usernames, and cloud resource names. Consider using `cryptography.fernet` for reversible encryption where the original value is needed for GDPR subject access requests.

---

### ARCH-013: GDPR Erasure Logs Plaintext PII

**Severity:** High
**Domain:** Security / GDPR Compliance

The GDPR erasure workflow correctly anonymizes PII in database records using `[REDACTED-xxxx]` HMAC tokens, but the erasure operation itself logs the plaintext email address of the data subject being erased.

**Evidence:**
- `warlock/workflows/gdpr.py` logs: `logger.info(f"Processing erasure request for {email}")` before performing the anonymization.
- The erasure result includes the original email in the return value, which may be captured by API response logging.
- After erasure, the database correctly contains only `[REDACTED-xxxx]` tokens, but the log files retain the plaintext association between the HMAC token and the original email.

**Impact:** Log files become a PII liability. If logs are shipped to a SIEM or log aggregation service, the erasure is incomplete -- the data subject's email persists in operational logs.

**Recommendation:** Log only the HMAC token or a request ID, never the plaintext email. Modify the erasure workflow to accept a `subject_request_id` instead of passing the email through the logging path. Add a log scrubbing filter that catches PII patterns before they reach log output.

---

### ARCH-014: No CSRF Protection

**Severity:** Medium
**Domain:** Security / Web

The FastAPI application does not implement CSRF protection. While the API currently uses JWT Bearer tokens (which are not automatically attached by browsers), the frontend's `AuthContext` stores the token and could be vulnerable if the token storage mechanism changes to cookies.

**Evidence:**
- No CSRF middleware in `warlock/api/app.py` or `warlock/api/middleware.py`.
- No `SameSite` cookie configuration (JWT is passed as a Bearer token in the Authorization header).
- No CSRF token generation or validation endpoints.
- The frontend uses `localStorage` for token storage (visible in the Next.js `AuthContext`), which is not vulnerable to CSRF but is vulnerable to XSS.

**Impact:** Currently low risk because JWT is in the Authorization header (not cookies). Risk increases if the auth mechanism changes to cookie-based sessions. The `localStorage` token storage is vulnerable to XSS, which is mitigated by the CSP headers but not eliminated.

**Recommendation:** Add `SameSite=Strict` cookie configuration as a defense-in-depth measure. If migrating to cookie-based auth, implement double-submit CSRF tokens. Consider moving token storage from `localStorage` to an `httpOnly` cookie with CSRF protection.

---

## 4. Frontend Domain

### ARCH-015: No Login Page or Auth Flow

**Severity:** High
**Domain:** Frontend / Authentication

The Next.js frontend has an `AuthContext` provider that manages JWT tokens, but there is no login page, no registration page, and no authentication UI. The demo auto-authenticates with hardcoded credentials.

**Evidence:**
- `frontend/src/contexts/AuthContext.tsx` defines `login()`, `logout()`, and `register()` methods.
- No `login.tsx`, `register.tsx`, or `auth/` route exists in the `frontend/src/app/` directory.
- `d88ac27` (commit) explicitly removed the login page and added auto-authentication with demo credentials.
- The `AuthContext` calls `POST /api/v1/auth/login` with hardcoded `demo` / `demo` credentials on mount.

**Impact:** The frontend cannot be used by real users. There is no way to log in, create accounts, or manage sessions through the UI. The auto-auth approach is appropriate for demo purposes but must be replaced before any real deployment.

**Recommendation:** Add a login page with email/password form, error handling, and redirect-after-login. Add a registration page if self-service signup is desired. Conditionally enable auto-auth only when `WLK_DEMO_MODE=true`.

---

### ARCH-016: Read-Only Frontend

**Severity:** High
**Domain:** Frontend / Functionality

The Next.js frontend contains zero forms, zero POST/PUT/DELETE requests, and zero mutation operations. Every page is a read-only dashboard that fetches data via GET requests and renders it.

**Evidence:**
- No `<form>` elements in any component.
- No `fetch()` or `axios` calls with methods other than GET.
- Pages: Dashboard, Frameworks, Findings, Controls, Infrastructure, Compliance, Remediation, Risk, POA&M, Pipeline, Settings.
- All pages follow the same pattern: `useEffect(() => fetch(url).then(setData))` with table or card rendering.

**Impact:** Users cannot create POA&M items, trigger pipeline runs, configure connectors, manage frameworks, remediate findings, or perform any write operation through the UI. All mutations must be done via CLI or direct API calls.

**Recommendation:** Prioritize forms for the most common write operations: (1) trigger pipeline run, (2) create/update POA&M items, (3) configure connectors, (4) update finding status. Use React Hook Form or similar for validation.

---

### ARCH-017: Dead UI Elements

**Severity:** Medium
**Domain:** Frontend / Quality

Several UI elements render interactive-looking controls (buttons, sliders, toggles) that have no event handlers and perform no actions.

**Evidence:**
- POA&M page: "Create POA&M", "Update Status", and action buttons render but have no `onClick` handlers.
- Settings page: Toggle switches for notification preferences, theme selection sliders, and configuration dropdowns are cosmetic -- they render with hardcoded values and no `onChange` handlers.
- Remediation page: "Apply Fix" and "Run Command" buttons render but do not execute any actions.
- Infrastructure page: Resource cards show "Drill Down" links that navigate to empty detail pages.

**Impact:** Users expect interactive elements to function. Non-functional buttons erode trust in the application and create support burden.

**Recommendation:** Either wire up the event handlers to API calls or remove the non-functional elements and replace them with clear "Coming Soon" indicators. Do not render interactive controls that do nothing.

---

## 5. Deployment Domain

### ARCH-018: No Containerization

**Severity:** High
**Domain:** Deployment / Packaging

There is no `Dockerfile`, no `docker-compose.yml`, no container registry configuration, and no container-based deployment path.

**Evidence:**
- No `Dockerfile` or `Containerfile` in the repository root or any subdirectory.
- No `docker-compose.yml` or `docker-compose.yaml`.
- No `.dockerignore`.
- The deployment guide (`docs/DEPLOYMENT_GUIDE.md`) describes manual Python installation steps.
- The demo runs via `make demo` which calls `scripts/demo.sh` (bare-metal Python process).

**Impact:** Cannot deploy to Kubernetes, ECS, Cloud Run, or any container orchestration platform without first creating container artifacts. Cannot guarantee reproducible environments across development, staging, and production.

**Recommendation:** Create a multi-stage `Dockerfile` (build stage with dev dependencies for testing, production stage with minimal runtime). Add `docker-compose.yml` with services for Warlock API, PostgreSQL, Redis, and OPA. Add `.dockerignore` to exclude `__pycache__`, `.git`, `node_modules`, `warlock.db`.

---

### ARCH-019: Single-Process Scheduler

**Severity:** High
**Domain:** Deployment / Scale

The pipeline scheduler (`warlock/pipeline/scheduler.py`) runs as a background thread in the API process. In a multi-worker deployment, each worker starts its own scheduler, leading to duplicate pipeline runs.

**Evidence:**
- `warlock/pipeline/scheduler.py` uses `threading.Timer` or `schedule` library to trigger periodic pipeline runs.
- The file-based lock (`$TMPDIR/warlock_pipeline.lock`) prevents concurrent runs on a single machine but not across multiple machines.
- `fcntl.flock()` is used for SQLite deployments; `pg_advisory_lock` for PostgreSQL. Neither prevents duplicate scheduling across hosts.

**Impact:** In a multi-instance deployment (e.g., 3 API servers behind a load balancer), three schedulers will attempt to trigger pipeline runs. The lock prevents concurrent execution but not duplicate scheduling -- each instance queues its own run, leading to redundant work.

**Recommendation:** Extract the scheduler to a standalone process (or use a distributed task scheduler like Celery Beat, APScheduler with a database job store, or a Kubernetes CronJob). Ensure only one scheduler instance exists across the entire deployment.

---

### ARCH-020: Frontend Not Integrated with Backend Deployment

**Severity:** High
**Domain:** Deployment / Integration

The Next.js frontend and FastAPI backend are completely separate applications with no shared build, deployment, or configuration pipeline.

**Evidence:**
- `frontend/` is a standalone Next.js project with its own `package.json`, `next.config.js`, and `tsconfig.json`.
- No proxy configuration in `next.config.js` to route API calls to the backend.
- No CORS configuration in `warlock/api/app.py` that includes the frontend's development or production URL (the `cors_origins` config defaults to an empty list `[]`).
- No shared deployment script, `Makefile` target, or CI/CD pipeline that builds and deploys both together.
- The frontend hardcodes `http://localhost:8000` as the API URL in several components.
- `make demo` starts only the backend; the frontend must be started separately with `cd frontend && npm run dev`.

**Impact:** The frontend cannot communicate with the backend in any deployment other than local development (and even then, CORS blocks requests unless manually configured). There is no path to deploy the full application as a single unit.

**Recommendation:** Add a `NEXT_PUBLIC_API_URL` environment variable to the frontend. Configure CORS in the backend to accept the frontend's origin. Add a `make demo-full` target that starts both backend and frontend. For production, either serve the frontend as static files from the backend (via FastAPI's `StaticFiles`) or deploy as separate services with proper CORS/proxy configuration.

---

## 6. Data Domain

### ARCH-021: No Query Result Caching

**Severity:** Medium
**Domain:** Data / Performance

The API computes every response from scratch on every request. There is no caching layer for expensive queries (compliance dashboards, framework summaries, control result aggregations).

**Evidence:**
- No Redis, Memcached, or in-process cache usage in any API route.
- No `@cache`, `@lru_cache`, or `functools.cache` decorators on query functions.
- No `Cache-Control`, `ETag`, or `Last-Modified` headers in API responses.
- The dashboard endpoint aggregates across `findings`, `control_results`, and `frameworks` on every request -- a query that touches hundreds of thousands of rows.
- The `LakeQueryCache` model exists in `warlock/db/models.py` but is only used by the data lake module, not by the main API.

**Impact:** API response times scale linearly with database size. Dashboard pages that aggregate 373,852+ control results will become slow as the database grows.

**Recommendation:** Add Redis-based caching for expensive aggregation queries with a TTL tied to pipeline run completion (cache invalidated when new pipeline run finishes). Add HTTP caching headers for read-heavy endpoints. Consider materialized views for dashboard aggregations.

---

### ARCH-022: Data Lake Is Optional and Disconnected

**Severity:** Medium
**Domain:** Data / Architecture

The GRC data lake (`warlock/lake/`) is a substantial subsystem (DuckDB, Parquet, RAG, Iceberg support) but it operates as an optional, disconnected module. The main pipeline does not write to the lake automatically, and the API does not query the lake for any endpoint.

**Evidence:**
- `warlock/lake/` contains modules for DuckDB analytics, Parquet file management, RAG (retrieval-augmented generation), and Iceberg table format.
- No pipeline stage writes to the lake. The `LakeIngestionRun` model exists but is only populated by explicit CLI commands (`warlock lake ingest`).
- No API route queries the lake. The `LakeQueryCache` is unused by the main API.
- The lake has its own CLI group (`warlock lake`) but is not part of the standard `make demo` flow.

**Impact:** The data lake's analytical capabilities (DuckDB OLAP, Parquet columnar storage, RAG for natural language queries) are inaccessible from the main application flow. Users must manually trigger lake ingestion and query via CLI.

**Recommendation:** Add a pipeline post-hook that automatically ingests normalized findings into the lake after each pipeline run. Expose lake-powered analytics via API endpoints (e.g., `/api/v1/analytics/trend`, `/api/v1/analytics/query`). Wire the frontend dashboard to lake-backed aggregations for better performance.

---

### ARCH-023: Platform Modules Are In-Memory Only

**Severity:** Medium
**Domain:** Data / Architecture

The platform modules (`warlock/platform/`) implement multi-tenancy, white-labeling, delegation, and sandboxing with in-memory data structures. No state survives a process restart.

**Evidence:**
- `warlock/platform/tenancy.py` stores tenant configuration in a module-level dictionary.
- `warlock/platform/whitelabel.py` stores branding configuration in memory.
- `warlock/platform/delegation.py` tracks delegation records in a list (the `DelegationRecord` model exists but is not used by the platform module).
- `warlock/platform/sandbox.py` stores sandbox state in memory.
- These modules have corresponding database models (`DelegationRecord`, `SandboxEnvironment`) but the platform code does not use them.

**Impact:** All platform configuration is lost on restart. Multi-tenant isolation, white-label branding, and delegation rules must be reconfigured after every deployment. The database models exist but are orphaned.

**Recommendation:** Wire the platform modules to their existing database models. Use `get_session()` for writes and `get_read_session()` for reads. Load platform state from the database on startup and cache in memory with invalidation on write.

---

## 7. Observability Domain

### ARCH-024: No Structured Logging

**Severity:** High
**Domain:** Observability / Logging

The application uses Python's standard `logging` module with unstructured format strings. There is no JSON logging, no log correlation, and no log level configuration per module.

**Evidence:**
- `warlock/logging_config.py` configures a basic `StreamHandler` with a format string: `%(asctime)s - %(name)s - %(levelname)s - %(message)s`.
- A `correlation_id` ContextVar exists and is set per pipeline run, but it is not included in the log format string.
- No JSON formatter (e.g., `python-json-logger`, `structlog`).
- Log output is plain text, making it difficult to parse in log aggregation tools (ELK, Datadog, CloudWatch).

**Impact:** Logs cannot be efficiently searched, filtered, or correlated in production. The existing `correlation_id` infrastructure is wasted because it is not included in log output.

**Recommendation:** Add `structlog` or `python-json-logger` for structured JSON output. Include `correlation_id`, `tenant_id`, `user_id`, and `request_id` in every log entry. Make log level configurable per module via environment variables.

---

### ARCH-025: No Distributed Tracing

**Severity:** Medium
**Domain:** Observability / Tracing

There is no OpenTelemetry, Jaeger, Zipkin, or any distributed tracing instrumentation. Request flows through the pipeline (collect -> normalize -> map -> assess -> export) cannot be traced end-to-end.

**Evidence:**
- No `opentelemetry` dependency in `pyproject.toml`.
- No trace context propagation in API middleware.
- No span creation in pipeline stages.
- The `correlation_id` ContextVar provides a basic form of request correlation but is not compatible with OpenTelemetry trace context.

**Impact:** Cannot diagnose latency issues, identify bottleneck stages, or trace a finding from collection through to export. Performance optimization is guesswork.

**Recommendation:** Add OpenTelemetry SDK with auto-instrumentation for FastAPI, SQLAlchemy, and HTTP clients. Create manual spans for each pipeline stage. Export traces to Jaeger or an OTLP-compatible backend.

---

### ARCH-026: No Error Tracking

**Severity:** Medium
**Domain:** Observability / Error Management

There is no Sentry, Bugsnag, Rollbar, or any error tracking integration. Unhandled exceptions are logged to stderr and lost.

**Evidence:**
- No `sentry-sdk` or equivalent in `pyproject.toml`.
- FastAPI exception handlers in `warlock/api/app.py` return generic 500 responses without capturing the exception context.
- Pipeline connector failures are counted in `PipelineRunStats.connectors_failed` but the exception details are only in the log stream.

**Impact:** Production errors are invisible unless someone is actively tailing logs. No aggregation, deduplication, or alerting on error frequency.

**Recommendation:** Add Sentry SDK with FastAPI integration. Configure `before_send` to scrub PII from error reports. Set up alerts for new error types and error rate spikes.

---

### ARCH-027: No Metrics Collection

**Severity:** Medium
**Domain:** Observability / Metrics

There is no Prometheus, StatsD, CloudWatch, or any metrics collection. Key operational metrics (request latency, pipeline duration, finding count, queue depth) are not tracked.

**Evidence:**
- No `prometheus-client`, `statsd`, or metrics library in `pyproject.toml`.
- No `/metrics` endpoint.
- `PipelineRunStats` captures per-run metrics (duration, counts) but only logs them -- they are not exported to a time-series database.
- No request latency histograms, no error rate counters, no active connection gauges.

**Impact:** Cannot set up dashboards, alerts, or SLO tracking. Capacity planning is impossible without historical metrics.

**Recommendation:** Add `prometheus-client` with a `/metrics` endpoint. Instrument: request latency (histogram), request count (counter by status code), pipeline run duration (histogram), finding count (gauge), active database connections (gauge), queue depth (gauge per backend).

---

### ARCH-028: No Health Check Depth

**Severity:** Medium
**Domain:** Observability / Operations

The health endpoints (`/health`, `/healthz`, `/readyz`) return static 200 responses without checking any dependencies.

**Evidence:**
- `warlock/api/app.py` defines health endpoints that return `{"status": "ok"}` unconditionally.
- No database connectivity check.
- No OPA reachability check.
- No disk space check.
- No check for stale pipeline runs (last successful run age).

**Impact:** A load balancer or Kubernetes liveness probe will consider the instance healthy even when the database is down, OPA is unreachable, or the disk is full. Unhealthy instances continue receiving traffic.

**Recommendation:** Implement tiered health checks: `/healthz` (liveness -- process is running, always 200), `/readyz` (readiness -- database connected, OPA reachable, disk space above threshold). Add a `/health` endpoint with detailed component status for debugging.

---

### ARCH-029: No Alerting Framework

**Severity:** Medium
**Domain:** Observability / Alerting

The export module (`warlock/export/alerts.py`) defines an alert routing system, but it is not connected to any operational alerting. There are no alerts for pipeline failures, error rate spikes, or security events.

**Evidence:**
- `warlock/export/alerts.py` implements alert routing to Slack, Teams, PagerDuty, and email -- but only for compliance events (non-compliant findings, POA&M deadlines).
- No operational alerts: pipeline run failure, API error rate above threshold, database connection pool exhaustion, OPA unreachable.
- No alert configuration in environment variables or config file.
- The alert system is not triggered by any operational event -- only by compliance assessment outcomes.

**Impact:** Operational failures go unnoticed until a user reports them. Compliance alerts exist but operational alerts do not.

**Recommendation:** Extend the alert routing system to cover operational events. Add alert rules for: pipeline run failure (immediate), API 5xx rate > 1% (warning), database connection timeout (critical), OPA unreachable (critical), disk space < 10% (warning).

---

### ARCH-030: Audit Trail Not Externally Verifiable

**Severity:** Medium
**Domain:** Observability / Compliance

The SHA-256 hash chain in the audit trail provides tamper detection within the application, but there is no external verification mechanism. An attacker with database access can recompute the entire chain after modifying entries.

**Evidence:**
- `warlock/db/audit.py` computes each entry's hash as `SHA256(sequence_number + event_type + data + previous_hash)`.
- The timestamp is intentionally excluded from the hash for deterministic recomputation.
- There is no external anchor: no periodic hash publication to a blockchain, no timestamping authority (TSA), no signed checkpoint.
- The genesis hash is the string `"genesis"` -- an attacker who recomputes from genesis can produce a valid chain for any modified history.

**Impact:** The audit trail is tamper-evident only against accidental modification, not against a determined attacker with database access. For regulatory compliance (SOX, HIPAA), external verification may be required.

**Recommendation:** Implement periodic signed checkpoints: every N entries (or every hour), publish a signed hash to an external, append-only store (AWS QLDB, Azure Immutable Blob, a timestamping authority, or even a public blockchain). Store the checkpoint's external reference in the audit trail itself.

---

## 8. Additional Findings

### ARCH-031: Frontend-Backend API Surface Mismatch

**Severity:** High
**Domain:** Frontend / Integration

The CLI, API, and frontend have significantly different capability coverage. Many features available via CLI have no API endpoint, and many API endpoints have no frontend page. This creates a fragmented user experience where different interfaces expose different subsets of functionality.

**Evidence:**

| Capability | CLI | API | Frontend |
|---|---|---|---|
| Pipeline run | `warlock pipeline run` | `POST /api/v1/pipeline/run` | View only |
| Findings list | `warlock findings list` | `GET /api/v1/findings` | View only |
| Control results | `warlock controls list` | `GET /api/v1/controls` | View only |
| POA&M management | `warlock poam create/update` | `POST/PUT /api/v1/poam` | Buttons (dead) |
| Connector config | `warlock connectors list` | None | None |
| Lake queries | `warlock lake query` | None | None |
| Risk scenarios | `warlock risk scenarios` | `GET /api/v1/risk/scenarios` | View only |
| OSCAL export | `warlock export oscal` | None | None |
| Audit binder | `warlock export binder` | None | None |
| Framework crosswalk | `warlock frameworks crosswalk` | None | None |
| User management | `warlock admin users` | `POST /api/v1/auth/register` | None |
| GDPR requests | `warlock gdpr erase/export` | `POST /api/v1/gdpr/*` | None |
| Sandbox management | `warlock sandbox create` | None | None |
| Alert configuration | None | None | None |

**Impact:** Users must switch between CLI, API, and frontend to access the full feature set. The frontend covers approximately 30% of the available functionality.

**Recommendation:** Prioritize API coverage first (every CLI command should have an API equivalent), then build frontend pages for the most common workflows. Use OpenAPI schema generation to keep CLI, API, and frontend in sync.

---

### ARCH-032: No Horizontal Scaling Path

**Severity:** High
**Domain:** Deployment / Scale

Multiple architectural decisions prevent horizontal scaling beyond a single process:

**Evidence:**
1. **File-based pipeline lock:** `$TMPDIR/warlock_pipeline.lock` uses `fcntl.flock()`, which is local to a single machine. A second instance on another host will not see the lock.
2. **In-memory event bus:** `warlock/pipeline/events.py` stores subscribers in a process-local dictionary. Events published in one instance are invisible to other instances.
3. **In-memory platform state:** Tenancy, white-label, delegation, and sandbox state (ARCH-023) diverge between instances immediately.
4. **Single-process scheduler:** (ARCH-019) Each instance runs its own scheduler, leading to duplicate pipeline runs.
5. **Per-worker rate limiting:** (ARCH-010) Rate limit counters are per-process, giving attackers N times the limit with N workers.

**Impact:** The application cannot be deployed behind a load balancer with multiple instances without data consistency issues, duplicate work, and security degradation.

**Recommendation:** Replace file locks with distributed locks (Redis `SET NX` or PostgreSQL advisory locks across hosts). Move the event bus to Redis Pub/Sub or the existing queue backend. Persist platform state in the database (ARCH-023). Extract the scheduler to a singleton process (ARCH-019). Use Redis for rate limiting (ARCH-010).

---

### ARCH-033: Auth Lacks Production Hardening

**Severity:** Medium
**Domain:** Security / Authentication

While the authentication subsystem has strong primitives (bcrypt, PBKDF2-SHA256, HMAC-SHA256 API keys, TOTP MFA, refresh token rotation), several production hardening features are missing.

**Evidence:**
- **MFA enrollment incomplete:** TOTP MFA infrastructure exists but there is no enrollment UI or API endpoint to generate QR codes and verify initial TOTP setup.
- **No SAML/OIDC:** Enterprise SSO integration is absent. No SAML SP metadata, no OIDC client configuration.
- **No account recovery:** No "forgot password" flow, no email verification, no recovery codes for MFA.
- **No account lockout:** Failed login attempts are rate-limited (ARCH-010, per-worker) but there is no account-level lockout after N consecutive failures.
- **No session management UI:** Users cannot view active sessions, revoke tokens, or see login history.

**Impact:** The authentication system is functionally complete for demo purposes but lacks the features enterprise customers expect: SSO, account recovery, and MFA enrollment.

**Recommendation:** Add OIDC client support (most enterprise IdPs support OIDC). Add MFA enrollment API endpoints. Add account lockout after 5 consecutive failures with exponential backoff. Add a "forgot password" flow with email verification.

---

### ARCH-034: Test Coverage Broad But Shallow

**Severity:** Medium
**Domain:** Quality / Testing

The test suite (32 files) covers many subsystems but lacks depth in critical areas.

**Evidence:**
- No `TestClient` usage for FastAPI endpoint testing -- API routes are untested at the HTTP level.
- No frontend tests (no Jest, no React Testing Library, no Playwright/Cypress).
- No integration tests that exercise the full pipeline (collect -> normalize -> map -> assess -> export) end-to-end.
- No load/performance tests.
- No property-based testing (e.g., Hypothesis) for data transformation functions.
- The demo seed (`scripts/demo_seed.py`) serves as an implicit integration test but is not structured as a test (no assertions beyond count checks).
- OPA policies have 335 test files (good coverage), but the Python-OPA integration is not tested.

**Impact:** Regressions in API behavior, frontend rendering, and cross-component interactions are caught only by manual testing or the demo seed.

**Recommendation:** Add FastAPI `TestClient` tests for all API routes, covering auth, ABAC, pagination, and error responses. Add at least smoke-level frontend tests with Playwright. Structure the demo seed as a proper integration test with explicit assertions.

---

### ARCH-035: OPA Policy Coverage Uneven

**Severity:** Medium
**Domain:** Security / Policy

OPA/Rego policy coverage varies dramatically across frameworks:

**Evidence:**

| Framework | Controls | Rego Files | Coverage |
|---|---|---|---|
| NIST 800-53 | 1,176 | 286 | ~24% |
| ISO 27001 | 93 | 186 | 200%* |
| SOC 2 | 46 | 26 | ~57% |
| HIPAA | 64 | 40 | ~63% |
| CMMC L2 | 110 | 50 | ~45% |
| UCF | 115 | 24 | ~21% |
| PCI DSS v4.0 | 63 | 24 | ~38% |
| ISO 27701 | 95 | 0 | 0% |
| ISO 42001 | 39 | 0 | 0% |
| FedRAMP | 26 | 0 | 0% |
| GDPR | 15 | 0 | 0% |
| NIST CSF 2.0 | 101 | 0 | 0% |
| EU AI Act | 33 | 0 | 0% |
| SEC Cyber | 20 | 0 | 0% |

*ISO 27001 has multiple Rego files per control (implementation + audit variants).

- Frameworks without Rego policies rely entirely on assertion-based evaluation (Tier 1) and AI reasoning (Tier 2).
- The `opa_compliance_fail_mode = "open"` default means missing policies silently pass rather than flagging gaps.

**Impact:** Compliance posture reporting is inconsistent across frameworks. Some frameworks have automated policy checks; others rely on manual or AI-based assessment, which may not be deterministic.

**Recommendation:** Prioritize Rego policy development for FedRAMP (regulatory requirement), GDPR (legal requirement), and PCI DSS (common customer demand). Track per-framework coverage as a metric. Consider generating baseline Rego policies from framework YAML control definitions.

---

### ARCH-036: Application-Level Audit Sequence (Detail)

**Severity:** Medium
**Domain:** Database / Integrity

This supplements ARCH-007 with additional detail on the `with_for_update()` implementation.

**Evidence:**
- `warlock/db/audit.py` uses `session.query(AuditTrail).order_by(AuditTrail.sequence.desc()).with_for_update().first()` to get the latest sequence.
- The `with_for_update()` call acquires a row-level lock on PostgreSQL, serializing concurrent writers. On SQLite, this is silently ignored.
- The sequence is incremented in Python: `new_sequence = (latest.sequence if latest else 0) + 1`.
- If two concurrent requests read sequence 42, both will write sequence 43 with different `previous_hash` values, forking the hash chain.
- PostgreSQL's `FOR UPDATE` prevents this race; SQLite's WAL mode provides writer serialization at the database level (only one writer at a time), which incidentally prevents the race -- but only for single-process deployments.

**Impact:** The audit trail is safe in single-process SQLite deployments (WAL serialization) and PostgreSQL deployments (row-level locking). It is unsafe in multi-process SQLite deployments (multiple processes can write simultaneously despite WAL).

**Recommendation:** For production, use PostgreSQL (which handles this correctly). For development/testing with SQLite, document the single-process requirement. Consider a database-managed sequence for PostgreSQL to eliminate the application-level increment entirely.

---

### ARCH-037: Frontend-Backend Industry Standard Comparison

**Severity:** Low (Informational)
**Domain:** Architecture / Positioning

Warlock's architecture compared to industry GRC platform standards:

**Evidence:**

| Capability | Industry Standard | Warlock Status |
|---|---|---|
| Pipeline architecture | Event-driven, incremental | Batch-only, full re-scan |
| Database | PostgreSQL/distributed | SQLite default, PostgreSQL optional |
| Caching | Redis/Memcached | None |
| Containerization | Docker + K8s | None |
| Observability | OpenTelemetry + SIEM | Basic logging |
| Authentication | SSO/SAML/OIDC | Local auth only |
| Frontend | Full CRUD application | Read-only dashboard |
| API coverage | 100% feature parity | ~30% of CLI features |
| Multi-tenancy | Database-level isolation | In-memory only |
| Horizontal scaling | Stateless workers + message queue | Single-process |

**Impact:** Informational. Warlock exceeds industry standards in policy depth (670 Rego files, 14 frameworks, OSCAL export) but lags in operational maturity.

**Recommendation:** Use this table for roadmap prioritization. The policy engine and compliance depth are differentiators -- operational gaps should be closed to match the compliance engine's maturity.

---

## 9. What Works Well

The following aspects of Warlock's architecture are well-designed and represent genuine strengths:

### Pipeline Architecture
- **Clear input/output contracts:** Each pipeline stage (collect, normalize, map, assess, export) has well-defined data classes (`RawEventData`, `FindingData`, `ControlResultData`, `PipelineRunStats`) with explicit fields and types.
- **SHA-256 hash chain:** Every pipeline stage produces a hash chain, ensuring tamper detection across the entire data flow from collection to export.
- **Per-connector transaction isolation (H-30):** Each connector runs in its own database transaction. A failure in one connector does not roll back findings from other connectors.
- **Pipeline concurrency locking:** `fcntl.flock()` for SQLite deployments and `pg_advisory_lock()` for PostgreSQL deployments prevent concurrent pipeline runs from corrupting state.
- **Pipeline orchestrator:** Manages the full lifecycle with `PipelineRunStats` tracking connectors succeeded/failed, events collected, findings normalized, and controls mapped.

### Queue Backend Abstraction
- **1,008 lines of production-ready queue code** (`warlock/pipeline/queue.py`) supporting four backends:
  - **Redis Streams:** Connection pooling, consumer groups, message acknowledgment.
  - **Kafka:** Producer/consumer with configurable partitions and consumer groups.
  - **SQS:** Message visibility timeout handling, receipt handle tracking.
  - **NATS JetStream:** Durable subscriptions with acknowledgment.
- The abstraction allows swapping queue backends without changing pipeline code.

### Control Mapping
- **4-tier control mapping:** (1) Explicit rules binding findings to controls, (2) resource-type rules for broad coverage, (3) semantic fallback using text similarity, (4) crosswalk propagation across frameworks ("assess once, report many").
- **14 active frameworks** with crosswalk mappings enabling a single finding to map across multiple compliance frameworks simultaneously.

### Risk Quantification
- **FAIR Monte Carlo simulation:** Real implementation with Loss Event Frequency and Loss Magnitude as probability distributions, configurable iterations (default 10,000), producing VaR and CVaR outputs.
- Not a placeholder -- the simulation runs actual Monte Carlo iterations with statistical outputs.

### OSCAL Export
- **Deterministic UUID5 generation:** Same input data always produces the same OSCAL output, enabling diff-based comparison across assessment periods.
- **Full OSCAL 1.1.2 support:** System Security Plan (SSP), Assessment Results (AR), and Plan of Action & Milestones (POA&M) documents.
- **JSON and XML output formats.**
- **AI-generated narratives:** Optional AI-powered control narrative generation for OSCAL documents.
- **Control ID normalization:** `AC-2` becomes `ac-2`, `CC6.1` becomes `cc6-1` -- consistent across all frameworks.

### Authentication and Cryptography
- **bcrypt (12 rounds)** for password hashing with **PBKDF2-SHA256 (600,000 iterations)** fallback.
- **HMAC-SHA256 API keys** with proper key derivation.
- **TOTP-based MFA** infrastructure (enrollment UI pending -- see ARCH-033).
- **JWT with proper expiration** and refresh token rotation.
- **Field-level encryption** using `cryptography.fernet` for sensitive database fields.

### Security Headers
- Correctly configured and comprehensive:
  - `Strict-Transport-Security` (HSTS)
  - `X-Frame-Options: DENY`
  - `Content-Security-Policy` with restrictive defaults
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy` restricting camera, microphone, geolocation
  - `X-Content-Type-Options: nosniff`

### OPA Rego Policy Library
- **670 Rego policy files** with **335 test files** across 9 framework directories.
- This is likely the largest OPA policy library in any open-source GRC tool.
- Policies cover NIST 800-53, ISO 27001, SOC 2, HIPAA, CMMC L2, UCF, and PCI DSS v4.0.

### Terraform Modules
- **12 Terraform modules** across AWS (8), Azure (2), and GCP (2).
- Compliance-by-default configurations: encryption at rest, logging enabled, least-privilege IAM.
- Self-registration evidence callbacks that feed compliance data back to Warlock connectors.

### Export Suite
- **Audit binder:** ZIP archive with all evidence, findings, and control mappings for a specific assessment period.
- **SOC 2 report:** Structured report generation with control descriptions and test results.
- **ISO Statement of Applicability (SoA):** Automated SoA generation from control results.
- **Excel workbook:** Multi-sheet workbook with findings, controls, and framework mappings.
- **FedRAMP package:** FedRAMP-specific document package generation.
- **Alert routing:** Slack, Teams, PagerDuty, and email notifications for compliance events.
- **Audit sink:** Append-only audit event streaming for external SIEM integration.

### GDPR Implementation
- **Anonymization over deletion:** PII fields become `[REDACTED-xxxx]` HMAC tokens, preserving referential integrity and audit chain.
- **Subject access request export:** Generates a data package of all PII associated with a data subject.
- Correct approach -- never deletes records, only anonymizes.

### Session and Database Management
- **Context manager pattern:** `with get_session() as session:` for writes, `with get_read_session() as session:` for reads. Automatic commit/rollback.
- **SQLite PRAGMAs:** `foreign_keys=ON`, `journal_mode=WAL`, `busy_timeout=5000` on every connection.
- **UUID primary keys:** All models use `String(36)` UUID PKs, avoiding auto-increment collision issues in distributed deployments.
- **JSONType abstraction:** Maps to JSONB on PostgreSQL (GIN-indexable) and JSON on SQLite.

---

## 10. Summary Table

| ID | Finding | Severity | Domain | Category |
|---|---|---|---|---|
| ARCH-001 | No Dead Letter Queue | High | Pipeline | Resilience |
| ARCH-002 | No Circuit Breaker Pattern | Medium | Pipeline | Resilience |
| ARCH-003 | Batch-Only Pipeline Processing | Medium | Pipeline | Scale |
| ARCH-004 | Synchronous Event Bus | Medium | Pipeline | Scale |
| ARCH-005 | POA&M CHECK Constraint Mismatch | High | Database | Integrity |
| ARCH-006 | 9 Models Without Alembic Migrations | High | Database | Schema |
| ARCH-007 | Application-Level Sequence Generation | Medium | Database | Concurrency |
| ARCH-008 | No Table Partitioning Strategy | Medium | Database | Scale |
| ARCH-009 | No Query Timeout Configuration | Medium | Database | Resilience |
| ARCH-010 | Per-Worker Rate Limiting | High | Security | API Protection |
| ARCH-011 | OPA Policy Gate Bypassed by Default | High | Security | Authorization |
| ARCH-012 | Weak PII Pseudonymization | High | Security | Data Protection |
| ARCH-013 | GDPR Erasure Logs Plaintext PII | High | Security | GDPR |
| ARCH-014 | No CSRF Protection | Medium | Security | Web |
| ARCH-015 | No Login Page or Auth Flow | High | Frontend | Authentication |
| ARCH-016 | Read-Only Frontend | High | Frontend | Functionality |
| ARCH-017 | Dead UI Elements | Medium | Frontend | Quality |
| ARCH-018 | No Containerization | High | Deployment | Packaging |
| ARCH-019 | Single-Process Scheduler | High | Deployment | Scale |
| ARCH-020 | Frontend Not Integrated with Backend | High | Deployment | Integration |
| ARCH-021 | No Query Result Caching | Medium | Data | Performance |
| ARCH-022 | Data Lake Optional and Disconnected | Medium | Data | Architecture |
| ARCH-023 | Platform Modules In-Memory Only | Medium | Data | Architecture |
| ARCH-024 | No Structured Logging | High | Observability | Logging |
| ARCH-025 | No Distributed Tracing | Medium | Observability | Tracing |
| ARCH-026 | No Error Tracking | Medium | Observability | Errors |
| ARCH-027 | No Metrics Collection | Medium | Observability | Metrics |
| ARCH-028 | No Health Check Depth | Medium | Observability | Operations |
| ARCH-029 | No Alerting Framework | Medium | Observability | Alerting |
| ARCH-030 | Audit Trail Not Externally Verifiable | Medium | Observability | Compliance |
| ARCH-031 | Frontend-Backend API Surface Mismatch | High | Frontend | Integration |
| ARCH-032 | No Horizontal Scaling Path | High | Deployment | Scale |
| ARCH-033 | Auth Lacks Production Hardening | Medium | Security | Authentication |
| ARCH-034 | Test Coverage Broad But Shallow | Medium | Quality | Testing |
| ARCH-035 | OPA Policy Coverage Uneven | Medium | Security | Policy |
| ARCH-036 | Audit Sequence Detail (supplements ARCH-007) | Medium | Database | Integrity |
| ARCH-037 | Industry Standard Comparison | Low | Architecture | Positioning |

### Severity Distribution

| Severity | Count |
|---|---|
| High | 15 |
| Medium | 21 |
| Low | 1 |
| **Total** | **37** |

### Domain Distribution

| Domain | Count |
|---|---|
| Pipeline | 4 |
| Database | 5 |
| Security | 7 |
| Frontend | 4 |
| Deployment | 4 |
| Data | 3 |
| Observability | 7 |
| Quality | 2 |
| Architecture | 1 |
| **Total** | **37** |
