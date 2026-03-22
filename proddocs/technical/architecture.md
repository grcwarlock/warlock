# System Architecture Overview

Warlock is a pipeline-first GRC (Governance, Risk, Compliance) platform. It treats compliance as a telemetry problem: evidence flows through four immutable stages with SHA-256 integrity hashing at every step. This document describes the system architecture for engineers joining the team.

## High-Level Architecture

```
                         82 Connectors
                              |
                    +---------v----------+
                    |  Stage 1: Collect  |  ConnectorRegistry.collect_all()
                    |  -> RawEventData   |  ThreadPoolExecutor (up to 32 workers)
                    +--------+-----------+
                             |
                    +--------v-----------+
                    |  Stage 2: Normalize|  NormalizerRegistry.normalize()
                    |  -> FindingData    |  1 raw event -> 0..N findings
                    +--------+-----------+
                             |
                    +--------v-----------+
                    |  Stage 3: Map      |  ControlMapper.map()
                    |  -> ControlMapping |  1 finding -> N controls x 14 frameworks
                    +--------+-----------+
                             |
                    +--------v-----------+
                    |  Stage 4: Assess   |  Assessor.assess()
                    |  -> ControlResult  |  Tier 1-4 evaluation
                    +--------+-----------+
                             |
         +-------------------+-------------------+
         |                   |                   |
    +----v----+        +-----v-----+       +-----v-----+
    |  OLTP   |        |   Lake    |       | Event Bus |
    | (Pg/SQ) |        | (Parquet) |       | (pub/sub) |
    +---------+        +-----------+       +-----------+
         |                                       |
    +----v----+                          +-------v--------+
    | REST API|                          | Webhooks/Slack |
    | 153 rts |                          | PagerDuty/Jira |
    +---------+                          +----------------+
```

## Pipeline Orchestrator

The pipeline lives in `warlock/pipeline/orchestrator.py`. The `Pipeline` class wires the four stages together. Key design decisions:

**All-or-nothing transactions.** All four stages run within a single database session. The caller's context manager commits on success or rolls back on any unhandled exception. A partial pipeline run (orphaned findings without assessments) is worse than no run at all.

**Concurrency control.** Only one pipeline run executes at a time. PostgreSQL uses `pg_try_advisory_lock(7301839201)`. SQLite uses `fcntl.flock` on a temp file. PgBouncer transaction-pool mode is supported via `pg_try_advisory_xact_lock`.

**Batched flushes.** The pipeline flushes to the database once per connector batch (not per record), then calls `session.expunge_all()` to release ORM identity-map memory. All needed IDs are captured as plain strings before expunge.

**Correlation ID.** Every pipeline run gets a UUID (`PipelineRunStats.run_id`) that propagates into every log record for the duration of the run.

### Pipeline Run Flow

```python
pipeline = Pipeline(connectors, normalizers, mapper, assessor, bus)
stats = pipeline.run(session)

# stats contains:
#   raw_events_collected: 191
#   findings_normalized:  547
#   controls_mapped:      29,207
#   results_assessed:     29,207
#   connectors_succeeded: 40
#   connectors_failed:    0
```

## Stage 1: Connectors (Data Collection)

**Source:** `warlock/connectors/base.py`

Connectors pull raw data from external systems. Each connector implements three methods:

| Method | Purpose |
|---|---|
| `validate()` | Return validation errors (empty list = valid) |
| `collect()` | Fetch data, return `ConnectorResult` with `RawEventData` list |
| `health_check()` | Can we reach the source? |

### Source Taxonomy

The `SourceType` enum defines 26 categories:

| Category | Examples |
|---|---|
| `cloud` | AWS, Azure, GCP, OCI, Alibaba |
| `edr` | CrowdStrike, Defender, SentinelOne |
| `iam` | Okta, Entra ID, CyberArk, SailPoint |
| `scanner` | Tenable, Qualys, Wiz |
| `siem` | Sentinel, Splunk, Elastic |
| `code` | Snyk, GitHub Advanced Security, Semgrep |
| `ci_cd` | Jenkins, GitHub Actions, GitLab CI |
| `ai_ml` | MLflow, SageMaker, Databricks |

### RawEventData

Every raw event is immutable once created:

```python
@dataclass
class RawEventData:
    source: str           # "aws", "crowdstrike", "tenable"
    source_type: SourceType
    provider: str
    event_type: str       # "iam_credential_report", "falcon_detections"
    raw_data: dict        # Verbatim API response
    observed_at: datetime
    id: str               # UUID
    sha256: str           # SHA-256 of raw_data (cached property)
```

The SHA-256 hash is computed deterministically from `json.dumps(raw_data, sort_keys=True, default=str)`. This hash is stored in the database and verified during integrity checks.

### ConnectorRegistry

The registry manages connector types and active instances. `collect_all()` runs all enabled connectors concurrently using `ThreadPoolExecutor` with up to 32 workers. Each connector failure is isolated: errors are recorded on the `ConnectorResult` and the pipeline continues with remaining connectors.

## Stage 2: Normalizers (Data Normalization)

**Source:** `warlock/normalizers/base.py`

Normalizers transform raw vendor-specific payloads into a universal `FindingData` format. There is one normalizer per (source, event_type) combination. A single raw event can produce zero, one, or many findings (e.g., an IAM credential report produces one finding per user).

### FindingData

```python
@dataclass
class FindingData:
    raw_event_id: str
    observation_type: str   # misconfiguration, vulnerability, alert,
                            # policy_violation, access_anomaly, inventory
    title: str
    detail: dict            # Structured finding details
    resource_id: str        # ARN, Azure resource ID, hostname
    resource_type: str      # ec2_instance, iam_user, okta_user
    severity: str           # critical, high, medium, low, info
    confidence: float       # 0.0-1.0
    sha256: str             # Hash of (type + detail + resource_id + resource_type)
```

### NormalizerRegistry

The registry uses a chain-of-responsibility pattern: each normalizer's `can_handle(raw_event)` method is checked in order. The first matching normalizer processes the event. If no normalizer matches, a warning is logged and zero findings are returned.

## Stage 3: Control Mapper

**Source:** `warlock/mappers/control_mapper.py`

The mapper determines which compliance controls a finding maps to across all 14 active frameworks (1,996 total controls). Mapping uses four prioritized strategies:

| Priority | Method | Confidence | Description |
|---|---|---|---|
| 1 | `explicit` | 1.0 | Direct mapping: source event_type -> control |
| 2 | `resource_rule` | 0.85 | Resource-type based: iam_user -> AC-2, CC6.1 |
| 3 | `semantic` | Varies | RAG-based fallback when rules produce nothing |
| 4 | `crosswalk` | min(parent, edge) | Expand to other frameworks via crosswalk graph |

Rules are loaded from 14 framework YAML files in `warlock/frameworks/`. Each YAML defines control families, checks, event_types, and resource_types. The crosswalk graph contains 1,843 edges mapping controls between frameworks.

### Performance Optimization

Mapping rules use O(1) dictionary lookups instead of linear scans. Explicit rules are indexed by `event_type`. Resource rules are indexed by `resource_type`. Wildcard rules (`event_type: *`) are stored separately and appended to every lookup.

### Deduplication

A `seen: set[tuple[str, str]]` tracks (framework, control_id) pairs to prevent duplicate mappings. Each finding maps to each control at most once, regardless of how many rules match.

## Stage 4: Assessment Engine

**Source:** `warlock/assessors/engine.py`

The assessor evaluates each mapped finding against its controls using a four-tier approach:

### Tier 1: Deterministic Assertions

101 registered assertion functions. Each takes `(finding_detail, raw_data)` and returns `(passed: bool, reasons: list[str])`. Multiple assertions can be bound to a single control; the control is compliant only if ALL assertions pass.

```python
# Assertion binding (list-based, never overwrites)
engine.bind_control("nist_800_53", "AC-2", "check_mfa_enabled")
engine.bind_control("nist_800_53", "AC-2", "check_password_policy")
```

### Tier 2: AI Reasoning

When no assertion is available, the optional `AIReasoner` evaluates the finding using an LLM (Gemini via `x-goog-api-key` header). Results below the confidence floor (default 0.7) are rejected and the control stays `not_assessed`. AI inline assessment can be disabled via `ai_inline_disabled` config; batch assessment then runs post-pipeline via `warlock lake assess`.

### Tier 3: OPA Compliance Evaluation

After the four-stage pipeline completes, an optional OPA stage evaluates Rego policies across all frameworks. The `OPAComplianceEvaluator` batches evaluations per-framework (reducing ~592 serial HTTP requests to ~7). Results are persisted as additional `ControlResult` records.

### Tier 4: Control Inheritance

Parent-child control inheritance: when AC-2 (parent) is assessed, AC-2(1), AC-2(2) (children) can inherit the parent's status if they have no assertion of their own. Inherited results have confidence reduced by 0.1 from the parent.

### ControlResultData

```python
@dataclass
class ControlResultData:
    status: str             # compliant, non_compliant, partial,
                            # not_assessed, not_applicable
    severity: str
    assertion_name: str     # "check_mfa_enabled,check_password_policy"
    assertion_passed: bool
    assertion_findings: list[str]  # Failure reasons
    ai_assessment: str      # LLM explanation (nullable)
    ai_confidence: float    # 0.0-1.0 (nullable)
    assessor: str           # "assertion:check_mfa", "ai:gemini", "inherited:AC-2"
    evidence_ids: list[str] # Raw event UUIDs that informed this result
```

## Event Bus

**Source:** `warlock/pipeline/bus.py`

The pipeline publishes events at every stage transition. The `EventBus` is a synchronous in-process pub/sub. Handlers run in the publisher's thread.

### Event Types

| Event | Published When |
|---|---|
| `raw_event.created` | After persisting a raw event |
| `finding.normalized` | After persisting a finding |
| `finding.mapped` | After mapping a finding to controls |
| `control.assessed` | After assessing a control |

### Subscribers

Subscribers auto-register when environment variables are set:

| Subscriber | Trigger Env Var | Events |
|---|---|---|
| `WebhookSubscriber` | `WLK_WEBHOOK_URLS` | finding.normalized, control.assessed |
| `SlackNotifier` | `WLK_SLACK_WEBHOOK_URL` | finding.normalized, control.assessed |
| `PagerDutyNotifier` | `WLK_PAGERDUTY_ROUTING_KEY` | control.assessed |
| `JiraNotifier` | `WLK_JIRA_BASE_URL` | control.assessed |
| `ServiceNowNotifier` | `WLK_SERVICENOW_INSTANCE` | control.assessed |
| `AuditEventSubscriber` | `WLK_AUDIT_SINK_BACKEND` | all events (wildcard) |
| `LakeWriter` | Programmatic | all events (wildcard) |

### Production Backends

The in-process bus is the default for development. Production deployments can swap to drop-in backends in `warlock/pipeline/queue.py`: `RedisStreamBus`, `KafkaBus`, `SQSBus`. The interface stays the same; the orchestrator does not change.

## Storage Layer

### OLTP Database (PostgreSQL / SQLite)

36 SQLAlchemy models across 8 domains. PostgreSQL for production; SQLite for development and testing. JSON columns use `JSONB` on PostgreSQL (GIN-indexable) and plain `JSON` on SQLite.

See [Data Model Reference](data-model.md) for complete schema documentation.

### GRC Data Lake (Parquet + DuckDB)

24 modules in `warlock/lake/`. Three zones: raw (immutable events), enrichment (normalized findings), curated (10 domain fact tables). DuckDB runs in-process for analytical queries. Parquet files are partitioned by source/date or framework/date.

See [Data Lake Architecture](data-lake.md) for complete lake documentation.

## Security Model

### Authentication

- **JWT bearer tokens** (HS256) for UI/browser sessions. 1-hour expiry. Refresh token rotation (30-day, SHA-256 hashed, single-use).
- **API keys** (`wlk_` prefix) for programmatic access. HMAC-SHA256 hashed with JWT secret. Scoped permissions intersect with role.
- **MFA/TOTP** (RFC 6238) with encrypted secret storage and PBKDF2-hashed backup codes.

### Authorization

- **RBAC**: 4 roles (admin, auditor, owner, viewer) with permission sets.
- **ABAC**: Per-user scoping on `allowed_frameworks`, `allowed_sources`, `allowed_control_families`.
- **OPA Policy Gate**: Fail-closed in production. Every API operation evaluated against Rego policies.

### Integrity

- **SHA-256 hashing** at every pipeline stage (raw events, findings, mappings, results).
- **Hash-chained audit trail**: Each audit entry includes the previous entry's hash, creating a tamper-evident chain.
- **Evidence integrity verification**: `Pipeline.verify_integrity()` recomputes SHA-256 for all stored raw events.

See [Security Architecture](security.md) for complete security documentation.

## Deployment Models

### Docker (Recommended for Production)

```bash
docker compose up demo
```

Starts PostgreSQL, Redis, OPA, runs migrations, seeds data, and launches the API server. All services in one command.

| Service | Port | Purpose |
|---|---|---|
| PostgreSQL | 5432 | OLTP database |
| Redis | 6379 | Cache, rate limiting, queue backend |
| OPA | 8181 | Policy enforcement |
| Warlock API | 8000 | FastAPI REST API |

### Local Development (SQLite)

```bash
./scripts/demo.sh
```

Creates a virtualenv, uses SQLite (file-based), no external services required. OPA policy evaluation is optional (fail-open by default in development).

### Infrastructure as Code

12 Terraform modules in `terraform/` covering AWS, Azure, and GCP deployments. Each module is validated and formatted in CI.

## Frameworks

14 compliance frameworks with 1,996 total controls:

| Framework | Controls | YAML | Rego Policies | OSCAL |
|---|---|---|---|---|
| NIST 800-53 Rev 5 | 1,176 | Yes | 286 files | Yes |
| ISO 27001:2022 | 93 | Yes | 186 files | Yes |
| ISO 27701:2019 | 95 | Yes | -- | Yes |
| ISO 42001:2023 | 39 | Yes | -- | Yes |
| SOC 2 (TSC) | 46 | Yes | 26 files | Yes |
| UCF (Unified) | 115 | Yes | 24 files | Yes |
| FedRAMP Moderate | 26 | Yes | -- | Yes |
| HIPAA Security Rule | 64 | Yes | 40 files | Yes |
| CMMC Level 2 | 110 | Yes | 50 files | Yes |
| GDPR | 15 | Yes | -- | Yes |
| PCI DSS v4.0 | 63 | Yes | 24 files | Yes |
| NIST CSF 2.0 | 101 | Yes | -- | -- |
| EU AI Act | 33 | Yes | -- | -- |
| SEC Cyber | 20 | Yes | -- | -- |

670 OPA/Rego policy files across 8 frameworks in `policies/`. 17 OSCAL catalog/profile JSON packages in `frameworks-oscal/`.

## CLI

40 Click commands across 8 domain modules in `warlock/cli/`:

| Domain | Key Commands |
|---|---|
| Pipeline | `collect`, `verify-integrity` |
| Compliance | `results`, `posture`, `posture-history`, `cadence`, `sufficiency`, `effectiveness` |
| Risk | `risk analyze`, `risk report` |
| Governance | `poam list`, `poam create`, `issue list` |
| Lake | `lake status`, `lake reconcile`, `lake query`, `lake assess`, `lake ask` |
| Export | `export oscal`, `export binder` |
| Admin | `users`, `api-keys`, `retention` |
| AI | `ai reason`, `ai converse` |

## REST API

153 routes across 9 domain routers in `warlock/api/`. All routes require authentication (JWT or API key) and are ABAC-scoped.

## Key Design Patterns

1. **Hash-chained audit trail.** SHA-256 at every pipeline stage. Each audit entry chains to the previous. Never break the chain.
2. **Fail-closed security.** OPA gate, assertions, and ABAC all default to deny.
3. **Multiple assertions per control.** List-based bindings. Append, never overwrite. AC-2 can have both MFA and password policy checks.
4. **Timezone-aware datetimes.** `ensure_aware()` from `warlock/utils/`. No naive datetimes anywhere.
5. **Prompt sanitization.** `<evidence>` tags + control character stripping in all LLM prompts. Secrets auto-redacted.
6. **Event-sourced lake materialization.** Pipeline writes to OLTP synchronously. `LakeWriter` subscribes to the event bus and batches writes to Parquet asynchronously.
