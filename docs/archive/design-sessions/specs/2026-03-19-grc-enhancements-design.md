# Warlock GRC Enhancement Spec — 19 Features, 6 Phases

**Date:** 2026-03-19
**Target repo:** `/Users/jsn/Coding/GitHub/warlock` (v1)
**Approach:** Value-Driven (Approach B) — each phase ships a complete vertical slice

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Migration strategy | Alembic from Phase 0 | Professional path; needed for production |
| ABAC model | Layered: Python RBAC + scope extensions, optional OPA | Respects optional OPA; extends existing `allowed_frameworks`/`allowed_sources` |
| Change event sources | Generic `ChangeEvent` model, cloud providers first | Same normalization philosophy as the pipeline |
| Auditor auth | Magic-link lightweight accounts with engagement scoping | Identity without password management; comment attribution |
| Framework versioning | YAML files with `version`/`supersedes` metadata | Frameworks stay as code; PR-diffable |

## Phase 0: Alembic Bootstrap

Initialize Alembic with current schema as baseline migration. All subsequent phases use Alembic for schema changes.

**Steps:**
1. `alembic init warlock/db/migrations`
2. Configure `env.py` to import `warlock.db.models.Base`
3. Generate initial migration from current `metadata.create_all()` state
4. Verify roundtrip: drop DB, run `alembic upgrade head`, confirm schema matches

## Phase 1: Compliance Health Dashboard

Items addressed: #1 (Continuous monitoring cadence), #3 (Evidence sufficiency), W3 (Posture time-series)

These three compose into "is my compliance posture healthy?" — the #1 question every CISO asks.

### 1a. Continuous Monitoring Cadence

**Schema changes:**
- Add `monitoring_frequency` to framework YAML controls. Values: `daily`, `weekly`, `monthly`, `quarterly`, `annual`. Default: `monthly`. **Note:** Framework YAML must be populated with per-control frequencies before Phase 1a is considered complete — NIST 800-53A Table D-2 defines frequency by control volatility (e.g., AC-2, AU-6, SI-4 require `daily`/`weekly`; PE-* physical controls are `annual`). The `monthly` default is a fallback only.
- Add `monitoring_frequency` column (`String(20)`) to `ControlMapping` table — populated from YAML during mapping stage.

**New module:** `warlock/assessors/cadence.py`
- `MonitoringCadence` dataclass: `framework, control_id, required_frequency, last_evidence_at, hours_since, is_stale, staleness_ratio` (1.0 = exactly at threshold, >1.0 = overdue)
- `CadenceChecker` class:
  - `check_control(session, framework, control_id) -> MonitoringCadence`
  - `check_framework(session, framework) -> list[MonitoringCadence]`
  - `check_all(session) -> dict[str, list[MonitoringCadence]]`
  - Frequency-to-hours mapping: daily=24, weekly=168, monthly=720, quarterly=2160, annual=8760
  - Emits `control.stale` event on the bus when `staleness_ratio > 1.0`

**Scheduler refactor (prerequisite):**
- Refactor `PipelineScheduler` from single-interval loop to multi-schedule dispatcher. The current implementation has `DEFAULT_SCHEDULES` with three entries but only runs `_execute_run()` on a single interval. Refactor to: track `last_run` per schedule name, iterate schedules on each loop tick, dispatch to `_execute_run()` / `_execute_snapshot()` / `_execute_cadence()` based on which schedules are due. This is required for Phase 1a, 1b, and 4a.

**Pipeline integration:**
- Wire cadence check into the refactored scheduler as `cadence_check` schedule (runs after every `pipeline_collect`)
- Add `cadence_check` to `DEFAULT_SCHEDULES` in `scheduler.py`

**CLI:** `warlock cadence [--framework F] [--stale-only]`
- Table output: control_id | frequency | last_evidence | hours_since | status (OK/STALE/CRITICAL)

**API:** `GET /api/v1/cadence?framework=X&stale_only=true`
- Returns list of `MonitoringCadence` objects

### 1b. Evidence Sufficiency (Wire Up Existing Code)

`EvidenceSufficiencyScorer` and `PostureAggregator.take_snapshot()` already exist and compute sufficiency. They are not called on schedule.

**Changes:**
- Wire `take_snapshot()` into the scheduler's `posture_snapshot` schedule (already defined at 1440min/daily in `DEFAULT_SCHEDULES` but `_execute_run` only runs the pipeline, not snapshots)
- Add a `_execute_snapshot()` method to `PipelineScheduler` called on the `posture_snapshot` schedule
- Enhance `EvidenceSufficiencyScorer.score_control()`: add `monitoring_frequency` awareness. A control with `daily` cadence and 48-hour-old evidence should score lower on freshness than one with `annual` cadence and 48-hour-old evidence. Adjust freshness thresholds relative to required frequency.

**CLI:** `warlock sufficiency [--framework F] [--below N]`
- Table output sorted by lowest sufficiency score
- `--below 60` shows only insufficient controls

**API:** `GET /api/v1/sufficiency?framework=X&below=60`

### 1c. Posture Time-Series

With snapshots running daily, `PostureSnapshot` accumulates history.

**New in `warlock/assessors/posture.py`:**
- `PostureTimeSeriesPoint` dataclass: `date, status, posture_score, sufficiency_score, evidence_freshness_hours`
- `PostureTimeSeries` dataclass: `framework, control_id, points: list[PostureTimeSeriesPoint], trend` (improving/stable/degrading — linear regression on posture_score)
- `PostureTimeSeriesQuery` class:
  - `query_control(session, framework, control_id, days=90) -> PostureTimeSeries`
  - `query_framework(session, framework, days=90) -> list[PostureTimeSeries]`
  - Trend calculation: simple linear regression slope on posture_score. Slope > 0.05/day = improving, < -0.05/day = degrading, else stable. (0.05/day ≈ 4.5 points over 90-day window — sensitive enough to detect meaningful change without noise.)

**CLI:** `warlock posture --history [--framework F] [--control C] [--days N]`
- Shows trend arrows (↑ ↓ →) and mini sparkline per control

**API:** `GET /api/v1/posture/history?framework=X&control_id=Y&days=90`

### ControlResult Status Enum (cross-cutting)

The `ControlResult.status` field gains new values across phases. Full enum after all phases:

| Status | Added In | Posture Scoring Behavior |
|---|---|---|
| `compliant` | Existing | Counts as compliant |
| `non_compliant` | Existing | Counts as non-compliant |
| `partial` | Existing | Counts as 50% compliant |
| `not_assessed` | Existing | Excluded from scoring |
| `not_applicable` | Existing | Excluded from scoring |
| `risk_accepted` | Phase 2c | Counts as partial (configurable) |
| `inherited_compliant` | Phase 3a | Counts as compliant |
| `inherited_at_risk` | Phase 3a | Counts as non-compliant |

`PostureAggregator.aggregate_control()` must be updated to handle all status values. Currently has a hard-coded switch (lines 164-173 in `posture.py`) that will silently drop unknown statuses. Update in Phase 2 when `risk_accepted` is introduced.

## Phase 2: Remediation Workflows

Items addressed: #5 (POA&M lifecycle), #4 (Compensating controls), #8 (Risk acceptance)

### 2a. POA&M as First-Class Entity

**New model `POAM`:**
```
id                  String(36) PK
finding_id          String(36) FK -> findings.id (nullable)
control_result_id   String(36) FK -> control_results.id (nullable)
framework           String(50) NOT NULL
control_id          String(50) NOT NULL
system_profile_id   String(36) FK -> system_profiles.id (nullable, wired in Phase 3)

weakness_description    Text NOT NULL
severity               String(20) NOT NULL
risk_level             String(20) default "moderate"

status                 String(20) NOT NULL default "draft"
  # draft -> open -> in_progress -> completed -> verified -> closed
  # draft -> open -> risk_accepted (via RiskAcceptance in 2c)

milestones             JSON  # [{description, due_date, completed_date, status}]
scheduled_completion   DateTime
actual_completion      DateTime
delay_count            Integer default 0
delay_justifications   JSON  # [{date, justification, approved_by}]
resources_required     Text

created_by             String(255)
updated_by             String(255)  # status transition attribution (complements AuditEntry)
approved_by            String(255)
approved_at            DateTime
vendor_dependency      String(255)

created_at             DateTime NOT NULL
updated_at             DateTime
```

**Indexes:** `(framework, control_id)`, `status`, `scheduled_completion`

**Auto-creation:** After Stage 4 assessment, if a `ControlResult` is `non_compliant`, check for existing open POA&M for that `(framework, control_id)`. If none exists, create one in `draft` status with weakness description from the finding title + assertion failures.

**Issue linkage:** Add `poam_id` column (`String(36)`, FK, nullable) to `Issue` table.

**Extension workflow:** `POST /api/v1/poams/{id}/extend` requires `{justification, new_completion_date}`. Increments `delay_count`, appends to `delay_justifications`, records in audit trail.

**OSCAL POA&M export** reads from the `POAM` table instead of synthesizing from Issues.

**CLI:** `warlock poams [--framework F] [--status S] [--overdue]`
**API:** Full CRUD on `/api/v1/poams`, plus `/api/v1/poams/{id}/extend`

### 2b. Compensating Controls

**New model `CompensatingControl`:**
```
id                      String(36) PK
original_framework      String(50) NOT NULL
original_control_id     String(50) NOT NULL
poam_id                 String(36) FK -> poams.id (nullable — compensating controls often created as part of POA&M remediation)
system_profile_id       String(36) FK -> system_profiles.id (nullable, wired in Phase 3)

title                   String(255) NOT NULL
description             Text NOT NULL
implementation_details  Text
evidence_references     JSON  # [{type, description, url, finding_id}]

status                  String(20) NOT NULL default "proposed"
  # proposed -> approved -> active -> expired | revoked

approved_by             String(255)
approved_at             DateTime
expiry_date             DateTime
review_frequency        String(20) default "quarterly"
last_reviewed           DateTime
effectiveness_score     Float  # 0-100

created_by              String(255)
created_at              DateTime NOT NULL
updated_at              DateTime
```

**Indexes:** `(original_framework, original_control_id)`, `status`

**Posture impact:** Assessor checks for active compensating controls before finalizing status. A `non_compliant` control with an `active` compensating control scores as `partial` with `assessor = "compensating_control:{id}"`.

**CLI:** `warlock compensating-controls [--framework F] [--status S]`
**API:** CRUD on `/api/v1/compensating-controls`

### 2c. Risk Acceptance Workflow

**New model `RiskAcceptance`:**
```
id                      String(36) PK
framework               String(50) NOT NULL
control_id              String(50) NOT NULL
poam_id                 String(36) FK -> poams.id (nullable)
system_profile_id       String(36) FK -> system_profiles.id (nullable, wired in Phase 3)

risk_description        Text NOT NULL
risk_level              String(20) NOT NULL  # critical, high, moderate, low
residual_risk_level     String(20)
conditions              JSON  # [{condition, met: bool}]

status                  String(20) NOT NULL default "requested"
  # requested -> reviewed -> approved -> active -> expired | revoked

requested_by            String(255) NOT NULL
reviewed_by             String(255)
reviewed_at             DateTime
approved_by             String(255)  # must be AO-level per SystemProfile
approved_at             DateTime
expiry_date             DateTime NOT NULL
auto_reeval_triggers    JSON  # {"severity_change": true, "new_finding": true}

created_at              DateTime NOT NULL
updated_at              DateTime
```

**Indexes:** `(framework, control_id)`, `status`, `expiry_date`

**Behavior:**
- When `active`, overrides control status to `risk_accepted` (new status value added to ControlResult)
- Expiry: scheduler checks for expired risk acceptances, reverts status to `non_compliant`, emits `risk_acceptance.expired` bus event
- Approval validation: `approved_by` must match `authorizing_official` or `ao_email` on the linked SystemProfile (enforced in API, not DB)

**CLI:** `warlock risk-acceptances [--framework F] [--status S] [--expiring-soon N-days]`
**API:** CRUD on `/api/v1/risk-acceptances`

## Phase 3: Enterprise Scale

Items addressed: #2 (Inheritance modeling), #10 (Multi-system scoping), W6 (Cross-system dependencies)

### 3a. Inheritance Modeling

**New model `ControlInheritance`:**
```
id                      String(36) PK
system_profile_id       String(36) FK -> system_profiles.id NOT NULL
framework               String(50) NOT NULL
control_id              String(50) NOT NULL

inheritance_type        String(20) NOT NULL
  # inherited, shared, common, system_specific
  # (per NIST SP 800-53A / FedRAMP CRM: "inherited" = fully provided,
  #  "shared" = split responsibility, "common" = org-wide controls,
  #  "system_specific" = system implements independently)

provider_system_id      String(36) FK -> system_profiles.id (nullable — who provides)
provider_description    Text  # "AWS provides physical security controls"
responsibility_description  Text  # "Consumer must configure IAM policies"

evidence_requirement    String(20) default "both"
  # provider_only, consumer_only, both

status                  String(20) default "active"
  # active, under_review, deprecated

created_at              DateTime NOT NULL
updated_at              DateTime
```

**Indexes:** `(system_profile_id, framework, control_id)` UNIQUE, `provider_system_id`

**Framework YAML:** Add optional `default_inheritance` per control (e.g., PE-* physical controls default to `inherited` for cloud deployments).

**Assessor behavior:** For controls with `inheritance_type = inherited` and `evidence_requirement = provider_only`:
- Look up provider system's posture for that control
- If provider is compliant → mark consumer as `inherited_compliant` (new status)
- If provider is non_compliant → mark consumer as `inherited_at_risk`

**CLI:** `warlock inheritance --system <id> [--framework F]`
**API:** CRUD on `/api/v1/systems/{id}/inheritance`

### 3b. Multi-System Scoping

**Schema changes (Alembic migration):**
- Add `system_profile_id` (String(36), FK, nullable) to: `Finding`, `ControlMapping`, `ControlResult`, `PostureSnapshot`
- Add index on `system_profile_id` to each table
- Note: `POAM.system_profile_id` was already defined (nullable) in Phase 2a. Phase 3b adds the index and begins populating it via pipeline scoping.

**Pipeline enhancement:**
- After normalization (Stage 2), orchestrator matches findings to system profiles:
  - Match by `account_id` against `SystemProfile.cloud_accounts[].account_id`
  - Match by `source` against `SystemProfile.connector_scope`
  - If no match → `system_profile_id = NULL` (unscoped)
- `system_profile_id` propagates through Stage 3 (mapping) and Stage 4 (assessment)

**Query changes:** All list endpoints gain `?system_id=` filter parameter.
**Posture:** Snapshots become per-system. Aggregation queries filter by `system_profile_id`.

### 3c. Cross-System Dependency Graph

**New model `SystemDependency`:**
```
id                      String(36) PK
consumer_system_id      String(36) FK -> system_profiles.id NOT NULL
provider_system_id      String(36) FK -> system_profiles.id NOT NULL

shared_controls         JSON  # ["nist_800_53:AC-2", "soc2:CC6.1"]
dependency_type         String(30) NOT NULL
  # infrastructure, identity, network, application

description             Text
created_at              DateTime NOT NULL
```

**Indexes:** `consumer_system_id`, `provider_system_id`

**Impact propagation:** When a provider system's control goes `non_compliant`:
1. Query `SystemDependency` for consumers sharing that control
2. Emit `dependency.impact` bus event per consumer
3. Consumer's posture snapshot flags affected controls as `inherited_at_risk`

**CLI:** `warlock dependencies [--system <id>]`
**API:** `GET /api/v1/systems/{id}/dependencies`, CRUD on `/api/v1/system-dependencies`

## Phase 4: Intelligence Layer

Items addressed: W1 (Drift detection), #9 (Change management), W2 (Audit simulation), W3 (Effectiveness scoring)

### 4a. Drift Detection + Change Events

**New model `ChangeEvent`:**
```
id                  String(36) PK
source              String(50) NOT NULL  # cloudtrail, github, servicenow, terraform
source_type         String(30) NOT NULL  # cloud_audit, ci_cd, itsm, iac
event_type          String(100) NOT NULL
actor               String(255)
action              String(255) NOT NULL
resource_id         Text
resource_type       String(100)
detail              JSON
occurred_at         DateTime NOT NULL
ingested_at         DateTime NOT NULL
sha256              String(64) NOT NULL
```

**Indexes:** `(source, source_type)`, `occurred_at`, `resource_id`, `sha256`

**Dedup & retention:** Skip insert if `sha256` already exists (CloudTrail alone can emit millions of events/day). Default retention: 90 days, configurable via `WLK_CHANGE_EVENT_RETENTION_DAYS`. Purged by scheduler on the `retention_purge` schedule.

**New model `ComplianceDrift`:**
```
id                          String(36) PK
framework                   String(50) NOT NULL
control_id                  String(50) NOT NULL
system_profile_id           String(36) FK (nullable)

previous_status             String(20) NOT NULL
new_status                  String(20) NOT NULL
drift_direction             String(20) NOT NULL  # improved, degraded
previous_posture_score      Float
new_posture_score           Float

correlated_change_event_ids JSON  # [change_event UUIDs]
root_cause_summary          Text  # AI-generated or manual
correlation_confidence      Float  # 0-1

detected_at                 DateTime NOT NULL
snapshot_id                 String(36)  # which snapshot detected it
```

**Indexes:** `(framework, control_id)`, `detected_at`, `drift_direction`

**Drift detector:** Runs after each `take_snapshot()` call. Compares current snapshot against previous snapshot for each control. If status changed, creates `ComplianceDrift` row.

**Temporal correlation:** For each drift event, queries `ChangeEvent` table for events where:
- `resource_type` matches any finding's `resource_type` for that control
- `occurred_at` is within ±2 hours of the finding's `observed_at`
- Ranked by temporal proximity

**Change event connectors:** Extend existing AWS connector to ingest CloudTrail management events. Extend GitHub connector to ingest push/PR events.

**Bus event:** `control.drift` with correlation data.

**CLI:** `warlock drift [--framework F] [--days N] [--direction degraded]`
**API:** `GET /api/v1/drift`, `GET /api/v1/change-events`

### 4b. Audit Simulation

**Not persisted — computed on demand.**

`AuditSimulator` class in `warlock/assessors/simulation.py`:
- Input: `framework, target_date, system_profile_id (optional), engagement_scope`
- Process:
  1. Query current posture per control
  2. For each control, check if evidence will be stale by `target_date` (using monitoring_frequency from cadence)
  3. Query open POA&Ms — which will be overdue by target_date?
  4. Query active risk acceptances — which expire before target_date?
  5. Use PostureTimeSeries trend to project posture scores at target_date
  6. For inherited controls, check provider system's projected posture at target_date
  7. Compute projected coverage: `controls_compliant / total_controls`
- Output: `AuditSimulationResult` dataclass with projected coverage, stale controls, overdue POA&Ms, expiring risk acceptances, at-risk controls

**CLI:** `warlock simulate-audit --framework soc2 --date 2026-09-01 [--system <id>]`
**API:** `POST /api/v1/audit-simulation` with `{framework, target_date, system_id}`

### 4c. Control Effectiveness Scoring

**Schema changes:** Add to `PostureSnapshot`:
- `uptime_pct` Float — % of time compliant over trailing window
- `mttr_hours` Float — mean time to remediate (avg hours from non_compliant→compliant)
- `drift_count` Integer — number of status changes in trailing window

**New dataclass:** `ControlEffectiveness`:
- `framework, control_id, uptime_pct, mttr_hours, drift_count, trend` (improving/stable/degrading)

**Computation:** During `take_snapshot()`, after creating the snapshot row:
1. Query PostureSnapshot history for trailing 365 days
2. Calculate `uptime_pct`: count of compliant snapshots / total snapshots × 100
3. Calculate `mttr_hours`: from ComplianceDrift pairs (degraded → improved), average the duration
4. Count drift events in the window

**CLI:** `warlock effectiveness [--framework F] [--days N]`
**API:** `GET /api/v1/effectiveness?framework=X&days=365`

## Phase 5: External & Advanced

Items addressed: #6 (SoD/ABAC), W7 (Auditor portal), #11 (Evidence packaging), W8 (Regulatory change), W5 (Compliance-as-code diffing), W4 (SSP narrative), #7 (Retention/legal hold)

### 5a. SoD / Layered ABAC

**Schema changes on `User`:**
- Add `allowed_control_families` JSON (default empty = all)
- Add `allowed_actions` JSON (default empty = use role defaults)

**New model `PolicyOverride`:**
```
id              String(36) PK
name            String(255) NOT NULL
description     Text
policy_rego     Text NOT NULL
is_active       Boolean default True
created_by      String(255)
created_at      DateTime NOT NULL
```

**Middleware enhancement:**
- `require_permission` decorator gains optional kwargs: `control_family=`, `system_id=`
- Python path: checks `user.allowed_control_families` (if set) and `user.allowed_frameworks` (existing)
- OPA path: if `WLK_OPA_URL` is configured, forwards `{user, action, resource, control_family, system_id}` to OPA after Python check passes. OPA can further restrict.
- `PolicyOverride` rows are loaded into OPA data on startup if OPA is enabled.

**API:** `GET /api/v1/auth/permissions` — returns effective permissions for current user

### 5b. Auditor Collaboration Portal

**New model `ExternalAuditor`:**
```
id                  String(36) PK
email               String(255) NOT NULL UNIQUE
name                String(255) NOT NULL
firm                String(255)
magic_link_hash     String(64)  # SHA256 of token
token_expires_at    DateTime
last_accessed       DateTime
is_active           Boolean default True

created_at          DateTime NOT NULL
```

**Junction table `AuditorEngagementAssignment`:**
```
auditor_id          String(36) FK -> external_auditors.id NOT NULL
engagement_id       String(36) FK -> audit_engagements.id NOT NULL
assigned_at         DateTime NOT NULL
```
Composite PK on `(auditor_id, engagement_id)`. Replaces JSON `engagement_ids` array for proper referential integrity and join-based queries.

**New model `EvidenceRequest`:**
```
id                  String(36) PK
engagement_id       String(36) FK -> audit_engagements.id NOT NULL
auditor_id          String(36) FK -> external_auditors.id NOT NULL
framework           String(50)
control_id          String(50)
description         Text NOT NULL

status              String(20) default "requested"
  # requested -> in_progress -> fulfilled -> closed

fulfilled_by        String(255)
fulfilled_at        DateTime
fulfillment_notes   Text
evidence_ids        JSON  # [finding_ids or raw_event_ids]

created_at          DateTime NOT NULL
updated_at          DateTime
```

**Magic link flow:**
1. System owner: `POST /api/v1/auditors/invite` with `{email, name, firm, engagement_id}`
2. System generates token, stores SHA256 hash, sends email (or returns token for manual sharing)
3. Auditor: `GET /api/v1/auditor/auth?token=X` → validates, returns scoped JWT
4. JWT claims: `{role: "external_auditor", auditor_id, engagement_ids, permissions: ["read", "comment", "request_evidence", "mark_examined"]}`

**Extend `ControlResult`:** Add `examined_at` (DateTime), `examined_by` (String) — set by auditor during engagement review.

**Extend `AuditComment`:** Add `external_auditor_id` (String(36), FK, nullable) as alternate author identity.

**API prefix:** `/api/v1/auditor/` for auditor-scoped endpoints:
- `GET /api/v1/auditor/engagements` — my engagements
- `GET /api/v1/auditor/engagements/{id}/controls` — controls with evidence
- `POST /api/v1/auditor/evidence-requests` — request additional evidence
- `POST /api/v1/auditor/comments` — leave comments
- `POST /api/v1/auditor/controls/{id}/examine` — mark as examined

### 5c. Evidence Packaging (Audit Binder)

**New module:** `warlock/export/binder.py`

`AuditBinderGenerator` class:
- Input: engagement_id
- Queries: all ControlResults in engagement period, grouped by control family
- Per control: evidence JSON, AI narrative summary, assessment results, related POA&Ms, compensating controls, risk acceptances
- Output: structured ZIP file:
  ```
  binder/
    index.html          # Table of contents with navigation
    summary.json        # Engagement metadata + coverage stats
    {control_family}/
      {control_id}/
        evidence.json   # Raw findings and results
        narrative.md    # AI-generated description
        poams.json      # Related POA&Ms
        compensating.json
  ```

**CLI:** `warlock export binder --engagement <id> -o binder.zip`
**API:** `POST /api/v1/engagements/{id}/binder` — returns download URL or streams ZIP

### 5d. Regulatory Change Impact Analysis

**Framework YAML changes:** Add top-level fields:
```yaml
framework_id: nist_800_53
version: "r5"
supersedes: null  # or "r4" for a newer version
effective_date: "2020-09-23"
```

**New module:** `warlock/frameworks/diff.py`

`FrameworkDiff` class:
- `diff(old_path, new_path) -> FrameworkDiffResult`
- `FrameworkDiffResult`: `added_controls, removed_controls, modified_controls, unchanged_controls`
- Modified = control exists in both but checks/event_types/resource_types changed

`FrameworkImpactAnalyzer`:
- For added controls: checks current evidence and mappings for coverage
- For modified controls: checks if existing evidence still satisfies new requirements
- For removed controls: flags any active POA&Ms/risk acceptances that reference them
- Output: `ImpactReport` with coverage gaps, suggested actions

**CLI:** `warlock framework-diff --old nist_800_53.yaml --new nist_800_53_r6.yaml`
**API:** `POST /api/v1/frameworks/diff` with `{old_version, new_version}`

### 5e. Compliance-as-Code Diffing

**New module:** `warlock/assessors/impact.py`

`ComplianceImpactAnalyzer`:
- Input: list of changed file paths (assertion modules, Rego policies, framework YAMLs)
- Process:
  1. Resolve changed assertions → which controls they bind to (via assertion registry)
  2. Resolve changed Rego policies → which controls they evaluate
  3. For each affected control, dry-run the assessor against current evidence
  4. Compare dry-run result against current stored ControlResult status
- Output: `{affected_controls: [...], predicted_flips: [{control, framework, from_status, to_status}]}`

Designed for CI integration — exit code 1 if any predicted flips to `non_compliant`.

**CLI:** `warlock impact-check --changed-files assertions.py,policies/encryption.rego`
**API:** `POST /api/v1/impact-check` with `{changed_files: [...]}`

### 5f. SSP Narrative Generation

**Enhance `warlock/assessors/ai_narrator.py`:**

Takes as input:
- `SystemProfile` (tech stack, boundary, categorization)
- `ControlPosture` per control family
- Evidence sources and freshness
- Active compensating controls
- Inheritance map

Structured prompt chain per control family:
1. System context prompt (from SystemProfile)
2. Control requirements prompt (from framework YAML)
3. Evidence summary prompt (from posture + findings)
4. Implementation description generation
5. Gap acknowledgment (from sufficiency gaps + POA&Ms)

Output: OSCAL SSP JSON with populated `control-implementations` sections.

**CLI:** `warlock generate-ssp --system <id> --framework nist_800_53 -o ssp.json`
**API:** `POST /api/v1/export/ssp` with `{system_id, framework}`

### 5g. Evidence Retention + Legal Hold Enforcement

**Pipeline purge enhancement:**
- Before any `DELETE` on `RawEvent` or `Finding`, query `LegalHold` for active holds where `start_date <= event.ingested_at` and (`end_date IS NULL` or `end_date >= event.ingested_at`)
- If hold exists: skip deletion, log `retention.hold_prevented` to audit trail
- If no hold: check `retention_policy_days` on the associated SystemProfile (via Finding.system_profile_id)
- Only delete if `event.ingested_at < now - retention_policy_days`

**Add to `SystemProfile`:** `retention_policy_days` Integer (default 2555 = 7 years)

**CLI:** `warlock retention purge --dry-run` — shows what would be deleted and what's held
**API:** `POST /api/v1/retention/purge?dry_run=true`

## Summary

| Phase | Items | New Models | Modified Models | New Endpoints | New CLI Commands |
|---|---|---|---|---|---|
| 0 | Alembic bootstrap | 0 | 0 | 0 | 0 |
| 1 | #1, #3, W3 | 0 | 1 (ControlMapping) | 3 | 3 |
| 2 | #5, #4, #8 | 3 (POAM, CompensatingControl, RiskAcceptance) | 1 (Issue) | 6 | 3 |
| 3 | #2, #10, W6 | 2 (ControlInheritance, SystemDependency) | 4 (Finding, ControlMapping, ControlResult, PostureSnapshot) + POAM index | 4 | 2 |
| 4 | W1, #9, W2, W3 | 2 (ChangeEvent, ComplianceDrift) | 1 (PostureSnapshot) | 4 | 3 |
| 5 | #6, W7, #11, W8, W5, W4, #7 | 4 (ExternalAuditor, AuditorEngagementAssignment, EvidenceRequest, PolicyOverride) | 3 (User, ControlResult, SystemProfile) | ~8 | 5+ |
| **Total** | **19** | **11** | — | **~25** | **~16** |
