# Data Model Reference

This document covers all 42 SQLAlchemy models in `warlock/db/models.py`, organized by domain. It describes the pipeline data flow, key relationships, JSON column contents, and how the OLTP schema relates to the GRC Data Lake.

## Overview

The schema is defined using SQLAlchemy's `DeclarativeBase`. All primary keys are UUID strings (36 chars). All timestamps are timezone-aware UTC. JSON columns use `JSONB` on PostgreSQL (GIN-indexable for containment queries) and plain `JSON` on SQLite.

```python
# JSON column type selection
JSONType = JSON().with_variant(JSONB(), "postgresql")
```

Two helper functions generate defaults across all models:

```python
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _uuid() -> str:
    return str(uuid4())
```

## Domain 1: Pipeline (5 tables)

These tables form the core evidence chain. Data flows through them in order during every pipeline run.

### ConnectorRun

Tracks each connector execution. One row per connector per pipeline run.

| Column | Type | Description |
|---|---|---|
| `id` | String(36) PK | UUID |
| `connector_name` | String(100) | e.g., "aws_iam_connector" |
| `source` | String(50) | e.g., "aws" |
| `source_type` | String(20) | SourceType enum value |
| `provider` | String(50) | Specific product name |
| `status` | String(20) | running, success, partial, error |
| `event_count` | Integer | Number of raw events collected |
| `error_count` | Integer | Number of errors encountered |
| `errors` | JSON | List of error message strings |
| `started_at` | DateTime(tz) | When collection started |
| `completed_at` | DateTime(tz) | When collection finished |
| `duration_seconds` | Float | Wall-clock duration |

**Relationships:** `raw_events` -> RawEvent (one-to-many)

### RawEvent

Verbatim data from sources. Never mutated after creation.

| Column | Type | Description |
|---|---|---|
| `id` | String(36) PK | UUID |
| `connector_run_id` | String(36) FK | -> connector_runs.id (CASCADE) |
| `source` | String(50) | "aws", "crowdstrike", "tenable" |
| `source_type` | String(20) | cloud, edr, scanner, siem, iam |
| `provider` | String(50) | Specific product |
| `event_type` | String(100) | "iam_credential_report", "ec2_security_groups" |
| `raw_data` | JSONB/JSON | Verbatim API response payload |
| `sha256` | String(64) | SHA-256 of raw_data |
| `ingested_at` | DateTime(tz) | When the event was stored |

**Indexes:** source+provider, ingested_at, sha256, connector_run_id

**Relationships:** `connector_run` -> ConnectorRun, `findings` -> Finding (one-to-many)

**Integrity:** The `sha256` column stores `hashlib.sha256(json.dumps(raw_data, sort_keys=True, default=str).encode()).hexdigest()`. The pipeline's `verify_integrity()` method recomputes this hash for all records and flags mismatches.

### Finding

Normalized observations. The universal unit of evidence.

| Column | Type | Description |
|---|---|---|
| `id` | String(36) PK | UUID |
| `raw_event_id` | String(36) FK | -> raw_events.id (CASCADE) |
| `observation_type` | String(50) | misconfiguration, vulnerability, alert, policy_violation, access_anomaly, inventory |
| `title` | Text | Human-readable finding title |
| `detail` | JSONB/JSON | Structured finding details (schema varies by source) |
| `resource_id` | Text | ARN, Azure resource ID, hostname |
| `resource_type` | String(100) | ec2_instance, iam_user, okta_user |
| `resource_name` | Text | Human-readable resource name |
| `account_id` | String(100) | Cloud account identifier |
| `region` | String(50) | Cloud region |
| `system_profile_id` | String(36) FK | -> system_profiles.id (SET NULL) |
| `source` | String(50) | Source provider |
| `source_type` | String(20) | SourceType value |
| `provider` | String(50) | Product name |
| `severity` | String(20) | critical, high, medium, low, info |
| `confidence` | Float | 0.0-1.0 |
| `observed_at` | DateTime(tz) | When the observation occurred |
| `ingested_at` | DateTime(tz) | When stored in Warlock |
| `pii_detected` | Boolean | True if PII was found and scrubbed during normalization |
| `sha256` | String(64) | Hash of (type + detail + resource_id + resource_type) |

**PII scrubbing:** All findings pass through `warlock.utils.pii.scrub_finding()` at the normalizer registry level. Emails, names, SSNs, and phone numbers are replaced with deterministic pseudonyms (`person:a1b2c3d4`). Raw payload dumps in the `detail` dict are stripped. The `pii_detected` flag records whether any PII was found — downstream consumers (lake, exports, reports) never see the original values.

**Indexes:** resource_type+resource_id, severity, observed_at, source+provider, observation_type, raw_event_id, system_profile_id

### ControlMapping

Maps findings to framework controls (many-to-many).

| Column | Type | Description |
|---|---|---|
| `id` | String(36) PK | UUID |
| `finding_id` | String(36) FK | -> findings.id (CASCADE) |
| `framework` | String(50) | nist_800_53, soc2, iso_27001 |
| `control_id` | String(50) | AC-2, CC6.1, A.9.2.1 |
| `control_family` | String(50) | AC, CC6, A.9 |
| `mapping_method` | String(30) | explicit, resource_rule, keyword, crosswalk |
| `confidence` | Float | 0.0-1.0 |
| `crosswalk_path` | JSON | For transitive: ["nist:AC-2", "soc2:CC6.1"] |
| `monitoring_frequency` | String(20) | daily, weekly, monthly, quarterly, annual |
| `created_at` | DateTime(tz) | When the mapping was created |

**Indexes:** finding_id, framework+control_id

### ControlResult

Compliance determination per finding per control. The terminal node of the pipeline.

| Column | Type | Description |
|---|---|---|
| `id` | String(36) PK | UUID |
| `finding_id` | String(36) FK | -> findings.id (CASCADE) |
| `control_mapping_id` | String(36) FK | -> control_mappings.id (CASCADE) |
| `framework` | String(50) | Framework identifier |
| `control_id` | String(50) | Control identifier |
| `system_profile_id` | String(36) FK | -> system_profiles.id (SET NULL) |
| `status` | String(20) | compliant, non_compliant, partial, not_assessed, not_applicable, risk_accepted, inherited_compliant, inherited_at_risk |
| `severity` | String(20) | Severity from finding |
| `assertion_name` | String(255) | Comma-separated assertion names |
| `assertion_passed` | Boolean | True if all assertions passed |
| `assertion_findings` | JSON | Specific failure reasons |
| `ai_assessment` | Text | LLM explanation |
| `ai_confidence` | Float | AI confidence score |
| `ai_model` | String(50) | Model used (e.g., "gemini") |
| `remediation_summary` | Text | Fix summary |
| `remediation_steps` | JSON | List of remediation steps |
| `console_path` | Text | Link to cloud console |
| `evidence_ids` | JSON | Raw event UUIDs |
| `assessed_at` | DateTime(tz) | When assessed |
| `assessor` | String(255) | "assertion:check_mfa" or "ai:gemini" or "inherited:AC-2" |
| `examined_at` | DateTime(tz) | Auditor examination timestamp |
| `examined_by` | String(255) | Auditor who examined |

**Indexes:** framework+control_id, status, assessed_at, finding_id, control_mapping_id, system_profile_id

## Pipeline Data Flow

```
ConnectorRun (1) ---> RawEvent (N)
                         |
                    Finding (N)
                         |
                  ControlMapping (N)
                         |
                  ControlResult (N)
```

A single pipeline run with 165 connectors produces approximately:
- 165 ConnectorRun rows
- 589 RawEvent rows
- ~5,475 Finding rows
- 373,852 ControlMapping rows
- 373,852 ControlResult rows

The foreign key chain preserves full lineage: every ControlResult traces back through ControlMapping -> Finding -> RawEvent -> ConnectorRun.

## Domain 2: Audit Trail (1 table)

### AuditEntry

Append-only audit log with hash chaining for tamper evidence.

| Column | Type | Description |
|---|---|---|
| `id` | String(36) PK | UUID |
| `sequence` | BigInteger | Monotonically increasing, unique |
| `previous_hash` | String(64) | Hash of the previous entry ("genesis" for first) |
| `entry_hash` | String(64) | SHA-256 of this entry's content |
| `action` | String(50) | evidence_collected, finding_created, control_assessed |
| `entity_type` | String(50) | raw_event, finding, control_result |
| `entity_id` | String(36) | UUID of the referenced entity |
| `actor` | String(100) | "pipeline", "api:user@example.com", "system" |
| `evidence_sha256` | String(64) | SHA-256 of the evidence payload |
| `extra` | JSON | Additional context metadata |
| `created_at` | DateTime(tz) | Entry creation time |

The hash chain works as follows: each entry's `entry_hash` is computed from `json.dumps({sequence, previous_hash, action, entity_type, entity_id, actor, evidence_sha256}, sort_keys=True)`. Verifying the chain recomputes every hash and checks that each entry's `previous_hash` matches the preceding entry's `entry_hash`.

## Domain 3: Posture & Effectiveness (1 table)

### PostureSnapshot

Point-in-time compliance posture per control per framework. Created periodically for trend analysis.

| Column | Type | Description |
|---|---|---|
| `id` | String(36) PK | UUID |
| `snapshot_date` | DateTime(tz) | Snapshot point in time |
| `framework` | String(50) | Framework identifier |
| `control_id` | String(50) | Control identifier |
| `status` | String(20) | Aggregated status |
| `posture_score` | Float | 0.0-100.0 |
| `total_findings` | Integer | Count of all findings |
| `compliant_findings` | Integer | Passing findings |
| `non_compliant_findings` | Integer | Failing findings |
| `evidence_sources` | JSON | ["aws", "okta", "crowdstrike"] |
| `evidence_freshness_hours` | Float | Hours since newest evidence |
| `sufficiency_score` | Float | 0.0-100.0 |
| `system_profile_id` | String(36) FK | Multi-system scoping |
| `uptime_pct` | Float | % of time compliant |
| `mttr_hours` | Float | Mean time to remediate |
| `drift_count` | Integer | Status changes in window |

## Domain 4: Identity & Access (2 tables)

### User

Platform user with RBAC and ABAC scoping.

| Column | Type | Description |
|---|---|---|
| `id` | String(36) PK | UUID |
| `email` | String(255) | Unique login email |
| `name` | String(255) | Display name |
| `hashed_password` | String(255) | bcrypt or PBKDF2 hash |
| `role` | String(20) | admin, auditor, owner, viewer |
| `allowed_frameworks` | JSON | ABAC: empty = all frameworks |
| `allowed_sources` | JSON | ABAC: empty = all sources |
| `allowed_control_families` | JSON | ABAC: empty = all families |
| `allowed_actions` | JSON | ABAC: override role defaults |
| `mfa_enabled` | Boolean | TOTP MFA active |
| `mfa_secret` | String(64) | Encrypted TOTP secret |
| `mfa_backup_codes` | JSON | PBKDF2-hashed backup codes |
| `refresh_token_hash` | String(64) | SHA-256 of current refresh token |
| `failed_login_count` | Integer | Lockout counter |
| `locked_until` | DateTime(tz) | Account lockout expiry |
| `token_valid_after` | DateTime(tz) | Tokens before this are revoked |

### APIKey

Programmatic access keys with scoped permissions.

| Column | Type | Description |
|---|---|---|
| `id` | String(36) PK | UUID |
| `user_id` | String(36) FK | -> users.id (CASCADE) |
| `key_hash` | String(64) | HMAC-SHA256 of raw key |
| `name` | String(100) | Key description |
| `scopes` | JSON | ["read", "write", "admin"] -- intersected with role |
| `is_active` | Boolean | Active/revoked |
| `expires_at` | DateTime(tz) | Optional expiry |

## Domain 5: Governance (6 tables)

### RiskAnalysis

FAIR Monte Carlo risk quantification results.

| Key Columns | Description |
|---|---|
| `scenario_name` | Risk scenario being modeled |
| `mean_ale` | Mean Annual Loss Expectancy |
| `var_95`, `var_99` | Value at Risk at 95th/99th percentile |
| `control_effectiveness` | 0.0-1.0 |
| `iterations` | Monte Carlo iterations (default 10,000) |
| `details` | JSON: full simulation parameters and results |

### AuditEngagement

Scoped audit periods for evidence packaging (e.g., "SOC 2 Type II 2025").

| Key Columns | Description |
|---|---|
| `framework` | Which framework this engagement covers |
| `period_start`, `period_end` | Audit window |
| `in_scope_controls` | JSON: list of control IDs (empty = all) |
| `excluded_controls` | JSON: explicitly excluded controls |
| `auditor_name`, `auditor_firm` | External auditor details |

### POAM (Plan of Action & Milestones)

Tracks remediation plans for non-compliant findings.

| Key Columns | Description |
|---|---|
| `finding_id`, `control_result_id` | Linked compliance data |
| `weakness_description` | What needs to be fixed |
| `status` | draft -> open -> in_progress -> completed -> verified -> closed |
| `milestones` | JSON: [{description, due_date, completed_date, status}] |
| `delay_count`, `delay_justifications` | Tracking schedule slippage |
| `vendor_dependency` | External dependency blocking remediation |

### CompensatingControl

Documents alternative controls when the primary control is non-compliant.

| Key Columns | Description |
|---|---|
| `original_framework`, `original_control_id` | The non-compliant control |
| `status` | proposed -> approved -> active -> expired / revoked |
| `evidence_references` | JSON: [{type, description, url, finding_id}] |
| `effectiveness_score` | 0-100 |
| `review_frequency` | quarterly, monthly, etc. |

### RiskAcceptance

Formal risk acceptance with AO-level approval and expiry.

| Key Columns | Description |
|---|---|
| `risk_level`, `residual_risk_level` | Before/after risk levels |
| `status` | requested -> reviewed -> approved -> active -> expired / revoked |
| `conditions` | JSON: [{condition, met: bool}] |
| `approved_by` | Must be Authorizing Official |
| `auto_reeval_triggers` | JSON: {"severity_change": true, "new_finding": true} |

### Issue

Tracks remediation of non-compliant findings.

| Key Columns | Description |
|---|---|
| `status` | open -> assigned -> in_progress -> remediated -> verified -> closed |
| `priority` | critical, high, medium, low |
| `risk_accepted` | Alternative path: risk acceptance instead of remediation |
| `remediation_evidence` | JSON: [{description, url, uploaded_at}] |

Supporting table: **IssueComment** for collaboration threads.

## Domain 6: Audit Collaboration (4 tables)

### Attestation

Sign-off workflow for control assessments with separation of duties.

| Key Columns | Description |
|---|---|
| `status` | draft -> submitted -> reviewed -> approved / rejected |
| `statement` | "Management asserts that..." |
| `evidence_references` | JSON: [{finding_id, description}] |
| `prepared_by`, `submitted_by`, `reviewed_by`, `approved_by` | All must be different |

### AuditComment

Auditor-practitioner collaboration on specific targets (controls, findings, attestations).

### ExternalAuditor

Lightweight auditor accounts with magic-link authentication.

### AuditorEngagementAssignment

Junction table: auditor <-> engagement (many-to-many).

### EvidenceRequest

Auditor requests for additional evidence during engagements.

## Domain 7: Intelligence (4 tables)

### Personnel

Unified personnel record cross-referencing HR (Workday) + IdP (Okta/Entra) + training (KnowBe4).

| Key Columns | Description |
|---|---|
| `hr_employee_id`, `idp_user_id` | Cross-references to source systems |
| `hr_status`, `idp_status`, `training_status` | Status from each source |
| `flags` | JSON: ["terminated_but_active_idp", "no_mfa", ...] |
| `risk_score` | 0-100 composite risk score |

### QuestionnaireTemplate

Reusable vendor questionnaire templates (SIG, DDQ, CAIQ, custom).

| Key Columns | Description |
|---|---|
| `questions` | JSON: [{id, category, text, response_type, required, mapped_controls}] |
| `template_type` | sig, sig_lite, ddq, caiq, custom |

### Questionnaire

A questionnaire instance sent to a specific vendor, with AI-suggested answers.

### DataSilo

Discovered data stores with sensitive data classification.

| Key Columns | Description |
|---|---|
| `silo_type` | s3_bucket, rds_database, sharepoint_site, snowflake_db, github_repo |
| `contains_pii`, `contains_phi`, `contains_pci`, `contains_credentials` | Classification flags |
| `scan_findings` | JSON: [{field_name, data_type, sample_masked, confidence}] |
| `encrypted_at_rest`, `encrypted_in_transit`, `access_logging_enabled` | Protection status |

## Domain 8: System Boundaries (4 tables)

### SystemProfile

Defines an authorization boundary for assessment scoping.

| Key Columns | Description |
|---|---|
| `confidentiality_impact`, `integrity_impact`, `availability_impact` | FIPS 199 categorization |
| `cloud_accounts` | JSON: [{provider, account_id, regions}] |
| `connector_scope` | JSON: which connectors feed this system |
| `frameworks` | JSON: applicable frameworks |
| `authorization_status` | not_authorized, in_process, authorized, denied, revoked |
| `retention_policy_days` | Default 2555 (7 years) |

### ControlInheritance

Maps control responsibility: inherited, shared, common, or system-specific (per NIST SP 800-53A / FedRAMP CRM).

### SystemDependency

Models cross-system control inheritance dependencies.

### ChangeEvent / ComplianceDrift

Change events from cloud audit logs, CI/CD, ITSM, IaC. Compliance drift records correlate status changes with change events.

## Domain 9: Trust Portal (2 tables)

### TrustAccessRequest

Tracks requests for compliance documentation.

### TrustDocument

NDA-gated compliance documents with three classification tiers: `public`, `nda`, `contract`.

## Domain 10: Policy & Embeddings (3 tables)

### PolicyOverride

Custom Rego policies for ABAC escalation via OPA.

### LegalHold

Prevents data purging during investigations or litigation. Checked by `expire_snapshots_safe()` before any data deletion.

### Embedding

Stored embedding vectors for semantic search (TF-IDF or external models). Vectors stored as JSON arrays for SQLite compatibility; production PostgreSQL can add a pgvector column.

## Domain 11: Domain Architecture (4 tables)

These tables support the domain service layer: operational policy management, asset inventory, and vendor tracking.

### Policy

Operational policies pushed and managed via `warlock policy set/list/show/history`. Supports rule-based enforcement across the platform.

| Column | Type | Description |
|---|---|---|
| `id` | String(36) PK | UUID |
| `policy_type` | String(100) | Policy category (e.g., access, retention, alerting) |
| `scope` | JSON | Scope constraints (frameworks, systems, resource types) |
| `rules` | JSON | Structured rule definitions evaluated by the policy engine |
| `priority` | Integer | Evaluation order; lower = higher priority |
| `enabled` | Boolean | Whether the policy is active |
| `created_by` | String(255) | Actor who created the policy |
| `effective_at` | DateTime(tz) | When the policy becomes active |
| `expires_at` | DateTime(tz) | Optional expiry (NULL = no expiry) |
| `created_at` | DateTime(tz) | Record creation time |

**Relationships:** `history` -> PolicyHistory (one-to-many)

### PolicyHistory

Append-only audit trail of every mutation to a Policy record.

| Column | Type | Description |
|---|---|---|
| `id` | String(36) PK | UUID |
| `policy_id` | String(36) FK | -> policies.id (CASCADE) |
| `action` | String(50) | created, updated, enabled, disabled, deleted |
| `old_rules` | JSON | Rules before the change (NULL for create) |
| `new_rules` | JSON | Rules after the change |
| `actor` | String(255) | Who made the change |
| `timestamp` | DateTime(tz) | When the change occurred |

### Asset

Tracks discovered resources across cloud accounts and systems. Populated from pipeline findings.

| Column | Type | Description |
|---|---|---|
| `id` | String(36) PK | UUID |
| `resource_id` | Text | Unique resource identifier (ARN, Azure ID, hostname) — unique constraint |
| `resource_type` | String(100) | ec2_instance, iam_user, s3_bucket, etc. |
| `resource_name` | Text | Human-readable name |
| `system_id` | String(36) FK | -> system_profiles.id (SET NULL) |
| `owner` | String(255) | Owning team or person |
| `classification` | String(50) | public, internal, confidential, restricted |
| `criticality` | String(20) | low, medium, high, critical |
| `status` | String(20) | active, inactive, decommissioned |
| `first_seen` | DateTime(tz) | When first observed in pipeline |
| `last_seen` | DateTime(tz) | Most recent pipeline observation |
| `metadata` | JSON | Additional resource-specific attributes |

### Vendor

Third-party vendor records for risk tracking and assessment scheduling.

| Column | Type | Description |
|---|---|---|
| `id` | String(36) PK | UUID |
| `name` | String(255) | Vendor name — unique constraint |
| `tier` | Integer | Risk tier (1 = highest risk) |
| `risk_score` | Float | 0.0-100.0 composite risk score |
| `contract_expires` | DateTime(tz) | Contract expiry date |
| `last_assessment` | DateTime(tz) | Date of most recent risk assessment |
| `assessment_cadence_days` | Integer | How often to reassess (e.g., 90, 180, 365) |
| `metadata` | JSON | Additional vendor attributes |

## JSON Column Reference

Several columns store schemaless JSON. Here is what goes in each:

| Table.Column | Content |
|---|---|
| `raw_events.raw_data` | Verbatim API response from source system |
| `findings.detail` | Structured finding details; schema varies by source/normalizer |
| `control_mappings.crosswalk_path` | ["nist_800_53:AC-2", "soc2:CC6.1"] |
| `control_results.assertion_findings` | ["MFA not enabled", "Password policy too weak"] |
| `control_results.remediation_steps` | ["Enable MFA in IAM console", "Set minimum length to 14"] |
| `control_results.evidence_ids` | ["uuid-1", "uuid-2"] |
| `connector_runs.errors` | ["Connection timeout", "Invalid credentials"] |
| `users.allowed_frameworks` | ["nist_800_53", "soc2"] (empty = all) |
| `users.mfa_backup_codes` | ["pbkdf2:salt:hash", ...] |
| `api_keys.scopes` | ["read", "write"] |
| `poams.milestones` | [{description, due_date, completed_date, status}] |
| `personnel.flags` | ["terminated_but_active_idp", "no_mfa"] |
| `system_profiles.cloud_accounts` | [{provider, account_id, regions}] |

## How the Lake Mirrors OLTP

The GRC Data Lake mirrors the OLTP pipeline tables plus 10 curated domain fact tables. The relationship:

| OLTP Table | Lake Zone | Partitioning |
|---|---|---|
| `raw_events` | raw/{source}/{date}/ | By source, then date |
| `findings` | enrichment/{source}/{date}/ | By source, then date |
| `control_mappings` | curated/control_mappings/{date}/ | By date |
| `control_results` | curated/control_results/{framework}/{date}/ | By framework, then date |
| `connector_runs` | curated/connector_runs/{date}/ | By date |
| `posture_snapshots` | curated/posture_snapshots/{framework}/{date}/ | By framework, then date |

Reconciliation (`warlock/lake/reconciliation.py`) compares row counts between OLTP and lake with a configurable drift threshold (default 0.1%). SHA-256 sample hashing verifies data integrity across both stores.

## Index Strategy

All foreign keys have dedicated indexes (tagged #20 in code comments). Composite indexes cover common query patterns:

- Finding lookups: `(resource_type, resource_id)`, `(source, provider)`, `(observation_type)`
- Control queries: `(framework, control_id)` on mappings, results, posture, drift
- Time-range scans: `observed_at`, `assessed_at`, `snapshot_date`, `created_at`
- Status filtering: `status` on results, POAMs, issues, engagements

## Migration Strategy

Schema is managed via `Base.metadata.create_all()` in `init_db()` (no Alembic versions directory). The demo seed validates the full schema by inserting 165 connectors, 589 raw events, ~5,475 findings, and 373,852 control results.
