# Warlock GRC Data Lake — Architecture Design Spec

**Date:** 2026-03-21
**Status:** Approved
**Scope:** Full architectural redesign — data lake, AI layer repositioning, consumption tier
**Supersedes:** `2026-03-20-ai-native-layer-design.md` (AI positioning), `2026-03-20-ai-grc-integration-brief.md` (AI integration)

---

## 1. Problem Statement

Warlock has a mature ingestion pipeline (58 connectors, 59 normalizers, 14 frameworks, 32K+ control results per run) but all data lands in a transactional OLTP database designed for CRUD, not analysis. There is no analytical layer between data collection and reasoning. The AI layer is trapped inside pipeline Stage 4, seeing one finding at a time with zero historical context. There is no way to answer "what's our compliance trajectory over 6 months?" or "are these findings across Okta and CrowdStrike correlated?" without scanning the entire OLTP database.

### What This Design Changes

1. Introduces a data lake (Apache Iceberg + Parquet on cloud-agnostic object storage) as the analytical backbone
2. Repositions the AI reasoning layer from pipeline Stage 4 to a top-level consumer that queries the entire curated zone
3. Separates OLTP (transactional state) from OLAP (analytical queries) — each does what it's built for
4. Adds 5 new data domains (Evidence, Privacy, Incident, Pipeline Health, Supply Chain) that don't exist today
5. Establishes 5 consumption paths for GRC professionals

---

## 2. Architecture Overview

### Layer Stack

```
1. INGESTION           Pipeline writes raw telemetry to the lake
2. RAW ZONE            Immutable, append-only, partitioned by source + date
3. ENRICHMENT ZONE     Normalized findings, entity resolution, hash chain
4. CURATED ZONE        10 fact domains (see Section 4)
5. CONSUMERS           Compliance Engine | Analytics | AI+ML (parallel, independent)
6. SERVING LAYER       API, CLI, exports
7. CONSUMPTION TIER    GRC Tools | BI/Queries | AI Chat | Regulatory Filing | Trust Center
```

### Source of Truth

The lake is the source of truth for all historical and analytical data. The OLTP database (PostgreSQL/SQLite) becomes a serving store for:
- Active user sessions, auth tokens, API keys
- Current-state projections (latest result per control per framework)
- Active governance items (open POA&Ms, open issues, in-progress attestations)
- Configuration (system profiles, connector configs, framework settings)
- Hash-chained audit trail (requires transactional writes with `FOR UPDATE` serialization)

### Key Technology Decisions

| Component | Choice | Rationale |
|---|---|---|
| Table format | Apache Iceberg | ACID transactions, schema evolution, time-travel, partition pruning. DuckDB reads natively. |
| File format | Parquet | Columnar, compressed, cloud-agnostic, standard. |
| Object storage | Cloud-agnostic: S3-compatible API (covers AWS, GCS, Alibaba, DigitalOcean, MinIO, OVH, etc.), Azure Blob adapter, local filesystem for dev | Matches existing connector provider footprint |
| Query engine | DuckDB (default, embedded) | Zero-infrastructure, reads Iceberg natively, no JVM. Pluggable to ClickHouse/BigQuery for enterprise scale. |
| Iceberg catalog | REST catalog (cloud), SQLite catalog (dev) | Lightweight, no JVM dependency |
| Event bus | Pluggable: cloud-native managed services (SQS/Pub-Sub/Event Hubs) default, NATS JetStream for self-hosted, in-memory for dev | Existing queue.py already has Redis/Kafka/SQS backends |
| Data freshness | Minutes-fresh (1-3 min lag between pipeline completion and lake availability) | Sufficient for all GRC use cases |

---

## 3. Lake Zones

### Raw Zone

Verbatim connector output. Never mutated after write. Audit evidence.

- **Contents:** Raw events (full API responses), connector run metadata, change events, webhook payloads
- **Partitioning:** `source/event_type/date`
- **Retention:** Framework-specific (HIPAA 6yr, FedRAMP 3yr, SOC 2 1yr). Legal holds override.
- **Integrity:** SHA-256 hash per record, identical to OLTP. Serialization uses same `json.dumps(raw_data, sort_keys=True, default=str)` to preserve hash chain.

### Enrichment Zone

Normalized, resolved, and tagged.

- **Contents:** Normalized findings (FindingData from 59 normalizers), entity graph (resolved across connectors), data silo inventory, personnel records
- **Entity resolution:** Okta user `john@acme.com` + CrowdStrike endpoint `JOHN-LAPTOP` + AWS IAM `john.doe` → one entity
- **Schema:** `detail` column stored as nested struct in Iceberg (not string-serialized JSON). Known fields as columns, `extra MAP<STRING, STRING>` for connector-specific keys. Frequently-queried keys promoted via `evolve_schema()` (metadata-only operation).

### Curated Zone

The 10 fact domains (see Section 4). This is what consumers query.

---

## 4. Curated Zone — 10 Domains

### Domain 1: Compliance Facts

Two fact tables at different grains (matching pipeline Stage 3 vs Stage 4 separation):

**`fact_control_mapping`** — grain: `(finding_id, framework, control_id)`
- mapping_method (explicit, resource_rule, keyword, crosswalk)
- confidence, crosswalk_path, monitoring_frequency
- inheritance_disposition (own, inherited, shared, common)
- baseline_applicability (in_scope, out_of_scope for active profile)
- Partitioned by `framework`

**`fact_control_assessment`** — grain: `(finding_id, control_mapping_id, assessor, assessed_at)`
- status (compliant, non_compliant, partial, not_assessed, not_applicable, risk_accepted, inherited_compliant, inherited_at_risk)
- assessment_method (assertion, opa, ai_reasoning, manual)
- assessor_id, assertion_name, assertion_passed, assertion_findings
- ai_confidence, ai_model (for AI assessments)
- remediation_summary, remediation_steps, console_path
- evidence_ref[] (links to Evidence Facts)
- pipeline_run_id, system_profile_id
- Partitioned by `framework`, `assessed_at` (daily). Sort key: `control_id`, `status`

**`fact_config_baseline_scan`** — grain: `(system_id, benchmark_id, scan_date)`
- benchmark_id (CIS, STIG, custom), benchmark_version
- total_checks, pass_count, fail_count, not_applicable_count
- deviations[] (check_id, expected, actual, severity, justification)
- Required for FedRAMP (CM-6), CMMC (CM.L2-3.4.2), CIS Controls (IG1-IG3)
- Partitioned by `benchmark_id`, `scan_date` (daily)

**Crosswalk linkage:** `bridge_control_crosswalk` — `(source_framework, source_control, target_framework, target_control, confidence)` as first-class fact for UCF-native cross-framework correlation.

### Domain 2: Temporal Facts

Materialized tables, NOT derived from Iceberg time-travel (time-travel used for rollback/audit only).

**`fact_posture_snapshot`** — grain: `(framework, control_id, system_profile_id, snapshot_date)`
- posture_score (0-100, severity-weighted)
- status counts (compliant, non_compliant, partial, not_assessed)
- evidence_freshness_hours, sufficiency_score
- uptime_pct, mttr_hours, mttd_hours, drift_count
- Partitioned by `snapshot_date` (daily). Sort key: `framework`, `control_id`

**`fact_compliance_drift`** — grain: `(framework, control_id, system_profile_id, detected_at)`
- previous_status, new_status, drift_direction (improved/degraded)
- change_trigger (re_assessment, evidence_expiry, policy_update, framework_version_bump, manual_override)
- correlated_change_event_ids, root_cause_summary, correlation_confidence
- Partitioned by `detected_at` (monthly)

**`fact_regulatory_deadline`** — grain: `(regulation, deadline_type, deadline_at)`
- deadline_type (regulatory, contractual, internal_policy)
- days_remaining, status (upcoming, overdue, met)
- linked_control_ids, linked_framework
- Covers: FedRAMP ConMon monthly, GDPR 72-hour, PCI quarterly ASV, POA&M milestones

**Framework version tracking:** `framework_version` dimension on all temporal facts to detect assessment invalidation on framework updates.

### Domain 3: Risk Facts

**`fact_risk_simulation`** — grain: `(framework, scenario_name, created_at)`
- mean_ale, var_95, var_99, control_effectiveness, iterations
- scenario_description, threat_context (MITRE ATT&CK mapping)
- treatment_type (mitigate, accept, transfer, avoid)
- Partitioned by `created_at` (monthly)

**`fact_vulnerability_lifecycle`** — grain: `(vuln_id, affected_entity_id, discovered_at)`
- cvss_score, epss_score, cisa_kev_member
- status (discovered, triaged, remediated, verified, closed)
- remediated_at, sla_target_days, sla_met
- linked_control_ids
- Partitioned by `discovered_at` (monthly)

**`fact_control_effectiveness`** — grain: `(control_id, framework, measurement_window)`
- effectiveness_rate (pass_count / total_assessments)
- trend (improving, degrading, stable)

**`dim_compensating_control`** — SCD Type 2: `(original_framework, original_control_id, id, valid_from, valid_to, is_current)`

**`dim_risk_acceptance`** — SCD Type 2: `(framework, control_id, id, valid_from, valid_to, is_current)`

### Domain 4: Entity Facts

All SCD Type 2 with `valid_from` / `valid_to` / `is_current`. Partitioned by `entity_type`.

**Dimension tables:**
- `dim_resource` — cloud accounts, hosts, endpoints, cloud resources
- `dim_system` — profiles, impact levels, authorization status, RTO/RPO, BIA criticality
- `dim_personnel` — HR status, IdP status, MFA, training, clearance, risk score
- `dim_vendor` — risk tier, questionnaire status, SLA compliance
- `dim_data_silo` — classification, PII/PHI/PCI flags, encryption status
- `dim_software_component` — SBOM: component_id, name, version, sbom_format, license, end_of_life

**Relationship tables:**
- `bridge_entity_relationship` — source_entity, target_entity, relationship_type, effective_date. Graph model for blast radius analysis.
- `fact_data_flow` — source_entity, destination_entity, data_classification, transfer_mechanism, legal_basis (GDPR), cross_border_flag
- `fact_boundary_membership` — entity_id, boundary_id, inclusion_type (in_boundary, connected, leveraged). For FedRAMP/CMMC authorization boundaries.
- `fact_training_completion` — personnel_id, program_id, completed_at, score, certification_expiry

### Domain 5: Governance Facts

**Mastering:** Governance artifacts (POA&Ms, issues, attestations, risk acceptances) are **mastered in OLTP** because they require read-modify-write transactions with lifecycle state machines. The lake receives replicated copies via the event bus for analytics and audit queries. OLTP is authoritative for current state; the lake is authoritative for historical state and cross-domain correlation.

Separate fact tables per artifact type (different cardinalities and query patterns):

- `fact_poam` — partitioned by `(framework, status)`
- `fact_issue` — partitioned by `(status, priority)`
- `fact_attestation` — partitioned by `(engagement_id)`
- `dim_audit_engagement` — small, single-file dimension
- `fact_policy_document` — policy_id, version, approved_by, approved_at, next_review_date, linked_control_ids
- `fact_exception` — policy exceptions/waivers, distinct from risk acceptances
- `fact_legal_hold` — hold_id, trigger_event, custodians, affected_data_scope, hold_start, hold_release
- `fact_audit_entry` — append-only, partitioned by `created_at` (daily), sort key: `sequence`. **OLTP is the authoritative hash chain.** The lake receives a read-replica for analytics queries. The lake writer MUST sort by `sequence` before writing Parquet batches (not by event bus arrival order, which may be out-of-order on SQS/Pub-Sub). `verify_chain()` runs only against OLTP. Lake gets `verify_chain_snapshot()` that validates batch integrity post-write. Add `tsa_token_ref` (RFC 3161 timestamp response reference) and `actor_auth_proof` (hash of authenticating JWT/session) for non-repudiation (FedRAMP High, CMMC AU-10).
- `fact_regulatory_change` — regulation, change_type, effective_date, impact_assessment, affected_controls

### Domain 6: Evidence Facts

The connective tissue. Many-to-many evidence-to-control relationships.

- `fact_evidence_artifact` — id, source_connector, collected_at, expires_at, artifact_type (config_snapshot, log_extract, screenshot, API_response, document), storage_ref, hash, pipeline_run_id
- `bridge_evidence_control` — evidence_id, control_id, framework, sufficiency_score
- `fact_evidence_freshness` — last_collected, collection_frequency, staleness_days, auto_refresh_enabled
- `fact_evidence_quality` — completeness, specificity, currency scores per evidence-control pair
- `fact_control_test` — test procedure, tester, sample_size, methodology, per-sample pass/fail, exceptions (SOC 2 Type II workpapers)

### Domain 7: Privacy Facts

Privacy has its own regulatory logic. Not a subset of compliance.

- `fact_processing_activity` — GDPR Article 30: purpose, legal_basis, data_categories, recipients, transfer_destinations, retention_period, safeguards
- `fact_dsar` — request_id, type (access/deletion/portability/rectification/objection), received_at, deadline_at, completed_at, status, linked_entity_ids
- `fact_consent` — subject_id, purpose, consent_given_at, withdrawn_at, mechanism, version
- `fact_cross_border_transfer` — source_jurisdiction, destination_jurisdiction, transfer_mechanism (SCCs, adequacy, BCRs), legal_basis, tia_completed
- `fact_dpia` — processing_activity_ref, risk_level, mitigations, dpo_sign_off, supervisory_authority_consultation_required
- `fact_breach_register` — discovered_at, reported_at, affected_subjects_count, data_categories_affected, notification_status, root_cause

### Domain 8: Incident Facts

Incidents span multiple domains. Own lifecycle, classification, notifications.

- `fact_security_event` — event_id, source_connector, event_type, severity, detected_at, raw_event_ref
- `fact_incident` — incident_id, classification (C/I/A), severity, status (detected→triaged→contained→eradicated→recovered→closed), commander, timeline
- `bridge_incident_control` — which controls failed or were bypassed
- `bridge_incident_entity` — which systems, personnel, vendors, data stores affected
- `fact_notification` — regulatory_body, notification_required, deadline_at, sent_at, content_ref
- `fact_tabletop_exercise` — exercise_id, scenario, participants, findings, action_items

### Domain 9: Pipeline Health Facts

Meta-compliance. Confidence calibration.

- `fact_pipeline_run` — run_id, raw_events_collected, findings_normalized, controls_mapped, results_assessed, duration_seconds, hash_chain_valid
- `fact_connector_run` — run_id, connector_name, status, event_count, error_count, duration_seconds
- `fact_data_freshness` — connector_id, last_successful_run, hours_since_last_success, expected_frequency, freshness_status (current, stale, critical)
- `fact_coverage_metric` — total_connectors_configured, healthy, degraded, failed, pct_controls_with_active_evidence

### Domain 10: Supply Chain Facts

Required by EU Cyber Resilience Act (2026-2027), EO 14028, DORA Chapter V.

- `fact_sbom_component` — component_id, name, version, sbom_format (CycloneDX/SPDX), parent_system, license, known_cves, slsa_level
- `fact_supplier_assessment` — supplier_id, assessed_at, rating_source (SecurityScorecard/BitSight), score, soc2_expiry, pentest_freshness, questionnaire_completion
- `fact_concentration_risk` — supplier_id, dependent_systems, shared_infrastructure, single_point_of_failure_flag
- `fact_provenance_attestation` — artifact_id, slsa_level, signer, signature_verified, build_reproducible

---

## 5. Consumer Layer

Three parallel consumers, all reading from the curated zone, all independent:

### Compliance Engine (deterministic, always-on)

- 101 assertions + 670 OPA policies
- Reads: Compliance Facts, Entity Facts, Evidence Facts
- Writes: assessment results back to Compliance Facts
- No AI in this path. Reproducible, auditable, deterministic.

### Analytics Layer (computed, scheduled)

- Posture trends, drift detection, anomaly detection, coverage heatmaps, MTTD/MTTR
- Reads: all 10 domains (cross-domain correlation)
- Writes: materialized aggregation tables
  - `agg_framework_posture` — grain: `(framework, system_profile_id, date)`
  - `agg_control_family_posture` — grain: `(framework, control_family, system_profile_id, date)`
- Runs after each pipeline completion (minutes-fresh) or on-demand

### AI + ML Layer (optional, conversation-driven)

- Queries entire curated zone via MCP-exposed tools
- RAG over compliance, risk, evidence, entity, incident facts
- Predictive risk, narrative generation, natural language compliance queries
- Does NOT run inline during pipeline execution
- When disabled, compliance engine and analytics layer still work completely

**Key change from current architecture:** AI moves from `Assessor.assess()` (one finding at a time, Stage 4) to a top-level consumer (queries everything, after pipeline completes).

---

## 6. Serving Layer

### OLTP Database (PostgreSQL / SQLite)

Retains permanently:
- Auth: users, sessions, API keys, MFA
- Governance workflows: POA&Ms, issues, risk acceptances, compensating controls, attestations, engagements
- Configuration: system profiles, connector configs, framework settings
- Hash-chained audit trail (requires transactional `FOR UPDATE` serialization)
- Current-state projections: latest result per control per framework (materialized view for governance workflows)

Does NOT retain:
- Historical control results (lake owns)
- Historical posture snapshots (lake owns)
- Historical raw events / findings (lake owns)
- Risk simulation results (lake owns)

### API and CLI

- REST API (9+ routers) — aggregation queries read from lake, entity lookups read from OLTP
- CLI (expanding from 43 to 70+ commands) — new command groups for lake, evidence, incidents, privacy, pipeline health, supply chain, analytics, AI chat
- OSCAL + FedRAMP export — direct curated zone queries via Iceberg

---

## 7. Consumption Tier — 5 Paths

| # | Path | What It Does | Data Source |
|---|------|-------------|-------------|
| 1 | **GRC Tools** | Outbound export to Vanta, Drata, AuditBoard, ServiceNow GRC | Pre-joined views from curated zone |
| 2 | **BI / Direct Queries** | Looker, Metabase, Python/SQL against lake, Trust Portal, executive views | DuckDB/JDBC against curated zone + aggregation tables |
| 3 | **AI Chat** | MCP-exposed curated zone → Claude/LLM, conversational compliance queries | All 10 curated zone domains via MCP tools |
| 4 | **Regulatory Filing** | Template-driven doc generation: GDPR DPA notification, SEC 8-K, DORA/NIS2 CSIRT reports, state breach notifications | Incident Facts + Privacy Facts + Governance Facts |
| 5 | **Trust Center + Questionnaire Automation** | Customer-facing portal: self-service artifacts, posture badges, AI-powered questionnaire auto-fill (SIG, CAIQ, DDQ) | Evidence Facts + Compliance Facts + AI layer |

---

## 8. Migration Strategy — 4 Phases

### Phase 0: Foundation (2-3 weeks)

- Storage abstraction interface (Python protocol/ABC for object storage)
- DuckDB feasibility spike (5 hardest compliance queries against sample Parquet)
- Iceberg catalog setup (REST for cloud, SQLite for dev)
- Local-dev lake story (no Docker, no JVM — SQLite catalog + local filesystem + DuckDB in-process)
- Event bus durable backend as default for non-dev (NATS JetStream is new work — not yet implemented in queue.py)
- Repository pattern completion — migrate raw `session.query()` calls in API routers to repository layer. The compliance router alone has 44+ calls; the full codebase has 460+. Phase 0 focuses on the 5 API routers that will migrate reads in Phase 2 (compliance, risk, pipeline, export, admin). Auth and governance routers keep direct ORM access since they stay on OLTP permanently.
- Generate Iceberg schemas from SQLAlchemy metadata programmatically (CI-validated)

### Phase 1: Lake Alongside OLTP (3-4 weeks)

- **Event-sourced materialization** (NOT synchronous dual-write): pipeline writes to OLTP as today, event bus subscriber asynchronously writes Parquet/Iceberg to lake. If lake write fails, event stays in queue for retry. OLTP never blocked. Eventually consistent.
- Raw, enrichment, and curated zone implementation
- 5 new lake-only domains (Evidence, Privacy, Incident, Pipeline Health, Supply Chain)
- Sub-domains added to existing domains (regulatory change mgmt, control testing, BIA, training)
- Backfill CLI command for existing OLTP historical data
- Reconciliation job (nightly row count + SHA-256 hash comparison)
- Batch Parquet writes per pipeline run (not per record)

### Phase 2: Consumer Migration (4-6 weeks)

- Migrate per-query-pattern (NOT per-router): all aggregation queries → lake, all entity lookups stay OLTP
- Analytics layer built with materialized aggregation tables
- Shadow queries for validation (per-query feature flags, log discrepancies)
- CLI expanded for all new domains
- Lake maintenance jobs (compaction, snapshot expiry, orphan cleanup)
- Freeze automated OLTP retention purging during migration, **except** for legally-mandated deletions (GDPR Article 17 erasure requests, CCPA deletion requests, court-ordered destruction). DPO retains manual override for compliance-required purges.
- Completion signal: zero aggregation queries hit OLTP + zero shadow query discrepancies for 2+ weeks

### Phase 3: Steady State (4-6 weeks)

- AI layer repositioned: removed from pipeline Stage 4, rebuilt as curated zone consumer
- MCP interface for AI chat over curated zone
- RAG rebuilt to index curated zone (not just control definitions)
- `warlock ask` CLI command for conversational compliance queries
- OLTP thinned: stop writing historical data, maintain current-state projections only
- All 5 consumption tier paths operational
- Full lake-native exports (OSCAL, FedRAMP SSP, SOA)

### Rollback Strategy

- **Phase 0:** No rollback needed (additive infrastructure)
- **Phase 1:** Unregister lake writer subscriber from event bus (one-line change). OLTP unaffected.
- **Phase 2:** Per-query feature flags in repository layer. Roll back individual queries to OLTP without affecting others. `settings.lake_reads_enabled("coverage_summary")` pattern.
- **Phase 3:** Do not drop OLTP columns/tables. Stop writing but keep schema. Re-enable writes if rollback needed. Only drop after 90 days of zero OLTP reads for those entities.

### Anti-Patterns to Avoid

1. No synchronous dual-write — use event-sourced materialization via bus
2. No generic "QueryEngine" abstraction — build two explicit query paths (SQLAlchemy + DuckDB)
3. No Parquet file-per-record — batch per pipeline run
4. Preserve SHA-256 hash integrity — same serialization across both stores
5. Build reconciliation in Phase 1, not Phase 3
6. Freeze automated OLTP retention purging during Phase 2 (except DSAR/legal-mandated deletions)
7. Audit trail hash chain stays OLTP-only through all phases
8. Before Phase 3 OLTP thinning, verify no active legal holds exist on affected data scope
9. Document the backfill date as the lake's historical data boundary — data purged before backfill is not recoverable

---

## 9. Connector Inventory

### Current: 58 connectors

Across 10 categories: Cloud (12), Identity (6), Endpoint (6), SIEM (6), Vuln/Code (8), Network (5), GRC (3), Collaboration (4), Infrastructure (5), HR (2), AI/ML (1).

### Gaps: 42+ identified, prioritized in 3 tiers

**Tier 1 (SOC 2 evidence essentials):** GitHub Actions/GHAS, AWS Backup, Terraform Cloud, Google Workspace, PagerDuty, Jira/Linear, AWS Secrets Manager/Doppler

**Tier 2 (second audit cycle):** Salesforce, Stripe, Kandji, JumpCloud, Auth0, GitLab, Slack, Semgrep, Trivy, GitGuardian, Veracode, Grafana/Loki, Docker/Aqua

**Tier 3 (enterprise/differentiating):** BitSight, ServiceNow GRC, Ping Identity, Cisco Umbrella, Kong/Istio, Mimecast, Exchange Online, Rippling, ADP, Gusto, SageMaker, Databricks, W&B, Vertex AI, HuggingFace, and 15+ others

### Missing connector categories identified

- CI/CD Pipeline Security (GitHub Actions, GitLab CI, CircleCI)
- Finance/Billing (Stripe, Brex, Ramp)
- CRM (Salesforce, HubSpot)
- Secrets Management beyond Vault (AWS Secrets Manager, Doppler, Infisical)
- API Gateway / Service Mesh (Kong, Istio)
- Backup/DR beyond Veeam (AWS Backup, Druva, Commvault)
- DNS/Domain Security (Route 53, registrar APIs)

---

## 10. Framework Gaps

### Current: 14 frameworks

NIST 800-53, ISO 27001, ISO 27701, ISO 42001, SOC 2, UCF, FedRAMP, HIPAA, CMMC L2, GDPR, PCI DSS, NIST CSF 2.0, EU AI Act, SEC Cyber

### Gaps: 8 identified

**HIGH:** CIS Controls v8, DORA, NIS2, CCPA/CPRA
**MEDIUM:** CSA CCM v4/STAR, ISO 22301, US State Privacy meta-framework, UK Cyber Essentials
**CONDITIONAL:** TISAX, SWIFT CSCF

---

## 11. Security Considerations for the Lake

- **Row-level security:** ABAC enforcement at the query engine level (not just API). Framework/source scoping must apply to direct lake queries.
- **Column-level masking:** PII fields (personnel email, vendor contacts) masked for roles that don't need PII.
- **Data classification propagation:** Tables inherit classification from source connector type, finding content, and framework association.
- **Cross-tenant isolation:** Separate Iceberg namespaces per system profile or tenant. Encryption key isolation.
- **Evidence immutability:** Object Lock (S3 Compliance mode, GCS Retention) on evidence artifacts.
- **Lake admin access controls:** Separate from application ABAC. Compaction/VACUUM must check legal holds before physical deletion.
- **Trusted timestamping:** RFC 3161 TSA for audit trail entries (strengthens legal defensibility).
- **Data sovereignty / residency:** Tenants subject to data residency requirements (GDPR, LGPD, APPI, PDPA) must have lake storage in a compliant region. The storage abstraction (Phase 0) must support per-tenant or per-classification bucket routing. Privacy Facts and Entity Facts containing PII must never be stored in a region that violates the data subject's jurisdiction requirements.

---

## 12. Dev Experience

### Local Stack (no Docker, no JVM)

- **Storage:** Local filesystem `file:///tmp/warlock-lake/`
- **Catalog:** SQLite-backed Iceberg catalog at `warlock-lake.db`
- **Query engine:** DuckDB in-process via `duckdb.connect()`
- **Event bus:** In-memory (default for dev). Lake writer subscribes synchronously.
- **Dependencies:** PyIceberg + DuckDB, both pip-installable, pure Python with C extensions

### Developer Workflow

```bash
# Existing (unchanged)
rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/python scripts/demo_seed.py

# With lake enabled
WLK_LAKE_ENABLED=true .venv/bin/python scripts/demo_seed.py
# → produces both warlock.db AND lake/ directory with Parquet files
# → QA gate validates both outputs have matching counts
```

### QA Gate Extension

When `WLK_LAKE_ENABLED=true`:
- Lake tables exist and readable by DuckDB
- Row counts match OLTP after demo seed
- At least one shadow query returns identical results
- SHA-256 hash samples match across stores

---

## 13. Success Criteria

| Metric | Target |
|---|---|
| Dashboard query latency | < 200ms from lake (currently 300s TTL cache because query is too slow) |
| Pipeline write impact | Zero — lake writes are async via event bus |
| Demo seed parity | Lake produces identical counts to OLTP |
| Drift detection | Derived from curated zone in < 5s (currently requires full OLTP scan) |
| AI reasoning context | Full curated zone (10 domains) vs current single-finding |
| Time-to-audit-answer | "Show me AC-2 posture over 6 months" answerable in one query |
| Local dev setup | Works on macOS without Docker or cloud credentials |
| Connector additions | New connectors require zero lake schema changes |
| Data freshness P99 | < 3 minutes from pipeline completion to lake queryability |

---

## 14. Error Handling and Failure Modes

### Event Bus Lake Writer Failures

- **Retry policy:** 3 retries with exponential backoff (1s, 5s, 25s). Configurable via `QueueConfig.max_retries`.
- **Dead-letter queue:** After max retries exhausted, event moves to DLQ. DLQ is a separate Iceberg table (`lake_dlq`) partitioned by date. Operators investigate and replay.
- **Poison message handling:** If a single event consistently fails (malformed payload, schema mismatch), it is logged with full context and moved to DLQ. Pipeline continues processing remaining events.
- **Maximum acceptable lag:** Alert if lake lag exceeds 5 minutes (P99 target is 3 min). Critical alert at 15 minutes. Measured as `max(event.published_at) - max(lake.ingested_at)`.
- **Consistency SLA:** Eventually consistent. OLTP is authoritative during Phase 1-2. Lake may lag by up to one retry cycle. Reconciliation job catches divergence nightly.

### Reconciliation Failures

- If reconciliation detects row count mismatch > 0.1%, alert and pause lake reads for the affected domain.
- If SHA-256 hash mismatch detected, flag specific records and trigger targeted re-ingestion from OLTP.
- Reconciliation runs nightly. Cannot be disabled during Phases 1-2.

---

## 15. Data Governance

### Domain Ownership

| Domain | Owner | Schema Change Approval |
|---|---|---|
| Compliance Facts | Compliance Engineering | Spec review required |
| Temporal Facts | Platform Engineering | Spec review required |
| Risk Facts | Risk Engineering | Spec review required |
| Entity Facts | Platform Engineering | Spec review required |
| Governance Facts | GRC Operations | Spec review required |
| Evidence Facts | Compliance Engineering | Spec review required |
| Privacy Facts | Privacy Engineering | Spec review + DPO sign-off |
| Incident Facts | Security Operations | Spec review required |
| Pipeline Health Facts | Platform Engineering | Standard PR review |
| Supply Chain Facts | Risk Engineering | Spec review required |

### Schema Evolution Governance

- **Additive changes** (new columns, new tables): standard PR review by domain owner
- **Breaking changes** (column removal, type narrowing): spec review + migration plan + backward-compat period
- **Iceberg schema evolution** used for all changes — no Parquet file rewrites for additive changes
- CI validates Iceberg schemas match SQLAlchemy metadata on every push

### Data Quality Monitoring

- **Completeness:** row count per domain per pipeline run, compared to expected (from PipelineRunStats)
- **Freshness:** `fact_data_freshness` in Pipeline Health Facts tracks per-connector staleness
- **Consistency:** nightly reconciliation job (OLTP vs lake)
- **Accuracy:** SHA-256 hash sampling across stores
- **Lineage:** every fact row carries `pipeline_run_id` linking back to the specific pipeline execution

---

## 16. Monitoring and Observability

### Metrics Emitted

| Metric | Source | Alert Threshold |
|---|---|---|
| `lake.write_latency_ms` | Lake writer subscriber | P99 > 5000ms |
| `lake.queue_depth` | Event bus queue | > 1000 events |
| `lake.lag_seconds` | Published vs ingested timestamp diff | > 300s (warn), > 900s (critical) |
| `lake.reconciliation_drift_pct` | Nightly reconciliation job | > 0.1% |
| `lake.parquet_file_count` | Per Iceberg table | > 500 small files (triggers compaction) |
| `lake.query_latency_ms` | DuckDB query execution | P99 > 500ms |
| `lake.shadow_query_mismatch` | Shadow query comparator | Any mismatch |
| `lake.dlq_depth` | Dead-letter queue | > 0 |

### Operational Runbooks

- **Lake lag alert:** Check event bus queue depth → check lake writer logs → check object storage connectivity → check Iceberg catalog availability
- **Reconciliation drift:** Identify affected domain → check DLQ for failed events → trigger targeted re-ingestion → verify hash integrity
- **Shadow query mismatch:** Compare query plans (SQLAlchemy vs DuckDB) → check for type coercion differences → check for ordering differences → file bug with reproduction

---

## 17. Testing Strategy

### Unit Tests

- Lake writer subscriber receives every pipeline event (mock bus, assert call count matches PipelineRunStats)
- Lake write failure does NOT roll back OLTP transaction (inject failure, verify OLTP commit succeeds)
- Retry logic delivers failed events after transient failures
- Parquet serialization preserves SHA-256 hash integrity (same json.dumps serialization)

### Integration Tests

- Parametric test per API query: seed OLTP + lake with demo data, execute against both, assert row-count and value equality
- Run as part of existing pytest suite (295+ baseline)
- CI runs with `WLK_LAKE_ENABLED=true` on a separate test matrix

### Warlock-Specific Invariants

- Hash chain integrity in lake (run `verify_chain()` against lake audit_entries via DuckDB)
- SHA-256 evidence integrity across both stores
- ABAC scope filtering produces identical results from lake and OLTP
- Posture snapshot computed from lake matches OLTP for same point in time

### QA Gate Extension

When `WLK_LAKE_ENABLED=true`, `scripts/qa.sh` additionally validates:
- Lake tables exist and are readable by DuckDB
- Row counts match OLTP after demo seed
- At least one shadow query returns identical results
- SHA-256 hash samples match across stores
- DLQ is empty after demo seed
