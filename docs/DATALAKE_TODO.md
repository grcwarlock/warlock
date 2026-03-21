# Warlock GRC Data Lake — Initiative TODO

Last updated 2026-03-21. Tracks all work items for the data lake architecture initiative.
This is the priority initiative — no other feature work until the lake foundation is in place.

---

## Phase 0 — Foundation (1-2 weeks)

### Infrastructure

- [ ] **DL-1. Storage abstraction interface** — Python protocol/ABC for object storage (S3-compatible, Azure Blob, local filesystem). The pipeline currently hardcodes `session.add()`. This creates the seam for lake writes without modifying the orchestrator.
- [ ] **DL-2. DuckDB feasibility spike** — Implement the 5 hardest compliance queries (dashboard aggregation, posture history, coverage computation, cadence staleness, temporal evidence packaging) in DuckDB against sample Parquet files. Measure latency at 10x demo scale. If any exceed 500ms, design materialized view strategy.
- [ ] **DL-3. Iceberg catalog setup** — REST catalog for cloud, SQLite catalog for dev. Local-dev story: SQLite catalog + local filesystem + DuckDB in-process. No Docker, no JVM.
- [ ] **DL-4. Local-dev lake story** — Extend demo seed to produce both `warlock.db` and a `lake/` directory with Parquet files when `WLK_LAKE_ENABLED=true`. QA gate validates both outputs.
- [ ] **DL-5. Event bus durable backend** — Make Redis Streams or NATS JetStream the default for non-dev environments. The event bus is the CDC mechanism for lake writes. Currently in-memory only.

### Codebase Preparation

- [ ] **DL-6. Repository pattern completion** — Migrate all 44+ raw `session.query()` calls in the compliance router to use the repository layer. This creates the seam where Phase 2 can swap SQLAlchemy for DuckDB without changing router code. Repeat for governance, risk, admin, and export routers.
- [ ] **DL-7. Generate Iceberg schemas from SQLAlchemy metadata** — Build a utility that reads `Base.metadata` and emits equivalent Iceberg table schemas. Run as part of CI to prevent schema divergence.

---

## Phase 1 — Lake Alongside OLTP (3-4 weeks)

### Lake Writer

- [ ] **DL-8. Lake writer event bus subscriber** — New subscriber that consumes pipeline events (`raw_event.created`, `finding.normalized`, `finding.mapped`, `control.assessed`) and writes Parquet/Iceberg to raw zone. Async, eventual consistency. If lake write fails, event stays in queue for retry. OLTP is never blocked.
- [ ] **DL-9. Raw zone implementation** — Immutable, append-only. Partitioned by `source/event_type/date`. Full history retained. SHA-256 integrity preserved identically to OLTP.
- [ ] **DL-10. Enrichment zone implementation** — 58 normalizers write FindingData to enrichment zone. Entity resolution + tagging. Hash chain integrity. Schema versioning via Iceberg.
- [ ] **DL-11. Curated zone — 10 domains** — Implement all 10 fact domain tables (see Domain Inventory below).
- [ ] **DL-12. Reconciliation job** — Nightly comparison of row counts and SHA-256 hash samples between OLTP and lake. Built from day one, not as afterthought.
- [ ] **DL-13. Backfill CLI command** — `warlock lake backfill` reads from OLTP read replica, streams to lake via `yield_per(1000)`. Audit trail backfilled in strict sequence order with chain verification.
- [ ] **DL-14. Batch Parquet writes** — One Parquet file per table per pipeline run, not per record. Prevents small file proliferation.

### New Lake-Only Domains

- [ ] **DL-15. Evidence Facts domain** — Artifacts, control bindings, freshness, quality scores, pipeline provenance. Many-to-many evidence-to-control relationships. This is the connective tissue of the platform.
- [ ] **DL-16. Privacy Facts domain** — Processing activities (GDPR Article 30), DSARs, consent records, cross-border transfers, DPIAs, breach register.
- [ ] **DL-17. Incident Facts domain** — Security events, incidents (lifecycle: detected→triaged→contained→eradicated→recovered→closed), regulatory notifications, post-incident/lessons learned, tabletop exercises.
- [ ] **DL-18. Pipeline Health Facts domain** — Connector runs, normalizer stats, data freshness per source, coverage metrics. Meta-compliance — confidence calibration for all other domains.
- [ ] **DL-19. Supply Chain Facts domain** — SBOM components (CycloneDX/SPDX), supplier security posture (time-series), concentration risk graph, provenance attestations (SLSA/Sigstore).

### Sub-Domains to Add to Existing Domains

- [ ] **DL-20. Regulatory Change Management** (Governance Facts) — Regulatory change events: regulation, change type, effective date, impact assessment, affected controls, remediation status.
- [ ] **DL-21. Control Testing Workpapers** (Evidence Facts) — Test procedure, test date, tester, sample size, methodology, per-sample pass/fail, exceptions. SOC 2 Type II auditor requirement.
- [ ] **DL-22. Business Continuity / BIA** (Entity Facts) — RTO/RPO per system, criticality classification, max tolerable downtime, DR test records.
- [ ] **DL-23. Training Program Records** (Entity Facts) — Programs, role-to-module mappings, completion rates by department, phishing simulation results. Links to Personnel SCD Type 2.

---

## Phase 2 — Consumer Migration (4-6 weeks)

### Query Pattern Migration

- [ ] **DL-24. Migrate aggregation queries to lake** — All GROUP BY, COUNT, AVG, SUM queries across all routers move to DuckDB/lake. Per-query feature flags in repository layer for rollback. Entity lookups (WHERE id=?) stay on OLTP.
- [ ] **DL-25. Analytics layer** — Materialized aggregation tables: `agg_framework_posture` at grain (framework, system_profile_id, date), `agg_control_family_posture` for heatmaps. Replace in-memory Python computation.
- [ ] **DL-26. Shadow queries for validation** — Feature flag per query: execute against both OLTP and lake, compare results, log discrepancies. OLTP result always returned. Completion signal: zero discrepancies for 2+ weeks.

### CLI Expansion

- [ ] **DL-27. Lake management commands** — `warlock lake status`, `warlock lake compact`, `warlock lake snapshot`, `warlock lake query`, `warlock lake backfill`, `warlock lake maintenance`.
- [ ] **DL-28. Evidence commands** — `warlock evidence list`, `warlock evidence freshness`, `warlock evidence link`, `warlock evidence quality`.
- [ ] **DL-29. Incident commands** — `warlock incidents`, `warlock incidents create`, `warlock incidents timeline`, `warlock incidents notify`.
- [ ] **DL-30. Privacy commands** — `warlock privacy dsar`, `warlock privacy processing-activities`, `warlock privacy transfers`, `warlock privacy dpia`.
- [ ] **DL-31. Pipeline health commands** — `warlock pipeline health`, `warlock pipeline freshness`, `warlock pipeline coverage`.
- [ ] **DL-32. Analytics commands** — `warlock trends`, `warlock heatmap`, `warlock anomalies`.
- [ ] **DL-33. Supply chain commands** — `warlock sbom`, `warlock suppliers`, `warlock concentration-risk`.

### Lake Maintenance

- [ ] **DL-34. Compaction job** — Daily, rewrite small files into ~256MB targets. Wire into pipeline scheduler.
- [ ] **DL-35. Snapshot expiry** — Daily. Raw zone: 7-day time-travel. Enrichment: 30-day. Curated: 365-day (audit period coverage).
- [ ] **DL-36. Orphan file cleanup** — Weekly. Remove unreferenced data files from object storage.
- [ ] **DL-37. Freeze OLTP retention purging** — During Phase 2, disable `RetentionManager.purge_expired()` on OLTP. Let Iceberg handle retention for migrated data.

---

## Phase 3 — Steady State (4-6 weeks)

### AI Layer Repositioning

- [ ] **DL-38. Remove AI from pipeline Stage 4** — Remove `ai_reasoner.evaluate()` from `Assessor.assess()` in `engine.py`. AI no longer runs inline during pipeline execution.
- [ ] **DL-39. MCP interface for curated zone** — Expose all 10 curated zone domains as MCP tools/resources. AI queries the entire lake conversationally.
- [ ] **DL-40. RAG over curated zone** — Rebuild RAG to embed and index curated zone data (compliance + risk + evidence + entity facts), not just control definitions.
- [ ] **DL-41. AI chat CLI** — `warlock ask "are we ready for SOC 2?"` — conversational compliance queries from terminal.

### OLTP Steady State

- [ ] **DL-42. OLTP retains governance + auth only** — Auth/sessions, governance workflows (POA&M, issues, attestations, risk acceptances), personnel, system profiles, audit trail hash chain, configuration. Stop writing historical control results to OLTP.
- [ ] **DL-43. Current-state projections** — OLTP maintains latest-result-per-control-per-framework materialized view for governance workflows that need it.

### Consumption Tier

- [ ] **DL-44. GRC tool export APIs** — Outbound push to Vanta, Drata, AuditBoard, ServiceNow GRC. Pre-joined views: control + assessment + evidence + assessor + framework version.
- [ ] **DL-45. BI/Dashboard lake access** — DuckDB/JDBC endpoint for Looker, Metabase, or direct Python/SQL queries against curated zone.
- [ ] **DL-46. Regulatory filing system** — Template-driven document generation from Incident Facts + Privacy Facts. GDPR DPA notification, SEC 8-K, DORA CSIRT report, NIS2 CSIRT report, US state breach notifications.
- [ ] **DL-47. Questionnaire automation** — AI-powered auto-fill of SIG, CAIQ, DDQ, custom questionnaires from curated zone data. Bridges AI layer + Evidence Facts + Compliance Facts.
- [ ] **DL-48. Trust center enhancement** — Customer-facing portal with self-service artifact access, real-time posture badges, NDA-gated documents, automated questionnaire response.

---

## Curated Zone Domain Inventory (10 Domains)

| # | Domain | Key Fact Tables | Grain |
|---|--------|----------------|-------|
| 1 | Compliance Facts | `fact_control_mapping`, `fact_control_assessment` | (finding, framework, control) and (finding, mapping, assessor, assessed_at) |
| 2 | Temporal Facts | `fact_posture_snapshot`, `fact_compliance_drift`, `fact_regulatory_deadline` | (framework, control, system, date) |
| 3 | Risk Facts | `fact_risk_simulation`, `fact_vulnerability_lifecycle`, `dim_compensating_control` (SCD2), `dim_risk_acceptance` (SCD2) | (framework, scenario, created_at) and (vuln_id, entity, discovered_at) |
| 4 | Entity Facts | `dim_resource`, `dim_system`, `dim_personnel`, `dim_vendor`, `dim_data_silo`, `bridge_entity_relationship`, `fact_data_flow`, `dim_software_component` | (entity_type, entity_id, valid_from) — all SCD Type 2 |
| 5 | Governance Facts | `fact_poam`, `fact_issue`, `fact_attestation`, `dim_audit_engagement`, `fact_policy_document`, `fact_exception`, `fact_legal_hold`, `fact_audit_entry` | Per artifact type, separate tables |
| 6 | Evidence Facts | `fact_evidence_artifact`, `bridge_evidence_control`, `fact_evidence_freshness`, `fact_evidence_quality` | (evidence_id, control_id, framework) |
| 7 | Privacy Facts | `fact_processing_activity`, `fact_dsar`, `fact_consent`, `fact_cross_border_transfer`, `fact_dpia`, `fact_breach_register` | Per privacy artifact type |
| 8 | Incident Facts | `fact_security_event`, `fact_incident`, `bridge_incident_control`, `bridge_incident_entity`, `fact_notification`, `fact_tabletop_exercise` | (incident_id) with bridges |
| 9 | Pipeline Health Facts | `fact_pipeline_run`, `fact_connector_run`, `fact_data_freshness`, `fact_coverage_metric` | (run_id, connector_name) |
| 10 | Supply Chain Facts | `fact_sbom_component`, `fact_supplier_assessment`, `fact_concentration_risk`, `fact_provenance_attestation` | (component_id, system) and (supplier_id, assessed_at) |

### Cross-Domain Infrastructure

- `bridge_finding_control` — pre-joined finding-to-control for star-schema joins
- `bridge_control_crosswalk` — framework-to-framework navigation
- `bridge_evidence` — evidence-to-entity many-to-many
- `agg_framework_posture` — daily rollup per framework per system
- `agg_control_family_posture` — daily rollup per control family per framework

### Dimensions on Every Fact Table

- `pipeline_run_id` — isolate results per run
- `system_profile_id` — scope to authorization boundary
- `assessed_at` / `created_at` — temporal dimension

---

## Connector Sprint — Post-Restructuring (immediately after Phase 3)

> **Sequencing:** Connectors are pure additive work — each is an independent unit
> (connector + normalizer + config entry) that plugs into the existing pipeline with
> zero structural changes. Building them after the lake restructuring means they
> automatically get dual-path (OLTP + lake) from day one. Sequence by SaaS company
> adoption, not audit framework.

### Tier 1 — Build immediately after Phase 3 (what SaaS companies use daily)

**Identity & Access**
- [ ] **JumpCloud** — device + identity, very popular with SaaS startups
- [ ] **Auth0 / Okta CIC** — login events, anomaly detection, dominant in SaaS dev

**Collaboration & DevOps**
- [ ] **GitLab** — security dashboard, SAST/DAST, audit events, major DevOps platform
- [ ] **Jira** — change request tracking, security bug SLAs, universal issue tracking
- [ ] **Slack** — enterprise audit logs, DLP events, audit trail for comms
- [ ] **Google Workspace** — SSO config, MFA status, sharing settings, admin audit

**Vulnerability & Code Security**
- [ ] **Semgrep** — SAST rules, secrets detection, fast-growing
- [ ] **Trivy** — container/IaC vulnerability scanning, standard scanner
- [ ] **GitGuardian** — secrets detection leader, incident remediation
- [ ] **Veracode** — enterprise AppSec standard

**Infrastructure & Secrets**
- [ ] **Terraform Cloud** — drift detection, plan/apply history, Sentinel policy checks, IaC standard
- [ ] **Docker / Aqua** — container runtime security

**Endpoint & MDM**
- [ ] **Kandji** — fast-growing Apple MDM, complements Jamf

**SIEM & Observability**
- [ ] **Grafana / Loki** — alerting, log aggregation, very popular open-source

**GRC & Compliance**
- [ ] **ServiceNow GRC** — policy, risk, audit, vendor risk management, enterprise dominant
- [ ] **BitSight** — external risk ratings, vendor scores

**HR & People**
- [ ] **Gusto** — dominant SMB payroll
- [ ] **Rippling** — fast-growing unified HR+IT, device+identity lifecycle

**AI/ML Operations**
- [ ] **SageMaker** — AWS ML standard, model registry, training jobs
- [ ] **Databricks** — Unity Catalog, model serving, audit logs

**Email & Messaging**
- [ ] **Microsoft Exchange Online** — message trace, mail flow rules, ubiquitous

### Tier 2 — Following sprint (enterprise or niche but common)

**Identity & Access**
- [ ] **Ping Identity** — SSO federation, adaptive MFA
- [ ] **OneLogin** — SSO events (being sunset by SAAM)

**Endpoint & MDM**
- [ ] **VMware Workspace ONE** — enterprise MDM

**SIEM & Observability**
- [ ] **Sumo Logic** — cloud SIEM

**Network & Perimeter**
- [ ] **Cisco Umbrella** — DNS security, web gateway

**GRC & Compliance**
- [ ] **Drata** — inbound connector (consumption tier is outbound export)
- [ ] **Vanta** — inbound connector (consumption tier is outbound export)
- [ ] **Archer (RSA)** — legacy enterprise GRC

**Collaboration & SaaS**
- [ ] **Salesforce** — customer data access audit trail (GDPR, HIPAA)

**Infrastructure & Secrets**
- [ ] **Ansible/AWX** — config management

**HR & People**
- [ ] **ADP** — enterprise payroll, workforce analytics
- [ ] **UKG (Kronos)** — workforce compliance
- [ ] **SAP SuccessFactors** — enterprise HR

**AI/ML Operations**
- [ ] **Weights & Biases** — ML experiment tracking
- [ ] **Vertex AI** — GCP ML model registry
- [ ] **Hugging Face** — model cards, dataset governance

**Email & Messaging**
- [ ] **Mimecast** — email gateway, URL protection

**Finance & Billing**
- [ ] **Stripe** — PCI DSS scope evidence, payment config
- [ ] **Brex / Ramp** — expense management (SOX-adjacent)

### Tier 3 — Demand-driven (build when a customer needs them)

- [ ] **Linode/Akamai** — cloud manager events
- [ ] **Hetzner** — firewall logs, server audit
- [ ] **LogRhythm** — SIEM (declining market share)
- [ ] **Barracuda** — email/WAF security
- [ ] **F5 BIG-IP** — load balancer, WAF
- [ ] **Paylocity** — payroll compliance

### Additional Connector Categories (from GRC Unicorn review)

These are net-new categories not in the original inventory. Build per customer demand within Tier 1-3 priority.

- [ ] **CI/CD Pipeline Security** — GitHub Actions/GHAS, GitLab CI, CircleCI
- [ ] **Supply Chain / SBOM** — Anchore, Grype, FOSSA (feeds Supply Chain Facts)
- [ ] **Third-Party Risk / Vendor Intel** — RiskRecon, UpGuard, Panorays, ProcessUnity (feeds Risk Facts)
- [ ] **Backup & DR Validation** — AWS Backup, Commvault, Rubrik, Cohesity, Druva
- [ ] **Physical Security** — Brivo, Openpath, Kisi (badge access → PE controls)
- [ ] **PAM (beyond CyberArk)** — BeyondTrust, Delinea (Thycotic), Teleport
- [ ] **Data Loss Prevention** — Symantec DLP, Digital Guardian, Code42 Incydr (feeds Privacy Facts)
- [ ] **API Gateways** — Kong, Istio (service mesh security)
- [ ] **CRM** — Salesforce, HubSpot (customer data audit trails)
- [ ] **DNS / Domain Security** — Route 53, registrar APIs
- [ ] **Secrets Management** — AWS Secrets Manager, Doppler (beyond HashiCorp Vault)

---

## Framework Gaps — 8 Missing (prioritized)

### HIGH — Enterprise buyers asking for these now

- [ ] **CIS Controls v8** — 18 controls, 153 safeguards. De facto vendor assessment framework. Maps to UCF crosswalk.
- [ ] **DORA** — EU Digital Operational Resilience Act. Effective Jan 2025. Mandatory for ICT services to EU financial institutions. Incident reporting within 4 hours.
- [ ] **NIS2** — EU Network and Information Security Directive 2. Transposition Oct 2024. Fines up to 10M EUR / 2% global turnover.
- [ ] **CCPA/CPRA** — California privacy. Different from GDPR in key areas (opt-out vs opt-in, "sale" definition). Every SaaS company has CA customers.

### MEDIUM — Needed for specific verticals or markets

- [ ] **CSA CCM v4 / STAR** — 197 control objectives, 17 domains. Cloud-specific assurance.
- [ ] **ISO 22301** — Business continuity. Increasingly requested alongside ISO 27001.
- [ ] **US State Privacy meta-framework** — 19+ state laws. Config matrix for per-state obligations.
- [ ] **UK Cyber Essentials** — Required for UK government contracts.

### CONDITIONAL — Depends on customer base

- [ ] **TISAX** — Automotive industry. ISO 27001 + automotive-specific additions.
- [ ] **SWIFT CSCF** — Financial messaging. Required for SWIFT network participants.

---

## Consumption Tier — 5 Paths

| # | Path | Description | Status |
|---|------|-------------|--------|
| 1 | GRC Tools | Outbound export to Vanta, Drata, AuditBoard, ServiceNow GRC | New |
| 2 | BI / Direct Queries | Looker, Metabase, Python/SQL against lake, Trust Portal, executive views | Partially exists (Trust Portal) |
| 3 | AI Chat | MCP-exposed curated zone → Claude/LLM, conversational compliance queries | New |
| 4 | Regulatory Filing | Template-driven document generation for GDPR DPA, SEC 8-K, DORA/NIS2 CSIRT reports, state breach notifications | New |
| 5 | Trust Center + Questionnaire Automation | Customer-facing portal with self-service artifacts, posture badges, AI-powered questionnaire auto-fill | Partially exists (Trust Portal + Questionnaires) |
