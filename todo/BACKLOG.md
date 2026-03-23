# Warlock Backlog

**Last updated:** 2026-03-23 (reconciled with CLI test results + development plan)
**Total:** 199 done / 311 total (64%) — excludes capability-gaps.md items

---

## Format

Every item follows this format:

```
- [x] ID: Description — Effort (S/M/L/XL) | Priority (P0/P1/P2/P3)
```

- **S** = < 1 day | **M** = 1–3 days | **L** = 3–5 days | **XL** = 1+ week
- **P0** = blocking production/adoption | **P1** = high value | **P2** = differentiation | **P3** = future

---

## 1. Hardening — Security & Performance

### 1.1 Sprint 1 — P0 security (DONE — 2026-03-23)

- [x] H-5: Auth on trust portal document listing — S | P0
- [x] H-6: Disable /docs, /redoc, /metrics in production — S | P0
- [x] H-7: Audit trail write lock review (correct as-is) — S | P0
- [x] H-8: Add 9 FK indexes (migration f2a3b4c5d6e7) — M | P0
- [x] H-9: Push trust portal aggregation to SQL GROUP BY — S | P0

### 1.2 Sprint 2 — Stability (DONE — 2026-03-23)

- [x] H-10: Create tests/conftest.py and tests/test_cli.py (DB setup duplicated 8x, 43 commands untested) — L | P1
- [x] H-11: Unify prompt sanitization paths (legacy path misses </evidence> tags) — M | P1
- [x] H-12: Scope AI conversation sessions to user (any user can read/delete others') — M | P0
- [x] H-13: Increase backup code entropy to 64 bits (NIST SP 800-63B) — S | P1
- [x] H-14: Add CHECK constraints on status/enum columns (zero across 34 models) — M | P1
- [x] H-15: Add MemoryCache eviction (rate limiter creates unbounded keys) — S | P1

### 1.3 Backlog — Quality

- [ ] H-16: Migrate to async def + AsyncSession (sync blocks threadpool at 50+ users) — XL | P2
- [ ] H-17: Replace COUNT+SELECT with window functions (10+ endpoints double-query) — M | P2
- [ ] H-18: Add eager loading strategies (all relationships lazy="select", N+1) — M | P2
- [ ] H-19: Split assertions.py (6,053 lines) into domain modules — L | P2
- [ ] H-20: Extract normalizer _base() into generic base class (40+ duplicate patterns) — L | P2
- [ ] H-21: Resolve duplicate Alembic env.py (alembic/ vs warlock/db/migrations/) — S | P2

### 1.4 Triaged findings (2026-03-21 review — Sprint 1 security items DONE)

- [x] H-22: GDPR anonymization uses hardcoded HMAC secret (workflows/gdpr.py:62) — S | P0
- [x] H-23: AI error messages leak internal exception details (assessors/ai_reasoning.py:273-391) — S | P1
- [x] H-24: In-memory rate limiter ineffective with multiple workers (api/middleware.py:39-106) — M | P1
- [x] H-25: Swallowed except Exception: pass in connectors hides data loss — M | P1
- [x] H-26: NormalizerRegistry catches exceptions, failure counter never fires — S | P1
- [ ] H-27: POA&M _CLOSED_STATUSES includes verified but state machine says intermediate — S | P1
- [ ] H-28: __import__() used as inline import in production paths — S | P2
- [x] H-29: Legacy SHA-256 password hashes accepted with no forced migration — M | P1
- [x] H-30: Pipeline runs all connectors in one transaction (~59K inserts hold write locks) — L | P1
- [x] H-31: Connection pool (5+10=15) too small for production with audit middleware — S | P1
- [ ] H-32: Test ordering dependency in test_integration_e2e.py — S | P2
- [ ] H-33: Tautological assertions in tests (len(x) >= 0, assert True) — S | P2
- [ ] H-34: 38/82 normalizers, 93/101 assertions, 8/16 workflows have zero behavioral tests — XL | P1
- [x] H-35: No UniqueConstraint on natural keys for ControlResult and PostureSnapshot — M | P1
- [x] H-36: AuditEntry.sequence is Integer in migration but BigInteger in model — S | P1

---

## 2. Data Lake

### 2.1 Complete (48 of 48)

<details>
<summary>Click to expand completed items</summary>

- [x] DL-1: Storage abstraction (local, S3, Azure) — L
- [x] DL-2: DuckDB feasibility — query.py with in-process DuckDB — M
- [x] DL-4: Local-dev lake story — demo seed produces lake/ when WLK_LAKE_ENABLED=true — M
- [x] DL-7: Iceberg schemas from SQLAlchemy — schema.py + catalog.py — L
- [x] DL-8: Lake writer event bus subscriber — writer.py — M
- [x] DL-9: Raw zone — immutable, append-only, partitioned by source/date — L
- [x] DL-10: Enrichment zone — normalized findings with hash chain — L
- [x] DL-11: Curated zone — 10 domains, ~47 tables via domains.py — XL
- [x] DL-12: Reconciliation — reconciliation.py with row counts + hash sampling — M
- [x] DL-13: Backfill CLI — warlock lake backfill — M
- [x] DL-14: Batch Parquet writes — one file per table per run — M
- [x] DL-15 to DL-19: 5 new lake-only domains (evidence, privacy, incident, pipeline health, supply chain) — XL
- [x] DL-20 to DL-23: Sub-domains (regulatory change, workpapers, BCA/BIA, training) — L
- [x] DL-24: Migrate aggregation queries to lake — readers.py with DuckDB — L
- [x] DL-25: Analytics layer — aggregations.py with materialized tables — L
- [x] DL-26: Shadow queries — shadow.py for OLTP/lake comparison — M
- [x] DL-27 to DL-33: All CLI commands — cli/lake.py (976 lines, 20+ commands) — XL
- [x] DL-34 to DL-36: Maintenance — compaction, snapshot expiry, orphan cleanup — L
- [x] DL-37: OLTP retention freeze — wired to RetentionManager — M
- [x] DL-38: AI inline disable — ai_inline_disabled config flag — S
- [x] DL-39: MCP interface — mcp_tools.py (8 tools) — L
- [x] DL-40: RAG over curated zone — rag.py (TF-IDF, 10,535 docs) — L
- [x] DL-41: AI chat CLI — warlock ask — M
- [x] DL-42 to DL-43: OLTP thinning — oltp_thin.py with legal hold guard — L
- [x] DL-44 to DL-48: Consumption tier — 5 paths in consumption.py — XL
- [x] DL-HARDENING: utils, posture readers, legal holds, ABAC, hash sampling, typed Parquet, bridges, SCD Type 2, Iceberg, RAG — XL

</details>

### 2.2 Remaining (0 items — ALL COMPLETE)

- [x] DL-WIRE: Wire orchestrator to lake writers — M | P1 (API pipeline route now calls register_lake_writer + flush)
- [x] DL-3: Iceberg REST catalog for cloud deployments — L | P2 (catalog.py supports both SQLite and REST)
- [x] DL-5: Event bus durable backend — L | P2 (queue.py: Redis Streams, Kafka, SQS, NATS, in-memory)
- [x] DL-6: Repository pattern completion — XL | P2 (23→8 raw queries; remaining 8 are ABAC/join/no-repo)
- [x] DL-CROSS: Crosswalks with confidence scores — M | P2 (CrosswalkEdge.confidence in YAML, dataclass, and DB)

---

## 3. Connectors (ALL DONE — 165 connectors + normalizers)

Check to see if all connector tiers are complete and wired into the demo and data seed

### 3.1 Tier 1 — DONE (21 of 21)

<details>
<summary>Click to expand completed connectors</summary>

- [x] JumpCloud — S
- [x] Auth0/Okta CIC — S
- [x] GitLab — M
- [x] Jira — S
- [x] Slack — S
- [x] Google Workspace — M
- [x] Semgrep — S
- [x] Trivy — S
- [x] GitGuardian — S
- [x] Veracode — M
- [x] Terraform Cloud — M
- [x] Aqua — S
- [x] Kandji — S
- [x] Grafana — S
- [x] BitSight — S
- [x] Gusto — S
- [x] Rippling — S
- [x] SageMaker — M
- [x] Databricks — M
- [x] Exchange Online — M
- [x] C-1: ServiceNow GRC connector — M | P1

</details>

### 3.2 Tier 2 — DONE (16 of 16)

<details>
<summary>Click to expand completed connectors</summary>

- [x] C-2: Ping Identity — S | P2
- [x] C-3: OneLogin — S | P2
- [x] C-4: VMware Workspace ONE — M | P2
- [x] C-5: Sumo Logic — M | P2
- [x] C-6: Cisco Umbrella — M | P2
- [x] C-7: Drata (inbound) — M | P2
- [x] C-8: Vanta (inbound) — M | P2
- [x] C-9: Archer — M | P2
- [x] C-10: Salesforce — M | P2
- [x] C-11: Ansible/AWX — M | P2
- [x] C-12: ADP — S | P2
- [x] C-13: UKG — S | P2
- [x] C-14: SAP SuccessFactors — M | P2
- [x] C-15: Weights & Biases — S | P2
- [x] C-16: Vertex AI — M | P2
- [x] C-17: Mimecast — M | P2

</details>

### 3.3 Tier 3 — DONE (6 of 6)

<details>
<summary>Click to expand completed connectors</summary>

- [x] C-18: Linode/Akamai — S | P3
- [x] C-19: Hetzner — S | P3
- [x] C-20: LogRhythm — M | P3
- [x] C-21: Barracuda — M | P3
- [x] C-22: F5 BIG-IP — M | P3
- [x] C-23: Paylocity — S | P3

</details>

### 3.4 New categories — DONE (43 of 43)

<details>
<summary>Click to expand completed connectors</summary>

- [x] C-24: Chainguard (Supply Chain/SBOM) — M | P2
- [x] C-25: Syft/Grype (Supply Chain/SBOM) — M | P2
- [x] C-26: FOSSA (Supply Chain/SBOM) — M | P2
- [x] C-27: Snyk Container (Supply Chain/SBOM) — M | P2
- [x] C-28: Socket.dev (Supply Chain/SBOM) — S | P2
- [x] C-29: Salt Security (API Security) — M | P2
- [x] C-30: Noname Security (API Security) — M | P2
- [x] C-31: Wallarm (API Security) — M | P2
- [x] C-32: 42Crunch (API Security) — M | P2
- [x] C-33: Tailscale (Zero Trust) — S | P2
- [x] C-34: Twingate (Zero Trust) — S | P2
- [x] C-35: Banyan Security (Zero Trust) — S | P2
- [x] C-36: Nightfall AI (DLP) — S | P1
- [x] C-37: Code42 Incydr (DLP) — M | P2
- [x] C-38: Varonis (DLP) — M | P2
- [x] C-39: BigID (DLP) — M | P2
- [x] C-40: Rubrik Security Cloud (DLP) — M | P2
- [x] C-41: Commvault (Backup & DR) — M | P2
- [x] C-42: Rubrik (Backup & DR) — M | P2
- [x] C-43: Cohesity (Backup & DR) — M | P2
- [x] C-44: Druva (Backup & DR) — M | P2
- [x] C-45: AWS Backup (Backup & DR) — S | P1
- [x] C-46: Orca Security (CSPM) — M | P1
- [x] C-47: Lacework (CSPM) — M | P1
- [x] C-48: Ermetic (CSPM) — M | P2
- [x] C-49: TrustArc (Privacy) — M | P2
- [x] C-50: Cookiebot (Privacy) — S | P2
- [x] C-51: Osano (Privacy) — S | P2
- [x] C-52: Rapid7 InsightVM (Vuln Mgmt) — M | P1
- [x] C-53: CrowdStrike Spotlight (Vuln Mgmt) — S | P1
- [x] C-54: Vulcan Cyber (Vuln Mgmt) — M | P2
- [x] C-55: Microsoft Teams Compliance (Comms) — M | P2
- [x] C-56: Zoom compliance APIs (Comms) — M | P2
- [x] C-57: Smarsh (Comms) — M | P2
- [x] C-58: Tanium (Endpoint) — M | P2
- [x] C-59: Automox (Endpoint) — M | P2
- [x] C-60: Fleet (Endpoint, open source) — M | P2
- [x] C-61: Drata API (Competitor Ingestion) — M | P2
- [x] C-62: Vanta API (Competitor Ingestion) — M | P2
- [x] C-63: Secureframe API (Competitor Ingestion) — M | P2
- [x] C-64: Kubecost (FinOps) — S | P3
- [x] C-65: Infracost (FinOps) — S | P3
- [x] C-66: Spot.io (FinOps) — S | P3

</details>

**Note:** All 165 connectors are mock implementations producing demo data. They still need real API validation (see OPS-6).

---

## 4. Frameworks (14 active — 10 remaining for new frameworks)

14 frameworks are live with pipeline YAMLs, control mappings, and demo seed results. The 10 remaining items are for adding *new* frameworks beyond the current 14.

### 4.1 HIGH — Enterprise buyers asking now

- [ ] FW-1: CIS Controls v8 (18 controls, 153 safeguards) — L | P1
- [ ] FW-2: DORA (EU financial sector, mandatory Jan 2025) — L | P1
- [ ] FW-3: NIS2 (EU network security, fines up to 10M EUR) — L | P1
- [ ] FW-4: CCPA/CPRA (California privacy) — M | P1

### 4.2 MEDIUM — Specific verticals

- [ ] FW-5: CSA CCM v4 / STAR (cloud assurance, 197 objectives) — L | P2
- [ ] FW-6: ISO 22301 (business continuity) — M | P2
- [ ] FW-7: US State Privacy meta-framework (19+ state laws) — XL | P2
- [ ] FW-8: UK Cyber Essentials — M | P2

### 4.3 CONDITIONAL — Customer-dependent

- [ ] FW-9: TISAX (automotive) — L | P3
- [ ] FW-10: SWIFT CSCF (financial messaging) — L | P3

---

## 5. Product Features — Demo to Production

### 5.1 Core models

- [x] PG-1: Alert model + CLI + API (severity, MITRE ATT&CK, finding linkage) — XL | P0 ✓ Sprint 5
- [x] PG-2: Alert rules engine (Finding patterns → Alert triggers) — L | P0 ✓ Sprint 5
- [ ] PG-3: CloudResource model + warlock cloud CLI — L | P1
- [ ] PG-4: Device model + warlock devices CLI (unified endpoint view) — L | P1
- [ ] PG-5: StorageBucket model + warlock storage CLI — M | P1
- [x] PG-6: AI reasoning structured output ({confidence, reasoning[], evidence[]}) — M | P0 ✓ Sprint 5
- [x] PG-7: Remediation workflow API (5-stage state machine) — L | P0 ✓ Sprint 6

### 5.2 Pipeline & API enhancements

- [x] PG-8: Real-time pipeline status API (GET /pipeline/status) — M | P1 ✓ Sprint 6
- [ ] PG-9: Per-connector collection status API — M | P1
- [ ] PG-10: WebSocket for live pipeline progress — L | P2
- [x] PG-11: Hash chain verification endpoint (GET /pipeline/verify-chain) — S | P1 ✓ Sprint 6
- [ ] PG-12: Audit simulation date picker + structured AI output — M | P2
- [ ] PG-13: Cross-view deep linking (URL-based entity navigation) — M | P2
- [ ] PG-14a: `warlock investigate <provider>` CLI — show non-compliant controls by provider (e.g. `warlock investigate aws`), pick one, show failing resources + remediation steps (static KB + optional AI) — M | P1

### 5.3 Demo seed enhancements

- [ ] PG-14: Generate drift events (realistic 90-day degradation/improvement) — M | P2
- [ ] PG-15: Generate posture snapshots over time (daily for 90 days) — M | P2
- [ ] PG-16: Generate realistic issue timelines with comments — M | P2
- [ ] PG-17: Generate POA&M milestone progress — S | P2

### 5.4 Export & reporting

- [x] PG-18: PDF report generation (WeasyPrint, cover page, TOC, page numbers) — L | P1 ✓ Sprint 8
- [x] PG-19: Executive summary template (posture score, top risks, trend) — M | P1 ✓ Sprint 8
- [ ] PG-20: Embeddable compliance widget (iframe HTML) — M | P3
- [ ] PG-21: SVG compliance badges for README — S | P3
- [ ] PG-22: Slack/Teams notification integration — M | P1

### 5.5 Web frontend

- [ ] PG-23: Choose stack (Next.js + React recommended) — S | P2
- [ ] PG-24: API client layer — M | P2
- [ ] PG-25: Authentication UI (JWT, OIDC) — L | P2
- [ ] PG-26: Dashboard page — L | P2
- [ ] PG-27: All demo views as React pages — XL | P2
- [ ] PG-28: Real-time updates — M | P2
- [ ] PG-29: OR: TUI alternative (Textual/Rich) — L | P2

---

## 6. Domain Architecture (DONE — 2026-03-22)

Built as part of the domain architecture initiative. All items complete.

<details>
<summary>Click to expand completed items</summary>

- [x] DA-1: DomainRegistry for cross-domain queries — M
- [x] DA-2: DomainEventBus with cascade safety and dedup — M
- [x] DA-3: PolicyEngine with scope resolution and history — L
- [x] DA-4: ControlsDomainService with cross-domain queries — M
- [x] DA-5: IssuesDomainService — unified POAMs + Issues — M
- [x] DA-6: EvidenceDomainService — freshness and sufficiency — M
- [x] DA-7: Policy, PolicyHistory, Asset, Vendor DB models — M
- [x] DA-8: Base dataclasses and DomainService protocol — S
- [x] DA-9: warlock policy set/list/show/history CLI commands — M
- [x] DA-10: warlock briefing and control-hub CLI commands — M
- [x] DA-11: Cross-domain integration smoke tests — S

</details>

---

## 7. CLI Expansion (DONE — 2026-03-22)

CLI grew from 42+ commands to **556 leaf commands** across 68 modules. All items complete.

<details>
<summary>Click to expand completed items</summary>

- [x] CLI-1: 84 new connectors + normalizers + 29 CLI modules (374 commands) — XL
- [x] CLI-2: 125 analytics, correlation, AI, and automation commands (499 total) — XL
- [x] CLI-3: Interactive GRC workflows (530 total) — L
- [x] CLI-4: 6 more interactive workflows (539 total) — M

</details>

---

## 8. P2 Features — Differentiation

### 8.1 Data Governance & Discovery

- [ ] F-1: Databricks Unity Catalog connector — M | P2
- [ ] F-2: DataHub connector — M | P2
- [ ] F-3: Atlan connector — M | P2
- [ ] F-4: Active data silo discovery — L | P2
- [ ] F-5: Data classification & sensitivity scoring — L | P2
- [ ] F-6: Data lineage tracking — XL | P2
- [ ] F-7: Data silo drift detection — M | P2

### 8.2 AI Governance & Shadow AI

- [ ] F-8: Shadow AI detection assertions — M | P2
- [ ] F-9: AI model inventory connectors — M | P2
- [ ] F-10: AI policy enforcement assertions — M | P2
- [ ] F-11: Cloud AI billing anomaly detection — M | P2
- [ ] F-12: AI incident tracking model — M | P2

### 8.3 AI Capabilities

- [ ] F-13: Natural language compliance queries — L | P2
- [ ] F-14: Automated evidence validation — L | P2
- [ ] F-15: Predictive drift — L | P2
- [ ] F-16: Remediation copilot — XL | P2
- [ ] F-17: Compliance-aware code review — L | P2

### 8.4 Architecture

- [ ] F-18: Multi-tenancy — XL | P2
- [ ] F-19: WebSocket real-time dashboard — L | P2
- [ ] F-20: Plugin architecture for connectors/normalizers — L | P2
- [ ] F-21: Compliance-as-code SDK for CI/CD — L | P2
- [ ] F-22: Table partitioning — M | P2
- [ ] F-23: TimescaleDB for posture snapshots — M | P2
- [ ] F-24: Full-text search (PostgreSQL tsvector) — M | P2
- [ ] F-25: Archive strategy (hot/warm/cold) — L | P2

### 8.5 Compliance Depth

- [ ] F-26: FedRAMP ConMon tooling — L | P2
- [x] F-27: SOC 2 points of focus (109 across 32 controls) — L | P2
- [x] F-28: Attestation workflow (SOC 2/ISO) — L | P2
- [ ] F-29: CIS Benchmark mappings — M | P2
- [ ] F-30: NIST 800-53 enhancements (1,034 gaps) — XL | P2
- [ ] F-31: Reverse crosswalks — M | P2

### 8.6 Risk

- [ ] F-32: Bayesian network risk models — L | P2
- [ ] F-33: Business Impact Analysis — XL | P2
- [ ] F-34: Insider threat scoring — L | P2
- [ ] F-35: Control effectiveness decay modeling — M | P2
- [ ] F-36: Monte Carlo parallelism — M | P2

### 8.7 Trust Portal

- [ ] F-37: Self-service evidence requests — M | P2
- [ ] F-38: NDA-gated tiered access — L | P2
- [ ] F-39: Incident communication status page — M | P2

### 8.8 Privacy

- [ ] F-40: Consent management (OneTrust) — L | P2
- [ ] F-41: Cross-border transfer tracking — M | P2
- [ ] F-42: Right to data portability — M | P2
- [ ] F-43: Transcend connector (DSR/data maps) — M | P2

### 8.9 Risk Management

- [ ] F-44: FAIR taxonomy full decomposition — L | P2
- [ ] F-45: Loss magnitude categories — M | P2
- [ ] F-46: Threat modeling (STRIDE/MITRE ATT&CK) — L | P2
- [ ] F-47: TPRM lifecycle — L | P2

### 8.10 Other

- [ ] F-48: Terraform multi-cloud parity (AWS 12, Azure 4, GCP 4) — L | P2
- [ ] F-49: Terragrunt wrapper — M | P2
- [ ] F-50: Private module registry — M | P2
- [ ] F-51: Cold start optimization (remove init_db from scheduler tick) — S | P2
- [ ] F-52: Iterator-based OPA data assembly — M | P2
- [ ] F-53: Presidio PII detector (blocked: Python 3.14 compat) — M | P2
- [ ] F-54: detect-secrets assessor — S | P2
- [ ] F-55: Human-readable SSP export (Markdown/PDF) — M | P2
- [ ] F-56: Audit package builder CLI — M | P2
- [ ] F-57: SBOM/supply chain compliance (CycloneDX/SPDX) — L | P2
- [ ] F-58: Pentest lifecycle management — L | P2

---

## 9. P3 Features — Future

- [ ] F-59: GraphQL API — L | P3
- [ ] F-60: GPU-accelerated Monte Carlo — M | P3
- [ ] F-61: Lambda SnapStart — M | P3
- [ ] F-62: Embedded OPA — L | P3
- [ ] F-63: Public Terraform Registry — M | P3
- [ ] F-64: Streaming SSP response — M | P3
- [ ] F-65: ITAR framework — L | P3
- [ ] F-66: CJIS framework — L | P3
- [ ] F-67: StateRAMP framework — L | P3
- [ ] F-68: NIST AI RMF framework — L | P3
- [ ] F-69: Nth-party vendor risk — L | P3
- [ ] F-70: SLA compliance per vendor — M | P3
- [ ] F-71: Vendor incident notification — M | P3
- [ ] F-72: DR testing tracking — M | P3
- [ ] F-73: KRI dashboard — L | P3
- [ ] F-74: Risk register (beyond POA&Ms) — M | P3
- [ ] F-75: Compliance deadline forecasting — M | P3
- [ ] F-76: Privacy by design CI enforcement — L | P3

---

## 10. Documentation

### 10.1 Production Docs — DONE (18 documents)

These were written as part of the proddocs initiative and live in `proddocs/`.

<details>
<summary>Click to expand completed docs</summary>

- [x] DOC-1: API reference (proddocs/api/reference.md) — L | P0
- [x] DOC-5: Deployment guide (proddocs/operations/deployment.md) — L | P0
- [x] DOC-7: Security hardening (proddocs/technical/security.md) — L | P0
- [x] DOC-8: CLI reference (proddocs/api/cli-reference.md) — M | P0
- [x] DOC-ARCH: Architecture doc (proddocs/technical/architecture.md) — M
- [x] DOC-LAKE: Data lake doc (proddocs/technical/data-lake.md) — M
- [x] DOC-MODEL: Data model doc (proddocs/technical/data-model.md) — M
- [x] DOC-CONN: Connectors doc (proddocs/features/connectors.md) — M
- [x] DOC-ASSESS: Assessment engine doc (proddocs/features/assessment-engine.md) — M
- [x] DOC-FW: Frameworks doc (proddocs/product/frameworks.md) — M
- [x] DOC-OVER: Product overview (proddocs/product/overview.md) — M
- [x] DOC-RUN: Operations runbook (proddocs/operations/runbook.md) — M
- [x] DOC-README: Proddocs index (proddocs/README.md) — S

</details>

### 10.2 P0 — DONE (Sprint 7, 2026-03-23)

- [x] DOC-2: API_AUTH_GUIDE.md (JWT + RBAC + ABAC) — M | P0 ✓
- [x] DOC-3: API_ERRORS.md (error code reference) — M | P0 ✓
- [x] DOC-4: OpenAPI schema export — S | P0 ✓
- [x] DOC-6: DOCKER_SETUP.md (standalone step-by-step) — M | P0 ✓
- [x] DOC-9: DEVELOPER_SETUP.md — M | P0 ✓
- [x] DOC-10: CONTRIBUTING.md update — S | P0 ✓
- [x] DOC-11: PR template — S | P0 ✓
- [x] DOC-12: README accuracy fixes — S | P0 ✓

### 10.3 P1 — High-value enablers (26 docs)

- [ ] DOC-13 to DOC-18: Framework guides (NIST, SOC 2, ISO 27001, HIPAA, CMMC, overview) — L each | P1
- [ ] DOC-19 to DOC-29: Connector guides (index + AWS + Okta + GCP + template + per-connector) — M each | P1
- [ ] DOC-30 to DOC-34: Operations runbooks (monitoring, DB failure, pipeline stuck, auth outage, audit trail) — M each | P1
- [ ] DOC-35 to DOC-37: Dev docs (test strategy, codebase structure, workflow) — M each | P1

### 10.4 P2 — Polish (20 docs)

- [ ] DOC-38 to DOC-40: Release management (changelog, versioning, release process) — S each | P2
- [ ] DOC-41 to DOC-47: Architecture Decision Records (7 ADRs) — M each | P2
- [ ] DOC-48 to DOC-49: Code style guides — S each | P2
- [ ] DOC-50 to DOC-51: Security architecture docs — M each | P2
- [ ] DOC-52: Compliance design doc — M | P2
- [ ] DOC-53 to DOC-57: Misc docs — S each | P2

---

## 11. Operational

- [x] OPS-1: Wire FedRAMP/HIPAA/CMMC/GDPR checks to event_types in YAMLs — M | P1 ✓
- [ ] OPS-2: demo_exports/ — pre-generated sample packages — S | P2
- [ ] OPS-3: docs/architecture-diagram.html — visual architecture — S | P2
- [ ] OPS-4: Celery integration (alternative task queue) — M | P3
- [x] OPS-5: nltk CVE remediation — S | P1 (N/A — nltk not in codebase) ✓
- [ ] OPS-6: Connector vendor accuracy pass (verify 165 connectors against real API docs) — XL | P0
- [x] OPS-7: Schema registry for event_types — M | P1 ✓ Sprint 3
- [ ] OPS-8: Smarter fallback normalizer (heuristics for unknown event_types) — M | P2
- [ ] OPS-9: Demo data vendor accuracy (match real API response schemas) — L | P2

---

## 12. CLI Bugs (NEW — 2026-03-23 comprehensive test)

Found during 170-command CLI test against live demo seed. See `warlock-issues.md` for full details.

### 12.1 Crashes — CRITICAL/HIGH

- [ ] CLI-BUG-004: `vendor-mgmt reassess-due` datetime naive/aware crash — S | P0
- [ ] CLI-BUG-005: `vendor-mgmt contracts` datetime naive/aware crash — S | P0
- [ ] CLI-BUG-007: `poam list --format json` invalid JSON output — S | P0
- [ ] CLI-BUG-008: `control-hub --format json` AttributeError on Attestation.owner — S | P0
- [ ] CLI-BUG-009: `incidents update` status enum mismatch blocks incident lifecycle — S | P0
- [ ] CLI-BUG-010: `calendar export --format ics` ImportError PersonnelRecord — S | P0
- [ ] CLI-BUG-011: `link training-access` ImportError TrainingRecord — S | P0
- [ ] CLI-BUG-012: `bulk import-findings --dry-run` crashes on empty file — S | P1

### 12.2 Missing commands

- [ ] MC-001: `correlate top-risk` — referenced but doesn't exist — S | P2
- [ ] MC-002: `comply gap-analysis` alias for `correlate gap-analysis` — S | P2

### 12.3 CLI inconsistencies

- [ ] CI-001: Framework arg: positional vs `-f` flag inconsistency across commands — M | P1
- [ ] CI-002: Vendor tier naming inconsistency (numeric vs word) — S | P2
- [ ] CI-005: `soc2_points_of_focus` ghost framework in list (0 controls) — S | P1

### 12.4 Cross-flow gaps (missing domain linkages)

- [ ] XF-001: `findings create-issue` command — most basic GRC workflow missing — M | P0
- [ ] XF-002: `privacy breach create --incident-id` flag — S | P1
- [ ] XF-003: `privacy dsar create --breach-id` flag — S | P1
- [ ] XF-004: `poam create --finding-id` flag — S | P1
- [ ] XF-005: `bulk link-findings-to-issues` — advertised in `bulk stats` but doesn't exist — M | P1
- [ ] XF-006: POA&M closure doesn't trigger control re-assessment — M | P2
- [ ] XF-007: Incident lifecycle doesn't affect control posture — M | P2
- [ ] XF-008: `control-hub` doesn't show linked incidents — S | P2
- [ ] XF-009: Privacy breach cascade automation — L | P2

---

## 13. Capability Gaps (2026-03-22)

Detailed in `capability-gaps.md`. 762 total capabilities identified, ~540 implemented, ~222 remaining across 20 domains. Key domains with gaps:

- Compliance Posture Views (12 gaps)
- Risk Quantification & Management (25 gaps)
- Evidence & Audit Management
- Vendor & Third-Party Risk
- Privacy & Data Protection
- Incident & Response
- Asset & Configuration Management

See `todo/capability-gaps.md` for full itemized list.

---

## 14. Implementation Plans (reference)

Completed plans (deleted): data-lake-phase-0 through phase-3, data-lake-hardening, demo-seed, domain-architecture.

| Plan | Status | File |
|------|--------|------|
| Full Codebase Audit | Not started | plan-codebase-audit.md |

---

## Summary

| Category | Done | Open | P0 | P1 | P2 | P3 |
|----------|------|------|----|----|----|----|
| Hardening (§1) | 18 | 9 | 0 | 2 | 7 | 0 |
| Data Lake (§2) | 48 | 0 | 0 | 0 | 0 | 0 |
| Connectors (§3) | 86 | 0 | 0 | 0 | 0 | 0 |
| Frameworks (§4) | 0 | 10 | 0 | 4 | 4 | 2 |
| Product Gaps (§5) | 8 | 21 | 0 | 5 | 12 | 2 |
| Domain Architecture (§6) | 11 | 0 | 0 | 0 | 0 | 0 |
| CLI Expansion (§7) | 4 | 0 | 0 | 0 | 0 | 0 |
| P2 Features (§8) | 2 | 56 | 0 | 0 | 56 | 0 |
| P3 Features (§9) | 0 | 18 | 0 | 0 | 0 | 18 |
| Documentation (§10) | 21 | 45 | 0 | 25 | 20 | 0 |
| Operational (§11) | 3 | 6 | 1 | 0 | 4 | 1 |
| CLI Bugs (§12) | 0 | 22 | 8 | 6 | 6 | 0 |
| **Total** | **201** | **187** | **9** | **42** | **109** | **23** |

**Progress: 201 done / 388 total (52%) — plus ~222 capability-gap items in separate tracker.**

**Current codebase stats:**
- 165 connectors + 165 normalizers
- 14 frameworks (1,996 controls)
- 556 CLI leaf commands (68 modules)
- 509 tests (32 files)
- 42 DB models, 16 migrations
- 23 lake modules, 7 domain services
- 670 OPA/Rego policies
- 17 OSCAL JSON packages
- 36 Terraform files (AWS, Azure, GCP)
- 24 assessor modules (101 assertions)
- 18 production docs

---

## What's Next — Prioritized

### Immediate (before any user touches the product)

**CLI bug sweep (~2 hours).** 7 crash bugs (CLI-BUG-004/005/007/008/009/010/011) and 1 missing core command (XF-001). These block the Finding → Issue → POA&M → Closure workflow, the vendor management flow, and JSON export. All are small fixes (ensure_aware, correct model names, enum alignment).

### Before beta (Sprints 3-4 scope)

1. **OPS-6: Real connector validation** — the single biggest v1.0 risk. 15+ connectors need real API credentials. Start with AWS, Okta, GitHub, CrowdStrike, Jira.
2. **PG-9: Per-connector collection status API** — needed to debug real connector issues.
3. **PG-22: Slack notification integration** — alert delivery for production use.
4. **CI-001: Framework arg standardization** — UX consistency across CLI.
5. **XF-002/003/004/005: Cross-domain linking flags** — tie findings → issues → POA&Ms → breaches.
6. **CI-005: Hide or fix `soc2_points_of_focus` ghost framework.**
7. **End-to-end SOC 2 demo walkthrough documentation.**

### Post-v1.0

Everything else: new frameworks (FW-1–10), web frontend (PG-23–29), P2/P3 features (F-1–76), remaining documentation (DOC-13–57), capability gaps, async migration (H-16).
