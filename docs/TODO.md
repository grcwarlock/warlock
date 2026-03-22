# Warlock — Unified TODO

**Last updated:** 2026-03-21
**Sources:** MASTER_TODO.md, MASTER_ROADMAP.md, DATALAKE_TODO.md, TODO.md, DOCUMENTATION_TODO.md, Warlock_GRC_Data_Lake_Status.md, codebase audit
**Total remaining:** 213 items | **Done:** 150 items (including Sprint 1 hardening 2026-03-21)

---

## How to read this

- `[x]` = Done and verified in code
- `[ ]` = Not started
- Items are numbered for cross-reference (H = hardening, DL = data lake, F = feature, D = docs)
- Effort: S (< 1 day), M (1-3 days), L (3-5 days), XL (1+ week)
- Severity on hardening items reflects production risk

---

## 1. Hardening — Security & Performance (12 remaining)

These are fixes to existing code. Ordered by severity.

### Sprint 1 — HIGH severity (DONE — 2026-03-21)

| # | What | Status |
|---|------|--------|
| H-5 | **Auth on trust portal document listing** — Added `get_current_user` + ownership check | [x] Done |
| H-6 | **Disable `/docs`, `/redoc`, `/metrics` in production** — Gated behind `env != "production"` | [x] Done |
| H-7 | **Audit trail write lock** — Reviewed: `FOR UPDATE` is correct for hash-chain integrity. No change needed | [x] Done (no change) |
| H-8 | **Add FK indexes** — 9 indexes across issues, compensating_controls, risk_acceptances, evidence_requests. Migration `f2a3b4c5d6e7` | [x] Done |
| H-9 | **Push trust portal aggregation to SQL** — Replaced Python loop with SQL `GROUP BY` | [x] Done |

### Sprint 2 — MEDIUM severity (6 items)

| # | What | Severity |
|---|------|----------|
| H-10 | **Create `tests/conftest.py` and `tests/test_cli.py`** — DB setup duplicated 8 times. CLI has 43 commands, zero tests | MEDIUM |
| H-11 | **Unify prompt sanitization paths** — Legacy `_sanitize_field()` doesn't strip `</evidence>` tags. 4 AI reasoners use legacy path | MEDIUM |
| H-12 | **Scope AI conversation sessions to user** — Any authenticated user can read/delete any other user's conversations | MEDIUM |
| H-13 | **Increase backup code entropy to 64 bits** — `secrets.token_hex(4)` = 32 bits. NIST SP 800-63B requires 64+ | MEDIUM |
| H-14 | **Add CHECK constraints on status/enum columns** — Zero `CheckConstraint` definitions across 34 models | MEDIUM |
| H-15 | **Add MemoryCache eviction** — No proactive eviction. Rate limiter creates unbounded keys | MEDIUM |

### Backlog — Quality improvements (6 items)

| # | What | Impact |
|---|------|--------|
| H-16 | **Migrate to `async def` + `AsyncSession`** — Sync handlers consume threadpool slots (40 default). Bottleneck at 50+ users | HIGH under load |
| H-17 | **Replace COUNT+SELECT with window functions** — 10+ endpoints execute same query twice | MEDIUM |
| H-18 | **Add eager loading strategies** — All `relationship()` use `lazy="select"`. N+1 queries on entity iteration | MEDIUM |
| H-19 | **Split `assertions.py` (6,053 lines)** — Into domain modules (IAM, network, encryption, etc.) | LOW |
| H-20 | **Extract normalizer `_base()` into generic base class** — 40+ normalizers duplicate dispatch patterns | LOW |
| H-21 | **Resolve duplicate Alembic `env.py`** — `alembic/env.py` vs `warlock/db/migrations/env.py` have divergent `render_as_batch` | LOW |

### Additional hardening findings (2026-03-21 review, not yet triaged)

- [ ] GDPR anonymization uses hardcoded HMAC secret (`workflows/gdpr.py:62`)
- [ ] AI error messages leak internal exception details (`assessors/ai_reasoning.py:273-391`)
- [ ] In-memory rate limiter ineffective with multiple workers (`api/middleware.py:39-106`)
- [ ] Swallowed `except Exception: pass` in connectors hides data loss
- [ ] NormalizerRegistry catches exceptions and returns `[]` — failure counter never fires
- [ ] POA&M `_CLOSED_STATUSES` includes `verified` but state machine says it's intermediate
- [ ] `__import__()` used as inline import in production paths
- [ ] Legacy SHA-256 password hashes accepted with no forced migration
- [ ] Pipeline runs all connectors in one transaction — ~59K inserts hold write locks
- [ ] Connection pool (5+10=15) too small for production with audit middleware
- [ ] Test ordering dependency in `test_integration_e2e.py`
- [ ] Tautological assertions in tests (`len(x) >= 0`, `assert True`)
- [ ] 38/82 normalizers, 93/101 assertions, 8/16 workflows have zero behavioral tests
- [ ] No `UniqueConstraint` on natural keys for `ControlResult` and `PostureSnapshot`
- [ ] `AuditEntry.sequence` is `Integer` in migration but `BigInteger` in model

---

## 2. Data Lake — Remaining Work (5 remaining of 48)

Phases 0-3 and hardening are complete. The following items from the original spec are NOT yet implemented.

### Pipeline wiring (1 item)

| # | What | Status |
|---|------|--------|
| DL-WIRE | **Wire orchestrator to lake writers** — `orchestrator.py` has zero lake imports. Pipeline writes exclusively to OLTP. Need to add `write_raw_zone()`, `write_enrichment_zone()`, `write_curated_zone()` calls after each stage, gated by `WLK_LAKE_ENABLED` | NOT DONE — the writers exist and work, the pipeline just never calls them |

### Infrastructure (2 items)

| # | What | Status |
|---|------|--------|
| DL-3 | **Iceberg catalog for cloud** — REST catalog for cloud deployments. Local SQLite catalog works. Cloud REST catalog not implemented | Schema + registration done, cloud REST catalog not wired |
| DL-5 | **Event bus durable backend** — Redis Streams or NATS JetStream for non-dev. Currently in-memory only | Protocol exists, no durable backend implemented |

### Codebase preparation (1 item)

| # | What | Status |
|---|------|--------|
| DL-6 | **Repository pattern completion** — Migrate 44+ raw `session.query()` calls in routers to repository layer. Creates seam for DuckDB swap | Not started |

### Data quality (1 item)

| # | What | Status |
|---|------|--------|
| DL-CROSS | **Crosswalks with confidence scores** — v1 crosswalks had `confidence: "high/medium/low"` and notes. Current crosswalks.yaml has edges but no confidence metadata | Not started |

### Completed data lake items (43 of 48)

<details>
<summary>Click to expand completed items</summary>

- [x] DL-1: Storage abstraction — `storage.py` (local, S3, Azure)
- [x] DL-2: DuckDB feasibility — `query.py` with in-process DuckDB
- [x] DL-4: Local-dev lake story — demo seed produces `lake/` when `WLK_LAKE_ENABLED=true`
- [x] DL-7: Iceberg schemas from SQLAlchemy — `schema.py` + `catalog.py`
- [x] DL-8: Lake writer event bus subscriber — `writer.py`
- [x] DL-9: Raw zone — immutable, append-only, partitioned by source/date
- [x] DL-10: Enrichment zone — normalized findings with hash chain
- [x] DL-11: Curated zone — 10 domains, ~47 tables via `domains.py`
- [x] DL-12: Reconciliation — `reconciliation.py` with row counts + hash sampling
- [x] DL-13: Backfill CLI — `warlock lake backfill`
- [x] DL-14: Batch Parquet writes — one file per table per run
- [x] DL-15-19: All 5 new lake-only domains (evidence, privacy, incident, pipeline health, supply chain)
- [x] DL-20-23: Sub-domains (regulatory change, workpapers, BCA/BIA, training)
- [x] DL-24: Migrate aggregation queries to lake — `readers.py` with DuckDB
- [x] DL-25: Analytics layer — `aggregations.py` with materialized tables
- [x] DL-26: Shadow queries — `shadow.py` for OLTP/lake comparison
- [x] DL-27-33: All CLI commands — `cli/lake.py` (976 lines, 20+ commands)
- [x] DL-34-36: Maintenance — compaction, snapshot expiry, orphan cleanup
- [x] DL-37: OLTP retention freeze — wired to `RetentionManager`
- [x] DL-38: AI inline disable — `ai_inline_disabled` config flag
- [x] DL-39: MCP interface — `mcp_tools.py` (8 tools)
- [x] DL-40: RAG over curated zone — `rag.py` (TF-IDF, 10,535 docs)
- [x] DL-41: AI chat CLI — `warlock ask`
- [x] DL-42-43: OLTP thinning — `oltp_thin.py` with legal hold guard
- [x] DL-44-48: Consumption tier — 5 paths in `consumption.py`
- [x] Hardening: utils extraction, posture readers, legal holds, ABAC filtering, hash sampling, typed Parquet, bridge tables, SCD Type 2, Iceberg wiring, RAG

</details>

---

## 3. New Connectors (30 remaining)

### Tier 1 — DONE (20 of 21 items built)

| Category | Connectors | Status |
|----------|------------|--------|
| Identity & Access | JumpCloud, Auth0/Okta CIC | [x] Done |
| Collaboration & DevOps | GitLab, Jira, Slack, Google Workspace | [x] Done |
| Vulnerability & Code Security | Semgrep, Trivy, GitGuardian, Veracode | [x] Done |
| Infrastructure & Secrets | Terraform Cloud, Docker/Aqua | [x] Done |
| Endpoint & MDM | Kandji | [x] Done |
| SIEM & Observability | Grafana/Loki | [x] Done |
| GRC & Compliance | BitSight | [x] Done |
| HR & People | Gusto, Rippling | [x] Done |
| AI/ML Operations | SageMaker, Databricks | [x] Done |
| Email & Messaging | Microsoft Exchange Online | [x] Done |
| GRC & Compliance | ServiceNow GRC | [ ] Not started |

### Tier 2 — Following sprint (16 items)

Ping Identity, OneLogin, VMware Workspace ONE, Sumo Logic, Cisco Umbrella, Drata (inbound), Vanta (inbound), Archer, Salesforce, Ansible/AWX, ADP, UKG, SAP SuccessFactors, Weights & Biases, Vertex AI, Hugging Face, Mimecast, Stripe, Brex/Ramp

### Tier 3 — Demand-driven (6 items)

Linode/Akamai, Hetzner, LogRhythm, Barracuda, F5 BIG-IP, Paylocity

### Additional categories (10 items, build per customer demand)

~~CI/CD Pipeline Security~~ (Done: Jenkins, GitHub Actions, GitLab CI, CircleCI), Supply Chain/SBOM, Third-Party Risk/Vendor Intel, Backup & DR Validation, Physical Security, PAM (beyond CyberArk), Data Loss Prevention, API Gateways, CRM, DNS/Domain Security, Secrets Management (beyond Vault)

---

## 4. New Frameworks (10 remaining)

### HIGH — Enterprise buyers asking now

| Framework | Controls | Why |
|-----------|----------|-----|
| CIS Controls v8 | 18 controls, 153 safeguards | De facto vendor assessment. Maps to UCF |
| DORA | EU financial sector | Mandatory Jan 2025. 4-hour incident reporting |
| NIS2 | EU network security | Fines up to 10M EUR / 2% turnover |
| CCPA/CPRA | California privacy | Different from GDPR. Every SaaS has CA customers |

### MEDIUM — Specific verticals

| Framework | Why |
|-----------|-----|
| CSA CCM v4 / STAR | Cloud-specific assurance, 197 control objectives |
| ISO 22301 | Business continuity, requested alongside 27001 |
| US State Privacy meta-framework | 19+ state laws, config matrix |
| UK Cyber Essentials | Required for UK government contracts |

### CONDITIONAL — Customer-dependent

TISAX (automotive), SWIFT CSCF (financial messaging)

---

## 5. P2 Features — Differentiation (56 remaining)

### Data Governance & Discovery (7 items)

Databricks Unity Catalog connector, DataHub connector, Atlan connector, active data silo discovery, data classification & sensitivity scoring, data lineage tracking, data silo drift detection

### AI Governance & Shadow AI (5 items)

Shadow AI detection assertions, AI model inventory connectors, AI policy enforcement assertions, cloud AI billing anomaly detection, AI incident tracking model

### GRC Platform Connectors (5 items)

Vanta (inbound), Drata (inbound), AuditBoard (inbound), Conveyor (inbound), outbound GRC export API

### AI Capabilities (5 items)

Natural language compliance queries, automated evidence validation, predictive drift, remediation copilot, compliance-aware code review

### Architecture (8 items)

Multi-tenancy (XL), WebSocket real-time dashboard, plugin architecture for connectors/normalizers, compliance-as-code SDK for CI/CD, table partitioning, TimescaleDB for posture snapshots, full-text search (PostgreSQL tsvector), archive strategy (hot/warm/cold)

### Terraform (3 items)

Multi-cloud parity (AWS 12, Azure 4, GCP 4), Terragrunt wrapper, private module registry

### Compliance Depth (6 items)

FedRAMP ConMon tooling, SOC 2 points of focus (200+), attestation workflow (SOC 2/ISO), CIS Benchmark mappings, NIST 800-53 enhancements (1,034 gaps), reverse crosswalks

### Risk (5 items)

Bayesian network risk models, Business Impact Analysis (XL), insider threat scoring, control effectiveness decay modeling, Monte Carlo parallelism

### Trust Portal (3 items)

Self-service evidence requests, NDA-gated tiered access, incident communication status page

### Privacy (4 items)

Consent management (OneTrust), cross-border transfer tracking, right to data portability, Transcend connector (DSR/data maps)

### Risk Management (4 items)

FAIR taxonomy full decomposition, loss magnitude categories, threat modeling (STRIDE/MITRE ATT&CK), TPRM lifecycle

### Performance (2 items)

Cold start optimization (remove `init_db()` from scheduler tick), iterator-based OPA data assembly

### Privacy Engineering (4 items)

Presidio PII detector (blocked: Python 3.14 compat), detect-secrets assessor, scrubadub export sanitizer, pii-codex classification (blocked: Presidio)

### Export & Reporting (2 items)

Human-readable SSP export (Markdown/PDF), audit package builder CLI

### Supply Chain & Pentest (2 items)

SBOM/supply chain compliance (CycloneDX/SPDX), pentest lifecycle management

---

## 6. P3 Features — Future (18 remaining)

### Platform (6)

GraphQL API, GPU-accelerated Monte Carlo, Lambda SnapStart, embedded OPA, public Terraform Registry, streaming SSP response

### Frameworks (4)

ITAR, CJIS, StateRAMP, NIST AI RMF

### Risk Management (5)

Nth-party vendor risk, SLA compliance per vendor, vendor incident notification, DR testing tracking, KRI dashboard

### Misc (3)

Risk register (beyond POA&Ms), compliance deadline forecasting, privacy by design CI enforcement

---

## 7. Documentation (58 documents planned)

### P0 — Blocking adoption (12 docs)

| Doc | Status | Notes |
|-----|--------|-------|
| API_REFERENCE.md | Not started | 153 routes need documenting |
| API_AUTH_GUIDE.md | Not started | JWT + RBAC + ABAC |
| API_ERRORS.md | Not started | Error code reference |
| OpenAPI Schema Export | Not started | From running server |
| DEPLOYMENT_GUIDE.md | Exists (21KB) | May need update for lake |
| DOCKER_SETUP.md | Not started | |
| SECURITY_HARDENING.md | Not started | Required for audits |
| CLI_REFERENCE.md | Not started | 42+ commands now |
| DEVELOPER_SETUP.md | Not started | |
| CONTRIBUTING.md | Exists | May need update |
| PR template | Not started | |
| README accuracy fixes | Not started | Counts are stale (connectors, tests, etc.) |

### P1 — High-value enablers (26 docs)

Framework guides (6: NIST, SOC 2, ISO 27001, HIPAA, CMMC, overview), connector guides (11: index + AWS + Okta + GCP + template + per-connector), operations runbooks (5: monitoring, DB failure, pipeline stuck, auth outage, audit trail), development docs (3: test strategy, codebase structure, workflow)

### P2 — Polish (20 docs)

Release management (3), architecture decisions (7 ADRs), code style (2), security architecture (2), compliance design (1), misc (5)

---

## 8. Operational Items (9 remaining)

| # | What | Priority |
|---|------|----------|
| O-1 | **Wire FedRAMP/HIPAA/CMMC/GDPR checks to event_types** — YAMLs load but don't produce control mappings. Need event_type + resource_type mappings | MEDIUM |
| O-2 | **demo_exports/** — Pre-generated sample packages for showing output without running | LOW |
| O-3 | **docs/architecture-diagram.html** — Visual architecture (have Figma version now) | LOW |
| O-4 | **Celery integration** — Alternative task queue option. Redis/Kafka/SQS exist, no Celery | LOW |
| O-5 | **nltk CVE remediation** — CVE-2026-33230 and CVE-2026-33231. Pin or isolate RAG module | MEDIUM |
| O-6 | **Connector vendor accuracy pass** — Verify each connector/normalizer against actual vendor API docs. Fix field names, response shapes, pagination patterns. Priority: connectors you plan to connect to real instances first | HIGH (pre-production) |
| O-7 | **Schema registry for event_types** — Catalog what event_types each connector produces and what fields each normalizer expects. Makes gaps visible, enables automated compatibility checks in CI | MEDIUM |
| O-8 | **Smarter fallback normalizer** — Enhance generic normalizer to extract findings from unknown event_types using heuristics (look for severity/status/resource fields in JSON). Prevents silent data loss when connectors produce unhandled event_types | MEDIUM |
| O-9 | **Demo data vendor accuracy** — Update demo_data.py generators to match actual vendor API response schemas so demo data is indistinguishable from real telemetry | LOW (after O-6) |

---

## Summary

| Category | Done | Remaining |
|----------|------|-----------|
| P0/P1 Features | 72 | 0 |
| Hardening (immediate) | 4 | 0 |
| Hardening (Sprint 1) | 5 | 0 |
| Hardening (Sprint 2 + backlog) | 0 | 12 |
| Hardening (untriaged findings) | 0 | 15 |
| Data Lake (Phases 0-3 + hardening) | 43 | 5 |
| New Connectors | 24 | 30 |
| New Frameworks | 0 | 10 |
| P2 Features | 0 | 56 |
| P3 Features | 0 | 18 |
| Documentation | 2 | 58 |
| Operational | 0 | 9 |
| **Total** | **150** | **213** |

---

## What to work on next (recommended order)

1. ~~**Hardening Sprint 1** (H-5 through H-9)~~ — DONE (2026-03-21)
2. **DL-WIRE** — Wire orchestrator to lake writers (the pipeline doesn't call them yet)
3. **Hardening Sprint 2** (H-10 through H-15) — MEDIUM-severity fixes
4. **HIGH frameworks** — CIS v8, DORA, NIS2, CCPA
5. **Tier 2 connectors** — Ping Identity, OneLogin, Sumo Logic, etc. (Tier 1 done)
6. **ServiceNow GRC connector** — Last remaining Tier 1 item

---

## Completed work log

<details>
<summary>P0 Features — 22/22 done</summary>

Parallel collection, batch OPA, double-normalization fix, YAML caching, coverage caching, parallel AI SSP, Prometheus metrics, run-ID correlation, JSONB migration, materialized views, composite indexes, GDPR/HIPAA/FedRAMP bindings, SOC 2 Type II retention, ISO SoA export, API docs, deployment guide, CONTRIBUTING, evidence chain, MFA/TOTP, continuous monitoring

</details>

<details>
<summary>P1 Features — 50/50 done</summary>

All original P1 items (42), MFA encryption, signed challenge tokens, ABAC scope coverage, router split (9 routers), CLI split (8 modules), API test suite (105 tests), shared cache abstraction, assertion expansion (25 → 101)

</details>

<details>
<summary>Hardening immediate — 4/4 done (2026-03-21)</summary>

SQL injection fix in rag.py, background pipeline constructors, PyJWT required, production config validation at startup

</details>

<details>
<summary>Data Lake — 43/48 done (2026-03-21)</summary>

See Section 2 above for full list. 24 lake modules, 535 tests, 10,535 RAG docs, 8/8 Iceberg tables, reconciliation passing.

</details>

<details>
<summary>Hardening Sprint 1 — 5/5 done (2026-03-21)</summary>

H-5: Auth on trust portal document listing (ownership + permission check)
H-6: Disable /docs, /redoc, /metrics in production
H-7: Audit trail write lock reviewed — correct as-is (FOR UPDATE is right for hash chain)
H-8: 9 FK indexes added (issues, compensating_controls, risk_acceptances, evidence_requests) + migration f2a3b4c5d6e7
H-9: Trust portal aggregation pushed to SQL GROUP BY

Also fixed: 2 missing AI task prompts (aggregate_control_assessment, compliance_query), verify_docs normalizer count bug, stale doc counts across README/CLAUDE/CONTRIBUTING.

</details>
