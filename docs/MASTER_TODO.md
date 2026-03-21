# Warlock Master TODO

Consolidated from MASTER_ROADMAP.md (features), HARDENING_TODO.md (security/performance/quality), and TODO.md (docs/ops).
Last updated 2026-03-21.

**Total items: 169** | **Done: 76** | **Remaining: 93**

| Category | Done | Remaining |
|----------|------|-----------|
| Features (P0/P1) | 72 | 0 |
| Hardening | 4 | 17 + 15 unprioritized |
| Features (P2) | 0 | 56 |
| Features (P3) | 0 | 18 |
| Documentation & Ops | 0 | 10 |

---

## Immediate — Before Next Release

All items complete.

- [x] **H-1. Fix SQL injection in `rag.py`** — Replaced f-string raw SQL with SQLAlchemy Core (`pg_insert`, `select`, `func.count`). Table name regex validation was already present. Also fixed bare `conn.execute("CREATE EXTENSION...")` to `text()`. **Done 2026-03-21**
- [x] **H-2. Fix background pipeline empty constructors** — Replaced manual empty constructors with `build_pipeline()` from `warlock.pipeline.loader`, matching the CLI path. Passes `source` filter as tuple. **Done 2026-03-21**
- [x] **H-3. Make PyJWT a required dependency** — PyJWT was already in required deps. Removed `_hmac_encode`/`_hmac_decode` fallback functions and all `_HAS_PYJWT` conditional branches. `decode_access_token` now uses PyJWT's built-in `exp` verification. **Done 2026-03-21**
- [x] **H-4. Call `validate_production_config()` at app startup** — Added call in `create_app()` before CORS and route registration. Production deploys now fail fast on missing JWT secret or encryption key. **Done 2026-03-21**

---

## Sprint 1 — Hardening (1 week)

Security and performance fixes for existing code.

- [ ] **H-5. Add auth to trust portal document listing** — `/trust/access-requests/{request_id}/documents` in `api/trust_portal.py:678-707` is unauthenticated. Any leaked UUID grants NDA-tier document access. Add authentication or email-verified access token. **Severity: HIGH**
- [ ] **H-6. Disable `/docs`, `/redoc`, `/metrics` in production** — Swagger UI exposes full API map (`api/app.py:37-38`). Prometheus metrics expose internal performance data (`api/app.py:126-133`). Set `docs_url=None`, `redoc_url=None` when `env == "production"`. Protect `/metrics` behind auth or internal-only binding. **Severity: HIGH**
- [ ] **H-7. Remove global audit trail write lock** — `FOR UPDATE` on latest `AuditEntry` row (`db/audit.py:96-101`) serializes all API writes. Every request contends for the same row lock via `RequestAuditMiddleware`. Replace with DB-native `SEQUENCE` on PostgreSQL, or batch audit writes asynchronously. **Severity: HIGH**
- [ ] **H-8. Add FK indexes on `issues` table** — `finding_id`, `control_result_id`, `poam_id` columns in `db/models.py:636-638` lack indexes. Governance API queries do full table scans on JOINs. Add `index=True` to each FK column. Also missing on: `attestations.engagement_id`, `compensating_controls.poam_id`, `risk_acceptances.poam_id`, `evidence_requests.engagement_id`. **Severity: HIGH**
- [ ] **H-9. Push trust portal aggregation to SQL** — `api/trust_portal.py:148` loads all ~1,996 `PostureSnapshot` rows into Python memory on every unauthenticated request, then aggregates in-memory. Replace with `GROUP BY framework` SQL query. **Severity: HIGH**

---

## Sprint 2 — Hardening (2 weeks)

Test coverage, data integrity, and security tightening.

- [ ] **H-10. Create `tests/conftest.py` and `tests/test_cli.py`** — No shared test fixtures exist; DB setup duplicated 8 times across 7 files. CLI has 43 commands and zero tests. Create `conftest.py` with shared `db_engine`/`db_session` fixtures. Create `test_cli.py` with `CliRunner` smoke tests for all 8 command groups. **Severity: MEDIUM**
- [ ] **H-11. Unify prompt sanitization paths** — Legacy `_sanitize_field()` in `assessors/ai_reasoning.py:155-164` does not strip `</evidence>` tags. Newer `warlock/ai/sanitize.py` does. All four AI reasoners use the legacy path. Redirect to the unified sanitizer. **Severity: MEDIUM**
- [ ] **H-12. Scope AI conversation sessions to user** — `/ai/converse`, `/ai/conversations/{session_id}`, `DELETE /ai/conversations/{session_id}` in `api/routers/ai_routes.py:340-434` check permissions but not session ownership. Any authenticated user can read/delete any other user's conversations. Store and verify `user_id` on `ConversationSession`. **Severity: MEDIUM**
- [ ] **H-13. Increase backup code entropy to 64 bits** — `secrets.token_hex(4)` in `api/auth.py:527` produces only 32 bits. NIST SP 800-63B recommends 64+ bits for authentication secrets. Change to `secrets.token_hex(8)`. **Severity: MEDIUM**
- [ ] **H-14. Add CHECK constraints on status/enum columns** — Zero `CheckConstraint` definitions across all 34 models in `db/models.py`. Status fields accept any string if ORM is bypassed. Add constraints for: `ControlResult.status`, `Finding.severity`, `ConnectorRun.status`, `Issue.status`, `Issue.priority`, `POAM.status`, `RiskAcceptance.status`, `Attestation.status`. **Severity: MEDIUM**
- [ ] **H-15. Add MemoryCache eviction** — `utils/cache.py:34-68` has no proactive eviction; expired entries only removed on `get()`. Rate limiter creates unbounded keys per client per minute window. Add LRU cap or periodic sweep thread. **Severity: MEDIUM**

---

## Hardening Backlog

Lower-priority quality and performance improvements. No fixed timeline.

- [ ] **H-16. Migrate sync handlers to `async def` with `AsyncSession`** — All API route handlers use synchronous `def`, consuming threadpool slots (default 40). Under 50+ concurrent users, threadpool exhaustion becomes the bottleneck. Requires `create_async_engine` + `AsyncSession` in `db/engine.py`. **Impact: HIGH under load**
- [ ] **H-17. Replace COUNT+SELECT with window functions** — 10+ paginated endpoints execute the same filtered query twice (`query.count()` then `query.all()`). Use `func.count().over()` in a single query. Found in: `compliance.py:291`, `governance.py:477`, `admin.py:778`, `export.py:252`, and 6+ others. **Impact: MEDIUM**
- [ ] **H-18. Add eager loading strategies to relationships** — All 8 `relationship()` declarations in `db/models.py` use default `lazy="select"`. Any code path iterating entities and accessing children triggers N+1 queries. Add `selectinload()` or `joinedload()` to frequently traversed paths. **Impact: MEDIUM**
- [ ] **H-19. Split `assertions.py` (6,053 lines) into domain modules** — Single file contains all 101 assertions, control bindings, and remediation data. Split into `assertions_iam.py`, `assertions_network.py`, `assertions_encryption.py`, etc. Use `__init__.py` to re-export. **Impact: LOW (maintainability)**
- [ ] **H-20. Extract normalizer `_base()` into generic base class** — 40+ normalizers duplicate identical `_base()`, `can_handle()`, and `normalize()` dispatch patterns. Extract a `DispatchNormalizer` base parameterized by `source_name` and `source_type`. Eliminates ~200 lines of boilerplate. **Impact: LOW (maintainability)**
- [ ] **H-21. Resolve duplicate Alembic `env.py`** — `alembic/env.py` and `warlock/db/migrations/env.py` have divergent `render_as_batch` behavior. Running `alembic upgrade head` from project root vs `warlock db upgrade` produces different results on SQLite. Keep only one. **Impact: LOW (correctness risk)**

---

## P2 Features — Next Quarter (56 items)

Differentiation. Makes Warlock unique.

### Data Governance & Discovery (7 items)

| # | What | Effort | Why |
|---|------|--------|-----|
| 136 | **Databricks Unity Catalog connector** — table/column access controls, audit logs, data lineage, ML model governance via REST API. SourceType: DATA_GOVERNANCE | L | Data governance + ML model inventory in one source |
| 137 | **DataHub connector** — open source (Apache 2.0) metadata platform. Pull data catalog, column-level lineage, quality assertions, governance policies via GraphQL. SourceType: DATA_GOVERNANCE | L | Free data catalog — instant data silo discovery, PCI CDE scoping, HIPAA PHI tracking, GDPR Article 30 |
| 138 | **Atlan connector** — enterprise data catalog. Pull metadata, lineage, classification, governance policies via REST + GraphQL. SourceType: DATA_GOVERNANCE | M | Enterprise data governance catalog |
| 139 | **Active data silo discovery** — enhance AWS/Azure/GCP connectors to enumerate all data stores (S3, RDS, DynamoDB, Redshift, Glue, Storage Accounts, SQL DBs, Cosmos DB, BigQuery, Cloud SQL, GCS). Auto-create DataSilo records for unclassified stores | L | Orgs don't know where all their data lives — automated discovery is table stakes for GDPR/HIPAA/PCI |
| 140 | **Data classification & sensitivity scoring** — PII/PHI/PCI pattern detection on discovered data stores. Column-level sensitivity tagging. Feed results into data silo model | L | Classification without detection is just a spreadsheet |
| 141 | **Data lineage tracking** — ETL pipeline tracking (Airflow, dbt, Fivetran), API call graphs, DataHub/Atlan integration for existing lineage | M | Required for GDPR DPIAs, PCI CDE scoping, breach impact analysis |
| 142 | **Data silo drift detection** — alert when new data stores appear that aren't classified. Compare current cloud inventory against known silos. EventBus integration for real-time alerts | M | Unknown data stores are unprotected data stores |

### AI Governance & Shadow AI (5 items)

| # | What | Effort | Why |
|---|------|--------|-----|
| 143 | **Shadow AI detection assertions** — analyze Zscaler/Netskope/proxy connector data for unauthorized calls to api.openai.com, api.anthropic.com, generativelanguage.googleapis.com. Map to ISO 42001 and EU AI Act controls | M | Growing regulatory requirement; orgs can't govern AI they don't know about |
| 144 | **AI model inventory connectors** — SageMaker Model Registry, Azure ML, Vertex AI Model Registry, HuggingFace Hub. Track deployed models, versions, training data provenance | L | ISO 42001 requires AI asset inventory; EU AI Act requires high-risk AI registry |
| 145 | **AI policy enforcement assertions** — approved model registry checks, data classification gates (PII/PHI must not be sent to external AI APIs), human oversight requirements for high-risk decisions | M | Maps directly to existing EU AI Act (33 controls) and ISO 42001 (39 controls) frameworks |
| 146 | **Cloud AI billing anomaly detection** — monitor cloud billing APIs for unexpected AI API charges as shadow AI signal | S | Low-effort shadow AI indicator from data already in cloud connectors |
| 147 | **AI incident tracking model** — AI-specific incident type for bias events, hallucination reports, data leakage via AI, model performance degradation | M | EU AI Act Article 62 requires serious incident reporting for high-risk AI |

### GRC Platform Connectors (5 items)

| # | What | Effort | Why |
|---|------|--------|-----|
| 148 | **Vanta connector** (inbound) — pull test results, evidence, monitor status via REST API. SourceType: GRC | M | Aggregation layer for orgs already running Vanta |
| 149 | **Drata connector** (inbound) — pull controls, evidence, personnel compliance via REST API. SourceType: GRC | M | Aggregation layer for orgs already running Drata |
| 150 | **AuditBoard connector** (inbound) — pull audit findings, control testing results, SOX workflows via REST API. SourceType: GRC | M | Enterprise GRC aggregation |
| 151 | **Conveyor connector** (inbound) — pull security review status, questionnaire responses via REST API. SourceType: GRC | S | Trust center / security review aggregation |
| 152 | **Outbound GRC export API** — export Warlock data in Vanta/Drata/AuditBoard formats so Warlock can be the compliance engine behind any GRC frontend | L | "Warlock powers them" play — the more interesting direction |

### Privacy Operations (1 item)

| # | What | Effort | Why |
|---|------|--------|-----|
| 153 | **Transcend connector** — pull privacy requests (DSR), data maps, consent records via REST API. Feed into GDPR workflows and data silo inventory. SourceType: GRC | M | Privacy operations automation — DSR compliance, consent management |

### AI (5 items)

| # | What | Effort |
|---|------|--------|
| 61 | Natural language compliance queries | L |
| 62 | Automated evidence validation | M |
| 63 | Predictive drift | M |
| 64 | Remediation copilot | M |
| 65 | Compliance-aware code review | L |

### Architecture (8 items)

| # | What | Effort |
|---|------|--------|
| 66 | Multi-tenancy | XL |
| 67 | WebSocket real-time dashboard | M |
| 68 | Plugin architecture for connectors/normalizers | L |
| 69 | Compliance-as-Code SDK for CI/CD | L |
| 70 | Table partitioning for 6 high-growth tables | M |
| 71 | TimescaleDB for posture snapshots | L |
| 72 | Full-text search via PostgreSQL tsvector | M |
| 73 | Archive strategy — hot/warm/cold with legal hold awareness | M |

### Terraform (3 items)

| # | What | Effort |
|---|------|--------|
| 74 | Multi-cloud parity — AWS 12, Azure 4, GCP 4 modules | L |
| 75 | Terragrunt wrapper for multi-account deployment | L |
| 76 | Private module registry | M |

### Compliance Depth (6 items)

| # | What | Effort |
|---|------|--------|
| 77 | FedRAMP ConMon tooling | L |
| 78 | SOC 2 points of focus (200+) | M |
| 79 | Attestation workflow — SOC 2/ISO artifact generation | M |
| 80 | CIS Benchmark mappings for AWS/Azure/GCP | M |
| 81 | NIST 800-53 enhancement-level coverage (1,034 gaps) | XL |
| 82 | Reverse crosswalks — HIPAA→UCF, GDPR→UCF | M |

### Risk (5 items)

| # | What | Effort |
|---|------|--------|
| 83 | Bayesian network risk models | L |
| 84 | Business Impact Analysis module | XL |
| 85 | Insider threat scoring from IAM/EDR behavioral data | M |
| 86 | Control effectiveness decay modeling | M |
| 87 | Monte Carlo ProcessPoolExecutor for portfolio parallelism | M |

### Trust Portal (3 items)

| # | What | Effort |
|---|------|--------|
| 88 | Self-service evidence requests | M |
| 89 | NDA-gated tiered access levels | M |
| 90 | Incident communication status page | M |

### Privacy (3 items)

| # | What | Effort |
|---|------|--------|
| 91 | Consent management integration (OneTrust connector) | M |
| 92 | Cross-border transfer tracking | M |
| 93 | Right to data portability — standardized export format | S |

### Risk Management (4 items)

| # | What | Effort |
|---|------|--------|
| 94 | FAIR taxonomy full decomposition | M |
| 95 | Loss magnitude categories — productivity/response/fines/reputation | M |
| 96 | Threat modeling integration — STRIDE/MITRE ATT&CK | L |
| 97 | TPRM lifecycle — onboarding/assessment/monitoring/offboarding | L |

### Performance (2 items)

| # | What | Effort |
|---|------|--------|
| 98 | Cold start optimization — remove `init_db()` from scheduler tick | S |
| 99 | Iterator-based OPA data assembly — eliminate second findings copy | M |

### Privacy Engineering (4 items)

| # | What | Effort | Notes |
|---|------|--------|-------|
| 119 | Presidio PII detector assessor | M | Blocked: Presidio incompatible with Python 3.14 |
| 120 | detect-secrets pipeline assessor | S | |
| 121 | scrubadub export sanitizer | S | |
| 122 | pii-codex regulatory classification | S | Blocked: depends on Presidio |

### Export & Reporting (2 items)

| # | What | Effort |
|---|------|--------|
| 124 | Human-readable SSP export — Markdown/PDF with narrative statements | L |
| 125 | Audit package builder CLI — bundles SSP + AR + POA&M + evidence binder | M |

### Supply Chain & Pentest (2 items)

| # | What | Effort |
|---|------|--------|
| 134 | SBOM / supply chain compliance — CycloneDX/SPDX, VEX, license compliance | L |
| 135 | Pentest lifecycle management — engagement tracking, finding dedup, vuln SLA | L |

---

## P3 Features — Future (18 items)

When the product has traction.

### Platform (6 items)

| # | What | Effort |
|---|------|--------|
| 100 | GraphQL API alongside REST | L |
| 101 | GPU-accelerated Monte Carlo via cupy | L |
| 102 | Lambda SnapStart for serverless | L |
| 103 | Embedded OPA — eliminate sidecar HTTP | L |
| 104 | Public Terraform Registry publication | XL |
| 105 | Streaming SSP response via `StreamingResponse` | M |

### Frameworks (4 items)

| # | What | Effort |
|---|------|--------|
| 106 | ITAR framework | L |
| 107 | CJIS framework | M |
| 108 | StateRAMP framework | M |
| 109 | NIST AI RMF | M |

### Risk Management (5 items)

| # | What | Effort |
|---|------|--------|
| 110 | Nth-party vendor risk visibility | M |
| 111 | SLA compliance tracking per vendor | S |
| 112 | Vendor incident notification workflow | M |
| 113 | DR testing tracking | M |
| 114 | KRI (Key Risk Indicators) dashboard | M |

### Misc (3 items)

| # | What | Effort |
|---|------|--------|
| 115 | Risk register — strategic/operational/financial beyond POA&Ms | M |
| 116 | Compliance deadline forecasting | M |
| 118 | Privacy by design CI enforcement | M |

---

## Documentation & Operations (10 items)

From v1 ZIP comparison (2026-03-19) and ongoing needs. Not blocking — operational/documentation quality.

### Medium Priority

- [ ] **DEPLOYMENT_GUIDE.md** — Port and update the 765-line production ops guide from v1 (cron scheduling, Lambda packaging, Docker/ECS, alerting setup, troubleshooting). Currently only have DEMO.md for local use.
- [ ] **CHANGELOG.md** — Create release history. v1 had 142 lines of changelog.
- [ ] **CONTRIBUTING.md** — Create contribution guidelines (branching, PR process, code style, test requirements).
- [ ] **Wire FedRAMP/HIPAA/CMMC/GDPR framework checks to event_types** — The 4 new framework YAMLs load but don't produce active control mappings because their checks don't reference connector event_types. Need to author the event_type + resource_type mappings for each control.
- [ ] **Crosswalks with confidence scores** — The v1 `config/crosswalks.yaml` (873 lines) has `confidence: "high/medium/low"` and notes per mapping. Our crosswalks.yaml has edges but no confidence metadata.

### Low Priority

- [ ] **demo_exports/** — Pre-generated sample audit packages, executive summaries, POA&M exports for showing output without running the platform.
- [ ] **docs/architecture-diagram.html** — Visual architecture diagram from v1.
- [ ] **Warlock_Technical_Documentation.pdf** — 1.3MB technical doc from v1. Review for reusable content.
- [ ] **Celery integration** — v1 had `celery_app.py` + `docker-compose.celery.yaml` as an alternative task queue. The repo has Redis/Kafka/SQS in `pipeline/queue.py` but no Celery option.
- [ ] **nltk CVE remediation** — `nltk 3.9.3` has CVE-2026-33230 and CVE-2026-33231. Pin to patched version when available, or isolate the RAG module as an optional extra.

---

## Additional Hardening Findings

Identified during the 2026-03-21 production quality review. Not yet prioritized into sprints — evaluate when touching adjacent code.

- GDPR anonymization uses hardcoded default HMAC secret (`workflows/gdpr.py:62`) — refuse to run without configured `WLK_GDPR_HMAC_SECRET` in production
- AI error messages leak internal exception details to callers (`assessors/ai_reasoning.py:273-391`) — log server-side, return generic message
- In-memory rate limiter ineffective with multiple uvicorn workers (`api/middleware.py:39-106`) — require `WLK_CACHE_URL` in production
- Swallowed `except Exception: pass` in connectors hides data loss (`connectors/okta.py:131`, `github.py:127`, etc.)
- NormalizerRegistry catches exceptions and returns `[]` — orchestrator failure counter never fires (`normalizers/base.py:128-138`)
- POA&M `_CLOSED_STATUSES` includes `verified` but state machine says it's intermediate (`workflows/poam.py:20-23`)
- `__import__()` used as inline import in production paths (`api/deps.py:108`, `pipeline/orchestrator.py:39`)
- Legacy SHA-256 password hashes still accepted with no forced migration (`api/auth.py:113-124`)
- Pipeline runs all connectors in one transaction — ~59K inserts hold write locks (`pipeline/orchestrator.py:92-249`)
- Connection pool size (5+10=15) too small for production with audit middleware doubling usage (`db/engine.py:50-55`)
- Test ordering dependency in `test_integration_e2e.py` — module-scoped session creates cross-class state leaks
- Tautological assertions in tests (`len(x) >= 0`, `assert True`) give false confidence
- 38/58 normalizers, 93/101 assertions, 8/16 workflows have zero behavioral test coverage
- No `UniqueConstraint` on natural keys for `ControlResult` and `PostureSnapshot`
- `AuditEntry.sequence` is `Integer` in migration but `BigInteger` in model — type mismatch on PostgreSQL

---

## Completed

<details>
<summary>P0 Features — 22/22 done</summary>

- [x] 1. Parallel connector collection — `ThreadPoolExecutor` in `collect_all()` (S)
- [x] 2. Batch OPA evaluation — 592 HTTP calls → 7 per framework (M)
- [x] 3. Fix double-normalization in OPA evaluator (S)
- [x] 4. Framework YAML `@lru_cache` — stop re-parsing disk every run (S)
- [x] 5. Coverage summary caching — hottest endpoint does full table scan (S)
- [x] 6. Parallel AI calls for SSP export — `asyncio.gather` (M)
- [x] 7. Prometheus `/metrics` endpoint (S)
- [x] 8. Run-ID log correlation (S)
- [x] 9. JSON → JSONB migration for PostgreSQL (S)
- [x] 10. Materialized views — coverage, posture, framework rollups (M)
- [x] 11. Composite index on `control_results(framework, status, assessed_at)` (S)
- [x] 12. GDPR assertion bindings + Rego policies (L)
- [x] 13. HIPAA assertion bindings (S)
- [x] 14. FedRAMP SSP template + CRM + CIS generation (XL)
- [x] 15. SOC 2 Type II historical evidence retention (L)
- [x] 16. ISO 27001 Statement of Applicability export (M)
- [x] 17. API documentation — mount FastAPI `/docs` (S)
- [x] 18. Deployment guide (L)
- [x] 19. CONTRIBUTING.md (S)
- [x] 20. Evidence chain of custody — hash verification (M)
- [x] 21. MFA/TOTP support (L)
- [x] 22. Continuous control monitoring — event-driven reassessment (L)

</details>

<details>
<summary>P1 Features — 50/50 done</summary>

- [x] 23–60, 123. All original P1 items (42 done)
- [x] 126. Encrypt MFA TOTP secrets with FieldEncryptor (S) — done 2026-03-21
- [x] 127. Signed MFA challenge tokens (S) — done 2026-03-21
- [x] 128. Complete ABAC scope coverage on risk/policy/simulation endpoints (M) — done 2026-03-21
- [x] 129. Split app.py into 9 FastAPI domain routers (L) — done 2026-03-21
- [x] 130. Split cli.py into 8 Click sub-modules (M) — done 2026-03-21
- [x] 131. API test suite — 105 HTTP-level tests covering auth, ABAC, pagination, all routers (L) — done 2026-03-21
- [x] 132. Move in-memory state to shared cache (MemoryCache/RedisCache abstraction) (M) — done 2026-03-21
- [x] 133. Assertion expansion 25 → 101 across 14 control families (XL) — done 2026-03-21

</details>

<details>
<summary>Hardening — 4/4 immediate items done (2026-03-21)</summary>

- [x] H-1. Fix SQL injection in `rag.py` — done 2026-03-21
- [x] H-2. Fix background pipeline empty constructors — done 2026-03-21
- [x] H-3. Make PyJWT required, remove fallback JWT — done 2026-03-21
- [x] H-4. Call `validate_production_config()` at startup — done 2026-03-21

</details>

---

## Effort Summary — Remaining Only

| Category | Items | S | M | L | XL |
|----------|-------|---|---|---|---|
| Hardening (Sprint 1) | 5 | 0 | 0 | 0 | 0 |
| Hardening (Sprint 2) | 6 | 0 | 0 | 0 | 0 |
| Hardening (Backlog) | 6 | 0 | 0 | 0 | 0 |
| P2 Features | 56 | 6 | 28 | 18 | 4 |
| P3 Features | 18 | 1 | 9 | 7 | 1 |
| Docs & Ops | 10 | — | — | — | — |
| **Total remaining** | **101** | | | | |

Hardening items are scoped by sprint, not sized by S/M/L — they are fixes, not features.

---

## Coverage Verification

Original roadmap coverage from 9 specialist agent analyses (2026-03-19), Senior GRC Assessment (2026-03-20), Product Vision (2026-03-21), and Production Quality Review (2026-03-21).

| Source | Total Findings | Covered | Gap |
|--------|---------------|---------|-----|
| GRC Engineer | 20 enhancements | 20/20 | 0 |
| Architect | 18 findings | 18/18 | 0 |
| Security | 36 findings | 36/36 | 0 |
| Database | 9 findings | 9/9 | 0 |
| Terraform | 7 findings | 7/7 | 0 |
| Compliance | 23 findings | 23/23 | 0 |
| Performance | 34 findings | 34/34 | 0 |
| Documentation | 7 categories | 7/7 | 0 |
| Risk Manager | 28 findings | 28/28 | 0 |
| Senior GRC Assessment (2026-03-20) | 10 new findings | 10/10 | 0 |
| Product Vision (2026-03-21) | 20 new items | 20/20 | 0 |
| Production Quality Review (2026-03-21) | 37 findings | 37/37 | 0 |
| **Total** | **249 findings** | **249/249** | **0 gaps** |
