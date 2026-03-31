# Warlock — Master TODO

> **Generated**: 2026-03-26
> **Source**: Merged from GAPS.md (101 findings), STUBS.md (33 findings), ARCHITECTURE.md (37 findings)
> **Effort scale**: S = <1 day, M = 1-3 days, L = 3-5 days, XL = 1+ week

---

## How to Use This File

Items are grouped by priority tier, then by domain within each tier. Each item references its source finding ID(s) for traceability back to the detailed analysis files.

**Priority definitions:**
- **P0** — Crash, data corruption, security bypass, or false confidence. Fix before any demo or eval.
- **P1** — Broken workflow, dead UI, missing model/migration. Blocks realistic usage.
- **P2** — Incomplete feature, weak coverage, cosmetic/UX issue. Limits credibility.
- **P3** — Nice-to-have, future roadmap. No current impact.

---

## P0 — CRITICAL (Fix Before Any Demo)

### Database / Models

- [x] **~~Fix POA&M CHECK constraint~~** — Already includes `risk_accepted` and `cancelled`. *(GAP-001)* `S`
- [x] **~~Unify audit chain hash algorithm~~** — Standardized `evidence_sha256 or ""` across record(), verify_chain(), CLI. *(GAP-002, STUB-028, STUB-027)* `S`

### CLI

- [x] **~~Fix ConMon crash on empty findings~~** — Already guarded with `if total_results > 0`. *(GAP-003)* `S`
- [x] **~~Fix `link change-compliance` crash~~** — Refactored: no longer takes `--framework` param. *(GAP-006)* `S`
- [x] **~~Fix `vendors list` mutating database~~** — Changed to `get_read_session()`. *(GAP-007)* `S`

### Frontend

- [x] **~~Wire POA&M action buttons~~** — Connected transition buttons to backend endpoints with loading state. *(GAP-004, STUB-024)* `M`
- [x] **~~Fix Create POA&M form~~** — Added create dialog with API call, loading state, success navigation. *(GAP-005)* `M`

### Platform

- [x] **~~Design multi-tenancy data isolation~~** — Tenant model, TenantMixin on all 47 models, ContextVar-based session filtering, API middleware, Alembic migration with backfill. *(GAP-008, STUB-030, ARCH-023)* `XL`

### False Confidence (EXTREME — Fix Immediately)

- [x] **~~Fix `control-tests gaps` false negative~~** — Added `no_manual_test` gap type for examined_at=NULL. *(GAP-032, STUB-021)* `M`
- [x] **~~Fix `evidence gaps` false negative~~** — Reports all controls lacking uploaded evidence. *(STUB-022)* `M`
- [x] **~~Fix dashboard hardcoded "Hash Chain: Verified"~~** — Calls useVerifyAuditTrail() API. *(STUB-023, GAP-070)* `S`
- [x] **~~Fix CLI `audit-trail verify` hash algorithm~~** — Uses JSON sort_keys=True matching audit.py. *(STUB-028)* `S`
- [x] **~~Fix audit trail hash chain broken in demo~~** — Moved verification after all entries seeded. *(STUB-027)* `M`

---

## P1 — SIGNIFICANT (Blocks Realistic Usage)

### Database / Migrations

- [x] **~~Add Alembic migration for Evidence model~~** *(GAP-009)* `M`
- [x] **~~Add Alembic migration for Policy model~~** *(GAP-010)* `M`
- [x] **~~Add Alembic migration for Workpaper model~~** *(GAP-013)* `M`
- [x] **~~Add Alembic migration for Incident model~~** *(GAP-014)* `M`
- [x] **~~Add Alembic migrations for 9+ remaining models~~** — PostureSnapshot, ChangeEvent, SystemProfile, CompensatingControl, RiskAcceptance, VendorAssessment, DataProcessingActivity, PrivacyImpactAssessment, AIModelCard, Embedding. *(GAP-015, GAP-016, ARCH-006)* `L`
- [x] **~~Fix POA&M date columns~~** — Change `scheduled_completion_date` and `actual_completion_date` from String to Date columns. *(GAP-011)* `M`
- [x] **~~Add DB connection pooling config for PostgreSQL~~** — pool_size, max_overflow, pool_pre_ping, pool_recycle. *(GAP-048)* `S`
- [x] **~~Add Asset model with FK to Finding~~** — Proper asset inventory model, not just string matching on resource_id. *(GAP-055)* `L`

### Workflows

- [x] **~~Fix risk acceptance lifecycle~~** — Add `review()` method to transition pending → reviewed, or accept pending in `approve()`. *(GAP-012)* `M`
- [x] **~~Fix SLA model enforcement~~** — SLA model tracks but doesn't enforce. Add auto-due-date on POA&M creation. *(GAP-034)* `M`
- [x] **~~Build approval workflow engine~~** — Multi-level approval chains, SLA tracking on approvals, escalation on stale approvals. *(GAP-042)* `L`
- [x] **~~Add evidence collection scheduling~~** — Automated "collect screenshot every 30 days" for recurring evidence. *(GAP-043)* `L`

### API

- [x] **~~Fix HTTP 429 to return JSON~~** — Rate limit responses return HTML instead of JSON. *(GAP-017)* `S`
- [x] **~~Add pagination to 6+ list endpoints~~** — Users, systems, attestations, engagements, API keys, connectors. *(GAP-018)* `M`
- [x] **~~Add API routes for 18 unexposed models~~** — RawEvent, ControlInheritance, SystemDependency, Vendor, Asset, PipelineRun, etc. *(GAP-020)* `XL`
- [x] **~~Add `/auth/me` endpoint~~** — Return current user's role, permissions, allowed frameworks. *(GAP-021)* `S`
- [x] **~~Add POA&M create/update/transition API endpoints~~** — POST, PATCH, and transition endpoints for POAMManager. *(GAP-022)* `M`
- [x] **~~Fix pipeline status endpoint~~** — Return actual queue depth, processing state, and throughput instead of hardcoded zeros. *(GAP-023, STUB-029)* `S`

### Frontend

- [x] **~~Fix or remove login page~~** — Either wire it to the auth API or remove since auto-auth is in place. *(GAP-025)* `S`
- [x] **~~Wire frontend forms to API~~** — Replace `console.log("TODO")` submit handlers with actual API calls. *(GAP-026)* `L`
- [x] **~~Fix frontend incident statuses~~** — Align frontend status values (investigating, mitigating) with backend-accepted values (assigned, in_progress). *(GAP-037)* `S`
- [x] **~~Build auditor self-service portal~~** — Consume existing trust portal API endpoints. *(GAP-047)* `L`
- [x] **~~Build user self-service evidence submission portal~~** — Control owners can upload evidence without CLI. *(GAP-054)* `L`

### Security

- [x] **~~Add CSRF protection~~** — Double-submit cookie or synchronizer token for state-changing requests. *(GAP-027, ARCH-014)* `S`
- [x] **~~Add Redis-backed rate limiting~~** — Replace per-worker in-memory counters with shared Redis backend. *(GAP-028, ARCH-010)* `M`
- [x] **~~Fix GDPR erasure logging~~** — Log HMAC pseudonym instead of plaintext email after anonymization. *(GAP-029, ARCH-013)* `S`
- [x] **~~Add session invalidation / token revocation~~** — Token blacklist in Redis/DB with TTL matching JWT expiry. *(GAP-050)* `M`

### CLI

- [x] **~~Fix `audit hash-verify` and `audit chain` crashes~~** *(GAP-035)* `S`
- [x] **~~Fix `system-controls` showing wrong framework~~** — Filter to system-associated frameworks only. *(GAP-036)* `S`
- [x] **~~Fix `reports executive-export -f` crash~~** — Fix `filter()` after `limit()` SQLAlchemy error. *(GAP-038)* `S`
- [x] **~~Fix pipeline hash-verify false mismatches~~** — Use same hash algorithm as pipeline storage. *(GAP-039)* `S`
- [x] **~~Fix risk appetite unit comparison~~** — Compare against FAIR ALE, not raw risk score vs dollar threshold. *(GAP-040)* `S`
- [x] **~~Fix `frameworks inheritance` to read reference file~~** — Wire CLI to `reference/inherited_controls.yaml`. *(GAP-041)* `S`

### Connectors

- [x] **~~Fix Veracode HMAC signing~~** — Recompute signature per request, use `secrets.token_hex()` for nonce. *(GAP-019)* `S`
- [x] **~~Add HTTP 429 retry to BaseConnector~~** — Exponential backoff with jitter on 429/5xx responses. *(ARCH-002)* `M`
- [x] **~~Add Palo Alto Networks connector~~** — Dominant NGFW, needed for PCI/NIST/ISO. *(GAP-051)* `M`
- [x] **~~Add ServiceNow CMDB connector~~** — Pull CIs and relationships for CM-8 compliance. *(GAP-052)* `L`

### Pipeline

- [x] **~~Fix demo seed phases 2-5~~** — Fix `AuditTrail.append()` AttributeError and `raw_event_count` invalid kwarg. *(GAP-030, STUB-020)* `S`
- [x] **~~Add dead letter queue~~** — DLQ table with failed event payload, error message, retry count, status. CLI for list/retry/purge. *(GAP-033, ARCH-001)* `M`

### Policy / OPA

- [x] **~~Fill NIST 800-53 empty checks~~** — 694 of 1,176 controls have empty `checks` arrays, always `not_assessed`. *(GAP-031)* `XL`

### DevOps

- [x] **~~Create Dockerfile and docker-compose~~** — Multi-stage Dockerfile, docker-compose with app + PostgreSQL + OPA + Redis. *(GAP-024, ARCH-018)* `M`

### Reporting

- [x] **~~Add PDF report generation~~** — WeasyPrint or ReportLab for board reports and audit packages. *(GAP-044)* `M`

### Integrations

- [x] **~~Add bi-directional Jira sync~~** — Webhook receiver for Jira status changes back to Warlock. *(GAP-045)* `M`
- [x] **~~Add email notification system~~** — SMTP/SES integration with templates for alerts, digests, evidence requests. *(GAP-046)* `M`

### Platform

- [x] **~~Add document management / policy repository~~** — Track policy documents with version history, approval workflow, review scheduling. *(GAP-053)* `L`
- [x] **~~Add webhook-based real-time ingestion~~** — EventBridge/Event Grid receivers alongside batch collection. *(GAP-049)* `L`

---

## P2 — HARDENING (Limits Credibility)

### Policy / OPA

- [x] **~~Add Rego policies for 6 zero-coverage frameworks~~** — ISO 27701, ISO 42001, FedRAMP, GDPR, EU AI Act, SEC Cyber. *(GAP-056)* `XL`
- [x] **~~Improve SOC 2 Rego coverage~~** — Currently 13 of 46 controls (28%). *(GAP-057)* `L`
- [x] **~~Add assertions for administrative controls~~** — SoD, data classification, training, background checks, BCP, vendor due diligence. *(GAP-058)* `L`

### Connectors

- [x] **~~Convert 84 mock connectors to real implementations~~** — Prioritize ASSET_MGMT, GRC, API_SECURITY, COST, BACKUP categories. *(GAP-059, STUB-001)* `XL`
- [x] **~~Add connector credential rotation~~** — Secrets backend abstraction with rotation support (Vault, AWS Secrets Manager). *(GAP-076)* `M`
- [x] **~~Add Proofpoint TAP connector~~** — Email threat data beyond URL defense. *(GAP-085)* `M`
- [x] **~~Add Zscaler connector~~** — ZIA/ZPA/ZDX for zero trust evidence. *(GAP-086)* `M`
- [x] **~~Add physical security connectors~~** — Lenel/S2, Genetec, HID Global, Brivo, Envoy. *(GAP-087)* `L`
- [x] **~~Add GovCloud connector variants~~** — AWS GovCloud, Azure Government, GCP Assured Workloads endpoints. *(GAP-088)* `M`
- [x] **~~Add ICS/OT, mainframe, and GRC connectors~~** — Claroty, Dragos, Nozomi, z/OS RACF, Archer export. *(GAP-093)* `XL`

### API

- [x] **~~Standardize API pagination~~** — Consistent limit/offset, total_count in all list endpoints. *(GAP-060)* `M`

### Security

- [x] **~~Fix OPA bypass on unknown endpoints~~** — `opa_compliance_fail_mode = "open"` allows all requests when OPA is down. Document and warn. *(GAP-061, ARCH-011)* `S`
- [x] **~~Improve PII scrubbing~~** — Add international phone, URL params, nested JSON, address heuristics. *(GAP-062, ARCH-012)* `M`
- [x] **~~Fix API key hashing~~** — Use HMAC with per-key salt instead of unsalted SHA-256. *(GAP-078)* `S`
- [x] **~~Add field-level encryption at rest~~** — Wire `encryption_key` config to sensitive model columns. *(GAP-079)* `M`
- [x] **~~Fix SSO state storage~~** — Move `_pending_states` from in-memory dict to Redis/DB. *(GAP-077)* `S`
- [x] **~~Add session invalidation on password change~~** — Verify `token_valid_after` is updated on password change. *(GAP-095)* `S`

### Export / OSCAL

- [x] **~~Replace OSCAL placeholder HREFs~~** — Real evidence links instead of `#` and `example.com/placeholder`. *(GAP-063)* `M`
- [x] **~~Add OSCAL export UI~~** — Frontend buttons for one-click OSCAL package generation. *(GAP-069)* `M`

### Architecture / Pipeline

- [x] **~~Wire event bus subscribers~~** — Connect Slack/Jira/PagerDuty integrations to pipeline events. *(GAP-064, STUB-002, ARCH-004)* `M`
- [x] **~~Add circuit breaker pattern~~** — Per-connector circuit breaker (closed/open/half-open) with cooldown. *(GAP-067, ARCH-002)* `M`
- [x] **~~Wire queue backends as selectable~~** — Add config setting to choose Redis/Kafka/SQS/NATS instead of hardwired in-memory EventBus. *(STUB-014)* `S`

### Frontend

- [x] **~~Add ~40 missing frontend pages~~** — Assessment, pipeline mgmt, framework config, user/role mgmt, reporting, vendor mgmt, GDPR workflows. *(GAP-068)* `XL`
- [x] **~~Fix dashboard hardcoded data~~** — Replace static values with real API calls. *(GAP-070)* `M`
- [x] **~~Add personnel/HR frontend pages~~** — View 50 personnel records, access reviews, training status. *(GAP-089)* `M`
- [x] **~~Improve drill-down depth~~** — Add region/account grouping, finding-level drill-down to compliance. *(GAP-090)* `L`
- [x] **~~Add real-time/live dashboard~~** — WebSocket or SSE-based live updates. *(GAP-091)* `M`
- [x] **~~Fix settings sliders~~** — Wire AI confidence and temperature sliders to actual API calls. *(STUB-025)* `S`

### Workflows

- [x] **~~Add vendor lifecycle monitoring~~** — Reassessment scheduling, offboarding workflow, sub-processor tracking. *(GAP-065)* `L`
- [x] **~~Add cATO workflow~~** — Authorization lifecycle management for FedRAMP. *(GAP-080)* `L`
- [x] **~~Add system authorization state machine~~** — Enforce valid transitions instead of arbitrary status setting. *(GAP-082)* `M`
- [x] **~~Implement GDPR right to rectification~~** — Add `rectify_subject_data()` method (Article 16). *(GAP-083)* `S`

### Database / Models

- [x] **~~Fix asset-finding disconnect~~** — Add FK between Asset.resource_id and Finding.resource_id. *(GAP-066)* `M`
- [x] **~~Add compliance calendar model~~** — Recurring obligations with due dates, owner assignment, completion tracking. *(GAP-084)* `M`
- [x] **~~Add change request model with CAB approval~~** — Separate from ChangeEvent, with approval workflow fields. *(GAP-092)* `M`
- [x] **~~Fix DateTime timezone mismatch~~** — 2 migration columns use DateTime() without timezone=True. *(GAP-096)* `S`
- [x] **~~Persist delegation records to DB~~** — Add DelegationGrant model, replace in-memory dict. *(GAP-097, STUB-031)* `M`
- [x] **~~Persist sandbox state to DB~~** — Add SandboxEnvironment model, replace in-memory dict. *(GAP-098, STUB-032)* `M`

### Testing

- [x] **~~Add tests for critical paths~~** — Hash chain, POA&M state machine, GDPR erasure, OSCAL export, ABAC, rate limiting. *(GAP-071, ARCH-034)* `L`
- [x] **~~Improve CLI tests~~** — Verify output content against seeded data, not just exit codes. *(GAP-072)* `M`
- [x] **~~Fix coverage matrix readability~~** — Rich table column widths for framework names. *(GAP-073)* `S`

### CLI

- [x] **~~Add SoA command~~** — Expose existing `warlock/export/soa.py` via CLI. *(GAP-074)* `S`
- [x] **~~Add CLI commands for 13 uncovered models~~** — PostureSnapshot, CompensatingControl, RiskAcceptance, etc. *(GAP-075)* `L`
- [x] **~~Fix multi-cloud view label~~** — Rename to "multi-source" or filter to actual cloud providers only. *(GAP-099)* `S`

### Reporting

- [x] **~~Add scheduled report delivery~~** — Cron-based report generation with email/Slack delivery. *(GAP-081)* `M`

### Configuration

- [x] **~~Expand production config validation~~** — Check gdpr_hmac_secret, trust_portal_secret, cache_url, cors_origins. *(GAP-094)* `S`

### Observability (Architecture)

- [x] **~~Add structured JSON logging~~** — Switch to structlog or JSON formatter with correlation_id, tenant_id, user_id. *(ARCH-024)* `M`
- [x] **~~Add OpenTelemetry distributed tracing~~** — Auto-instrumentation for FastAPI, SQLAlchemy, HTTP clients. *(ARCH-025)* `L`
- [x] **~~Add Sentry error tracking~~** — With environment, release version, and user context. *(ARCH-026)* `S`
- [x] **~~Add Prometheus metrics~~** — `prometheus-fastapi-instrumentator` + custom pipeline counters. *(ARCH-027)* `M`
- [x] **~~Add health check depth~~** — `/readyz` should check DB ping, OPA ping, queue backend ping. *(ARCH-028)* `S`
- [x] **~~Implement alerting framework~~** — Evaluate AlertRule conditions on pipeline completion and timer. *(ARCH-029)* `L`
- [x] **~~Add external hash chain anchor~~** — Publish chain head hash to S3/external DB for independent verification. *(ARCH-030)* `M`

### Stubs to Complete

- [x] **~~Implement domain event handlers~~** — Evidence, Controls, Issues handlers should react to cross-domain events. *(STUB-002)* `M`
- [x] **~~Implement bulk/legacy import persistence~~** — `persist_batch()` should actually call `session.add()`. *(STUB-008)* `M`
- [x] **~~Persist workpapers to DB~~** — Add Workpaper model, save workpaper dicts to database. *(STUB-009)* `M`
- [x] **~~Wire SoD analysis engine~~** — Add CLI command and API endpoint for existing `sod.py` code. *(STUB-012)* `S`
- [x] **~~Fix compensating control evaluation~~** — Replace hardcoded `{"score": 0.8}` with actual evaluation logic. *(STUB-013)* `M`
- [x] **~~Implement lake NL query beyond keywords~~** — Replace keyword routing with LLM-based intent classification. *(STUB-005)* `L`
- [x] **~~Implement regulatory filing templates~~** — Replace "To be determined" placeholders with real content generation. *(STUB-006)* `M`
- [x] **~~Implement questionnaire automation persistence~~** — Save questionnaire responses and scores to DB. *(STUB-007)* `M`
- [x] **~~Upgrade RAG from TF-IDF to vector search~~** — Integrate pgvector or FAISS instead of dict-based TF-IDF. *(STUB-015)* `L`
- [x] **~~Enable lake by default~~** — Set `WLK_LAKE_ENABLED=true` in demo/default config. *(STUB-016)* `S`
- [x] **~~Fix forecast model~~** — Replace linear extrapolation with proper Monte Carlo using remediation curves. *(STUB-019)* `M`
- [x] **~~Fix peer benchmark~~** — Replace synthetic data with actual anonymized cohort data or clearly label as simulated. *(STUB-026)* `M`

---

## P3 — NICE-TO-HAVE (Future Roadmap)

- [x] **~~Persist white-label branding to DB~~** — Add BrandingConfig model, replace in-memory dict. *(GAP-100, STUB-033)* `M`
- [x] **~~Tighten CSP headers~~** — Add nonce or hash validation instead of permissive `default-src 'self'`. *(GAP-101)* `S`
- [x] **~~Add batch-only pipeline incremental mode~~** — Store high-water marks per connector for change-detection. *(ARCH-003)* `L`
- [x] **~~Add table partitioning strategy~~** — Monthly partitioning for findings, control_results, audit_trail on PostgreSQL. *(ARCH-008)* `L`
- [x] **~~Add query timeout configuration~~** — `statement_timeout` for PostgreSQL, `timeout` for SQLite. *(ARCH-009)* `S`
- [x] **~~Add query result caching~~** — Redis-backed caching for dashboard aggregations with pipeline-completion invalidation. *(ARCH-021)* `M`
- [x] **~~Integrate data lake into default pipeline~~** — Populate lake on every pipeline run, use for analytics queries. *(ARCH-022)* `L`
- [x] **~~Add SAML/OIDC for enterprise SSO~~** — Table stakes for enterprise customers. *(ARCH-033)* `L`
- [x] **~~Add single-process scheduler leader election~~** — PostgreSQL advisory lock or Redis SETNX for multi-instance. *(ARCH-019)* `M`
- [x] **~~Integrate frontend build with backend deployment~~** — Unified deployment or CDN + API proxy config. *(ARCH-020)* `M`

---

## Summary

| Priority | Count | Description |
|----------|-------|-------------|
| P0 | 0 (was 13) | All complete |
| P1 | 0 (was 49) | All complete |
| P2 | 0 (was 75) | All complete |
| P3 | 0 (was 10) | All complete |
| **Total** | **0 remaining (147 resolved)** | |

### By Effort

| Effort | Count | Time |
|--------|-------|------|
| S (<1 day) | 42 | ~42 person-days |
| M (1-3 days) | 56 | ~112 person-days |
| L (3-5 days) | 27 | ~108 person-days |
| XL (1+ week) | 9 | ~63 person-days |
| **Total** | **134** | **~325 person-days** |

### Quick Wins (P0/P1 + S effort)

All 17 quick wins resolved.

---

## Audit Backlog (2026-03-30)

> Source: Independent Cursor audit (`warlock-full-audit-todo.md`). IDs prefixed **AUDIT-###**.

### P0 — Risk / Correctness

- [x] **AUDIT-001** — Tighten `except Exception` in orchestrator.py and pipeline API: add logging to silent catches, comment deliberate broad catches. `S`
- [x] **AUDIT-002** — Multi-tenancy spot-check: verify new/changed list endpoints respect tenant scoping. `S`

### P1 — Quality Gates

- [x] **AUDIT-003** — Add mypy to `pyproject.toml` + CI, scoped to `warlock/api/`, `warlock/db/`, `warlock/pipeline/`. `S`
- [x] **AUDIT-004** — Expand ruff lint rules (E, W, F, I, B, UP, SIM, RUF) with per-file ignores. `S`
- [x] **AUDIT-005** — Fix CI "Run tests with coverage" step naming (no `--cov` present). `S`

### P2 — Maintainability

- [x] **AUDIT-006** — Document PyJWT vs python-jose usage split in pyproject.toml comments. `S`
- [ ] **AUDIT-007** — Split `demo_seed.py` into modules (23K lines). Deferred — requires careful validation against expected demo counts. `L`
- [x] **AUDIT-008** — Add debug logging to silent `except Exception: pass` blocks in TUI. `S`

### P3 — Hygiene

- [x] **AUDIT-009** — Document Terraform disk usage for contributors. `S`
- [x] **AUDIT-010** — Reconcile audit items with this TODO file. `S`
