# Warlock — Master Gap Analysis

> **Generated**: 2026-03-26
> **Sources merged**: 4 independent audit sessions against the same codebase
> **Total unique gaps**: 83

## Methodology

Four independent analysis sessions audited the Warlock codebase between 2026-03-22 and 2026-03-26. Each session used a different lens:

| Source | Approach | Gap Count |
|--------|----------|-----------|
| Source 1 (GAPS.md) | Platform/infra/integration sweep | 30 (G-01 to G-30) |
| Source 2 (GAPS copy.md) | Connector/frontend/security deep-dive | 41 (sectioned) |
| Source 3 (GAPS copy 2.md) | Model/lifecycle/test coverage audit | 53 (sectioned) |
| Source 4 (GAPS copy 3.md) | GAP-numbered superset with sub-findings | 53 + 7 sub-findings |

**Merge rules applied:**
- Overlapping findings resolved to the richest description with the most evidence.
- Sub-findings (GAP-024b through GAP-024n) promoted to top-level entries.
- Unique findings from Sources 1-3 appended as GAP-054 onward.
- All entries grouped by priority (P0 > P1 > P2 > P3), then by domain within each priority.

**Priority definitions:**
- **P0** — Crash, data corruption, or security bypass. Must fix before any demo or eval.
- **P1** — Broken workflow, dead UI, missing model/migration. Blocks realistic usage.
- **P2** — Incomplete feature, weak coverage, cosmetic/UX issue. Limits credibility.
- **P3** — Nice-to-have, future roadmap. No current impact.

**Effort scale:** S = <1 day, M = 1-3 days, L = 3-5 days, XL = 1+ week

---

## P0 — Crash / Data Corruption / Security Bypass

### GAP-001 — POA&M CHECK constraint rejects valid statuses

| Field | Detail |
|-------|--------|
| Priority | P0 |
| Effort | S |
| Domain | Database / Models |
| File(s) | `warlock/db/models.py` |
| Evidence | The `POAMItem.status` column has a `CheckConstraint` that lists only `draft, open, in_progress, remediated, verified, completed` but the `POAMManager` state machine also allows `risk_accepted` and `cancelled` as reachable-from-any-state transitions. Inserting a POA&M with status `risk_accepted` raises `IntegrityError`. |
| Impact | Any risk-acceptance or cancellation workflow crashes at the DB layer. |
| Fix | Add `risk_accepted` and `cancelled` to the CHECK constraint. Generate an Alembic migration. |

### GAP-002 — Three different hash algorithms in the audit chain

| Field | Detail |
|-------|--------|
| Priority | P0 |
| Effort | S |
| Domain | Security / Audit Trail |
| File(s) | `warlock/db/models.py`, `warlock/pipeline/orchestrator.py`, `warlock/export/oscal.py` |
| Evidence | `AuditTrail.compute_hash()` uses SHA-256. `PipelineRun.compute_hash()` uses SHA-512. OSCAL export uses UUID5 (SHA-1 internally). The CLAUDE.md contract specifies SHA-256 everywhere. Pipeline hash verification (`hash-verify`) compares SHA-256 expectations against SHA-512 actuals and reports false mismatches. |
| Impact | Hash chain verification is unreliable. Audit trail integrity cannot be proven. |
| Fix | Standardize all hash computation to SHA-256 with `json.dumps(data, sort_keys=True, default=str)`. |

### GAP-003 — ConMon crash on empty findings

| Field | Detail |
|-------|--------|
| Priority | P0 |
| Effort | S |
| Domain | Workflows |
| File(s) | `warlock/workflows/continuous_monitoring.py` |
| Evidence | `generate_conmon_report()` calls `statistics.mean()` on an empty list when no findings exist for the selected period. Raises `StatisticsError: mean requires at least one data point`. |
| Impact | Continuous monitoring report crashes for any framework with zero findings in the window. |
| Fix | Guard with `if not scores: return 0.0` before calling `statistics.mean()`. |

### GAP-004 — POA&M action buttons do nothing in frontend

| Field | Detail |
|-------|--------|
| Priority | P0 |
| Effort | M |
| Domain | Frontend |
| File(s) | `frontend/src/app/poam/page.tsx` |
| Evidence | "Transition Status", "Add Milestone", and "Link Finding" buttons render but have no `onClick` handlers wired. The API endpoints exist (`PATCH /api/v1/poam/{id}/transition`, `POST /api/v1/poam/{id}/milestones`) but the frontend never calls them. |
| Impact | POA&M management is view-only in the UI despite full API support. |
| Fix | Wire button click handlers to the corresponding API endpoints with optimistic UI updates. |

### GAP-005 — Create POA&M form is a dead end

| Field | Detail |
|-------|--------|
| Priority | P0 |
| Effort | M |
| Domain | Frontend |
| File(s) | `frontend/src/app/poam/page.tsx` |
| Evidence | The "Create POA&M" button opens a dialog, but the submit handler is a no-op (`console.log("TODO")`). Users fill out the form, click submit, and nothing happens. No error, no feedback, no creation. |
| Impact | Users cannot create POA&M items through the UI at all. |
| Fix | Implement `POST /api/v1/poam` call in the submit handler, add loading state, success toast, and list refresh. |

### GAP-006 — `link change-compliance` crashes on missing framework

| Field | Detail |
|-------|--------|
| Priority | P0 |
| Effort | S |
| Domain | CLI |
| File(s) | `warlock/cli/link_cmd.py` |
| Evidence | `warlock link change-compliance --change-id X --framework Y` raises `AttributeError: 'NoneType' object has no attribute 'controls'` when framework Y has no loaded controls. No guard for `framework is None`. |
| Impact | CLI crash on a common workflow — linking changes to compliance impact. |
| Fix | Add `if not framework: click.echo("Framework not found"); return`. |

### GAP-007 — `vendors list` mutates database on read

| Field | Detail |
|-------|--------|
| Priority | P0 |
| Effort | S |
| Domain | CLI / Database |
| File(s) | `warlock/cli/vendors_cmd.py` |
| Evidence | The `vendors list` command calls `vendor_risk.compute_score()` for each vendor during display, which writes the computed `risk_score` back to the DB via `session.commit()`. A read-only listing command silently modifies data. Uses `get_session()` (write session) instead of `get_read_session()`. |
| Impact | Viewing vendors changes their risk scores. Violates read/write separation. Audit trail records phantom writes. |
| Fix | Use `get_read_session()`, compute scores in-memory without persisting. Separate score recalculation into an explicit `vendors recalculate` command. |

### GAP-008 — Multi-tenancy data isolation is in-memory only

| Field | Detail |
|-------|--------|
| Priority | P0 |
| Effort | XL |
| Domain | Platform / Multi-Tenancy |
| File(s) | `warlock/platform/tenancy.py`, `warlock/db/models.py` |
| Evidence | None of the 47 DB models have a `tenant_id` column. `TenantManager` stores tenants in a Python dict. `isolate_query()` filters on `account_id` (which is an API-level concept, not a DB column on most tables). Server restart loses all tenant state. Cross-tenant data leakage is trivial. |
| Impact | Multi-tenancy is entirely fictional. Any production deployment would serve all tenants from the same unpartitioned tables. |
| Fix | Add `tenant_id` FK to all models, add composite indexes, implement row-level security via SQLAlchemy event listeners or query middleware. This is an XL effort. |

---

## P1 — Broken Workflow / Dead UI / Missing Migration

### GAP-009 — Evidence model has no DB migration

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Database |
| File(s) | `warlock/db/models.py`, `warlock/db/migrations/` |
| Evidence | The `Evidence` model is defined in `models.py` but has no corresponding Alembic migration. Table is created only via `Base.metadata.create_all()` (demo path). Production deployments using Alembic would not have this table. |
| Impact | Evidence collection fails in any Alembic-managed deployment. |

### GAP-010 — Policy model has no DB migration

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Database |
| File(s) | `warlock/db/models.py`, `warlock/db/migrations/` |
| Evidence | Same issue as GAP-009 but for the `Policy` model. Defined in `models.py`, no migration script. |
| Impact | Policy management features fail in Alembic-managed deployments. |

### GAP-011 — POA&M scheduled dates are strings, not dates

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Database / Models |
| File(s) | `warlock/db/models.py` |
| Evidence | `POAMItem.scheduled_completion_date` and `actual_completion_date` are `String` columns, not `Date` or `DateTime`. Date comparisons (overdue checks, SLA calculations) use string comparison, which breaks for non-ISO formats and prevents DB-level date arithmetic. |
| Impact | POA&M overdue detection is fragile. Cannot use SQL date functions for reporting. |
| Fix | Change to `Date` columns, add migration, update all string-date comparisons. |

### GAP-012 — Risk acceptance lifecycle broken

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Workflows |
| File(s) | `warlock/workflows/risk_acceptance.py` |
| Evidence | `approve()` requires status `"reviewed"` but there is no `review()` method to transition from `"pending"` to `"reviewed"`. The only path is `submit()` -> `"pending"`, then `approve()` fails because status is not `"reviewed"`. Dead end. |
| Impact | Risk acceptances can never be approved through the normal workflow. |
| Fix | Add a `review()` method that transitions `pending` -> `reviewed`, or change `approve()` to accept `pending` status. |

### GAP-013 — Workpaper model has no DB migration

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Database |
| File(s) | `warlock/db/models.py`, `warlock/db/migrations/` |
| Evidence | `Workpaper` model defined but no Alembic migration exists. Same class of issue as GAP-009/010. |
| Impact | Audit workpaper features fail in Alembic-managed deployments. |

### GAP-014 — Incident model has no DB migration

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Database |
| File(s) | `warlock/db/models.py`, `warlock/db/migrations/` |
| Evidence | `Incident` model defined but no Alembic migration. Same class of bug. |
| Impact | Incident management features fail in Alembic-managed deployments. |

### GAP-015 — 9+ models without Alembic migrations

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | L |
| Domain | Database |
| File(s) | `warlock/db/models.py`, `warlock/db/migrations/` |
| Evidence | At least 9 models lack migrations: `Evidence`, `Policy`, `Workpaper`, `Incident`, `ChangeEvent`, `AuditEngagement`, `EvidenceRequest`, `CompensatingControl`, `ComplianceDrift`. These all work in demo (via `create_all()`) but fail in production (via Alembic). |
| Impact | Major feature areas are demo-only. Production deployments break silently. |
| Fix | Generate migrations for all missing models. Ensure `alembic upgrade head` produces the same schema as `create_all()`. |

### GAP-016 — 10 models without migrations (adds Embedding)

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | L |
| Domain | Database |
| File(s) | `warlock/db/models.py`, `warlock/db/migrations/` |
| Evidence | Extends GAP-015 to include the `Embedding` model (used by RAG/vector search). Total count of models without migrations: 10. |
| Impact | RAG/semantic search features also fail in Alembic-managed deployments. |

### GAP-017 — HTTP 429 returns HTML, not JSON

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | S |
| Domain | API |
| File(s) | `warlock/api/middleware.py` |
| Evidence | Rate limiter returns `PlainTextResponse("Rate limit exceeded", status_code=429)` instead of `JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)`. API clients parsing JSON responses crash on the plain text body. |
| Impact | Rate-limited API clients get unparseable responses. |
| Fix | Change to `JSONResponse`. |

### GAP-018 — API pagination missing on 6+ list endpoints

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | API |
| File(s) | `warlock/api/*.py` |
| Evidence | Several list endpoints return unbounded `session.query().all()` results without `Depends(get_pagination)`. CLAUDE.md mandates pagination on all list endpoints with a hard cap of 1000 rows. |
| Impact | Large datasets cause OOM or timeout on list requests. |

### GAP-019 — Veracode HMAC signing bug

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Connectors |
| File(s) | `warlock/connectors/veracode.py` |
| Evidence | HMAC signature is computed once with a static URL during connector initialization. Subsequent API requests to different endpoints reuse the stale signature. Veracode API rejects requests after the first because the HMAC does not match the actual request URL. |
| Impact | Veracode connector only succeeds on its first API call per session. All subsequent calls fail with 401. |
| Fix | Compute HMAC per-request with the actual request URL. |

### GAP-020 — 18 models have no API routes

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | L |
| Domain | API |
| File(s) | `warlock/api/` |
| Evidence | Models including `ChangeEvent`, `ComplianceDrift`, `DataSilo`, `Questionnaire`, `AuditEngagement`, `EvidenceRequest`, `CompensatingControl`, `Workpaper`, `Incident`, `IssueComment`, `Personnel`, `SystemProfile`, `Asset`, `RiskScenario`, `Policy`, `ControlInheritance`, `ExternalAuditor`, and `Embedding` have no corresponding API routes. They are accessible only via CLI or direct DB queries. |
| Impact | Frontend and API consumers cannot interact with these entities. |

### GAP-021 — `/auth/me` endpoint missing

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | S |
| Domain | API / Auth |
| File(s) | `warlock/api/auth.py` |
| Evidence | Frontend calls `GET /api/v1/auth/me` to fetch the current user profile. This endpoint does not exist. Frontend falls back to hardcoded demo user data. |
| Impact | User profile display is fictional. Role-based UI hiding cannot work. |
| Fix | Add `GET /api/v1/auth/me` that decodes the JWT and returns the user profile. |

### GAP-022 — POA&M API is read-only

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | API |
| File(s) | `warlock/api/poam.py` |
| Evidence | Only `GET /api/v1/poam` and `GET /api/v1/poam/{id}` exist. No `POST`, `PATCH`, or `DELETE` endpoints. Frontend POA&M creation (GAP-005) and transitions (GAP-004) have no backend to call. |
| Impact | POA&M management is entirely read-only via the API. |

### GAP-023 — Pipeline status endpoint returns zeros

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | API |
| File(s) | `warlock/api/pipeline.py` |
| Evidence | `GET /api/v1/pipeline/status` returns `{"connectors": 0, "findings": 0, "controls": 0}` because it queries `PipelineRun` for the latest run stats but the demo seed does not create `PipelineRun` records. |
| Impact | Dashboard shows zero counts despite thousands of findings in the DB. |
| Fix | Either create `PipelineRun` records in demo seed, or fall back to direct table counts. |

### GAP-024 — No Dockerfile or production CI/CD

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | DevOps |
| File(s) | Project root |
| Evidence | No `Dockerfile`, no `docker-compose.yml`, no production deployment config. CI runs lint and tests but has no build/deploy stage. The `Makefile` targets are all local-dev oriented. |
| Impact | No path to production deployment. Cannot containerize for cloud hosting. |

### GAP-025 — Frontend login page still exists despite auto-auth

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | S |
| Domain | Frontend |
| File(s) | `frontend/src/app/login/page.tsx` |
| Evidence | Commit `d88ac27` removed the login page and added auto-authentication, but the login route still exists and is accessible. Users who navigate to `/login` see a broken page. |
| Impact | Confusing UX. Users may attempt to log in manually and get stuck. |

### GAP-026 — Frontend forms submit to console.log

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | L |
| Domain | Frontend |
| File(s) | `frontend/src/app/*/page.tsx` |
| Evidence | Multiple frontend forms (Create POA&M, Create Finding, Add Vendor, etc.) have submit handlers that `console.log()` the form data instead of calling API endpoints. Identified in at least 5 pages. |
| Impact | All create/update operations in the frontend are non-functional. |

### GAP-027 — No CSRF protection

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Security |
| File(s) | `warlock/api/middleware.py` |
| Evidence | No CSRF token generation or validation. State-changing API endpoints accept requests without origin verification. `SameSite` cookie attribute not set on JWT cookies (JWT is in Authorization header, but if cookies are used for session, CSRF is needed). |
| Impact | Cross-site request forgery possible if cookies are used for auth. |

### GAP-028 — No API rate limiting on sensitive endpoints

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Security |
| File(s) | `warlock/api/middleware.py` |
| Evidence | `_ENDPOINT_LIMITS` defines per-endpoint rate limits (login=10/min, register=5/min, AI=30/min, pipeline=5/min) but the middleware only checks a global rate limit. The per-endpoint limits are defined but not enforced. |
| Impact | Brute-force attacks on login, registration spam, and AI endpoint abuse are not throttled. |
| Fix | Implement per-endpoint rate limit checking in the middleware using the `_ENDPOINT_LIMITS` dict. |

### GAP-029 — GDPR audit log incomplete

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Compliance / GDPR |
| File(s) | `warlock/workflows/gdpr.py` |
| Evidence | GDPR erasure and export operations do not create `AuditTrail` entries. Article 30 requires a record of processing activities including erasures. The audit trail hash chain has no entries for GDPR operations. |
| Impact | GDPR compliance gap — cannot prove to a DPA that erasure/export was performed. |

### GAP-030 — Demo seed phases 2-5 incomplete

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | L |
| Domain | Demo |
| File(s) | `scripts/demo_seed.py` |
| Evidence | Seed creates connectors, findings, and control results (phase 1) but several entity types are seeded with minimal data: incidents (2 records), personnel (50 records), vendors (5 records), policies (0 explicit), evidence (0 explicit). Many CLI commands show "no data" against the demo DB. |
| Impact | Demo cannot showcase vendor management, incident response, evidence collection, or policy management workflows. Violates Rule 8: "No data = failed demo". |

### GAP-031 — NIST 800-53 empty checks in Rego

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | L |
| Domain | Policy / OPA |
| File(s) | `policies/nist-800-53/*.rego` |
| Evidence | Multiple NIST 800-53 Rego policy files contain `deny` rules with empty bodies or `true` conditions that always deny. These were generated as stubs but never implemented with actual logic. |
| Impact | OPA evaluation returns false denials for controls that should be assessed by their actual criteria. |

### GAP-032 — `control-tests` command always returns false

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | CLI |
| File(s) | `warlock/cli/control_tests_cmd.py` |
| Evidence | The `control-tests` command evaluates assertions but returns `False` for all controls because it compares assertion results against an empty expected-results dict. Without expected values loaded, every comparison fails. |
| Impact | Control testing is non-functional. All controls appear to fail. |

### GAP-033 — Dead letter queue not implemented

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Pipeline |
| File(s) | `warlock/pipeline/queue_backends.py` |
| Evidence | `DLQMixin` is defined with `send_to_dlq()` and `process_dlq()` methods, but no queue backend inherits from it. Failed messages are silently dropped. |
| Impact | Pipeline failures lose data silently. No retry mechanism, no failure visibility. |

### GAP-034 — SLA model tracks but doesn't enforce

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Workflows |
| File(s) | `warlock/db/models.py`, `warlock/workflows/` |
| Evidence | SLA configuration exists in models (severity-based SLA days) but no background job or pipeline step checks for SLA breaches and triggers escalations. The `sla_breach` CLI command reports breaches but takes no action. |
| Impact | SLA tracking is passive. Overdue items are never escalated. |

### GAP-035 — `audit hash-verify` and `audit chain` crash

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | CLI |
| File(s) | `warlock/cli/audit_cmd.py` |
| Evidence | `warlock audit hash-verify` crashes with `KeyError` when recomputing hashes because the serialization format differs from the original computation. `warlock audit chain` fails similarly. Related to GAP-002 (multiple hash algorithms). |
| Impact | Audit trail integrity verification is non-functional. |

### GAP-036 — `system-controls` shows wrong framework

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | S |
| Domain | CLI |
| File(s) | `warlock/cli/system_controls_cmd.py` |
| Evidence | `warlock system-controls list --framework nist-800-53` shows controls from all frameworks, not just NIST 800-53. The `--framework` filter is applied after the query limit, so results are random. |
| Impact | Framework-specific control views are unreliable. |
| Fix | Apply framework filter in the SQL query, before the limit. |

### GAP-037 — Frontend incident statuses don't match backend

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | S |
| Domain | Frontend / API |
| File(s) | `frontend/src/app/incidents/page.tsx`, `warlock/db/models.py` |
| Evidence | Frontend sends incident statuses `investigating` and `mitigating` which are not in the backend's `Incident.status` CHECK constraint. Backend rejects these with `IntegrityError`. Backend expects: `open, triaged, contained, eradicated, recovered, closed, post_mortem`. |
| Impact | Incident status updates from the frontend crash. |
| Fix | Align frontend status values with backend CHECK constraint. |

### GAP-038 — `reports executive-export -f <framework>` crashes

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | S |
| Domain | CLI |
| File(s) | `warlock/cli/reports_cmd.py` |
| Evidence | The `--framework` filter applies `.filter()` after `.limit()` has already been called on the query, raising `InvalidRequestError`. SQLAlchemy does not allow filter after limit. |
| Impact | Framework-filtered executive exports crash. |
| Fix | Move `.filter()` before `.limit()` in the query chain. |

### GAP-039 — Pipeline hash-verify reports false mismatches

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Pipeline |
| File(s) | `warlock/pipeline/orchestrator.py` |
| Evidence | `hash-verify` recomputes hashes using SHA-256 but `PipelineRun` stores SHA-512 hashes (see GAP-002). Every verification reports a mismatch. |
| Impact | Pipeline integrity verification is useless — 100% false positive rate. |

### GAP-040 — Risk appetite check compares incompatible units

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | S |
| Domain | Risk Engine |
| File(s) | `warlock/domains/risk_engine.py` |
| Evidence | `check_appetite_breach()` compares a risk score (e.g., 15, dimensionless) against a monetary threshold (e.g., `$2,000,000` ALE). These are different units. A score of 15 < $2M is always true, so appetite breaches are never detected. |
| Impact | Risk appetite monitoring is non-functional. Board-level risk alerts never fire. |
| Fix | Compare like units — either both scores or both monetary values. |

### GAP-041 — `frameworks inheritance` shows empty despite data

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | S |
| Domain | CLI |
| File(s) | `warlock/cli/frameworks_cmd.py` |
| Evidence | `warlock frameworks inheritance` shows "No inherited controls found" even though `warlock/frameworks/reference/inherited_controls.yaml` contains data. The CLI command queries the DB (`ControlInheritance` model) instead of reading the YAML file. Demo seed does not populate the `ControlInheritance` table. |
| Impact | Inherited controls feature appears broken. |
| Fix | Either populate `ControlInheritance` in demo seed, or read from YAML as fallback. |

### GAP-042 — No approval workflow engine

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | L |
| Domain | Workflows |
| File(s) | `warlock/workflows/` |
| Evidence | No multi-level approval chain, no SLA on approvals, no escalation when approvals are overdue. `attestations.py` has multi-party sign-off but it is a simple counter, not a configurable approval chain with roles, delegation, and timeout. |
| Impact | Cannot enforce segregation of duties or require management sign-off on risk acceptances. |

### GAP-043 — No evidence collection scheduling

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Workflows |
| File(s) | `warlock/workflows/` |
| Evidence | No automated "collect evidence every 30 days" capability. Evidence collection is entirely manual. No `EvidenceSchedule` model, no cron integration, no reminder system. |
| Impact | Evidence goes stale. Auditors find expired evidence. Continuous compliance is manual. |

### GAP-044 — No PDF report generation

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Reporting |
| File(s) | `warlock/cli/reports_cmd.py`, `warlock/export/` |
| Evidence | `reports executive-export` generates Markdown output. No PDF generation despite `weasyprint` being in dependencies. `RPT-2` in capability-gaps.md is marked DONE but the actual CLI command outputs Markdown, not PDF. |
| Impact | Cannot deliver board-ready reports. Evaluators expect PDF output from a GRC platform. |

### GAP-045 — No bi-directional Jira sync

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | L |
| Domain | Integrations |
| File(s) | `warlock/integrations/jira.py` |
| Evidence | Jira integration pushes findings to Jira but has no webhook receiver for Jira status changes back to Warlock. When an engineer resolves a Jira ticket, the corresponding Warlock finding remains open. |
| Impact | Dual maintenance required. Compliance status diverges from actual remediation state. |

### GAP-046 — No email notification system

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Platform |
| File(s) | `warlock/export/alerts.py`, `warlock/config.py` |
| Evidence | `alerts.py` defines an email channel but the send method contains `# TODO: implement SMTP`. No `WLK_SMTP_*` config vars. No SMTP integration (SES, SendGrid, Postmark). Escalation, approval, and SLA breach notifications cannot be delivered. |
| Impact | All email-based workflows are non-functional: escalations, approvals, report delivery, DSAR notifications. |

### GAP-047 — No auditor self-service portal frontend

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | L |
| Domain | Frontend |
| File(s) | `warlock/api/trust_portal.py`, `frontend/` |
| Evidence | `trust_portal.py` implements API endpoints for external auditor access (magic link auth, scoped read-only views) but no frontend page consumes these endpoints. External auditors have no UI. |
| Impact | Trust portal / auditor portal feature is API-only, not usable by non-technical auditors. |

### GAP-048 — No DB connection pooling for production

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | S |
| Domain | Database |
| File(s) | `warlock/db/session.py` |
| Evidence | `create_engine()` is called without `pool_size`, `max_overflow`, or `pool_pre_ping` parameters. SQLite uses `NullPool` by default which is fine, but PostgreSQL deployments get the default pool (5 connections, 10 overflow) with no health checks. Under load, connections go stale. |
| Impact | Production PostgreSQL deployments will experience connection timeouts and stale connections. |
| Fix | Add `pool_pre_ping=True`, configurable `pool_size` and `max_overflow` via `WLK_DB_POOL_SIZE` / `WLK_DB_MAX_OVERFLOW`. |

### GAP-049 — No real-time/webhook ingestion

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | L |
| Domain | Pipeline |
| File(s) | `warlock/connectors/webhook.py` |
| Evidence | `webhook.py` defines a generic webhook receiver but no push connectors exist for AWS EventBridge, Azure Event Grid, or GCP Pub/Sub. All 351 connectors are pull-based (poll on schedule). Real-time security events (GuardDuty, Defender alerts) are delayed until next poll. |
| Impact | No real-time threat response. Minimum detection latency equals poll interval. |

### GAP-050 — No session invalidation / token revocation

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Security / Auth |
| File(s) | `warlock/api/auth.py`, `warlock/api/session_manager.py` |
| Evidence | JWT tokens have no blacklist mechanism. `session_manager.py` stores sessions in-memory (lost on restart). No token revocation on password change, no forced logout, no concurrent session limit. A compromised token is valid until expiry. |
| Impact | Cannot respond to account compromise. Cannot enforce session policies. |

### GAP-051 — Missing Palo Alto Networks connector

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Connectors |
| File(s) | `warlock/connectors/` |
| Evidence | No Palo Alto Networks connector (PAN-OS, Panorama, Cortex XDR, Prisma Cloud). Palo Alto is the dominant NGFW vendor, deployed in 70%+ of Fortune 500 enterprises. Missing this connector is a credibility gap for network security posture. |
| Impact | Cannot assess firewall rule compliance, network segmentation, or threat prevention for the most common enterprise firewall. |

### GAP-052 — Missing ServiceNow CMDB connector

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Connectors |
| File(s) | `warlock/connectors/servicenow.py` |
| Evidence | ServiceNow connector pulls ITSM incidents only, not CMDB Configuration Items (CIs). CMDB is the authoritative asset inventory in most enterprises. Without CI data, asset-to-finding mapping is incomplete. |
| Impact | Cannot build a complete asset inventory from the most common enterprise ITSM/CMDB. |

### GAP-053 — No document management / policy repository

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | L |
| Domain | Platform |
| File(s) | `warlock/db/models.py` |
| Evidence | `Policy` model exists with `content` (text) and `version` fields, but there is no file upload, no document storage, no policy approval workflow, no review cycle tracking. Policies are text blobs, not managed documents. |
| Impact | Cannot manage policy documents as a GRC platform should. Auditors expect versioned policy PDFs with approval signatures. |

### GAP-054 — No user self-service portal for evidence submission

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Frontend |
| File(s) | `frontend/` |
| Evidence | Control owners cannot upload evidence through any UI. Evidence submission requires CLI access or direct API calls. No self-service portal for non-technical stakeholders to submit screenshots, documents, or attestations. |
| Impact | Evidence collection bottlenecks on the compliance team. Cannot delegate evidence gathering to control owners. |

### GAP-055 — No asset inventory model with FK to findings

| Field | Detail |
|-------|--------|
| Priority | P1 |
| Effort | M |
| Domain | Database / Models |
| File(s) | `warlock/db/models.py` |
| Evidence | `Finding` has a `resource_id` string column but no FK to an `Asset` table. The `Asset` model exists but has no relationship to `Finding`. Cannot answer "which findings affect this asset?" via a JOIN — requires string matching on `resource_id`. |
| Impact | Asset-centric compliance views are expensive and unreliable. Cannot build an asset risk profile. |

---

## P2 — Incomplete Feature / Weak Coverage / Cosmetic

### GAP-056 — 6 frameworks have zero Rego policies

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | L |
| Domain | Policy / OPA |
| File(s) | `policies/` |
| Evidence | ISO 27701, ISO 42001, FedRAMP, GDPR, EU AI Act, and SEC Cyber have no Rego policy files. OPA evaluation for these frameworks returns empty results, falling through to assertion-only assessment. |
| Impact | No automated policy evaluation for 6 of 14 frameworks. |

### GAP-057 — SOC 2 has only 28% Rego coverage

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Policy / OPA |
| File(s) | `policies/soc2/` |
| Evidence | 26 Rego files covering 13 of 46 SOC 2 controls (28%). The remaining 33 controls rely solely on assertions. SOC 2 is the most requested framework for SaaS audits. |
| Impact | OPA-based SOC 2 assessment is partial. Assessors fall back to assertion-only for 72% of controls. |

### GAP-058 — Assertion gaps across frameworks

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | L |
| Domain | Assessors |
| File(s) | `warlock/assessors/` |
| Evidence | Multiple frameworks have controls with no assertions bound. These controls are always `not_assessed` regardless of evidence. The assessment tier fallback (assertions -> AI -> inheritance) starts with nothing. |
| Impact | Compliance posture percentages are artificially low due to unassessed controls. |

### GAP-059 — 84 mock connectors return static data

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | XL |
| Domain | Connectors |
| File(s) | `warlock/connectors/` |
| Evidence | Of 352 connector files, approximately 84 return hardcoded/static mock data rather than making actual API calls. They satisfy the connector interface but produce identical findings on every run regardless of the target environment. |
| Impact | Demo looks real but production deployments with these connectors would get fake data. Cannot distinguish mock from real connectors without reading source. |

### GAP-060 — API pagination inconsistent

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | API |
| File(s) | `warlock/api/*.py` |
| Evidence | Some list endpoints use `Depends(get_pagination)` with proper offset/limit, others use `.limit(50)` hardcoded, others return all results. No consistent pagination metadata (total count, next page URL) in responses. |
| Impact | API consumers cannot paginate reliably across all endpoints. |

### GAP-061 — OPA bypass on unknown endpoints

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | S |
| Domain | Security |
| File(s) | `warlock/api/policy_gate.py` |
| Evidence | `_HEALTH_PATHS` skips OPA enforcement for health endpoints. But the check uses `startswith()`, so any path starting with `/health` (e.g., `/healthz-backdoor`) bypasses OPA. Additionally, unknown/unregistered paths bypass OPA because the policy gate only enforces on known routes. |
| Impact | Path manipulation can bypass OPA policy enforcement. |
| Fix | Use exact path matching for health paths. Default-deny for unregistered routes. |

### GAP-062 — PII scrubbing weak

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Security / Privacy |
| File(s) | `warlock/utils/pii.py` |
| Evidence | `scrub_finding()` uses regex patterns for email and SSN but misses: IP addresses in finding descriptions, AWS account IDs, credit card numbers (PCI DSS relevance), and names embedded in resource identifiers. |
| Impact | PII leaks into normalized findings despite scrubbing. |

### GAP-063 — OSCAL export uses placeholder UUIDs

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Export / OSCAL |
| File(s) | `warlock/export/oscal.py` |
| Evidence | Several OSCAL fields use placeholder strings like `"TODO"` or `"placeholder"` instead of deterministic UUID5 values. These appear in the `responsible-parties` and `metadata` sections. |
| Impact | OSCAL packages fail strict validation. Cannot submit to FedRAMP or other OSCAL-consuming systems. |

### GAP-064 — Domain event bus has no subscribers

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Architecture |
| File(s) | `warlock/domains/event_bus.py` |
| Evidence | `EventBus` class has `publish()` and `subscribe()` methods, events are defined, but no module calls `subscribe()`. Events are published into the void. |
| Impact | Domain-driven design is structurally present but functionally inert. |

### GAP-065 — Vendor lifecycle no background monitoring

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Workflows |
| File(s) | `warlock/workflows/vendor_lifecycle.py` |
| Evidence | `vendor_import()` and `vendor_offboard()` exist but no scheduled job checks `contract_expires`, `assessment_cadence_days`, or `last_assessment` dates. Vendors with expired contracts or overdue assessments are never flagged. |
| Impact | Vendor risk monitoring requires manual review. Contract expirations go unnoticed. |

### GAP-066 — Asset-finding disconnect

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Database / Models |
| File(s) | `warlock/db/models.py` |
| Evidence | `Asset` and `Finding` both exist but have no FK relationship. `Finding.resource_id` is a free-text string, not a FK to `Asset.id`. Joining requires string matching which is slow and error-prone (different connectors format resource IDs differently). |
| Impact | Cannot build reliable asset-centric risk views. Same physical asset may appear as multiple unrelated resource IDs. |

### GAP-067 — Circuit breaker not implemented

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Pipeline |
| File(s) | `warlock/pipeline/` |
| Evidence | No circuit breaker pattern for connector failures. A connector that times out or returns errors is retried indefinitely on the next pipeline run. No backoff, no failure threshold, no open/half-open/closed states. |
| Impact | One failing connector can slow down the entire pipeline. Repeated failures generate noise in logs. |

### GAP-068 — ~40 CLI commands have no frontend equivalent

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | XL |
| Domain | Frontend |
| File(s) | `frontend/src/app/` |
| Evidence | The CLI has ~599 commands across 30+ groups. The frontend implements pages for approximately 8 entities (dashboard, findings, controls, frameworks, poam, vendors, incidents, settings). The remaining ~40 major command groups (audit, risk-engine, lake, privacy, bcp, access-review, compliance-drift, etc.) have no frontend pages. |
| Impact | Frontend users see a fraction of the platform's capabilities. |

### GAP-069 — OSCAL export has no UI

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Frontend |
| File(s) | `frontend/` |
| Evidence | OSCAL export is available via CLI (`warlock oscal export`) and API but has no frontend page. Users cannot trigger OSCAL package generation from the UI. |
| Impact | FedRAMP-oriented users who need OSCAL packages must use the CLI. |

### GAP-070 — Dashboard uses hardcoded data

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Frontend |
| File(s) | `frontend/src/app/dashboard/page.tsx` |
| Evidence | Dashboard widgets display hardcoded numbers and charts instead of fetching from API endpoints. The API endpoints exist (`/api/v1/dashboard/stats`, `/api/v1/dashboard/posture`) but the frontend does not call them. |
| Impact | Dashboard looks functional but shows fictional data. Changes in the backend are not reflected. |

### GAP-071 — Test coverage zero on critical paths

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | L |
| Domain | Testing |
| File(s) | `tests/` |
| Evidence | 509+ tests exist but zero coverage on: GDPR erasure/export, API middleware (rate limiting, ABAC), OSCAL export, integration modules (Jira, ServiceNow, Teams), platform modules (tenancy, delegation, sandbox, white-label), and AI reasoning. All these paths are untested. |
| Impact | Regressions in critical compliance and security paths go undetected. |

### GAP-072 — CLI tests only check exit codes

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Testing |
| File(s) | `tests/test_cli_*.py` |
| Evidence | CLI tests invoke commands via `CliRunner` and assert `result.exit_code == 0` but do not verify output content. A command that exits 0 but prints "No data found" or empty tables passes the test. Violates Rule 8. |
| Impact | Tests pass for commands that produce no useful output. |

### GAP-073 — Coverage matrix unreadable

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | S |
| Domain | Testing |
| File(s) | `tests/` |
| Evidence | No test coverage matrix or report configuration. Cannot determine which modules have coverage and which do not without manually inspecting test files. `pytest-cov` is in dev dependencies but no `.coveragerc` or `pyproject.toml` coverage config exists. |
| Impact | Cannot prioritize test writing. Coverage gaps are invisible. |

### GAP-074 — SoA command missing for some frameworks

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | S |
| Domain | CLI |
| File(s) | `warlock/cli/soa_cmd.py` |
| Evidence | `warlock soa generate --framework <fw>` works for NIST 800-53 and ISO 27001 but returns empty or errors for GDPR, EU AI Act, SEC Cyber, and NIST CSF 2.0. The SoA generator expects specific control ID formats that these frameworks don't use. |
| Impact | Statement of Applicability generation is incomplete for newer frameworks. |

### GAP-075 — 13 models have no CLI commands

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | L |
| Domain | CLI |
| File(s) | `warlock/cli/` |
| Evidence | Models including `Embedding`, `ControlInheritance`, `ExternalAuditor`, `ComplianceDrift` (partial), `DataSilo` (partial), `AuditEngagement`, `EvidenceRequest`, `Workpaper`, `CompensatingControl`, `IssueComment`, `RiskScenario`, `SystemProfile`, and `Asset` have no or minimal CLI commands. |
| Impact | Cannot manage these entities without direct API or DB access. |

### GAP-076 — No connector credential rotation

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Connectors / Security |
| File(s) | `warlock/connectors/base.py` |
| Evidence | `BaseConnector.get_secret()` reads from environment variables. No integration with HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault. No credential rotation, no expiry tracking, no secret versioning. |
| Impact | Connector secrets are static. Credential rotation requires redeployment. No audit trail for secret access. |

### GAP-077 — SSO state stored in-memory

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Auth / SSO |
| File(s) | `warlock/api/sso.py` (line ~34) |
| Evidence | OIDC nonce and state parameters are stored in a Python dict (`_pending_states`). The code itself acknowledges the bug with a comment: `# TODO: This should be stored in Redis or DB, not in-memory`. Multi-instance deployments break SSO (state created on instance A, callback hits instance B). Server restart loses all pending SSO flows. |
| Impact | SSO fails in any multi-instance deployment. Users mid-SSO-flow lose their session on restart. |

### GAP-078 — API key stored as unsalted SHA-256

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | S |
| Domain | Security |
| File(s) | `warlock/api/auth.py` |
| Evidence | API keys are hashed with SHA-256 but no salt. Identical API keys produce identical hashes. A database leak allows rainbow table attacks against API keys. |
| Impact | API key security is weaker than industry standard (bcrypt/argon2 with salt). |

### GAP-079 — No field-level encryption at rest

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Security |
| File(s) | `warlock/config.py`, `warlock/db/models.py` |
| Evidence | `WLK_ENCRYPTION_KEY` config exists and is documented as "required in production for field-level encryption" but no model columns use encrypted types. No `EncryptedString` column type, no encrypt/decrypt hooks. The config is defined but never consumed. |
| Impact | Sensitive data (PII, secrets, evidence content) is stored in plaintext in the database. |

### GAP-080 — No cATO workflow

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | L |
| Domain | Workflows |
| File(s) | `warlock/workflows/`, `warlock/export/fedramp.py` |
| Evidence | FedRAMP package generation exists (`fedramp.py`) but no continuous Authority to Operate (cATO) lifecycle: no authorization boundary tracking, no continuous monitoring tied to ATO status, no authorization decision workflow, no ATO expiry/renewal. |
| Impact | Cannot manage the full FedRAMP authorization lifecycle. |

### GAP-081 — No scheduled report delivery

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Reporting |
| File(s) | `warlock/export/` |
| Evidence | No cron-based report generation and delivery. Cannot schedule "send executive report every Monday to CISO". No integration with email (see GAP-046) or Slack for report delivery. |
| Impact | Reports must be manually generated and distributed. |

### GAP-082 — System authorization not enforced

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Workflows |
| File(s) | `warlock/db/models.py` |
| Evidence | `SystemProfile` has valid authorization statuses defined but no state machine enforces transitions. Status can be set to any value directly, bypassing approval workflows. Unlike POA&M (which has `POAMManager.transition()`), system authorization has no equivalent. |
| Impact | System authorization lifecycle is uncontrolled. An unauthorized system can be marked "authorized" without any review. |

### GAP-083 — GDPR right to rectification not implemented

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Compliance / GDPR |
| File(s) | `warlock/workflows/gdpr.py` |
| Evidence | GDPR module implements erasure (Art 17) and export (Art 20) but not rectification (Art 16). The module docstring mentions Art 16 but there is no `rectify()` method. Data subjects can request erasure but cannot request correction of inaccurate data. |
| Impact | Incomplete GDPR compliance. Cannot respond to Article 16 rectification requests. |

### GAP-084 — No compliance calendar model

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Database / Models |
| File(s) | `warlock/db/models.py` |
| Evidence | No `ComplianceCalendarEntry` model. Audit deadlines, evidence collection dates, framework assessment windows, and regulatory filing dates are tracked manually or in people's heads. No calendar view in CLI or frontend. |
| Impact | Compliance deadlines are invisible to the platform. Cannot proactively manage assessment schedules. |

### GAP-085 — Missing Proofpoint TAP connector

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Connectors |
| File(s) | `warlock/connectors/` |
| Evidence | Proofpoint connectors cover URL Defense and Security Awareness Training but not Targeted Attack Protection (TAP). TAP provides quarantine events, phishing campaign data, and threat intelligence that are critical for email security posture assessment. |
| Impact | Email threat detection posture is incomplete. Cannot assess phishing risk from the most common email security platform. |

### GAP-086 — Missing Zscaler connector

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Connectors |
| File(s) | `warlock/connectors/` |
| Evidence | No Zscaler connectors (ZIA, ZPA, ZDX). Zscaler is required for NIST 800-207 Zero Trust Architecture assessments. Cannot evaluate zero-trust network access posture. |
| Impact | Cannot assess ZTNA compliance for organizations using Zscaler. |

### GAP-087 — Missing physical security connectors

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | L |
| Domain | Connectors |
| File(s) | `warlock/connectors/` |
| Evidence | Only Verkada cameras connector exists. No connectors for Lenel/S2, HID Global, Brivo, Envoy (visitor management), Genetec, or Honeywell. Physical security is required for ISO 27001 Annex A.11 and NIST PE controls. |
| Impact | Physical security assessment relies on manual evidence. Cannot automate PE control assessment. |

### GAP-088 — Missing GovCloud connectors

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Connectors |
| File(s) | `warlock/connectors/` |
| Evidence | AWS, Azure, and GCP connectors use commercial region endpoints. No GovCloud-specific endpoints (AWS GovCloud, Azure Government, Google Workspace for Government). FedRAMP and CMMC assessments require GovCloud-specific data. |
| Impact | Cannot assess compliance for government cloud deployments. |

### GAP-089 — No personnel/HR frontend pages

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Frontend |
| File(s) | `frontend/` |
| Evidence | 50 `Personnel` records exist in the demo DB but no frontend page displays or manages them. Personnel management (training status, access reviews, background checks) requires CLI access. |
| Impact | HR/personnel compliance management is invisible in the UI. |

### GAP-090 — Limited drill-down depth in frontend

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Frontend |
| File(s) | `frontend/src/app/` |
| Evidence | Frontend supports 5 of 8 drill-down levels: framework -> family -> control -> finding -> detail. Missing: region grouping, cloud account grouping, and resource-type grouping between framework and control levels. |
| Impact | Cannot navigate compliance data by infrastructure topology. |

### GAP-091 — No real-time/live dashboard in frontend

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Frontend |
| File(s) | `frontend/src/app/dashboard/page.tsx` |
| Evidence | CLI has `dashboard live` command with refresh capability but the frontend dashboard has no WebSocket or SSE connection. Data is fetched once on page load (and even that is hardcoded — see GAP-070). No live updates for new findings, status changes, or alerts. |
| Impact | Frontend dashboard is a static snapshot, not a monitoring tool. |

### GAP-092 — No change request model with CAB approval

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Database / Workflows |
| File(s) | `warlock/db/models.py` |
| Evidence | `ChangeEvent` model tracks changes that happened but has no Change Advisory Board (CAB) approval workflow. No `ChangeRequest` model with approval states (requested -> reviewed -> approved -> implemented -> verified). Cannot enforce change management policy. |
| Impact | Change management is observation-only, not control-enforcing. |

### GAP-093 — Missing enterprise connectors (ICS/OT, Mainframe, GRC)

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | XL |
| Domain | Connectors |
| File(s) | `warlock/connectors/` |
| Evidence | Missing connector categories: ICS/OT (Claroty, Dragos, Nozomi Networks), Mainframe (z/OS RACF, AS/400), GRC platforms (Archer export, ServiceNow GRC import), Email DLP (Proofpoint DLP, Microsoft Purview DLP). These are required for regulated industries (energy, manufacturing, finance). |
| Impact | Cannot assess compliance for industrial control systems, mainframe environments, or migrate from legacy GRC platforms. |

### GAP-094 — Production config validation incomplete

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | S |
| Domain | Configuration |
| File(s) | `warlock/config.py` |
| Evidence | Production startup validates `jwt_secret` and `encryption_key` but does not check `gdpr_hmac_secret` (required for GDPR erasure), `trust_portal_secret` (required for auditor portal), or `cache_url` (required for multi-instance rate limiting). These fail at runtime instead of at startup. |
| Impact | Production deployments discover missing config at runtime, causing user-facing errors. |

### GAP-095 — No session invalidation on password change

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | S |
| Domain | Security / Auth |
| File(s) | `warlock/api/auth.py`, `warlock/db/models.py` |
| Evidence | `User` model has a `token_valid_after` timestamp field that could be used to invalidate tokens issued before a password change. However, the password change endpoint does not update this field, and the JWT validation does not check it. |
| Impact | Old tokens remain valid after password change. Compromised sessions persist. |
| Fix | Update `token_valid_after` on password change. Check it during JWT validation. |

### GAP-096 — DateTime timezone mismatch in 2 migration columns

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | S |
| Domain | Database |
| File(s) | `warlock/db/migrations/` |
| Evidence | `escalation_sent_at` and `session_expires_at` columns are defined as `DateTime` without `timezone=True` in their migration scripts, despite the model definition using `DateTime(timezone=True)`. This creates a schema drift between migration-created and `create_all()`-created databases. |
| Impact | Timezone handling differs between demo (create_all) and production (Alembic) deployments. |

### GAP-097 — Delegation Manager in-memory

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Platform |
| File(s) | `warlock/platform/delegation.py` |
| Evidence | `DelegationManager` stores delegation rules in a Python dict. No DB persistence. Server restart loses all delegations. Cannot query delegation history. |
| Impact | Delegated administration is non-persistent. |

### GAP-098 — Sandbox Manager in-memory

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | M |
| Domain | Platform |
| File(s) | `warlock/platform/sandbox.py` |
| Evidence | `SandboxManager` stores sandbox environments in a Python dict. No DB backing. Sandboxes disappear on restart. |
| Impact | Sandbox/staging environments are non-persistent. |

### GAP-099 — Multi-cloud view mislabeled

| Field | Detail |
|-------|--------|
| Priority | P2 |
| Effort | S |
| Domain | CLI / UX |
| File(s) | `warlock/cli/dashboard_cmd.py` |
| Evidence | The "multi-cloud" dashboard view shows findings from ALL 33 connector sources (including SaaS tools like Jira, Slack, GitHub) not just cloud providers (AWS, Azure, GCP). The label implies cloud-only but the query has no source type filter. |
| Impact | Misleading dashboard. Users expect cloud infrastructure findings but see SaaS tool findings mixed in. |

---

## P3 — Nice-to-Have / Future Roadmap

### GAP-100 — White-Label in-memory

| Field | Detail |
|-------|--------|
| Priority | P3 |
| Effort | L |
| Domain | Platform |
| File(s) | `warlock/platform/white_label.py` |
| Evidence | `WhiteLabelManager` stores branding config (logos, colors, domain) in a Python dict. No DB persistence. MSSP customers would lose branding on restart. |
| Impact | White-label capability is non-persistent. Low priority since MSSP use case is future roadmap. |

### GAP-101 — CSP too permissive

| Field | Detail |
|-------|--------|
| Priority | P3 |
| Effort | S |
| Domain | Security |
| File(s) | `warlock/api/middleware.py` |
| Evidence | Content Security Policy header uses `default-src 'self'` without `nonce` or `hash` directives for inline scripts. While `'self'` is reasonable, it allows any script from the same origin. Modern CSP best practice requires nonce-based script allowlisting. |
| Impact | Marginal XSS risk reduction. Low priority since the frontend is a separate SPA that doesn't serve inline scripts from the API. |

---

## Summary Tables

### By Priority

| Priority | Count | Description |
|----------|-------|-------------|
| P0 | 8 | Crash, data corruption, security bypass |
| P1 | 47 | Broken workflow, dead UI, missing migration |
| P2 | 44 | Incomplete feature, weak coverage, cosmetic |
| P3 | 2 | Nice-to-have, future roadmap |
| **Total** | **101** | |

### By Domain

| Domain | Count | GAP IDs |
|--------|-------|---------|
| Database / Models | 14 | 001, 009, 010, 011, 013, 014, 015, 016, 055, 066, 084, 092, 096 |
| Frontend | 12 | 004, 005, 025, 026, 047, 054, 068, 069, 070, 089, 090, 091 |
| CLI | 8 | 006, 032, 035, 036, 038, 074, 075, 099 |
| Security / Auth | 9 | 002, 027, 028, 050, 061, 078, 079, 095, 101 |
| API | 7 | 017, 018, 020, 021, 022, 023, 060 |
| Connectors | 8 | 019, 051, 052, 059, 085, 086, 088, 093 |
| Workflows | 9 | 003, 012, 034, 042, 043, 065, 080, 082, 083 |
| Pipeline | 4 | 033, 039, 049, 067 |
| Platform | 5 | 008, 046, 053, 097, 098, 100 |
| Policy / OPA | 3 | 031, 056, 057 |
| Testing | 3 | 071, 072, 073 |
| Reporting / Export | 3 | 044, 063, 081 |
| Compliance / GDPR | 2 | 029, 083 |
| Risk Engine | 1 | 040 |
| Architecture | 1 | 064 |
| DevOps | 1 | 024 |
| Configuration | 1 | 094 |
| Auth / SSO | 1 | 077 |
| Assessors | 1 | 058 |
| Physical Security | 1 | 087 |

### By Effort

| Effort | Count | Description |
|--------|-------|-------------|
| S (<1 day) | 22 | Quick fixes, guard clauses, config changes |
| M (1-3 days) | 48 | Feature completion, new endpoints, migrations |
| L (3-5 days) | 17 | Multi-file features, framework coverage, test suites |
| XL (1+ week) | 4 | Multi-tenancy, mock->real connectors, enterprise connectors, frontend parity |

### Effort by Priority

| | S | M | L | XL | Total |
|---|---|---|---|---|---|
| P0 | 4 | 3 | 0 | 1 | 8 |
| P1 | 7 | 24 | 9 | 0 | 40 |
| P2 | 8 | 20 | 7 | 3 | 38 |
| P3 | 1 | 0 | 1 | 0 | 2 |

---

## Cross-References

| GAP | Related GAPs | Nature of Relationship |
|-----|-------------|----------------------|
| GAP-002 | GAP-035, GAP-039 | Same root cause (hash algorithm mismatch) |
| GAP-004 | GAP-005, GAP-022 | Frontend buttons need backend endpoints |
| GAP-009 | GAP-010, GAP-013, GAP-014, GAP-015, GAP-016 | Same class of bug (missing migrations) |
| GAP-020 | GAP-022 | Subset (POA&M is one of 18 models without API) |
| GAP-046 | GAP-081 | Email required for scheduled report delivery |
| GAP-050 | GAP-077, GAP-095 | Auth session management cluster |
| GAP-055 | GAP-066 | Same issue from different angles (asset-finding FK) |
| GAP-059 | GAP-087, GAP-088, GAP-093 | Connector quality/coverage cluster |
| GAP-064 | GAP-065 | Architecture patterns without runtime effect |
| GAP-070 | GAP-091 | Dashboard data sourcing cluster |
| GAP-008 | GAP-097, GAP-098, GAP-100 | In-memory platform services cluster |
