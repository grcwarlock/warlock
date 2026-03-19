# Warlock Codebase Audit Report

**Date:** 2026-03-19
**Audited by:** 10 parallel specialized agents
**Scope:** Full codebase — Python backend, OPA policies, OSCAL packages, Terraform modules, CLI, REST API

---

## Executive Summary

| Severity | Count |
|----------|-------|
| **CRITICAL** | 10 |
| **HIGH** | 27 |
| **MEDIUM** | 33 |
| **LOW** | 22 |
| **INFO** | 14 |
| **TOTAL** | 106 |

### Top 10 Most Urgent Findings

| # | Severity | Domain | Finding |
|---|----------|--------|---------|
| 1 | CRITICAL | Security | ABAC scope filters exist but are never called — every user sees all data |
| 2 | CRITICAL | Security | ZIP path traversal in binder.py — malicious control IDs write files outside ZIP |
| 3 | CRITICAL | OPA | 592 Rego policies are dead code — no compliance evaluation engine exists |
| 4 | CRITICAL | OSCAL | Exporter has zero linkage to OSCAL packages — completely disconnected |
| 5 | CRITICAL | Security | OPA policy gate defaults to fail-open — network attack bypasses all policy |
| 6 | CRITICAL | Terraform | CloudTrail has no KMS key — SC-28 compliance gap |
| 7 | CRITICAL | Terraform | S3 audit log bucket has no lifecycle policy |
| 8 | CRITICAL | Terraform | IAM role name collision on multi-VPC deployments |
| 9 | CRITICAL | Assessors | Assertion bindings silently overwrite — only last assertion runs per control |
| 10 | CRITICAL | CLI | `_resolve_system_id("")` matches ALL systems via `startswith("")` |

---

## Findings by Domain

### 1. REST API Security (Agent 3)

| # | Sev | Finding |
|---|-----|---------|
| S-1 | CRITICAL | ABAC scope filters (`apply_framework_scope`, `apply_source_scope`) exist in deps.py but are never called in any endpoint. Every user sees all data regardless of `allowed_frameworks`/`allowed_sources`. |
| S-2 | CRITICAL | OPA policy gate defaults to `fail_mode="open"`. OPA unreachable = all requests allowed. |
| S-3 | CRITICAL | JWT secret accepts empty string and short keys in non-production. |
| S-4 | HIGH | No token revocation on user deactivation — tokens valid up to 60 min after firing. |
| S-5 | HIGH | API keys hashed with unsalted SHA-256 — no salt, no HMAC, no stretching. |
| S-6 | HIGH | Rate limiter is per-process in-memory — 4 workers = 4x the limit. Trivially bypassed. |
| S-7 | HIGH | Trust portal exposes exact control counts to unauthenticated users. |
| S-8 | HIGH | Readiness probe leaks database error details to unauthenticated callers. |
| S-9 | MEDIUM | OPA dependency never gets authenticated user — OPA always sees `user=None`. |
| S-10 | MEDIUM | No CORS validation — `cors_origins=["*"]` with `allow_credentials=True` is allowed. |
| S-11 | MEDIUM | No input validation on API key scopes — invalid scopes stored in DB. |
| S-12 | MEDIUM | Missing pagination on several list endpoints — memory exhaustion risk. |
| S-13 | MEDIUM | Dummy hash for timing oracle has wrong length — user enumeration possible. |
| S-14 | MEDIUM | Legacy SHA-256 password hashes with no forced migration deadline. |
| S-15 | LOW | JWT without `exp` claim valid forever in HMAC fallback. |
| S-16 | LOW | Password complexity only checks length — no character class requirements. |
| S-17 | LOW | Trust portal email validation only checks `"@" in email`. |
| S-18 | LOW | No request size limits configured. |

### 2. Assessors & Assertions (Agent 2)

| # | Sev | Finding |
|---|-----|---------|
| A-1 | CRITICAL | `bind_control` is single-value dict — last binding overwrites previous. AT-2 loses `training_completion_rate`, AC-2 loses `mfa_enabled`. |
| A-2 | HIGH | Prompt injection risk in AI reasoning — untrusted connector data in LLM prompts. |
| A-3 | HIGH | Same prompt injection in AI narrator (SSP generation). |
| A-4 | HIGH | Gemini API key exposed in URL query parameter — appears in logs. |
| A-5 | MEDIUM | `mfa_enabled` returns True on insufficient data — fail-open assertion. |
| A-6 | MEDIUM | `no_root_access_keys` returns True by default — fail-open. |
| A-7 | MEDIUM | Portfolio VaR summation is statistically unsound (not additive). |
| A-8 | MEDIUM | Vendor risk `_assessment_currency_score` can return negative. |
| A-9 | MEDIUM | PgVector SQL injection via table name f-string interpolation. |
| A-10 | LOW | `dlp_policies_active` has no SOC 2 or NIST binding. |
| A-11 | LOW | `backup_job_successful` missing SOC 2 A1.1 binding. |
| A-12 | LOW | Legacy `numpy.random.seed()` not thread-safe. |

### 3. Database & Migrations (Agent 4)

| # | Sev | Finding |
|---|-----|---------|
| D-1 | HIGH | Missing index: `posture_snapshots.system_profile_id`. |
| D-2 | HIGH | Missing index: `control_results.control_mapping_id`. |
| D-3 | HIGH | Nullable FKs missing `ondelete` on POAM, Issue, CompensatingControl, RiskAcceptance. |
| D-4 | HIGH | Connection pool `pool_size=20` too large for multi-worker PostgreSQL. |
| D-5 | MEDIUM | N+1 query: `build_audit_package` does 3N queries for N controls. |
| D-6 | MEDIUM | Three unbounded COUNT queries per dashboard poll. |
| D-7 | MEDIUM | `ExternalAuditor.magic_link_hash` unindexed — full table scan on auth. |
| D-8 | MEDIUM | `PolicyOverride`, `ComplianceDrift.system_profile_id` unindexed. |
| D-9 | MEDIUM | `AuditEntry.extra` column aliased as `"metadata"` — reserved word. |
| D-10 | LOW | Generic `JSON` instead of `JSONB` on PostgreSQL — no GIN support. |
| D-11 | LOW | `api_keys.user_id` no `ondelete` — stale keys survive user deletion. |
| D-12 | LOW | Subquery IN-list for framework-filtered findings — use JOIN instead. |

### 4. Pipeline & Integration (Agent 9)

| # | Sev | Finding |
|---|-----|---------|
| P-1 | HIGH | No concurrency protection — simultaneous pipeline runs produce duplicate data. |
| P-2 | HIGH | Lambda EventBridge detection has operator precedence bug — misroutes invocations. |
| P-3 | MEDIUM | SHA-256 integrity hashes computed but never verified — write-only. |
| P-4 | MEDIUM | Normalizer failure silently drops findings — pipeline appears successful. |
| P-5 | MEDIUM | SQS VisibilityTimeout set to `batch_size` value — semantically wrong. |
| P-6 | MEDIUM | EventBus has no production subscribers — dead infrastructure. |
| P-7 | MEDIUM | All-or-nothing transaction — one connector failure rolls back entire run. |
| P-8 | LOW | Scheduler creates in-memory EventBus, ignoring queue backend config. |
| P-9 | LOW | Demo seed normalizer registration diverges from production loader. |

### 5. Connectors & Normalizers (Agent 1)

| # | Sev | Finding |
|---|-----|---------|
| N-1 | MEDIUM | AWS connector emits `config_compliance`, `iam_policies`, `ec2_vpcs`, `ec2_flow_logs`, `cloudtrail_status` — no normalizer handlers. |
| N-2 | MEDIUM | No normalizer checks `raw_data` for None — all crash on malformed events. |
| N-3 | MEDIUM | 4 connectors (IBM Cloud, Qualys, Prisma, Wiz) use `httpx` without null-guard in collect(). |
| N-4 | LOW | Azure connector doesn't set `region` in raw_data — all findings have empty region. |
| N-5 | LOW | Dead code: unused imports, unused constants in 15+ files. |
| N-6 | LOW | Tenable connector `time.sleep` blocks collection thread up to 5 minutes. |

### 6. Workflows & Exports (Agent 10)

| # | Sev | Finding |
|---|-----|---------|
| W-1 | CRITICAL | ZIP path traversal in binder.py — control ID injection writes files outside ZIP. |
| W-2 | HIGH | POA&M has no status transition validation — any state change allowed. |
| W-3 | HIGH | GDPR erasure doesn't cascade to Issue, POAM, RiskAcceptance, AuditEntry, Questionnaire. |
| W-4 | HIGH | 6 datetime naive/aware bugs across poam.py, compensating.py, risk_acceptance.py, questionnaires.py, system_profile.py, retention.py. |
| W-5 | HIGH | Legal hold is binary (all-or-nothing) — blocks ALL purging, not scoped to matter. |
| W-6 | MEDIUM | GDPR anonymization uses record ID prefix — trivially linkable pseudonymization. |
| W-7 | MEDIUM | Issues auto-create deduplicates by control_result_id, not (framework, control_id) — duplicates on re-run. |
| W-8 | MEDIUM | Email alerts stubbed but returns True (success) — callers think email was sent. |
| W-9 | MEDIUM | No alert deduplication — same finding triggers Slack on every pipeline run. |
| W-10 | MEDIUM | OSCAL SSP uses `"id"` instead of `"identifier"` — fails schema validation. |
| W-11 | MEDIUM | Binder output path is user-controlled — arbitrary file write on server. |
| W-12 | MEDIUM | Questionnaire scoring: all "no" answers treated as negative (fails for inverse questions). |
| W-13 | LOW | Purge order creates orphans if interrupted mid-transaction. |

### 7. OPA Rego Policies (Agent 5)

| # | Sev | Finding |
|---|-----|---------|
| R-1 | CRITICAL | 592 Rego policies are never invoked at runtime — no compliance evaluation engine. |
| R-2 | HIGH | Policy input schema (`input.normalized_data.*`) doesn't match pipeline's FindingData. |
| R-3 | MEDIUM | 540 unguarded `not input.*` expressions — false positives on partial data. |
| R-4 | MEDIUM | SOC 2 policies hardcode `input.provider == "aws"` — multi-cloud gap. |
| R-5 | MEDIUM | NIST coverage: 144 base controls only, 1,032 enhancements missing. |

### 8. OSCAL Packages (Agent 6)

| # | Sev | Finding |
|---|-----|---------|
| O-1 | CRITICAL | OSCAL exporter has zero linkage to OSCAL packages — completely disconnected. |
| O-2 | HIGH | 249 Rego files in frameworks-oscal are byte-identical duplicates of policies/. |
| O-3 | HIGH | NIST catalog missing 883 control enhancements (293 vs 1,176). |
| O-4 | HIGH | ISO 42001 IDs: zero crosswalk match between OSCAL and pipeline. |
| O-5 | HIGH | UCF IDs: zero crosswalk match (22 vs 115 controls). |
| O-6 | MEDIUM | UCF catalog uses non-standard OSCAL root element. |
| O-7 | MEDIUM | 5 OSCAL packages (CMMC, FedRAMP, GDPR, HIPAA, PCI-DSS) have no pipeline YAML. |
| O-8 | MEDIUM | ISO 27701 pipeline has no OSCAL package. |
| O-9 | MEDIUM | SOC 2 dot-vs-hyphen normalization mismatch in exporter. |

### 9. Terraform Modules (Agent 7)

| # | Sev | Finding |
|---|-----|---------|
| T-1 | CRITICAL | CloudTrail has no KMS key — SC-28 compliance gap. |
| T-2 | CRITICAL | S3 audit log bucket has no lifecycle policy — retention not enforced. |
| T-3 | CRITICAL | IAM role name collision on multi-VPC deployments. |
| T-4 | HIGH | Provider version `>= 5.0` unbounded — breaking changes not blocked. |
| T-5 | HIGH | Azure provider `~> 3.80` outdated, deprecated args. |
| T-6 | HIGH | CloudWatch log group for flow logs not KMS-encrypted. |
| T-7 | HIGH | Hardcoded names: `warlock-auditor`, `grc-security-alerts`, `grc_audit_logs`. |
| T-8 | HIGH | `data.azurerm_subscription` fails under restricted service principals. |
| T-9 | MEDIUM | `terraform fmt` fails on 4 of 5 modules. |
| T-10 | MEDIUM | No `validation` blocks on any variable in any module. |
| T-11 | MEDIUM | Route tables bypass `local.common_tags` — compliance tag gap. |
| T-12 | MEDIUM | GCP deprecated V1 org policy API — AC-3 gap. |
| T-13 | MEDIUM | Cross-module dependency: secure-account-baseline missing CloudWatch Logs for CloudTrail. |
| T-14 | LOW | No output descriptions in any module. |
| T-15 | LOW | Azure storage account missing blob soft-delete. |

### 10. CLI Commands (Agent 8)

| # | Sev | Finding |
|---|-----|---------|
| C-1 | CRITICAL | `_resolve_system_id("")` matches ALL systems — `startswith("")` is always true. |
| C-2 | CRITICAL | `ingest -f` means `--file`, not `--framework` — dangerous semantic collision. |
| C-3 | HIGH | `simulate-audit --date` leaks full stack trace on invalid input. |
| C-4 | HIGH | `framework-diff` leaks full stack trace on missing files. |
| C-5 | HIGH | `_resolve_system_id` silently returns first match on ambiguous prefix. |
| C-6 | MEDIUM | `sources` accesses private `registry._normalizers` field. |
| C-7 | LOW | `risk` takes ~43 seconds with no progress indicator. |
| C-8 | LOW | No commands validate enum-style filter values. |

---

## Priority Fix Plan

### Immediate (data integrity and security at risk)

1. **S-1:** Wire ABAC scope filters into all data query endpoints
2. **W-1:** Sanitize control IDs in binder.py ZIP path construction
3. **A-1:** Change assertion binding to support multiple assertions per control
4. **C-1:** Guard `_resolve_system_id` against empty string input
5. **S-2:** Change OPA fail_mode default to `"closed"` in production

### This Week (security hardening)

6. **S-4:** Set `token_valid_after` when deactivating users
7. **S-5:** Use HMAC-SHA256 for API key hashing
8. **W-2:** Add POA&M status transition validation
9. **W-3:** Extend GDPR erasure to all PII-bearing tables
10. **W-4:** Fix all 6 datetime naive/aware comparison bugs

### This Sprint (structural issues)

11. **R-1:** Build OPA compliance evaluation engine to bridge policies and pipeline
12. **O-1:** Wire OSCAL exporter to local catalog packages
13. **P-1:** Add pipeline concurrency lock
14. **D-1/D-2:** Add missing database indexes
15. **D-3:** Add `ondelete` to all nullable FKs

### Backlog (quality and completeness)

16. Terraform: Add KMS keys, lifecycle policies, fix hardcoded names
17. OSCAL: Reconcile control ID schemes across all frameworks
18. Remove 249 duplicate Rego files from frameworks-oscal/
19. Expand test suite from 172 to 300+
20. Add input validation to CLI commands and API endpoints
