# Full Codebase Audit & Diagnostic Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run a comprehensive parallel audit of every component in the Warlock codebase — find bugs, dead code, security issues, missing interconnections, and test gaps — then produce a single health report with actionable findings.

**Architecture:** Dispatch 10 specialized agents in parallel, each auditing one domain. Each agent reads code, runs validation commands, and writes findings to a structured JSON file. A final coordinator agent merges all findings into one report.

**Tech Stack:** Python 3.12+, OPA, Terraform, SQLAlchemy, FastAPI, Click, pytest

---

## Audit Surface Area

| Domain | Files | LOC | Current Tests | Agent Type |
|---|---|---|---|---|
| Connectors (40) | 43 .py | 8,551 | 75 tests | code-reviewer |
| Normalizers (41) | 42 .py | 12,332 | 73 tests | code-reviewer |
| Assessors (14 modules, 25 assertions) | 14 .py | 7,775 | ~20 tests | code-reviewer |
| Pipeline (orchestrator, bus, queue, scheduler, loader) | 5 .py | 1,819 | ~10 tests | code-reviewer |
| Database (models, migrations, engine, audit, repository) | 6 .py | 3,622 | ~15 tests | database-optimizer |
| REST API (124 routes, auth, middleware, policy gate) | 6 .py | 5,397 | ~5 tests | security-auditor |
| CLI (34 commands) | 1 .py | ~2,000 | 0 dedicated tests | code-reviewer |
| OPA Rego Policies (592 files) | 592 .rego | 25,857 | 599 OPA tests | grc-engineer |
| OSCAL Packages (275 files, 10 frameworks) | 275 .json/.rego | 68,965 | 0 tests | grc-engineer |
| Terraform (5 modules, 3 clouds) | 15 .tf | 782 | 0 tests | terraform-engineer |
| Workflows (7 modules) | 7 .py | 4,045 | ~15 tests | code-reviewer |
| Exports (OSCAL, binder, alerts, reports, temporal) | 5 .py | 3,580 | ~2 tests | code-reviewer |
| Demo Seed | 1 .py | 9,228 | 1 test | code-reviewer |
| Config, logging, lambda, utils | 4 .py | ~500 | 0 tests | security-auditor |

---

## Phase 1: Parallel Agent Swarm (10 agents, simultaneous)

Each agent gets a focused brief, reads its files, runs its checks, and writes findings. All 10 run at the same time.

### Task 1: Agent — Python Backend Code Review (connectors + normalizers)

**Agent type:** `code-reviewer`

**Brief:** Audit all 40 connectors in `warlock/connectors/` and all 41 normalizers in `warlock/normalizers/`. For each file:
- Check every normalizer's `can_handle()` matches the connector's source/event_type values
- Find dead code (methods never called, imports never used)
- Find inconsistent patterns (some normalizers use `raw_data.get("response", [])`, others use `raw_data.get("records", [])` — are any wrong?)
- Check error handling: what happens when raw_data is malformed?
- Check for duplicate `region=` bugs like the ones found in GCP and OVH normalizers
- Verify every connector registered in `connectors/__init__.py` has a matching normalizer
- List any normalizer event_type handlers that no connector ever produces

**Files to read:**
- `warlock/connectors/*.py` (all 43 files)
- `warlock/normalizers/*.py` (all 42 files)
- `warlock/connectors/base.py` (BaseConnector, SourceType, ConnectorResult)
- `warlock/normalizers/base.py` (BaseNormalizer, FindingData, NormalizerRegistry)

**Commands to run:**
- `grep -rn "def _normalize_" warlock/normalizers/ | wc -l` (count all handler methods)
- `grep -rn "event_type==" warlock/normalizers/ | sort` (verify event_type dispatch)

**Output:** List of bugs, dead code, pattern inconsistencies, and missing error handling.

- [ ] Dispatch agent
- [ ] Review findings

---

### Task 2: Agent — Assessor & Assertion Audit

**Agent type:** `code-reviewer`

**Brief:** Audit the entire assessment engine:
- Verify all 25 assertions in `assertions.py` are bound to at least one control in every relevant framework
- Check assertion logic: do any assertions have logic bugs (wrong comparison, missing edge case)?
- Verify `engine.py` Tier 1 → Tier 2 fallback works correctly
- Check `ai_reasoning.py` for prompt injection risks in the compliance context passed to LLMs
- Audit `risk_engine.py` FAIR Monte Carlo implementation for statistical correctness
- Check `vendor_risk.py` scoring algorithm
- Verify `anomaly.py`, `rag.py`, `policy_discovery.py` are functional or dead code
- Check `cadence.py`, `drift.py`, `simulation.py`, `posture.py` for datetime bugs (naive vs aware — we already found one)

**Files to read:**
- `warlock/assessors/*.py` (all 14 files)
- `warlock/pipeline/loader.py` (where assertions are loaded and bound)

**Commands to run:**
- `grep -c "engine.bind_control" warlock/assessors/assertions.py` (count bindings)
- `grep -c "@engine.assertion" warlock/assessors/assertions.py` (count assertions)

**Output:** Assertion coverage gaps, logic bugs, dead modules, datetime issues, security concerns in AI prompts.

- [ ] Dispatch agent
- [ ] Review findings

---

### Task 3: Agent — REST API Security Audit

**Agent type:** `security-auditor`

**Brief:** Full security audit of the FastAPI application:
- Check all 124 routes for missing authentication (`Depends(get_current_user)`)
- Check for SQL injection in any raw query usage
- Check for IDOR vulnerabilities (can user A access user B's data?)
- Audit JWT implementation: secret handling, expiry, revocation
- Audit password hashing: bcrypt rounds, PBKDF2 fallback
- Check rate limiting configuration and bypass potential
- Check CORS configuration
- Check for information leakage in error responses
- Audit the `policy_gate.py` OPA integration: fail-open vs fail-closed
- Check `auth.py` lockout implementation for timing attacks
- Verify ABAC scoping actually filters data (not just checks permissions)
- Check if any endpoint returns unhashed passwords, tokens, or secrets

**Files to read:**
- `warlock/api/app.py` (all routes)
- `warlock/api/auth.py` (JWT, passwords, API keys)
- `warlock/api/deps.py` (auth dependencies, ABAC)
- `warlock/api/middleware.py` (rate limiting, headers, audit logging)
- `warlock/api/policy_gate.py` (OPA enforcement)
- `warlock/api/trust_portal.py` (public-facing portal)
- `warlock/config.py` (secrets, defaults)

**Output:** Categorized findings: CRITICAL / HIGH / MEDIUM / LOW with exact file:line references.

- [ ] Dispatch agent
- [ ] Review findings

---

### Task 4: Agent — Database & Migration Audit

**Agent type:** `database-optimizer`

**Brief:** Audit the database layer:
- Verify all 34 models in `models.py` have proper indexes for query patterns used in the API/CLI
- Check for N+1 query patterns in workflows and API routes
- Verify all foreign key relationships have correct `ondelete` behavior
- Check migration chain integrity (do all 7 migrations apply cleanly on fresh DB?)
- Look for missing indexes on columns used in WHERE clauses or JOINs
- Check for schema drift between models.py and actual migrations
- Verify SQLite compatibility (JSON columns, datetime handling, FK enforcement)
- Check `engine.py` connection pool settings

**Files to read:**
- `warlock/db/models.py`
- `warlock/db/engine.py`
- `warlock/db/repository.py`
- `warlock/db/audit.py` (if exists)
- `alembic/env.py`
- All migration files in `warlock/db/migrations/versions/`

**Commands to run:**
- `alembic check` (verify no schema drift)
- `alembic history` (verify migration chain)

**Output:** Missing indexes, N+1 patterns, FK issues, migration problems.

- [ ] Dispatch agent
- [ ] Review findings

---

### Task 5: Agent — OPA Rego Policy Audit

**Agent type:** `grc-engineer`

**Brief:** Audit the 592 Rego policy files:
- Verify every NIST 800-53 control family in `policies/nist-800-53/` maps to a control in `warlock/frameworks/nist_800_53.yaml`
- Same for ISO 27001, SOC 2, CMMC, HIPAA
- Check for policies that reference non-existent input fields
- Verify `policies/` are loadable by `policy_gate.py` — do the package names match what the gate queries?
- Check if any policy has `default allow = true` (dangerous)
- Verify test coverage: which policies have `_test.rego` files and which don't
- Check for dead policies that no control references

**Files to read:**
- All files in `policies/` (592 .rego files)
- `warlock/api/policy_gate.py` (to understand what package paths are queried)
- `warlock/frameworks/*.yaml` (to cross-reference control IDs)

**Commands to run:**
- `opa check policies/` (already passed — confirm)
- `opa test policies/ -v --format json 2>&1 | tail -5` (run all OPA tests)
- `grep -r "default allow = true" policies/` (find dangerous defaults)

**Output:** Unmapped policies, missing test coverage, dangerous defaults, integration gaps with policy_gate.py.

- [ ] Dispatch agent
- [ ] Review findings

---

### Task 6: Agent — OSCAL Package Validation

**Agent type:** `grc-engineer`

**Brief:** Audit the 275 OSCAL framework package files:
- Validate all JSON catalogs against OSCAL 1.1.2 schema structure
- Check if `warlock/export/oscal.py` references any of these catalog files (it likely doesn't — find the gap)
- Verify control IDs in OSCAL catalogs match control IDs in `warlock/frameworks/*.yaml`
- Check for duplicate control definitions across packages
- Verify each framework package has both a catalog and profile
- Check Rego policies inside OSCAL packages (e.g., `iso-27001-oscal/policies/`) — are they duplicates of `policies/iso-27001/`?

**Files to read:**
- All files in `frameworks-oscal/` (275 files)
- `warlock/export/oscal.py` (the OSCAL exporter)
- `warlock/frameworks/*.yaml` (the pipeline's framework definitions)

**Output:** Schema issues, exporter disconnection, control ID mismatches, duplicate policies.

- [ ] Dispatch agent
- [ ] Review findings

---

### Task 7: Agent — Terraform Module Audit

**Agent type:** `terraform-engineer`

**Brief:** Audit the 5 Terraform modules:
- Verify each module follows Terraform best practices (variables validated, outputs documented, no hardcoded values)
- Check if modules reference Warlock-specific tags or naming conventions
- Verify security: are there any overly permissive IAM policies, open security groups, or missing encryption defaults?
- Check if the modules are usable standalone or require Warlock-specific context
- Verify provider version constraints

**Files to read:**
- All 15 `.tf` files in `terraform/modules/`

**Commands to run:**
- `terraform validate` for each module (already passed — confirm)
- `terraform fmt -check -recursive terraform/` (formatting check)

**Output:** Security issues, best practice violations, missing documentation.

- [ ] Dispatch agent
- [ ] Review findings

---

### Task 8: Agent — CLI Command Audit

**Agent type:** `code-reviewer`

**Brief:** Audit all 34 CLI commands:
- Run every command against the seeded database and verify it exits 0
- Check for commands that crash on empty database
- Check for commands that silently return nothing when they should show data
- Verify `--help` text is accurate for every command
- Check for inconsistent option naming (some use `-f` for framework, do all?)
- Verify the `_resolve_system_id` function works for all system commands
- Check if any command leaks sensitive data to stdout

**Files to read:**
- `warlock/cli.py` (the entire CLI — ~2000 lines)

**Commands to run:**
- Every `warlock <command>` with appropriate flags against the seeded DB
- `warlock --help` (verify all commands listed)

**Output:** Broken commands, inconsistent interfaces, missing help text.

- [ ] Dispatch agent
- [ ] Review findings

---

### Task 9: Agent — Pipeline & Integration Audit

**Agent type:** `code-reviewer`

**Brief:** Audit the pipeline orchestration and cross-module integration:
- Trace the full data flow: connector → raw_event → normalizer → finding → mapper → control_result → assessor
- Verify the EventBus pub/sub actually delivers events (or is it dead code?)
- Check `pipeline/queue.py` — is the Redis/Kafka/SQS backend functional or stubbed?
- Check `pipeline/scheduler.py` — does the multi-schedule scheduler actually work?
- Verify `pipeline/loader.py` `build_pipeline()` correctly wires all components
- Check for race conditions in concurrent pipeline runs
- Verify the demo seed's pipeline produces the same results as `warlock collect` would
- Check `lambda_handler.py` — is it functional or dead code?

**Files to read:**
- `warlock/pipeline/*.py` (all 5 files)
- `warlock/lambda_handler.py`
- `scripts/demo_seed.py` (main function pipeline setup)
- `warlock/config.py` (queue and scheduler settings)

**Output:** Dead code, broken integrations, race conditions, non-functional modules.

- [ ] Dispatch agent
- [ ] Review findings

---

### Task 10: Agent — Workflow & Export Module Audit

**Agent type:** `code-reviewer`

**Brief:** Audit the 7 workflow modules and 5 export modules:
- Check each workflow for datetime naive/aware bugs (we already found one in `personnel.py`)
- Verify GDPR export/erase actually anonymizes data properly
- Check retention purge: does it respect legal holds?
- Verify OSCAL export produces valid OSCAL 1.1.2 JSON
- Check the binder ZIP export for path traversal vulnerabilities
- Verify `alerts.py` Slack/PagerDuty/webhook integration
- Check `questionnaires.py` for complete CRUD lifecycle
- Verify `personnel.py` HR/IdP/training sync doesn't create duplicates

**Files to read:**
- `warlock/workflows/*.py` (all 7 files)
- `warlock/export/*.py` (all 5 files)

**Output:** Datetime bugs, security issues in exports, broken workflows.

- [ ] Dispatch agent
- [ ] Review findings

---

## Phase 2: Merge & Report

### Task 11: Consolidate Findings

After all 10 agents complete:

- [ ] Collect all agent outputs
- [ ] Deduplicate findings (multiple agents may flag the same issue)
- [ ] Categorize: CRITICAL (breaks functionality) / HIGH (security or data integrity) / MEDIUM (bugs) / LOW (code quality) / INFO (suggestions)
- [ ] Write consolidated report to `docs/audit-report-2026-03-19.md`
- [ ] Count findings by category
- [ ] Identify top 5 highest-priority fixes

---

## Phase 3: Fix Critical & High Findings

### Task 12: Fix CRITICAL findings

- [ ] Fix each CRITICAL finding
- [ ] Write regression test for each fix
- [ ] Run full test suite after each fix

### Task 13: Fix HIGH findings

- [ ] Fix each HIGH finding
- [ ] Write regression test for each fix
- [ ] Run full test suite after each fix

### Task 14: Expand Test Suite

Based on audit gaps, add tests for:

- [ ] Every CLI command (34 commands × smoke test = 34 new tests)
- [ ] Every API route authentication check (124 routes = 124 new tests minimum)
- [ ] OSCAL export validation (schema compliance test)
- [ ] Rego → policy_gate integration test
- [ ] Each new demo connector produces valid findings (33 new connectors × 1 test)
- [ ] Datetime handling across all workflow modules

### Task 15: Final Verification

- [ ] Run full pytest suite (target: 300+ tests, all green)
- [ ] Run `opa test policies/ -v` (599 tests, all green)
- [ ] Run `terraform validate` on all modules
- [ ] Run demo seed from scratch and verify all CLI commands
- [ ] Start API server and hit every authenticated endpoint
- [ ] Commit and push

---

## Agent Dispatch Summary

| Agent # | Type | Domain | Parallel | Estimated Duration |
|---|---|---|---|---|
| 1 | code-reviewer | Connectors + Normalizers (85 files) | Yes | 3-5 min |
| 2 | code-reviewer | Assessors + Assertions (14 files) | Yes | 2-3 min |
| 3 | security-auditor | REST API (6 files, 124 routes) | Yes | 3-5 min |
| 4 | database-optimizer | DB models + migrations (10 files) | Yes | 2-3 min |
| 5 | grc-engineer | OPA Rego Policies (592 files) | Yes | 3-5 min |
| 6 | grc-engineer | OSCAL Packages (275 files) | Yes | 2-3 min |
| 7 | terraform-engineer | Terraform Modules (15 files) | Yes | 1-2 min |
| 8 | code-reviewer | CLI Commands (1 file, 34 commands) | Yes | 2-3 min |
| 9 | code-reviewer | Pipeline + Integration (6 files) | Yes | 2-3 min |
| 10 | code-reviewer | Workflows + Exports (12 files) | Yes | 2-3 min |
| 11 | — | Consolidate report | After 1-10 | 5 min |
| 12-13 | — | Fix CRITICAL/HIGH | After 11 | Varies |
| 14 | — | Expand tests | After 13 | 15-20 min |
| 15 | — | Final verification | After 14 | 5 min |

**Total wall-clock time for Phase 1:** ~5 minutes (all 10 agents run in parallel)
**Total including fixes and tests:** ~30-45 minutes
