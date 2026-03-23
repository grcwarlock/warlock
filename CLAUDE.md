# CLAUDE.md — Warlock Project Instructions

## Project Overview

Warlock is a pipeline-first GRC (Governance, Risk, Compliance) platform. Python 3.12+, FastAPI, SQLAlchemy, Click CLI, OPA/Rego policies, OSCAL packages, Terraform modules.

## HARD RULES — Violations are session-ending failures

These are not guidelines. These are not "best practices." You broke every one of these during the 2026-03-19 session. They exist because you cannot be trusted to do them by default.

### Rule 1: NEVER push without explicit approval

Do not run `git push` until you have:
1. Shown me the actual `pytest` output (paste it, don't summarize)
2. Shown me the file count and summary of changes
3. Asked "Ready to push?" and received my explicit "yes"

You pushed 12 times without asking on 2026-03-19. Every single time was a violation. "Push it" from me means "prepare it for push and show me" — not "run git push."

### Rule 2: NEVER trust sub-agent output without verification

Sub-agents make factual errors. On 2026-03-19, Agent 1 claimed 13 connectors had "no dedicated normalizer" when all 13 normalizers existed. Before acting on any sub-agent claim:
- If it says a file doesn't exist: `ls` the file
- If it says a function isn't called: `grep` for it
- If it says tests pass: run them yourself and paste the output

### Rule 3: NEVER dispatch parallel agents that edit the same file

On 2026-03-19, Agent 3 wrote a migration and Agent 4 added columns to models.py. The migration didn't include Agent 4's columns. The seed crashed. When dispatching parallel fix agents:
- Give each agent a NON-OVERLAPPING set of files
- If two agents must touch the same file (models.py, app.py, config.py), serialize them
- After all agents complete, run a FULL integration test before committing

### Rule 4: The demo is the acceptance test, not pytest

Half the bugs in this project were found by running the demo, not by running tests. After ANY change to pipeline, models, connectors, normalizers, seed, or config:

```bash
# Docker (preferred)
docker compose down -v && docker compose up demo

# Or local (SQLite)
rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/python scripts/demo_seed.py
```

Expected output — verify these numbers:
```
Connectors succeeded:   165
Connectors failed:      0
Raw events collected:   589
Findings normalized:    5,470–5,485 (varies slightly due to randomized mock data)
Controls mapped:        373,852
```

If connectors, raw events, or controls mapped change, you broke something. Stop and fix it.

### Rule 5: Test after EVERY change, not at the end

Do not batch 20 edits and test once. Do not dispatch 6 agents and test after all 6 finish. Every logical change gets its own test run. If a sub-agent reports "172 passed" but other agents haven't finished editing shared files, that test run is meaningless.

### Rule 6: NEVER add or remove files without asking

The v1 frontend incident: you copied 1,010 files from a ZIP into the repo without being asked. You then had to remove 129 of them. Before adding or removing any directory or large set of files, state what you plan to do and wait for approval.


---

## Pre-Push QA Gate

Run the automated QA gate. It covers everything. No manual steps.

```bash
./scripts/qa.sh
```

The script verifies: lint, format, imports, pytest (657+ baseline), demo seed (165 connectors, 0 failures), CLI smoke tests, TUI import, OPA policies, Terraform validate + fmt, OSCAL JSON, framework YAML, secrets scan, .env check, dependency audit, migration reversibility, documentation count accuracy, AI task prompt coverage, CLI --ai/--ask flags, AI service import, production docs completeness (18 required docs in proddocs/), and production docs accuracy (connector/framework counts match codebase).

ALL checks must pass. If any fail, fix before committing.

For a quick check during development (lint + tests only):

```bash
./scripts/qa.sh --quick
```

Or via Make:

```bash
make qa          # full gate
make qa-quick    # lint + test only
make verify-docs # documentation accuracy check only
```

### After the QA gate passes

1. List EVERY file you changed and what specifically changed in each one
2. Paste the actual QA gate output (not a summary)
3. Ask: "Ready to push?"
4. WAIT for explicit "yes" before running `git push`

### Pre-push hook (REQUIRED — installed in both repos)

A pre-push hook runs `ruff check` + `ruff format --check` on the exact committed state before pushing. This catches duplicate imports from merge resolutions — the #1 CI failure pattern. It stashes uncommitted changes first so it checks what would actually hit CI.

Location: `.git/hooks/pre-push` (already installed in both `~/Coding/GitHub/warlock` and `~/Desktop/stress-testing/warlock`).

If the hook fails, fix with: `.venv/bin/ruff check --fix warlock/ scripts/ && .venv/bin/ruff format warlock/ scripts/`

### After rebase/merge resolution — ALWAYS run lint before continuing

Merge resolutions routinely introduce duplicate imports (both sides import the same thing). After `git rebase --continue` or any merge conflict resolution:

```bash
.venv/bin/ruff check --fix warlock/ scripts/demo_seed.py scripts/demo_connectors_new.py
.venv/bin/ruff format warlock/ scripts/demo_seed.py scripts/demo_connectors_new.py
git add -u && git commit --amend --no-edit
```

This amends the rebase commit with clean imports before pushing.

---

## Parallel Agent Safety

### When dispatching audit/review agents (read-only)

Safe to run in parallel. No file conflicts. Dispatch as many as needed.

### When dispatching fix/build agents (write)

**Each agent gets a non-overlapping file set.** Divide by domain:

| Agent | Owns these files exclusively |
|---|---|
| Security agent | `warlock/api/*.py`, `warlock/config.py` |
| Assessor agent | `warlock/assessors/*.py` |
| Database agent | `warlock/db/*.py`, `alembic/`, migrations |
| Workflow agent | `warlock/workflows/*.py`, `warlock/export/*.py` |
| CLI agent | `warlock/cli/*.py` (66 modules — assign by domain, not all at once) |
| Demo seed agent | `scripts/demo_seed.py`, `scripts/demo_connectors_new.py` |
| Terraform agent | `terraform/**/*.tf` |
| OSCAL agent | `frameworks-oscal/**/*`, `warlock/normalizers/*.py`, `warlock/connectors/*.py` |

**Shared files (models.py, config.py, app.py) go to ONE agent only.** If two agents need to change models.py, the second agent must wait for the first to finish.

### After all agents complete

1. Run `pytest` — if failures reference files from different agents, the agents conflicted
2. Run the demo seed — if it crashes, check for migration gaps
3. Run `git diff --stat` — verify no file was edited by two agents with conflicting changes
4. Only then commit

---

## Dependency Chain Table

When you change the left column, you MUST update every file in the right column. Walk this table for every file you touched. Do not skip.

| If you change... | You MUST also update... |
|---|---|
| Connector (`warlock/connectors/`) | config.py, matching normalizer, demo_seed.py, README.md |
| Normalizer (`warlock/normalizers/`) | `__init__.py`, verify matching connector, re-run demo seed |
| DB model (`warlock/db/`) | Alembic migration, API routes, CLI commands, demo seed |
| Config setting (`warlock/config.py`) | `.env.example`, README.md if user-facing |
| API route (`warlock/api/`) | ABAC enforcement, input validation, auth decorator, update middleware skip paths for health endpoints |
| Assertion (`warlock/assessors/`) | All control bindings (list-based), demo seed |
| Pipeline (`warlock/pipeline/`) | Demo seed, connector count, hash chain |
| AI reasoning (`warlock/assessors/`) | Prompt sanitization, API key in header not URL, confidence floor |
| Workflow (`warlock/workflows/`) | State machine transitions, GDPR cascade, `ensure_aware()` |
| Dependency | `pyproject.toml`, `pip install -e ".[dev,ai]"` |
| Terraform (`terraform/`) | `terraform validate` + `terraform fmt -check` on ALL modules |
| OPA policies (`policies/`) | `opa check` + `opa test`, input schema matches normalizer output |
| OSCAL packages (`frameworks-oscal/`) | Validate JSON, check control IDs match pipeline YAML, update README.md counts |
| Framework YAML (`warlock/frameworks/`) | Re-run demo seed, verify loader doesn't crash, update README.md framework table |
| CLI command (`warlock/cli/*.py`) | `.github/workflows/ci.yml` CLI smoke test list, README.md, DEMO.md, CONTRIBUTING.md, CLI-REFERENCE.md |
| CI workflows (`.github/workflows/`) | Verify command/group names match actual CLI, test locally before pushing — CI failures block all PRs |
| Docker (`Dockerfile`, `docker-compose.yml`) | Rebuild image (`docker compose build demo`), verify `docker compose up demo` succeeds |
| Connector/normalizer/framework count changes | Update `proddocs/features/connectors.md`, `proddocs/product/frameworks.md`, `proddocs/product/overview.md` counts |
| API route changes | Update `proddocs/api/reference.md` endpoint list |
| CLI command changes | Update `proddocs/api/cli-reference.md` command list |
| DB model changes | Update `proddocs/technical/data-model.md` schema tables |
| Lake changes | Update `proddocs/technical/data-lake.md` |
| Security changes | Update `proddocs/technical/security.md` |

---

## Architecture Quick Reference

```
warlock/
  connectors/    — 165 source connectors
  normalizers/   — 165 parsers (raw → FindingData)
  mappers/       — control mapping (findings → 1,996 controls across 14 frameworks)
  assessors/     — assertion engine (101 assertions) + AI reasoning + OPA evaluator
  api/           — FastAPI REST API (163 routes, ABAC-scoped, 11 domain routers)
  cli/           — Click CLI package (599 leaf commands, 68 modules)
  db/            — SQLAlchemy models (42), schema via Base.metadata.create_all()
  export/        — OSCAL, binder, alerts, reports
  workflows/     — POA&M, risk acceptance, compensating controls, GDPR, retention
  pipeline/      — orchestrator, event bus, queue backends, scheduler
  lake/          — 23 GRC data lake modules (DuckDB, Parquet, RAG, Iceberg)
  domains/       — 7 domain service modules (registry, event bus, policy engine, controls, issues, evidence)
  frameworks/    — 14 framework YAMLs + crosswalks + baselines + inherited controls
  frameworks/reference/ — baselines.yaml (NIST Low/Mod/High), inherited_controls.yaml
tests/           — 657 pytest tests (32 files)
policies/        — 670 OPA/Rego files across 8 frameworks
frameworks-oscal/ — OSCAL catalog/profile JSON for 11 frameworks (17 JSON files)
terraform/       — 12 IaC modules (AWS, Azure, GCP)
.github/workflows/
  ci.yml             — Python lint + test + Docker build
  compliance-gate.yaml — OPA validation, Terraform validation, OSCAL + YAML checks
scripts/
  demo.sh        — one-command local demo (DB + OPA + seed + API)
  demo_seed.py   — 165 mock connectors, ~5,475 findings, 373K+ results
  demo_api.sh    — API query helper with auto-auth
  docker-demo.sh — Docker demo entrypoint (migrate + seed + serve)
```

## Key Patterns

- **Hash-chained audit trail**: SHA-256 at every pipeline stage. Never break the chain.
- **Fail-closed security**: OPA gate, assertions, ABAC all default to deny.
- **Multiple assertions per control**: List-based bindings. Append, never overwrite.
- **Timezone-aware datetimes**: Use `ensure_aware()` from `warlock/utils/`. No naive datetimes. SQLite returns naive datetimes even with `timezone=True` — always wrap DB values.
- **Rich markup escaping**: Use `rich.markup.escape()` on ALL user-supplied text before passing to `console.print()`. Unescaped `[brackets]` in titles/descriptions crash Rich.
- **Root health endpoints**: `/health`, `/healthz`, `/readyz` at app root (not just `/api/v1/health`). Required for k8s probes, load balancers, Docker HEALTHCHECK.
- **CLI groups show defaults**: All CLI groups use `invoke_without_command=True` and show a useful summary when called without a subcommand. Never error on bare group invocation.
- **Prompt sanitization**: `<evidence>` tags + control character stripping in all LLM prompts.
- **Gemini API key in header**: `x-goog-api-key`, never in URL query params.

## CI/CD Pipelines

Two GitHub Actions workflows run on every push/PR:

### `.github/workflows/ci.yml` — Python CI
- **Triggers:** push to main, all PRs
- **Jobs:** lint (ruff), test (pytest 657 tests), build (Docker image)
- If lint fails (like the 128 F401 errors on 2026-03-19), the whole pipeline is red. Run `ruff check warlock/` locally first.

### `.github/workflows/compliance-gate.yaml` — Compliance CI
- **Triggers:** push/PR that touches `policies/`, `terraform/`, `frameworks-oscal/`, `warlock/frameworks/`, `warlock/assessors/`
- **4 jobs run in parallel:**
  - OPA Policy Validation — syntax check, policy count regression guard (min 300), test coverage check
  - Terraform Validation — `terraform validate` + `terraform fmt -check` on all 12 modules
  - OSCAL Package Validation — all JSON files parse correctly
  - Framework YAML Validation — all YAMLs have valid v2 dict-based structure

If you touch policies or terraform, both CI workflows run. Fix failures locally before pushing.

## Frameworks (14 total)

| Framework | Pipeline YAML | Rego Policies | OSCAL Package | Active in Demo |
|---|---|---|---|---|
| NIST 800-53 | nist_800_53.yaml (1,176 controls) | 286 files | Yes | Yes |
| ISO 27001 | iso_27001.yaml (93 controls) | 186 files | Yes | Yes |
| ISO 27701 | iso_27701.yaml (95 controls) | — | Yes | Yes |
| ISO 42001 | iso_42001.yaml (39 controls) | — | Yes | Yes |
| SOC 2 | soc2.yaml (46 controls) | 26 files | Yes | Yes |
| UCF | ucf.yaml (115 controls) | 24 files | Yes | Yes |
| FedRAMP | fedramp.yaml (26 controls) | — | Yes | Yes |
| HIPAA | hipaa.yaml (64 controls) | 40 files | Yes | Yes |
| CMMC L2 | cmmc_l2.yaml (110 controls) | 50 files | Yes | Yes |
| GDPR | gdpr.yaml (15 controls) | — | Yes | Yes |
| PCI DSS v4.0 | pci_dss.yaml (63 controls) | 24 files | Yes | Yes |
| NIST CSF 2.0 | nist_csf.yaml (101 controls) | — | — | Yes |
| EU AI Act | eu_ai_act.yaml (33 controls) | — | — | Yes |
| SEC Cyber | sec_cyber.yaml (20 controls) | — | — | Yes |

**"Active in Demo"** means the framework produces control results in the demo seed. All 14 frameworks are wired with event_types and produce control results.

## Security-Critical Config Defaults

| Setting | Default | Do NOT change without asking |
|---|---|---|
| `opa_fail_mode` | `"closed"` | Changing to "open" bypasses all API policy enforcement |
| `ai_confidence_floor` | `0.7` | Lowering accepts unreliable AI compliance assessments |
| `ai_temperature` | `0.0` | Raising makes compliance results non-deterministic |
| `jwt_secret` | `""` | Must be 32+ chars in production |
| `cors_origins` | `[]` | Never add `"*"` wildcard |
| `opa_compliance_fail_mode` | `"open"` | Intentionally open — OPA compliance eval is optional |

## Agent Swarm QA Gate

### Tier 1 — Always run (5+ files changed)

Dispatch ALL in parallel:

| Agent | Checks |
|---|---|
| `python-pro` | Type safety, async patterns, error handling |
| `code-reviewer` | Logic bugs, dead code, complexity |
| `security-auditor` | OWASP top 10, auth bypass, secrets |
| `test-automator` | Missing tests, coverage gaps |
| `dependency-manager` | Vulnerabilities, version conflicts |

### Tier 2 — Run when domain is touched

| Agent | When |
|---|---|
| `database-optimizer` | DB models, migrations, queries |
| `terraform-engineer` | `terraform/` changes |
| `compliance-auditor` | Policies, OSCAL, frameworks, assessors |
| `security-engineer` | API routes, auth, ABAC, JWT |
| `grc-unicorn` | OPA policies, compliance logic |

### Tier 3 — Weekly or before releases

| Agent | Task |
|---|---|
| `penetration-tester` | Full offensive security test |
| `qa-expert` | Test strategy review |
| `refactoring-specialist` | Code smell detection |

### After swarm completes

1. Read every finding. Do not skim.
2. Cross-check: if code-reviewer says OK but security-auditor flags it, investigate.
3. Verify factual claims (Rule 2).
4. Fix CRITICAL and HIGH before committing.
5. Present MEDIUM to user for triage.
6. Re-run pytest and demo seed after fixes.
7. Only then proceed to Pre-Push QA Gate.

## Lessons From 2026-03-19 Session

These are not theoretical. These all happened.

1. **Pushed 12 times without asking.** Now Rule 1.
2. **Sub-agent claimed 13 normalizers missing — they all existed.** Now Rule 2.
3. **Parallel agents conflicted on models.py — migration gap crashed the seed.** Now Rule 3.
4. **Copied v1 frontend (1,010 files) without being asked.** Now Rule 6.
5. **`warlock retention` printed in seed output instead of `warlock retention report`.** Demo found it, not tests.
6. **Login endpoint had ImportError (`ACCESS_TOKEN_EXPIRE_MINUTES`) — never caught by tests.** Demo found it.
7. **Datetime naive/aware bug in personnel.py — never caught by tests.** User found it by running the demo in their terminal.
8. **README said 172 tests when there were 190.** Stale docs are lies.
9. **OPA policies (592 files, 25K LOC) were dead code.** Nobody noticed until the audit.
10. **ABAC scope filters existed but were never called.** Every user could see everything.
11. **Assertion bindings silently overwrote each other.** AC-2 lost its MFA check.

## Lessons From 2026-03-22 Sessions

12. **Datetime naive/aware bugs hit 6 CLI commands (lake-analytics summary/sources/freshness, reports sla, etc.).** Tests passed, demo crashed. `_utcnow()` returns aware, SQLite returns naive. Always wrap DB datetime values with `ensure_aware()`.
13. **Rich markup injection crashed incidents CLI.** User text with `[brackets]` in titles caused `MarkupError`. All user-supplied strings in Rich output must be wrapped with `escape()`.
14. **Demo seed had zero audit trail entries.** The core hash-chain trust mechanism was completely untestable. Seed data must cover every feature path, not just the happy path.
15. **Coverage rate showed NIST 800-53 at 4%.** Denominator included 213K `not_assessed` controls. Metrics that include irrelevant data are misleading — worse than no data.
16. **CLI groups errored (exit 2) on bare invocation.** 8 groups (`findings`, `connectors`, `assertions`, etc.) gave unhelpful Click errors instead of showing data. Every group must have a useful default.
17. **Working across two repo copies caused merge conflicts.** The `~/Coding/GitHub/warlock` and `~/Desktop/stress-testing/warlock` repos diverged. Same fixes applied twice = 13-file rebase conflict. Use one repo per task.
18. **demo_seed.py is the #1 conflict-prone file.** At 18K+ lines, it's the most edited file in the project. Never let two agents touch it simultaneously. Never make changes there without re-running the full seed.

Every rule in this document exists because one of these happened.
