# CLAUDE.md — Warlock Project Instructions

## Project Overview

Warlock is a pipeline-first GRC (Governance, Risk, Compliance) platform. Python 3.12+, FastAPI, SQLAlchemy, Click CLI, OPA/Rego policies, OSCAL packages, Terraform modules.

## HARD RULES

These exist because every one was violated. They are not guidelines.

### Rule 1: NEVER push without explicit approval

Do not run `git push` until you have:
1. Run `./scripts/qa.sh` and pasted the FULL output (not a summary)
2. Run `make verify-docs` and fixed any stale counts
3. Listed every file changed and what specifically changed
4. Asked "Ready to push?" and received explicit "yes"

When the user says "push" after seeing QA output, that means push. But never push preemptively or silently.

### Rule 2: NEVER trust sub-agent output without verification

Before acting on any sub-agent claim:
- If it says a file doesn't exist: `ls` the file
- If it says a function isn't called: `grep` for it
- If it says tests pass: run them yourself and paste the output

### Rule 3: NEVER dispatch parallel agents that edit the same file

When dispatching parallel fix agents:
- Give each agent a NON-OVERLAPPING set of files
- If two agents must touch the same file (models.py, app.py, config.py), serialize them
- After all agents complete, run a FULL integration test before committing

File ownership by domain:

| Agent | Owns exclusively |
|---|---|
| Security | `warlock/api/*.py`, `warlock/config.py` |
| Assessor | `warlock/assessors/*.py` |
| Database | `warlock/db/*.py`, `warlock/db/migrations/`, `alembic.ini` |
| Workflow | `warlock/workflows/*.py`, `warlock/export/*.py` |
| CLI | `warlock/cli/*.py` (assign by domain, not all at once) |
| Demo seed | `scripts/demo_seed.py`, `scripts/demo_connectors_new.py` |
| Terraform | `terraform/**/*.tf` |
| OSCAL | `frameworks-oscal/**/*`, `warlock/normalizers/*.py`, `warlock/connectors/*.py` |

**Shared files (models.py, config.py, app.py) go to ONE agent only.**

### Rule 4: The demo IS the product

`make demo` must work perfectly in ONE command — no manual steps, no copy-paste, no workarounds. The demo experience is what evaluators see. Every friction point is a failure.

After ANY change to pipeline, models, connectors, normalizers, seed, or config:

```bash
make reset    # rm warlock.db + alembic upgrade + demo_seed.py
```

Expected output — verify these numbers:
```
Connectors succeeded:   351
Connectors failed:      0
Raw events collected:   1,071
Findings normalized:    7,300–7,330 (varies slightly)
Controls mapped:        373,852
```

If these numbers change, you broke something. Stop and fix it. Always test `make demo` yourself before claiming it works.

### Rule 5: Test after EVERY change, not at the end

Every logical change gets its own test run. Do not batch 20 edits and test once. If a sub-agent reports tests passed but other agents haven't finished editing shared files, that test run is meaningless.

### Rule 6: NEVER add or remove files without asking

Before adding or removing any directory or large set of files, state what you plan to do and wait for approval.

### Rule 7: Plan before code

For any non-trivial task (more than a single-file fix), present a plan BEFORE writing code:
1. State what you're going to change and why
2. List the files you'll touch
3. Identify risks (shared files, migration gaps, demo seed impact)
4. Wait for approval before starting implementation

### Rule 8: No data = failed demo

A CLI command that runs without a traceback but shows "no data found", "0 results", or empty tables against the seeded demo database has FAILED. The demo seed must be extended to cover it. Never mark "expected empty" as passing.

### Rule 9: NEVER let doc counts go stale

After ANY change that adds/removes connectors, models, CLI commands, API routes, tests, assertions, framework YAMLs, or OSCAL files — run `make verify-docs` and fix EVERY doc that mentions the changed count. Check: README.md, CLAUDE.md, DEMO.md, CONTRIBUTING.md, docs/warlock-one-pager.md, and all proddocs/.

**Note:** Demo seed outputs 351 connectors, connector files number 352. Normalizer files also number 352.

---

## Pre-Push QA Gate

```bash
./scripts/qa.sh          # full gate — MUST pass before commit
./scripts/qa.sh --quick  # lint + tests only (development)
make verify-docs         # doc accuracy check only
```

The QA script covers: lint, format, imports, pytest, demo seed, CLI smoke tests, OPA policies, Terraform, OSCAL JSON, framework YAML, secrets scan, dependency audit, migration reversibility, doc count accuracy, AI flags, production docs completeness/accuracy.

ALL checks must pass. If any fail, fix before committing.

### After QA passes

1. List EVERY file changed and what changed
2. Paste actual QA output
3. Run `make verify-docs` — fix any mismatches across ALL docs
4. Verify `make demo` works end-to-end
5. Ask "Ready to push?" and WAIT for explicit "yes"

### Pre-push hook

A git pre-push hook runs `ruff check` + `ruff format --check` on committed state. Location: `.git/hooks/pre-push`.

If it fails: `.venv/bin/ruff check --fix warlock/ scripts/ && .venv/bin/ruff format warlock/ scripts/`

### After rebase/merge — ALWAYS run lint

Merge resolutions introduce duplicate imports. After `git rebase --continue`:

```bash
.venv/bin/ruff check --fix warlock/ scripts/demo_seed.py scripts/demo_connectors_new.py
.venv/bin/ruff format warlock/ scripts/demo_seed.py scripts/demo_connectors_new.py
git add -u && git commit --amend --no-edit
```

---

## Dependency Chain

When you change the left column, you MUST update every file in the right column. Walk this table for every file you touched.

| If you change... | You MUST also update... |
|---|---|
| Connector (`warlock/connectors/`) | config.py, matching normalizer, demo_seed.py, README.md, `proddocs/features/connectors.md` |
| Normalizer (`warlock/normalizers/`) | `__init__.py`, verify matching connector, re-run demo seed |
| DB model (`warlock/db/`) | Alembic migration, API routes, CLI commands, demo seed, `proddocs/technical/data-model.md` |
| Config setting (`warlock/config.py`) | `.env.example`, README.md if user-facing |
| API route (`warlock/api/`) | ABAC enforcement, input validation, auth decorator, middleware skip paths, `proddocs/api/reference.md` |
| Assertion (`warlock/assessors/`) | All control bindings (list-based), demo seed |
| Pipeline (`warlock/pipeline/`) | Demo seed, connector count, hash chain |
| AI reasoning (`warlock/assessors/`) | Prompt sanitization, API key in header not URL, confidence floor |
| Workflow (`warlock/workflows/`) | State machine transitions, GDPR cascade, `ensure_aware()` |
| Dependency | `pyproject.toml`, `pip install -e ".[dev,ai]"` |
| Terraform (`terraform/`) | `terraform validate` + `terraform fmt -check` on ALL modules |
| OPA policies (`policies/`) | `opa check` + `opa test`, input schema matches normalizer output |
| OSCAL packages (`frameworks-oscal/`) | Validate JSON, check control IDs match pipeline YAML |
| Framework YAML (`warlock/frameworks/`) | Re-run demo seed, verify loader, update README.md framework table |
| CLI command (`warlock/cli/*.py`) | ci.yml CLI smoke test list, README.md, DEMO.md, CONTRIBUTING.md, CLI-REFERENCE.md, `proddocs/api/cli-reference.md` |
| CI workflows (`.github/workflows/`) | Verify command/group names match actual CLI, test locally |
| Any count change (connectors, models, routes, etc.) | Run `make verify-docs`, fix ALL docs that mention the count |

---

## Architecture

Run `make verify-docs` for current counts. The tree below shows structure, not exact numbers (those drift — the QA gate catches mismatches).

```
warlock/
  connectors/    — source connectors (Stage 1)
  normalizers/   — parsers: raw → FindingData (Stage 2)
  mappers/       — control mapping across 14 frameworks (Stage 3)
  assessors/     — assertions + AI reasoning + OPA evaluator (Stage 4)
  api/           — FastAPI REST API, ABAC-scoped
  cli/           — Click CLI package
  tui/           — Interactive Textual TUI (7 screens, command palette, Arcane Elegance)
  db/            — SQLAlchemy models, schema via Base.metadata.create_all()
  export/        — OSCAL, binder, alerts, reports
  workflows/     — POA&M, risk acceptance, compensating controls, GDPR, retention
  pipeline/      — orchestrator, event bus, queue backends, scheduler
  lake/          — GRC data lake (DuckDB, Parquet, RAG, Iceberg)
  domains/       — domain service modules (registry, event bus, policy engine)
  integrations/  — Jira, ServiceNow, Teams, STIX/TAXII, Terraform provider
  platform/      — tenancy, white-label, delegation, sandbox, legacy/bulk import
  frameworks/    — framework YAMLs + crosswalks + baselines + inherited controls
tests/           — pytest tests (33 files)
policies/        — OPA/Rego files across 9 framework dirs
frameworks-oscal/ — OSCAL catalog/profile JSON
terraform/       — 142 IaC modules (AWS, Azure, GCP, + 12 more providers)
scripts/
  demo.sh        — one-command local demo (DB + OPA + seed + API)
  demo_seed.py   — mock connectors, ~7,325 findings, 373K+ results
  demo_api.sh    — API query helper with auto-auth
  qa.sh          — full QA gate
  verify_docs.py — doc count accuracy checker
```

## Key Patterns

- **Hash-chained audit trail**: SHA-256 at every pipeline stage. Never break the chain.
- **Fail-closed security**: OPA gate, assertions, ABAC all default to deny.
- **Multiple assertions per control**: List-based bindings. Append, never overwrite.
- **Timezone-aware datetimes**: Use `ensure_aware()` from `warlock/utils/`. No naive datetimes. SQLite returns naive even with `timezone=True` — always wrap DB values.
- **Rich markup escaping**: Use `rich.markup.escape()` on ALL user-supplied text before `console.print()`. Unescaped `[brackets]` crash Rich.
- **Root health endpoints**: `/health`, `/healthz`, `/readyz` at app root (not just `/api/v1/health`).
- **CLI groups show defaults**: All CLI groups use `invoke_without_command=True` and show a useful summary when called without a subcommand.
- **Prompt sanitization**: `<evidence>` tags + control character stripping in all LLM prompts.
- **Gemini API key in header**: `x-goog-api-key`, never in URL query params.
- **demo_seed.py is the #1 conflict-prone file**: 18K+ lines. Never let two agents touch it simultaneously. Re-run the full seed after any change.
- **Session management**: Always use `with get_session() as session:` for writes, `with get_read_session() as session:` for reads. Never call `session.commit()` manually (context manager handles it). Never create sessions with `sessionmaker()` directly — miss SQLite PRAGMAs and pool config.
- **UUID primary keys**: All models use `String(36)` UUID PKs via `_uuid()`. Never use Integer auto-increment PKs.
- **JSONType for JSON columns**: Use `JSONType` (not raw `JSON`), which maps to JSONB on PostgreSQL (GIN-indexable) and JSON on SQLite.
- **FK indexes required**: SQLite does not auto-index foreign keys. Every FK column needs an explicit `Index()`. Tag with `# #20: FK index`.
- **SQLite PRAGMAs**: Engine sets `foreign_keys=ON`, `journal_mode=WAL`, `busy_timeout=5000` on every connection. Never remove these.
- **Alembic batch mode**: Migrations use `render_as_batch=True` for SQLite ALTER TABLE support. Migration scripts live at `warlock/db/migrations/`, NOT `alembic/versions/`.
- **Config is a singleton**: Use `get_settings()`, never `Settings()` directly. All env vars use `WLK_` prefix.
- **Ruff line-length**: 100 characters (not default 88). Target: Python 3.12.
- **Optional dependencies**: Use `try/except ImportError` with `_HAS_X` boolean guard. Never assume optional packages are installed. Production raises RuntimeError if critical deps (cryptography) are missing.
- **PII scrubbing**: All normalizer output passes through `scrub_finding()` from `warlock.utils.pii`. New normalizers that skip this persist raw PII.
- **Connector secrets**: Use `self.get_secret("ENV_VAR")` from BaseConnector, never `os.environ.get()` directly.
- **Pipeline data classes**: `RawEventData`, `FindingData`, `ControlResultData`, `PipelineRunStats` are `@dataclass` (not Pydantic). Pydantic is only for config and API schemas.
- **SHA-256 deterministic serialization**: `json.dumps(data, sort_keys=True, default=str)`. Both `sort_keys=True` and `default=str` are required for hash stability.
- **Correlation ID tracing**: Pipeline runs set `correlation_id` ContextVar from `warlock.logging_config`. Use `logging.getLogger(__name__)` — never `print()`.
- **WLK_AI_ENABLED=false for seed/QA**: Both `scripts/qa.sh` and `scripts/demo.sh` set this. Without it, the seed attempts real AI calls and fails.
- **Pipeline lock file**: `$TMPDIR/warlock_pipeline.lock` persists after crashes. `scripts/qa.sh` cleans it before seed runs. `make reset` does not — be aware.
- **API pagination**: All list endpoints use `Depends(get_pagination)` with a hard cap of 1000 rows (default 50). Never return unbounded results.
- **Per-endpoint rate limits**: Login=10/min, register=5/min, AI=30/min, pipeline=5/min. Add new sensitive endpoints to `_ENDPOINT_LIMITS` in middleware.py.
- **Two separate skip-path sets**: `_SKIP_PATHS` in middleware.py (audit logging) and `_HEALTH_PATHS` in policy_gate.py (OPA bypass) must stay in sync for health endpoints.
- **GDPR erasure anonymizes, never deletes**: PII fields become `[REDACTED-xxxx]` HMAC tokens. Referential integrity and audit chain preserved. Never add DELETE logic.
- **Audit trail hash chain**: Uses `with_for_update()` (SELECT FOR UPDATE) to serialize. Initial previous_hash is `"genesis"` (not empty/None). Timestamp excluded from hash for deterministic recompute.
- **Control status enum**: Only 5 values: `compliant`, `non_compliant`, `partial`, `not_assessed`, `not_applicable`. Never invent new statuses.
- **Assessment tier fallback**: Tier 1 (assertions) → Tier 2 (AI, only if not_assessed) → inheritance (only if still not_assessed). Never skip or reorder tiers.
- **POA&M state machine**: draft→open→in_progress→remediated→verified→completed. Two statuses reachable from any state: risk_accepted, cancelled. Always use `POAMManager.transition()` — never set status directly.
- **OSCAL deterministic UUIDs**: Uses UUID5 with fixed namespace. Same data = same OSCAL output. Control IDs normalized to lowercase with hyphens (AC-2 → ac-2, CC6.1 → cc6-1). Never use uuid4 for OSCAL.
- **Framework YAML v2 structure**: `framework_id` at root, `control_families` as dict-of-dicts, each control has `checks` with `event_types`/`resource_types` arrays. Never use list-based structures.

## Sub-Agent Anti-Patterns

Sub-agents don't read CLAUDE.md. When dispatching agents that write Python code, ALWAYS include these in the prompt:

```
MANDATORY — DO NOT USE THESE PATTERNS:
1. NEVER compare DB datetimes with datetime.now(timezone.utc) directly.
   SQLite returns naive datetimes. ALWAYS wrap: ensure_aware(db_value)
   Import: from warlock.utils import ensure_aware
2. NEVER use .cast(int) on SQLAlchemy boolean expressions.
   USE: case((ControlResult.status == "x", 1), else_=0)
   Import: from sqlalchemy import case
3. NEVER use cast(column, Date) for SQLite date grouping.
   USE: func.strftime("%Y-%m-%d", column).label("day")
4. NEVER use func.case() — doesn't exist in SQLAlchemy 2.0.
   USE: case() as a standalone import from sqlalchemy.
5. NEVER use [/] or [{empty_var}]text[/] in Rich markup.
   Conditionally apply styles: f"[{style}]{text}[/{style}]" if style else escape(text)
6. ALWAYS escape() user-supplied text before Rich output.
   Import: from rich.markup import escape
7. NEVER use Finding.created_at — it doesn't exist. Use Finding.ingested_at.
8. NEVER self-join a table (Table.col == Table.col) — always cartesian product.
9. NEVER create sessions with sessionmaker() — use get_session()/get_read_session().
10. NEVER set POA&M status directly on the model — use POAMManager.transition().
11. ALWAYS use get_settings() for config, never Settings() directly.
12. ALWAYS set WLK_AI_ENABLED=false when running demo seed in scripts/tests.
```

## CI/CD Pipelines

### `.github/workflows/ci.yml` — Python CI
- **Triggers:** push to main, all PRs
- **Jobs:** lint (ruff), test (pytest), security (pip-audit), QA gate

### `.github/workflows/compliance-gate.yaml` — Compliance CI
- **Triggers:** push/PR that touches `policies/`, `terraform/`, `frameworks-oscal/`, `warlock/frameworks/`, `warlock/assessors/`
- **4 parallel jobs:** OPA validation, Terraform validation, OSCAL JSON validation, Framework YAML validation

Fix failures locally before pushing.

## Frameworks (14)

| Framework | Controls | Rego | OSCAL |
|---|---|---|---|
| NIST 800-53 | 1,176 | 286 files | Yes |
| ISO 27001 | 93 | 186 files | Yes |
| ISO 27701 | 95 | — | Yes |
| ISO 42001 | 39 | — | Yes |
| SOC 2 | 46 | 26 files | Yes |
| UCF | 115 | 24 files | Yes |
| FedRAMP | 26 | — | Yes |
| HIPAA | 64 | 40 files | Yes |
| CMMC L2 | 110 | 50 files | Yes |
| GDPR | 15 | — | Yes |
| PCI DSS v4.0 | 63 | 24 files | Yes |
| NIST CSF 2.0 | 101 | — | — |
| EU AI Act | 33 | — | — |
| SEC Cyber | 20 | — | — |

All 15 framework YAMLs (including SOC 2 Points of Focus) are active in the demo seed.

## Security-Critical Config Defaults

| Setting | Default | Do NOT change without asking |
|---|---|---|
| `opa_fail_mode` | `"closed"` | Changing to "open" bypasses all API policy enforcement |
| `ai_confidence_floor` | `0.7` | Lowering accepts unreliable AI compliance assessments |
| `ai_temperature` | `0.0` | Raising makes compliance results non-deterministic |
| `jwt_secret` | `""` | Must be 32+ chars in production |
| `cors_origins` | `[]` | Never add `"*"` wildcard |
| `opa_compliance_fail_mode` | `"open"` | Intentionally open — OPA compliance eval is optional |
| `encryption_key` | `""` | Required in production for field-level encryption. Empty crashes at runtime |
| `gdpr_hmac_secret` | `""` | Required for GDPR erasure/export. Must be 32+ chars. Empty = RuntimeError |
