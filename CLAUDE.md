# CLAUDE.md — Warlock Project Instructions

## Project Overview

Warlock is a pipeline-first GRC (Governance, Risk, Compliance) platform. Python 3.12+, FastAPI, SQLAlchemy, Click CLI, OPA/Rego policies, OSCAL packages, Terraform modules.

## MANDATORY: Pre-Push QA Gate

**NEVER push code without completing ALL of the following steps. NEVER skip any step. If a step fails, fix it before proceeding.**

### 1. Run the full Python test suite

```bash
.venv/bin/pytest tests/ --tb=short -q
```

There are currently 172 tests across 8 test files. ALL must pass. Zero failures tolerated. Always check the actual count — run `pytest --collect-only -q | tail -1` to confirm. If you add features or fix bugs, you should be ADDING tests too, not just running the existing ones.

### 2. Run OPA policy tests (if policies/ was touched)

```bash
opa check policies/ && opa test policies/
```

All 599+ OPA tests must pass.

### 3. Run Terraform validation (if terraform/ was touched)

```bash
for dir in terraform/modules/*/*; do
  (cd "$dir" && terraform init -backend=false -input=false > /dev/null 2>&1 && terraform validate && terraform fmt -check)
done
```

All modules must validate and pass fmt check.

### 4. Run the demo seed end-to-end (if DB models, migrations, connectors, normalizers, or pipeline code changed)

```bash
rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/python scripts/demo_seed.py
```

Seed must complete without errors.

### 5. Update ALL files in the dependency chain

When you change one file, you MUST update every file that depends on it. This is not optional. This is not "check if maybe something needs updating." These are hard dependencies — if you touch the left column, you MUST update every file in the right column:

| If you change... | You MUST also update... |
|---|---|
| **Add/remove a connector** (`warlock/connectors/`) | `warlock/config.py` (add `WLK_*` settings), `.env.example` (add env vars), `warlock/normalizers/` (matching normalizer), `scripts/demo_seed.py` (register in demo), `README.md` (connector count + list), `DEMO.md` (if expected seed output numbers change) |
| **Add/remove a normalizer** (`warlock/normalizers/`) | `warlock/normalizers/__init__.py` (register), verify matching connector exists, re-run demo seed to check counts |
| **Change a DB model** (`warlock/db/`) | Create Alembic migration, verify `alembic upgrade head` on fresh DB, check API routes that query that model, check CLI commands that query that model, re-run demo seed |
| **Add/change config setting** (`warlock/config.py`) | `.env.example` (add/update the env var with comment), `README.md` if it's user-facing |
| **Change an API route** (`warlock/api/`) | Check ABAC enforcement is applied, check input validation, check auth decorator is present |
| **Change an assertion** (`warlock/assessors/`) | Check all control bindings that reference it (list-based — multiple per control), re-run demo seed to verify assessment results |
| **Change the pipeline** (`warlock/pipeline.py`) | Re-run demo seed end-to-end, verify all 40 connectors still succeed, check hash chain integrity |
| **Change AI reasoning** (`warlock/assessors/`) | Verify prompt sanitization preserved, verify API key not in URL, verify `ai_confidence_floor` still enforced |
| **Change a workflow** (`warlock/workflows/`) | Check state machine transitions, check GDPR cascade if PII-related, check timezone awareness (`ensure_aware()`) |
| **Add a dependency** | Add to `pyproject.toml` in the correct extras group, verify `pip install -e ".[dev,ai]"` still works |
| **Change Terraform modules** | Run `terraform validate` + `terraform fmt -check` on ALL modules, not just the one you changed |
| **Change OPA policies** | Run `opa check policies/ && opa test policies/`, verify input schema matches normalizer output |

**Do NOT just "think about what might break." Walk the table above for every file you touched.**

### 6. Update documentation

If your changes affect any of the following, update the corresponding docs:
- **README.md** — connector counts, framework counts, feature descriptions, quick start instructions
- **DEMO.md** — if demo workflow changed
- **docs/** — if architectural decisions, integration patterns, or audit findings changed
- **docstrings/comments** — only in files you modified, only where behavior changed

### 7. ASK before pushing

**NEVER push to remote (git push) without explicitly asking me first.** Present:
- What changed (summary)
- Test results (paste the output)
- Any docs updated
- Ask: "Ready to push?"

Wait for my confirmation before running `git push`.

## MANDATORY: Pre-Commit Checklist

Before every `git commit`:
- [ ] All Python tests pass (`pytest tests/`)
- [ ] No new lint errors (`ruff check warlock/ tests/`)
- [ ] If DB models changed: migration exists and `alembic upgrade head` works on fresh DB
- [ ] If adding new files: they are properly imported/registered (not orphaned)
- [ ] Commit message describes the WHY, not just the WHAT

## Things Claude Keeps Forgetting (DO NOT SKIP THESE)

1. **Run tests after EVERY change, not just at the end.** Don't batch up 20 edits and then test. Test after each logical change.
2. **Check that new code doesn't break existing code.** If you add a column to a model, make sure the migration covers it. If you add a dependency, make sure it's in pyproject.toml.
3. **Don't push without asking.** Ever. Even if I said "fix it." That means fix it and show me — not fix it and push.
4. **Update README.md and docs** when counts change (connectors, tests, frameworks), features are added/removed, or CLI commands change.
5. **Don't remove things I didn't ask you to remove.** The v1 frontend incident — don't repeat it. If something seems like it should be removed, ask first.
6. **When dispatching sub-agents, verify their work.** Sub-agents make mistakes (e.g., claiming normalizers don't exist when they do). Cross-check findings before acting on them.
7. **Migrations must cover ALL model changes.** If Agent A changes models and Agent B changes models, the migration must include both. Don't let parallel agent work create migration gaps.
8. **Write new tests when you write new code.** Fixing 92 bugs without adding a single test is not QA — it's wishful thinking. Every fix should have a regression test. Every new feature should have coverage. If the plan says "expand to 300+ tests," actually do it.
9. **Verify claims with real output.** Don't say "all tests pass" without pasting the actual pytest output. Don't say "expanded to 300 tests" when `pytest --collect-only` still shows 172. Evidence, not assertions.

## Development Environment

```bash
# Activate venv
source .venv/bin/activate

# Install with dev + AI extras
pip install -e ".[dev,ai]"

# Run tests
pytest tests/ --tb=short -q

# Run API server
warlock-api  # or: uvicorn warlock.api.app:app --reload

# Run CLI
warlock --help

# Lint
ruff check warlock/ tests/
```

## Architecture Quick Reference

```
warlock/
  connectors/   — 40 source connectors (AWS, Azure, GCP, Okta, etc.)
  normalizers/   — 41 parsers (raw → FindingData)
  mappers/       — control mapping engine (findings → 1,564 controls)
  assessors/     — assertion engine + AI reasoning (Tier 1-4)
  api/           — FastAPI REST API (100+ routes)
  cli.py         — Click CLI (30+ commands)
  db/            — SQLAlchemy models + Alembic migrations
  export/        — OSCAL, reports, temporal exports
  workflows/     — POA&M, risk acceptance, compensating controls
tests/           — 172+ pytest tests (8 files)
policies/        — 592 OPA/Rego policy files (599 tests)
frameworks-oscal/ — 275 OSCAL catalog/profile JSON files
terraform/       — 5 IaC modules (AWS, Azure, GCP)
```

## Key Patterns

- **Hash-chained audit trail**: SHA-256 integrity hashing at every pipeline stage. Don't break the chain.
- **Fail-closed security**: OPA policy gate, assertions, and ABAC all default to deny. Don't change this to fail-open.
- **Multiple assertions per control**: Controls support list-based assertion bindings. Don't overwrite — append.
- **Timezone-aware datetimes**: Use `ensure_aware()` helper. No naive datetimes in models or API responses.

## Config & Demo Environment Guardrails

All config lives in `warlock/config.py` (Pydantic Settings, env prefix `WLK_`). Reference: `.env.example`.

**If you change ANYTHING in config, models, connectors, normalizers, or pipeline code, re-run the demo seed:**

```bash
rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/python scripts/demo_seed.py
```

Expected output (verify these numbers — don't just assume it worked):
```
Connectors succeeded:   40
Connectors failed:      0
Raw events collected:   191
Findings normalized:    547
Controls mapped:        26,135
```

If any connector fails or counts drop, you broke something. Fix it before moving on.

### Security-critical config defaults — DO NOT CHANGE these without asking:

| Setting | Default | Why |
|---|---|---|
| `opa_fail_mode` | `"closed"` | Deny all if OPA is unreachable. Changing to "open" is a security bypass (audit finding S-2). |
| `ai_confidence_floor` | `0.7` | Minimum AI confidence to accept an assessment. Lowering = accepting garbage AI output. |
| `ai_temperature` | `0.0` | Reproducible AI assessments. Raising = non-deterministic compliance results. |
| `jwt_secret` | `""` | MUST be 32+ chars in production. Short keys were audit finding S-3. |
| `opa_compliance_fail_mode` | `"open"` | This one is intentionally open — OPA compliance eval is optional, not a gate. |
| `cors_origins` | `[]` (empty) | No CORS by default. Don't add `*` wildcard. |
| `env` | `"development"` | Controls security strictness. Production mode enforces JWT length, rate limits, etc. |

### AI Reasoning module (`warlock/assessors/`):

- Prompt sanitization uses `<evidence>` tags and control character stripping (audit fix A-2/A-3). Don't bypass this.
- Gemini API key goes in HEADER, not URL query params (audit fix A-4). Don't regress.
- Untrusted connector data flows into LLM prompts — any change to prompt construction must preserve sanitization.
- `ai_provider` supports: `anthropic`, `openai`, `gemini`, `ollama`. If adding a new provider, follow the same sanitization pattern.
