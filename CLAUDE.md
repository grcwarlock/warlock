# CLAUDE.md — Warlock Project Instructions

## Project Overview

Warlock is a pipeline-first GRC (Governance, Risk, Compliance) platform. Python 3.12+, FastAPI, SQLAlchemy, Click CLI, OPA/Rego policies, OSCAL packages, Terraform modules.

## MANDATORY: Pre-Push QA Gate

**NEVER push code without completing ALL of the following steps. NEVER skip any step. If a step fails, fix it before proceeding.**

### 1. Run the full Python test suite

```bash
.venv/bin/pytest tests/ --tb=short -q
```

There are currently 190 tests across 9 test files. ALL must pass. Zero failures tolerated. Always check the actual count — run `pytest --collect-only -q | tail -1` to confirm. If you add features or fix bugs, you should be ADDING tests too, not just running the existing ones.

### 2. Run OPA policy tests (if policies/ was touched)

```bash
opa check policies/ && opa test policies/
```

All 631+ OPA tests must pass.

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

### 5. Import smoke test

```bash
.venv/bin/python -c "import warlock; print('OK')"
```

Catches circular imports and missing modules that pytest might not cover.

### 6. Verify the package installs cleanly

```bash
.venv/bin/pip install -e ".[dev,ai]" --quiet && echo "INSTALL OK"
```

If you added a dependency anywhere, this catches it missing from `pyproject.toml`.

### 7. Secrets scan — NEVER commit credentials

Before staging files, check that NONE of these are being committed:
- `.env` files (only `.env.example` is safe)
- API keys, tokens, passwords, or secrets in any file
- Hardcoded credentials in config or test files

```bash
git diff --cached --name-only | xargs grep -l -i -E "(api_key|secret|password|token|credential)=" 2>/dev/null
```

If that returns hits, inspect every one. False positives from variable names are fine. Actual values are NOT.

### 8. Dependency vulnerability scan

```bash
.venv/bin/pip audit 2>&1 || echo "VULNERABILITIES FOUND — review before pushing"
```

If vulnerabilities are found in dependencies, flag them to me. Don't silently push known-vulnerable code.

### 9. Migration reversibility (if migrations changed)

```bash
rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/alembic downgrade -1 && echo "DOWNGRADE OK"
```

If you can't roll back, the migration is not production-safe. Fix the downgrade path.

### 10. OSCAL JSON validation (if frameworks-oscal/ was touched)

```bash
python -c "
import json, pathlib
errors = []
for f in pathlib.Path('frameworks-oscal').rglob('*.json'):
    try: json.loads(f.read_text())
    except Exception as e: errors.append(f'{f}: {e}')
print(f'{len(errors)} invalid JSON files') if errors else print('All OSCAL JSON valid')
for e in errors: print(f'  BROKEN: {e}')
"
```

All 275+ OSCAL JSON files must parse without errors.

### 11. API backwards compatibility check

If you renamed, removed, or changed the signature of any API endpoint:
- **Don't do it without asking me first.**
- If approved: update the OpenAPI schema, update any CLI commands that call the endpoint, update DEMO.md if demo curl commands changed.

### 12. Test coverage direction

```bash
.venv/bin/pytest tests/ --tb=short -q | tail -1
```

Test count must be **equal to or greater than** the last known count. If you added code and the test count didn't go up, you forgot to write tests. Current baseline: **190 tests** (update this number when tests are added).

### 13. Update ALL files in the dependency chain

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

### 14. Update documentation

If your changes affect any of the following, update the corresponding docs:
- **README.md** — connector counts, framework counts, feature descriptions, quick start instructions
- **DEMO.md** — if demo workflow changed
- **docs/** — if architectural decisions, integration patterns, or audit findings changed
- **docstrings/comments** — only in files you modified, only where behavior changed

### 15. ASK before pushing

**NEVER push to remote (git push) without explicitly asking me first.** Present:
- What changed (summary)
- Test results (paste the output)
- Any docs updated
- Ask: "Ready to push?"

Wait for my confirmation before running `git push`.

## MANDATORY: Branch Hygiene

**Do NOT commit directly to `main` for non-trivial changes.** Create a feature branch:

```bash
git checkout -b feat/description-of-change
```

Only push to `main` after all QA checks pass AND I approve. This way if something goes wrong, `main` is still clean.

Exception: typo fixes, single-line config changes, and doc-only updates can go directly to `main` if all tests pass.

## MANDATORY: Pre-Commit Checklist

Before every `git commit`:
- [ ] All Python tests pass (`pytest tests/`)
- [ ] No new lint errors (`ruff check warlock/ tests/`)
- [ ] Import smoke test passes (`python -c "import warlock"`)
- [ ] No secrets/credentials in staged files
- [ ] If DB models changed: migration exists, upgrade works on fresh DB, downgrade works
- [ ] If adding new files: they are properly imported/registered (not orphaned)
- [ ] If adding dependencies: they are in `pyproject.toml` and `pip install -e ".[dev,ai]"` works
- [ ] Test count has not decreased
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
9. **Verify claims with real output.** Don't say "all tests pass" without pasting the actual pytest output. Don't say "expanded to 300 tests" when `pytest --collect-only` still shows 190. Evidence, not assertions.

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
tests/           — 190 pytest tests (9 files)
policies/        — 604 OPA/Rego policy files (631 tests)
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

## MANDATORY: Agent Swarm QA Gate

Before any push, dispatch these agents in parallel for a full validation sweep. This is NOT optional for non-trivial changes (anything touching more than 3 files or any security/DB/pipeline/config change).

### Tier 1 — Always run (every push)

Dispatch ALL of these in parallel:

| Agent | Task | What it checks |
|---|---|---|
| `python-pro` | Review all changed Python files | Type safety, Pythonic patterns, async correctness, error handling |
| `code-reviewer` | Review all changed files for quality | Logic bugs, dead code, complexity, missing error handling |
| `security-auditor` | Security audit of changed files | SQL injection, auth bypass, secrets exposure, OWASP top 10 |
| `test-automator` | Verify test coverage for changes | Missing tests, coverage gaps, test quality, flaky test risk |
| `dependency-manager` | Audit dependencies | Vulnerabilities, version conflicts, unused deps, license compliance |

### Tier 2 — Run when relevant domain is touched

| Agent | When to dispatch | What it checks |
|---|---|---|
| `database-optimizer` | DB models, migrations, queries changed | Missing indexes, N+1 queries, migration safety, schema drift |
| `terraform-engineer` | `terraform/` changed | Module validation, security best practices, provider version pins |
| `compliance-auditor` | Policies, OSCAL, frameworks, assessors changed | Framework coverage gaps, control mapping accuracy, evidence chain |
| `security-engineer` | API routes, auth, ABAC, JWT, encryption changed | Auth enforcement, ABAC applied, secrets management, CORS |
| `architect-reviewer` | New modules, major refactors, pipeline changes | Design patterns, coupling, scalability, breaking changes |
| `performance-engineer` | Pipeline, DB queries, API endpoints changed | N+1 queries, slow paths, resource leaks, batch size issues |
| `documentation-engineer` | Any user-facing change | README accuracy, DEMO.md accuracy, API docs, config docs |
| `risk-manager` | Compliance logic, assessment, policy gate changed | Control effectiveness, risk scoring accuracy, fail-mode safety |

### Tier 3 — Run periodically (weekly or before releases)

| Agent | Task |
|---|---|
| `penetration-tester` | Full offensive security test of API + auth |
| `qa-expert` | Full test strategy review — coverage gaps, test quality, missing edge cases |
| `error-detective` | Error pattern analysis across all modules |
| `refactoring-specialist` | Code smell detection, complexity hotspots, duplication |
| `database-administrator` | Full DB health — replication readiness, backup strategy, HA config |

### How to dispatch the swarm

For Tier 1 (always run), use a single message with all 5 agent calls in parallel:

```
Launch agents in parallel:
  - python-pro: "Review all files changed in this branch for type safety, async patterns, error handling"
  - code-reviewer: "Review all changed files for logic bugs, dead code, missing error handling"
  - security-auditor: "Security audit all changed files for OWASP top 10, auth bypass, secrets"
  - test-automator: "Check test coverage for all changed code, identify missing tests"
  - dependency-manager: "Audit pyproject.toml and all imports for vulnerabilities and conflicts"
```

For Tier 2, add the relevant agents based on what changed. The swarm runs in parallel — all agents at once, not sequentially.

### After the swarm completes

1. **Read every agent's findings.** Don't skim. Don't dismiss.
2. **Cross-check findings against each other.** If the code-reviewer says a function is fine but the security-auditor flags it, investigate.
3. **Fix all CRITICAL and HIGH findings before committing.**
4. **Present MEDIUM findings to me** — I'll decide which to fix now vs. later.
5. **Re-run pytest after fixing** to make sure fixes didn't break anything.
6. **Only then proceed to the Pre-Push QA Gate steps** (tests, seed, docs, ask me).
