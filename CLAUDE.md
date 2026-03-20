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
rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/python scripts/demo_seed.py
```

Expected output — verify these exact numbers:
```
Connectors succeeded:   40
Connectors failed:      0
Raw events collected:   191
Findings normalized:    547
Controls mapped:        29,207
```

If any number changes, you broke something. Stop and fix it.

### Rule 5: Test after EVERY change, not at the end

Do not batch 20 edits and test once. Do not dispatch 6 agents and test after all 6 finish. Every logical change gets its own test run. If a sub-agent reports "172 passed" but other agents haven't finished editing shared files, that test run is meaningless.

### Rule 6: NEVER add or remove files without asking

The v1 frontend incident: you copied 1,010 files from a ZIP into the repo without being asked. You then had to remove 129 of them. Before adding or removing any directory or large set of files, state what you plan to do and wait for approval.

### Rule 7: If the user shares a secret, warn immediately

If an API key, password, or credential appears in the conversation, immediately tell the user to rotate it. Do not store it in any file, env var, or command history. On 2026-03-19, an Anthropic API key was shared in chat.

---

## Pre-Push QA Gate

**Complete ALL steps in order. Do not skip. Do not reorder. If any step fails, fix it before proceeding.**

### Step 1: Get actual test count

```bash
.venv/bin/pytest --collect-only -q 2>&1 | tail -1
```

Do NOT trust the hardcoded number in this document. The actual count from this command is the truth. As of last update: **190 tests, 9 files**.

### Step 2: Run the full test suite

```bash
.venv/bin/pytest tests/ --tb=short -q
```

ALL must pass. Zero failures. Paste the actual output — do not say "all tests pass" without evidence.

### Step 3: Run the demo seed on a clean database

```bash
rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/python scripts/demo_seed.py
```

Must complete with 40 connectors succeeded, 0 failed.

### Step 4: OPA policy tests

```bash
opa check policies/ && opa test policies/
```

All OPA tests must pass.

### Step 5: Terraform validation

```bash
cd /Users/jsn/Coding/GitHub/warlock
for dir in terraform/modules/*/*; do
  cd "/Users/jsn/Coding/GitHub/warlock/$dir"
  terraform init -backend=false -input=false > /dev/null 2>&1
  terraform validate 2>&1 | grep -q "Success" && echo "PASS $(echo $dir | sed 's|terraform/modules/||')" || echo "FAIL $dir"
done
cd /Users/jsn/Coding/GitHub/warlock
```

All 12 modules must pass.

### Step 6: Import smoke test

```bash
.venv/bin/python -c "import warlock; print('OK')"
```

### Step 7: Package install

```bash
.venv/bin/pip install -e ".[dev,ai]" --quiet && echo "INSTALL OK"
```

### Step 8: OSCAL JSON validation

```bash
.venv/bin/python -c "
import json, pathlib
errors = []
for f in pathlib.Path('frameworks-oscal').rglob('*.json'):
    try: json.loads(f.read_text())
    except Exception as e: errors.append(f'{f}: {e}')
print(f'All {len(list(pathlib.Path(\"frameworks-oscal\").rglob(\"*.json\")))} OSCAL JSON valid') if not errors else [print(f'BROKEN: {e}') for e in errors]
"
```

### Step 9: Secrets scan

```bash
git diff --cached --name-only | xargs grep -l -i -E "(sk-ant-|sk-proj-|AKIA|password\s*=\s*['\"][^'\"]{8,}['\"])" 2>/dev/null
```

Any real credential = do not commit. Variable names and placeholders are fine.

### Step 10: Migration reversibility (if migrations changed)

```bash
rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/alembic downgrade -1 && echo "DOWNGRADE OK"
```

### Step 11: Dependency vulnerability scan

```bash
.venv/bin/pip-audit 2>&1 | tail -10
```

If CRITICAL or HIGH CVEs found in packages actually imported at runtime, pin to patched version or remove dependency before pushing. Flag to user either way.

### Step 12: Test count direction

```bash
.venv/bin/pytest --collect-only -q 2>&1 | tail -1
```

Count must be >= the baseline from Step 1. If you added code and count didn't go up, you forgot to write tests.

### Step 12b: CLI AI flag verification

```bash
.venv/bin/python -c "
from warlock.cli import cli
from click.testing import CliRunner
runner = CliRunner()
# ai group in top-level help
r = runner.invoke(cli, ['--help']); assert 'ai ' in r.output, 'ai group missing'
# ai subcommands
r = runner.invoke(cli, ['ai', '--help']); assert all(c in r.output for c in ['status','models','configure','test'])
# --ai flag on key commands
for cmd in ['coverage','remediate','simulate-audit','policy-coverage','risk analyze']:
    parts = cmd.split()
    r = runner.invoke(cli, parts + ['--help']); assert '--ai' in r.output, f'{cmd} missing --ai'
# --ask flag
for cmd in ['remediate','findings','issues']:
    r = runner.invoke(cli, [cmd, '--help']); assert '--ask' in r.output, f'{cmd} missing --ask'
print('CLI AI flags: ALL PRESENT')
"
```

### Step 13: Change manifest

Before asking to push, list EVERY file you changed and what you changed in it. Not "updated models.py" — what specifically. If you can't explain a change, you don't understand it and shouldn't push it.

### Step 14: Documentation check

Re-read README.md and DEMO.md top to bottom as if you are a new user following the instructions. If any command, count, or instruction is wrong, fix it. This caught stale test counts (172 vs 190), wrong CLI commands (`warlock retention` vs `warlock retention report`), and missing `make demo` in this session.

### Step 15: Ask to push

Present:
- Change summary (from Step 13)
- Pytest output (from Step 2)
- Demo seed output (from Step 3)
- Ask: "Ready to push?"

WAIT for explicit "yes" before running `git push`.

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
| Workflow agent | `warlock/workflows/*.py`, `warlock/export/*.py`, `warlock/cli.py` |
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
| API route (`warlock/api/`) | ABAC enforcement, input validation, auth decorator |
| Assertion (`warlock/assessors/`) | All control bindings (list-based), demo seed |
| Pipeline (`warlock/pipeline/`) | Demo seed, connector count, hash chain |
| AI reasoning (`warlock/assessors/`) | Prompt sanitization, API key in header not URL, confidence floor |
| Workflow (`warlock/workflows/`) | State machine transitions, GDPR cascade, `ensure_aware()` |
| Dependency | `pyproject.toml`, `pip install -e ".[dev,ai]"` |
| Terraform (`terraform/`) | `terraform validate` + `terraform fmt -check` on ALL modules |
| OPA policies (`policies/`) | `opa check` + `opa test`, input schema matches normalizer output |
| OSCAL packages (`frameworks-oscal/`) | Validate JSON, check control IDs match pipeline YAML, update README.md counts |
| Framework YAML (`warlock/frameworks/`) | Re-run demo seed, verify loader doesn't crash, update README.md framework table |
| CI workflows (`.github/workflows/`) | Test the workflow logic locally before pushing — CI failures block all PRs |

---

## Architecture Quick Reference

```
warlock/
  connectors/    — 41 source connectors
  normalizers/   — 41 parsers (raw → FindingData)
  mappers/       — control mapping (findings → 1,996 controls across 14 frameworks)
  assessors/     — assertion engine (25 assertions) + AI reasoning + OPA evaluator
  api/           — FastAPI REST API (139 routes, ABAC-scoped)
  cli.py         — Click CLI (38 commands)
  db/            — SQLAlchemy models (34) + Alembic migrations (11)
  export/        — OSCAL, binder, alerts, reports
  workflows/     — POA&M, risk acceptance, compensating controls, GDPR, retention
  pipeline/      — orchestrator, event bus, queue backends, scheduler
  frameworks/    — 14 framework YAMLs + crosswalks + baselines + inherited controls
  frameworks/reference/ — baselines.yaml (NIST Low/Mod/High), inherited_controls.yaml
tests/           — 190 pytest tests (9 files)
policies/        — 670 OPA/Rego files across 8 frameworks
frameworks-oscal/ — OSCAL catalog/profile JSON for 11 frameworks (17 JSON files)
terraform/       — 12 IaC modules (AWS, Azure, GCP)
.github/workflows/
  ci.yml             — Python lint + test + Docker build
  compliance-gate.yaml — OPA validation, Terraform validation, OSCAL + YAML checks
scripts/
  demo.sh        — one-command full demo (DB + OPA + seed + API)
  demo_seed.py   — 40 mock connectors, 547+ findings, 29K results
  demo_api.sh    — API query helper with auto-auth
```

## Key Patterns

- **Hash-chained audit trail**: SHA-256 at every pipeline stage. Never break the chain.
- **Fail-closed security**: OPA gate, assertions, ABAC all default to deny.
- **Multiple assertions per control**: List-based bindings. Append, never overwrite.
- **Timezone-aware datetimes**: Use `ensure_aware()` from `warlock/utils/`. No naive datetimes.
- **Prompt sanitization**: `<evidence>` tags + control character stripping in all LLM prompts.
- **Gemini API key in header**: `x-goog-api-key`, never in URL query params.

## CI/CD Pipelines

Two GitHub Actions workflows run on every push/PR:

### `.github/workflows/ci.yml` — Python CI
- **Triggers:** push to main, all PRs
- **Jobs:** lint (ruff), test (pytest 190 tests), build (Docker image)
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
| `grc-engineer` | OPA policies, compliance logic |

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
5. **User's API key pasted in chat — not flagged.** Now Rule 7.
6. **`warlock retention` printed in seed output instead of `warlock retention report`.** Demo found it, not tests.
7. **Login endpoint had ImportError (`ACCESS_TOKEN_EXPIRE_MINUTES`) — never caught by tests.** Demo found it.
8. **Datetime naive/aware bug in personnel.py — never caught by tests.** User found it by running the demo in their terminal.
9. **README said 172 tests when there were 190.** Stale docs are lies.
10. **OPA policies (592 files, 25K LOC) were dead code.** Nobody noticed until the audit.
11. **ABAC scope filters existed but were never called.** Every user could see everything.
12. **Assertion bindings silently overwrote each other.** AC-2 lost its MFA check.

Every rule in this document exists because one of these happened.
