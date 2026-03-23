# Contributing to Warlock

Thank you for considering a contribution to Warlock, the pipeline-first GRC platform. This document outlines our development workflow, coding standards, and contribution process.

## Development Setup

### Prerequisites
- Python 3.12 or higher
- pip and virtualenv
- git
- Docker (recommended for demo environment)
- (Optional but recommended) OPA for policy evaluation

### Clone and Install

```bash
git clone https://github.com/grcwarlock/warlock.git
cd warlock
python3 -m venv .venv
source .venv/bin/activate    # On Windows: .venv\Scripts\activate
pip install -e ".[dev,ai]"
```

### Verify Installation

**Docker (recommended):**
```bash
docker compose up demo          # Full demo: Postgres + Redis + OPA + seed + API
```

**Local Python:**
```bash
make demo                      # Full demo: DB setup, seed data, API start
```

Or run the demo manually:

```bash
alembic upgrade head
python scripts/demo_seed.py
warlock-api
```

Expected demo output shows:
- 165 connectors succeeded
- 0 connectors failed
- 589 raw events collected
- ~5,475 findings normalized
- 373,852 controls mapped

---

## Branch Strategy

### Naming Convention

- **Feature branches:** `feature/short-description` (e.g., `feature/aws-connector-retry`)
- **Bug fixes:** `fix/issue-description` (e.g., `fix/null-pointer-assertion`)
- **Refactoring:** `refactor/what-changed` (e.g., `refactor/async-pipeline`)
- **Documentation:** `docs/what-added` (e.g., `docs/deployment-guide`)

### Branch Rules

1. Branch off **main** only
2. Push frequently to signal intent — incomplete work is okay on feature branches
3. Non-trivial changes require a **pull request** with code review
4. Trivial changes: README typos, inline comment fixes, etc. can merge directly
5. All CI workflows must pass before merge
6. At least one approval from a maintainer required

---

## Code Style

### Linting

We use **[ruff](https://github.com/astral-sh/ruff)** for Python linting and formatting.

Before committing, run:

```bash
.venv/bin/ruff check warlock/ --fix
```

Commit if no errors remain:

```bash
.venv/bin/ruff check warlock/
```

This checks for:
- Unused imports (F401, F841)
- Undefined names (F821)
- Syntax errors (E9xx)
- Common mistakes (E7xx, W6xx)

### Style Guides

**Python:**
- Follow PEP 8
- Type hints required for all function signatures
- Docstrings for modules, classes, public methods
- Active voice in docstrings and comments
- Snake_case for variables and functions, PascalCase for classes

**Naming:**
- Use full words, not abbreviations (e.g., `assessment` not `assess`, `connector_id` not `conn_id`)
- Boolean variables start with `is_`, `has_`, `can_` (e.g., `is_compliant`, `has_evidence`)
- Private functions/variables start with `_` (e.g., `_internal_helper()`)

**Line Length:**
- Maximum 99 characters (matches ruff default)

---

## Testing Requirements

### Running Tests

All pull requests must pass the full test suite:

```bash
.venv/bin/pytest tests/ --tb=short -q
```

Expected output (as of this date):
- 295 tests across 10 files
- 0 failures
- 0 errors
- All green

### Writing Tests

For any new code or bug fix, add corresponding tests:

1. **Unit tests** go in `tests/test_<module>.py`
2. **Integration tests** go in `tests/integration/`
3. Use `pytest` fixtures for setup/teardown
4. Test both success and error paths
5. Name test functions descriptively: `test_<function>_<scenario>` (e.g., `test_mapper_handles_missing_finding_id`)

Example:

```python
def test_connector_retries_on_transient_error(mock_aws):
    """Verify connector retries failed API calls."""
    mock_aws.side_effect = [ConnectionError(), {"instances": []}]
    result = collect_aws()
    assert result.success
    assert mock_aws.call_count == 2
```

### Test Coverage

- New code must include tests
- Aim for >80% coverage on new modules
- Use `pytest --cov` to check coverage:

```bash
.venv/bin/pytest tests/ --cov=warlock --cov-report=term-missing
```

---

## Pre-Commit Checklist

Before pushing, verify these are complete:

- [ ] Linting passes: `ruff check warlock/`
- [ ] All tests pass: `pytest tests/ -q`
- [ ] No new test files skipped or marked `@pytest.mark.skip`
- [ ] Docstrings added for new public functions
- [ ] Type hints on all function signatures
- [ ] No print() statements (use logging instead)
- [ ] No hardcoded secrets, API keys, or credentials
- [ ] No commented-out code blocks (delete or explain)
- [ ] Related files updated (see Dependency Chain below)

### Dependency Chain

When you modify a file, check this table — related files may need updates:

| If you change... | You MUST also update... |
|---|---|
| Connector (`warlock/connectors/`) | matching normalizer, demo_seed.py, README.md framework connector list |
| Normalizer (`warlock/normalizers/`) | `__init__.py` if new, re-run demo seed, verify with matching connector |
| DB model (`warlock/db/`) | Create an Alembic migration, update API routes, verify demo seed |
| Config setting (`warlock/config.py`) | `.env.example`, README.md if user-facing, update DEPLOYMENT_GUIDE.md |
| API route (`warlock/api/`) | Add input validation, verify ABAC scoping, check auth decorator |
| OPA policies (`policies/`) | Run `opa check policies/ && opa test policies/` |
| Framework YAML (`warlock/frameworks/`) | Re-run demo seed, verify loader completes |

---

## Pull Request Template

When opening a PR, use this format for the description:

```markdown
## What Changed
Brief description of the change.

## Why
Explain the motivation — what problem does this solve?

## How to Test
Step-by-step instructions for a reviewer to verify the change:
1. Run `...`
2. Verify that `...`
3. Check `...`

## Test Output
Paste the actual pytest output:
```
$ pytest tests/ -q
... N passed in X.XXs
```

## Files Changed
- `warlock/api/app.py` — Added /docs mount
- `docs/DEPLOYMENT_GUIDE.md` — New file

## Related Issues
Closes #123 (if applicable)

## Checklist
- [ ] Tests added/updated
- [ ] Linting passes
- [ ] Docstrings added
- [ ] Related files updated
- [ ] Demo still works (`docker compose up demo` or `make demo`)
```

---

## Architecture Overview

Warlock's architecture is **pipeline-first**: evidence flows through four immutable stages with SHA-256 integrity hashing at every step.

```
Stage 1: Connectors (82)    → RawEventData         → collect from cloud/EDR/IAM/SIEM APIs
Stage 2: Normalizers (82)   → FindingData          → transform to universal findings format
Stage 3: Control Mapper     → ControlMappingData   → map to 1,996 controls across 14 frameworks
Stage 4: Assessor (Tier 1-4) → ControlResultData  → deterministic assertions + optional AI reasoning
```

Every control result traces back to its raw API response — the hash chain is tamper-evident.

### Key Components

- **Connectors** (`warlock/connectors/`) — 165 source integrations (AWS, Azure, EDR, SIEM, IAM, etc.)
- **Normalizers** (`warlock/normalizers/`) — Parse raw API responses into universal FindingData
- **Mappers** (`warlock/mappers/`) — Cross-reference findings against 1,996 controls
- **Assessors** (`warlock/assessors/`) — Tier 1-4 assertions + optional AI reasoning via Claude/Gemini/OpenAI
- **API** (`warlock/api/`) — FastAPI REST endpoints (139 routes), ABAC-scoped access control
- **CLI** (`warlock/cli.py`) — Click CLI (45+ commands) for pipeline, monitoring, export, workflows, domain views
- **Domains** (`warlock/domains/`) — Domain service architecture (registry, event bus, policy engine, cross-domain queries)
- **Integrations** (`warlock/integrations/`) — Slack, PagerDuty, Jira, ServiceNow outbound subscribers
- **Database** (`warlock/db/`) — SQLAlchemy ORM, 40 models, 12 Alembic migrations
- **Frameworks** (`warlock/frameworks/`) — 14 compliance frameworks (NIST, ISO, SOC 2, PCI DSS, etc.)
- **OPA** (`policies/`) — 670 Rego files across 8 frameworks (NIST, ISO, SOC 2, CMMC, HIPAA, UCF, PCI DSS, Terraform)
- **Export** (`warlock/export/`) — OSCAL, audit evidence binders, risk reports
- **Workflows** (`warlock/workflows/`) — POA&M, risk acceptance, compensating controls, GDPR

For details, see [README.md](README.md) and [CLAUDE.md](CLAUDE.md).

### Security-First Design

- **Fail-closed:** OPA policy gate, ABAC scope filters, assertion defaults to deny
- **Hash-chained audit trail:** SHA-256 at every pipeline stage — tamper evident
- **Field-level encryption:** Optional for sensitive data via `WLK_ENCRYPTION_KEY`
- **JWT authentication:** Token-based API access with configurable expiry
- **Scope enforcement:** Users see only data from their assigned frameworks and sources

---

## Questions?

- **Architecture:** See [CLAUDE.md](CLAUDE.md) for technical depth
- **Deployment:** See [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md)
- **API:** Start the server and visit `http://localhost:8000/docs` for interactive Swagger UI
- **Issues:** File a GitHub issue with details and reproduction steps

Happy contributing!
