# Developer Setup

Set up a local Warlock development environment with Python, run the demo, execute tests, and contribute code.

## Prerequisites

- Python 3.12 or higher
- pip and virtualenv (bundled with Python 3.12+)
- Node.js 20+ and npm (for the web UI)
- git
- OPA CLI (optional, for policy evaluation -- `brew install opa`)

Verify your Python version:

```bash
python3 --version   # Python 3.12+
```

---

## Clone and Install

```bash
git clone https://github.com/grcwarlock/warlock.git
cd warlock
python3 -m venv .venv
source .venv/bin/activate    # On Windows: .venv\Scripts\activate
pip install -e ".[dev,ai]"
```

This installs the core platform, development tools (pytest, ruff, pip-audit), and AI reasoning support.

### Optional Extras

Install additional extras for specific features:

```bash
pip install -e ".[dev,ai,lake,monitoring]"    # Data lake + Prometheus metrics
pip install -e ".[dev,ai,aws]"                # AWS connector SDK
pip install -e ".[dev,ai,azure]"              # Azure connector SDK
pip install -e ".[dev,ai,gcp]"                # GCP connector SDK
```

---

## Run the Demo

### One-command demo (recommended)

```bash
./scripts/demo.sh
```

This script creates a venv, installs dependencies, optionally starts OPA, seeds a SQLite database with demo data, optionally configures AI, and starts the API server on port 8000.

### Manual demo

```bash
rm -f warlock.db
alembic upgrade head
python scripts/demo_seed.py
warlock-api
```

### Expected demo output

```
Connectors succeeded:   351
Connectors failed:      0
Raw events collected:   1,071
Findings normalized:    ~7,325
Controls mapped:        373,852
```

If these numbers change, something is broken. Check the dependency chain table in CLAUDE.md.

### Demo credentials

- **Login:** `admin@acme.com` / `WarlockAdmin2026!`
- **API:** http://localhost:8000/docs (Swagger UI)
- **Health:** http://localhost:8000/api/v1/health

---

## Run Tests

```bash
pytest tests/ -v --tb=short
```

Expected: 509 tests across 32 files, 0 failures. Run a quick subset:

```bash
pytest tests/test_api.py -v             # API tests only
pytest tests/test_security_fixes.py -v  # Security tests only
pytest tests/ -k "test_connector" -v    # Filter by name
```

### Test with coverage

```bash
pytest tests/ --cov=warlock --cov-report=term-missing
```

---

## Run the API Server

```bash
# Default: binds to 0.0.0.0:8000
warlock-api

# Or with uvicorn directly (enables reload for development)
uvicorn warlock.api.app:create_app --factory --reload --port 8000
```

API documentation is auto-generated at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

---

## Linting and Formatting

Warlock uses [ruff](https://github.com/astral-sh/ruff) for linting and formatting. No black, no flake8.

```bash
# Check for lint errors
ruff check warlock/

# Auto-fix safe lint errors
ruff check warlock/ --fix

# Check formatting
ruff format --check warlock/

# Apply formatting
ruff format warlock/
```

Configuration is in `pyproject.toml`:
- Target: Python 3.12
- Line length: 100 characters

---

## QA Gate

Run the full QA gate before committing. This is mandatory -- it covers lint, tests, demo seed, CLI smoke tests, OPA policies, Terraform validation, OSCAL checks, secrets scanning, and documentation accuracy.

```bash
# Full QA gate
./scripts/qa.sh

# Quick check (lint + tests only, ~30s)
./scripts/qa.sh --quick
```

Or via Make:

```bash
make qa          # full gate
make qa-quick    # lint + test only
make verify-docs # documentation accuracy check only
```

All checks must pass before pushing.

---

## Pre-Push Hook

Set up a pre-commit hook to run quick QA automatically:

```bash
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
./scripts/qa.sh --quick
EOF
chmod +x .git/hooks/pre-commit
```

This runs lint and tests before every commit. Commits are blocked if either fails.

---

## Make Targets

```bash
make install     # Install dependencies
make test        # Run pytest
make lint        # Run ruff linter
make qa          # Full QA gate
make qa-quick    # Quick QA (lint + test only)
make verify-docs # Check documentation counts match codebase
make migrate     # Run Alembic migrations
make seed        # Run demo seed
make demo        # Full one-command demo
make cli         # Show how to activate CLI
make clean       # Remove DB, clean __pycache__

# Frontend
make frontend-install   # Install npm dependencies
make frontend-dev       # Start dev server (proxy to API on :8000)
make frontend-build     # Production build
```

---

## Project Structure

For full architecture details, see [Architecture](../technical/architecture.md).

```
warlock/
  connectors/    -- 352 source connectors (Stage 1)
  normalizers/   -- 352 parsers (Stage 2)
  mappers/       -- Control mapping (Stage 3)
  assessors/     -- Assertion engine + AI reasoning (Stage 4)
  api/           -- FastAPI REST API (171 routes)
  cli/           -- Click CLI (686 leaf commands across 73 modules)
  db/            -- SQLAlchemy models (47), schema via Base.metadata.create_all()
  export/        -- OSCAL, binder, alerts
  workflows/     -- POA&M, risk acceptance, GDPR, retention
  pipeline/      -- Orchestrator, event bus, queue backends, scheduler
  lake/          -- GRC Data Lake (DuckDB, Parquet, RAG)
  domains/       -- Domain service modules
  frameworks/    -- 14 framework YAMLs (1,996 controls)
tests/           -- 509 tests across 32 files
policies/        -- 670 OPA/Rego files
frameworks-oscal/ -- OSCAL catalog/profile JSON
terraform/       -- 12 IaC modules
scripts/         -- Demo, QA gate, seed scripts
```

---

## Common Development Tasks

### Add a new connector

1. Create `warlock/connectors/my_connector.py`
2. Create matching `warlock/normalizers/my_connector.py`
3. Register in `warlock/config.py` with `WLK_MYCONNECTOR_ENABLED`
4. Add to `demo_seed.py`
5. Update `.env.example`
6. Run the demo to verify

### Add a database model

1. Add the model class to `warlock/db/models.py`
2. Create an Alembic migration: `alembic revision --autogenerate -m "add my_table"`
3. Run migration: `alembic upgrade head`
4. Update API routes and CLI commands if needed
5. Run the demo to verify

### Add an API route

1. Add the route to the appropriate router in `warlock/api/routers/`
2. Add input validation with Pydantic models
3. Verify ABAC scoping is applied
4. Add auth decorator
5. Add tests in `tests/test_api.py`
