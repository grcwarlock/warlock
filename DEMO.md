# Warlock Demo Setup

**Requirements:** [Docker](https://docs.docker.com/get-docker/) (recommended) OR Python 3.12+ (local).

---

## Docker (recommended)

```bash
git clone https://github.com/grcwarlock/warlock.git
cd warlock
docker compose up demo
```

That's it. The stack starts:
- **Postgres 16** — production database
- **Redis 7** — event bus / queue backend
- **OPA** — 670 Rego policies across 8 frameworks
- **Warlock** — migrations, seed data (81 connectors, 5,008 findings, 373,852 control results), API server

When it finishes:

```
============================================================
  Demo is live!
============================================================

  API:    http://localhost:8000/api/v1/health
  Docs:   http://localhost:8000/docs

  Login:  admin@acme.com / WarlockAdmin2026!

  Stop:   docker compose down
  Reset:  docker compose down -v && docker compose up demo
============================================================
```

### Docker Commands

```bash
docker compose up demo          # start everything
docker compose down             # stop (data persists in volumes)
docker compose down -v          # full reset (wipe all data)
docker compose logs demo        # view seed + API logs
docker compose ps               # check container health
```

---

## Local Python (alternative)

### One Command

```bash
git clone https://github.com/grcwarlock/warlock.git
cd warlock
./scripts/demo.sh
```

The script:
1. Creates a virtualenv and installs dependencies
2. Starts OPA with 670 Rego policies (if installed)
3. Runs database migrations (SQLite)
4. Seeds 81 connectors, 5,008 findings, 373,852 control results across 14 frameworks
5. Prompts for AI provider configuration (optional)
6. Starts the API server on port 8000

### Or use Make

```bash
make demo
```

---

## CLI

```bash
source .venv/bin/activate       # if using local Python

warlock coverage                       # compliance summary
warlock findings                       # all findings
warlock results --status non_compliant # non-compliant results
warlock poams                          # POA&M tracking
warlock drift                          # compliance drift
warlock systems                        # system profiles
warlock vendors                        # vendor risk
warlock retention report               # data retention
warlock lake status                    # data lake zone sizes
warlock lake query "SOC 2 readiness"   # natural language query
warlock ask "are we HIPAA ready?"      # conversational compliance
warlock dashboard                      # interactive TUI dashboard
```

## API

```bash
# Using curl (get a token first)
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.com","password":"WarlockAdmin2026!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s http://localhost:8000/api/v1/compliance/findings?limit=5 \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Or use the helper script (local Python only)
./scripts/demo_api.sh                              # coverage
./scripts/demo_api.sh /api/v1/findings?limit=5     # findings
./scripts/demo_api.sh /api/v1/poams                # POA&Ms
```

## Demo Accounts

| Email | Password | Role |
|---|---|---|
| admin@acme.com | WarlockAdmin2026! | Full admin |
| eve.nakamura@acme.com | SecurityFirst2026! | Auditor (read-only) |
| frank.torres@acme.com | EngineerBuild2026! | System owner (NIST/SOC2/ISO27001) |
| carol.park@acme.com | FinanceReview2026! | Viewer (SOC 2 only) |

## Install OPA (local Python only)

```bash
brew install opa
```

With OPA installed, the local demo evaluates 670 Rego policies across 8 frameworks. Without OPA, it skips policy evaluation. The Docker demo always includes OPA.
