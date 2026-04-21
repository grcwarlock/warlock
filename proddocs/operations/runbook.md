# Warlock Operations Runbook

This runbook covers day-to-day operations: QA procedures, pipeline management, troubleshooting, database operations, and monitoring.

## QA Gate

The QA gate is the single pass/fail check that must pass before any commit. It is implemented in `scripts/qa.sh`.

### Running the QA Gate

```bash
# Full QA gate (all checks)
./scripts/qa.sh

# Quick mode (lint + test only, ~30s)
./scripts/qa.sh --quick

# Via Make
make qa          # full gate
make qa-quick    # quick mode
```

### What the Full QA Gate Checks

The gate runs these checks in order. All must pass.

**Section 1: Code Quality**

| Check | What It Does |
|-------|-------------|
| Ruff Lint | `ruff check warlock/` -- no lint errors allowed |
| Ruff Format | `ruff format --check warlock/` -- all files must be formatted |
| Package Import | `import warlock` must succeed |

**Section 2: Testing**

| Check | What It Does |
|-------|-------------|
| Pytest Suite | `pytest tests/ --tb=short -q` -- all tests must pass |
| Test Count Baseline | Must collect >= 509 tests (prevents accidental test deletion) |

**Section 3: Integration**

| Check | What It Does |
|-------|-------------|
| Demo Seed (clean DB) | Fresh `alembic upgrade head` + `demo_seed.py`. Requires >= 55 connectors succeeded, 0 failed. |
| CLI Smoke Test | Runs `--help` on every CLI command via Click CliRunner. |
| Integrations Import | Verifies Slack, PagerDuty, Jira, ServiceNow integrations import. |

**Section 4: Compliance Infrastructure**

| Check | What It Does |
|-------|-------------|
| OPA Policy Check | `opa check policies/` + `opa test policies/` (skipped if OPA not installed) |
| Terraform Validate | `terraform validate` on all 142 modules (skipped if terraform not installed) |
| Terraform Format | `terraform fmt -check -recursive terraform/` |
| OSCAL JSON | Validates all JSON files in `frameworks-oscal/` parse correctly |
| Framework YAML | Validates all YAMLs in `warlock/frameworks/` have valid v2 dict-based structure |

**Section 5: Security**

| Check | What It Does |
|-------|-------------|
| Secrets Scan | Scans for hardcoded API keys, passwords, tokens |
| .env Check | Verifies `.env` is not committed to git |
| Dependency Audit | Checks for known vulnerabilities in dependencies |

**Section 6: Documentation and AI**

| Check | What It Does |
|-------|-------------|
| Documentation Counts | Verifies documented counts match reality (connector count, normalizer count, etc.) |
| AI Task Prompts | Verifies all AI task prompts exist |
| CLI AI Flags | Verifies `--ai` and `--ask` flags are present on expected commands |
| AI Service Import | Verifies AI service module imports correctly |

### QA Gate Output

The gate prints a summary table at the end:

```
CHECK                               RESULT TIME
---                                 ---    ---
Ruff Lint                           PASS   0.8s
Ruff Format Check                   PASS   0.5s
Package Import                      PASS   0.3s
Pytest Suite                        PASS   12.4s
Test Count Baseline (>= 295)        PASS   1.2s
Demo Seed (clean DB)                PASS   7.1s
CLI Smoke Test (--help)             PASS   2.3s
...

Total: 45.2s

ALL CHECKS PASSED
```

---

## Demo Seed

The demo seed script (`scripts/demo_seed.py`) creates a complete, realistic environment with no external API calls.

### Running the Demo Seed

```bash
# Fresh database + seed
rm -f warlock.db
alembic upgrade head
python scripts/demo_seed.py
```

### What the Demo Seed Creates

The seed registers mock connectors that produce realistic events, then runs the full pipeline (collect, normalize, map, assess).

**Expected output numbers:**

| Metric | Expected Value |
|--------|---------------|
| Connectors succeeded | 351 |
| Connectors failed | 0 |
| Raw events collected | 1,071 |
| Findings normalized | ~7,325 |
| Controls mapped | 373,852 |

Additionally, the seed creates:

- 5 system profiles with authorization boundaries
- Issues from non-compliant control results
- POA&Ms, compensating controls, and risk acceptances
- Personnel records with HR/IdP/training cross-references
- Data silos with classification data
- Audit engagements
- Compliance drift events and posture snapshots
- Legal holds
- Control inheritance mappings
- System dependencies

If any expected number changes after a code change, something is broken. Stop and investigate.

---

## Pipeline Operations

### Running the Pipeline

**CLI (interactive):**

```bash
warlock collect                    # full pipeline run
warlock collect -s aws -s okta     # specific sources only
```

**API (background):**

```bash
curl -X POST http://localhost:8000/api/v1/pipeline/collect \
  -H "Authorization: Bearer <token>"
```

Returns `202 Accepted` with a `run_id`. Check status:

```bash
curl http://localhost:8000/api/v1/pipeline/status \
  -H "Authorization: Bearer <token>"
```

### Pipeline Scheduler

The scheduler runs the pipeline at a configurable interval.

**Start via CLI (foreground, blocks):**

```bash
warlock scheduler start --interval 60    # every 60 minutes
```

**Start via API (background):**

```bash
curl -X POST http://localhost:8000/api/v1/scheduler/start \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"interval_minutes": 60}'
```

**Check status:**

```bash
warlock scheduler status
# or
curl http://localhost:8000/api/v1/scheduler/status \
  -H "Authorization: Bearer <token>"
```

### Scheduled Tasks

The scheduler runs multiple tasks at independent intervals:

| Task | Default Interval | Description |
|------|-----------------|-------------|
| `pipeline_collect` | 60 min | Main pipeline: collect, normalize, map, assess |
| `posture_snapshot` | 1440 min (daily) | Capture posture scores for trend tracking |
| `cadence_check` | 60 min | Flag stale controls |
| `retention_purge` | 10080 min (weekly) | Purge expired records |
| `ccm_stale_check` | 60 min | Continuous control monitoring: stale control scan |
| `risk_reeval_check` | 360 min (6h) | Re-evaluate risk acceptances |
| `risk_cache_precompute` | 10080 min (weekly) | Pre-warm Monte Carlo cache (opt-in, disabled by default) |

---

## Troubleshooting

### Pipeline Fails to Start

**Symptom:** `POST /pipeline/collect` returns 409 Conflict.

**Cause:** A previous pipeline run is still marked as running in the database.

**Fix:**

The pipeline now auto-recovers stale locks by checking whether the PID in the lock file is still alive. If the holder process is dead, the lock is reclaimed automatically. Manual intervention should no longer be needed.

If you still hit this error:
```bash
# Check for stuck runs
warlock scheduler status

# Manual fallback: remove the lock file
# The lock file is at $TMPDIR/warlock_pipeline.lock
rm -f "${TMPDIR:-/tmp}/warlock_pipeline.lock"
```

### Demo Seed Fails

**Symptom:** Connector count is wrong, or the seed crashes.

**Common causes:**

1. **Stale database:** Always start fresh.
   ```bash
   rm -f warlock.db && alembic upgrade head && python scripts/demo_seed.py
   ```

2. **Migration gap:** A model change was not accompanied by an Alembic migration.
   ```bash
   alembic upgrade head
   # If errors, check alembic/versions/ for the latest migration
   ```

3. **Import error:** A new dependency was added but not installed.
   ```bash
   pip install -e ".[dev,ai]"
   ```

### OPA Policy Evaluation Fails

**Symptom:** OPA compliance results are missing or all controls show `not_assessed`.

**Check:**
```bash
# Is OPA running?
curl http://localhost:8181/health

# Are policies loaded?
curl http://localhost:8181/v1/data

# Test a specific policy
opa eval -b policies/ "data.nist_800_53"
```

**Fix:**
```bash
# Restart OPA with the policy bundle
opa run --server --addr :8181 --bundle policies/
```

### AI Not Working

**Symptom:** AI features return "AI not configured" or 503 errors.

**Check:**
```bash
warlock ai status
```

**Fix:**
```bash
# Configure AI provider
export WLK_AI_ENABLED=true
export WLK_AI_PROVIDER=anthropic   # or openai, gemini, ollama
export WLK_AI_API_KEY=sk-ant-...
export WLK_AI_MODEL=claude-sonnet-4-20250514

# Test connectivity
warlock ai test
```

### Database Connection Issues

**Symptom:** API returns 503 on readiness check, or SQLAlchemy errors in logs.

**Check:**
```bash
# Readiness probe
curl http://localhost:8000/api/v1/health/ready

# Direct database check (PostgreSQL)
psql $WLK_DATABASE_URL -c "SELECT 1"

# Direct database check (SQLite)
sqlite3 warlock.db "SELECT 1"
```

**Common fixes:**
- Verify `WLK_DATABASE_URL` is correct
- Check connection pool: if using PgBouncer, set `WLK_PGBOUNCER_MODE=true`

### Import Errors After Code Changes

**Symptom:** `ImportError` or `ModuleNotFoundError` when starting the API or CLI.

**Fix:**
```bash
pip install -e ".[dev,ai]"
```

### Rate Limiting Errors (429)

**Symptom:** API returns `429 Too Many Requests`.

**Cause:** Per-endpoint rate limits exceeded.

**Check:** The rate limits are defined in `warlock/api/middleware.py`. Login is limited to 10/min, pipeline collect to 5/min.

**Fix for development:** Rate limits are counter-based and reset naturally. If using Redis cache, counters are shared across workers.

---

## Database Operations

### Backup (PostgreSQL)

```bash
# Dump full database
pg_dump $WLK_DATABASE_URL > backup.sql

# Dump specific tables
pg_dump $WLK_DATABASE_URL -t control_results -t findings > partial.sql
```

### Restore (PostgreSQL)

```bash
# Restore from backup
psql $WLK_DATABASE_URL < backup.sql
```

### Backup (SQLite)

```bash
cp warlock.db warlock.db.backup
```

### Migration Troubleshooting

```bash
# View current migration version
alembic current

# View migration history
alembic history --verbose

# Downgrade one step
alembic downgrade -1

# Upgrade to specific revision
alembic upgrade <revision>

# Generate a new migration (after model changes)
alembic revision --autogenerate -m "description"
```

---

## Monitoring

### Prometheus Metrics

When `prometheus_client` is installed, metrics are exposed at `/metrics`:

```bash
curl http://localhost:8000/metrics
```

### Audit Trail Verification

The audit trail uses SHA-256 hash chains. Verify integrity:

```bash
# Via API
curl http://localhost:8000/api/v1/audit-trail/verify \
  -H "Authorization: Bearer <token>"

# Response
{
  "chain_valid": true,
  "total_entries": 1234,
  "verified_entries": 1234,
  "broken_at": null
}
```

### Posture Monitoring

Check if controls are being assessed on schedule:

```bash
# All stale controls
warlock cadence --stale-only

# Compliance drift in the last 30 days
warlock drift -d 30

# Evidence sufficiency below threshold
warlock sufficiency --below 60
```

### Retention Status

```bash
# View retention report
warlock retention report

# Dry run purge
warlock retention purge

# Execute purge
warlock retention purge --execute
```

---

## Scheduled Maintenance

### Daily

- Check `/api/v1/health/ready` returns 200
- Review `warlock cadence --stale-only` for overdue controls

### Weekly

- Run `warlock risk precompute` to warm the Monte Carlo cache
- Check `warlock retention report` for records approaching retention limits
- Review `warlock drift` for unexpected compliance changes

### Monthly

- Run `warlock simulate-audit -f <framework>` for each active framework
- Review `warlock vendors` for high-risk vendor scores
- Verify audit trail integrity via `/api/v1/audit-trail/verify`

### Before Releases

- Run the full QA gate: `./scripts/qa.sh`
- Run the demo seed on a clean database
- Verify all 351 connectors succeed with 0 failures
- Check that documented counts match reality: `make verify-docs`

---

## Alert Configuration

Configure outbound alerts for compliance events.

### Slack

```bash
export WLK_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx
export WLK_SLACK_MIN_SEVERITY=medium
```

### PagerDuty

```bash
export WLK_PAGERDUTY_ROUTING_KEY=<routing-key>
export WLK_PAGERDUTY_MIN_SEVERITY=high
```

### Jira

```bash
export WLK_JIRA_BASE_URL=https://acme.atlassian.net
export WLK_JIRA_EMAIL=warlock@acme.com
export WLK_JIRA_API_TOKEN=<token>
export WLK_JIRA_PROJECT_KEY=GRC
export WLK_JIRA_MIN_SEVERITY=high
```

### ServiceNow

```bash
export WLK_SERVICENOW_OUTBOUND_INSTANCE=acme
export WLK_SERVICENOW_OUTBOUND_USERNAME=warlock
export WLK_SERVICENOW_OUTBOUND_PASSWORD=<password>
export WLK_SERVICENOW_MIN_SEVERITY=high
```

Configure via API:

```bash
curl -X PUT http://localhost:8000/api/v1/alerts/config \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"slack_enabled": true, "pagerduty_enabled": true}'
```

---

## Data Lake Operations

The data lake stores pipeline data in Apache Parquet format with Iceberg table management.

### Initialize

```bash
warlock lake init
# or
warlock lake init --path /data/lake
```

This creates the zone directory structure:
- `lake/raw/` -- Raw events from connectors
- `lake/enrichment/` -- Normalized findings
- `lake/curated/control_results/` -- Assessed control results
- `lake/curated/control_mappings/` -- Control-to-finding mappings
- `lake/curated/connector_runs/` -- Connector run metadata

### Check Status

```bash
warlock lake status
```

### Query (Natural Language)

```bash
warlock ask "What controls are failing for NIST 800-53?"
warlock ask "Show me all critical findings from AWS"
```

Requires `WLK_LAKE_ENABLED=true`.

---

## Emergency Procedures

### Pipeline Stuck in Running State

```bash
# 1. Check if the pipeline process is actually running
ps aux | grep warlock

# 2. Kill the pipeline lock
rm -f "${TMPDIR:-/tmp}/warlock_pipeline.lock"
```

### Database Corruption (SQLite)

```bash
# 1. Stop the API server
# 2. Make a backup
cp warlock.db warlock.db.corrupt

# 3. Start fresh
rm warlock.db
alembic upgrade head
python scripts/demo_seed.py
```

### OPA Denying All Requests

If `WLK_OPA_FAIL_MODE=closed` (default) and OPA is down, all API requests (except health and trust portal) are denied.

```bash
# 1. Check OPA health
curl http://localhost:8181/health

# 2. If OPA is down, restart it
opa run --server --bundle policies/

# 3. If OPA cannot be restarted immediately, temporarily disable the OPA gate
#    (NOT recommended for production — this bypasses policy enforcement)
export WLK_OPA_URL=""
```

### Full System Recovery

```bash
# Start fresh
rm -f warlock.db
alembic upgrade head
python scripts/demo_seed.py
warlock-api

# Verify
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/health/ready
```
