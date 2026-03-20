# Warlock Deployment Guide

This guide covers production and staging deployment of Warlock GRC platform. For development setup, see [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Prerequisites

### System Requirements

- **Python:** 3.12 or higher
- **PostgreSQL:** 15 or higher (required for production; SQLite for dev)
- **Redis:** 7 or higher (for distributed queue backend)
- **OPA (Open Policy Agent):** Latest stable version (recommended for policy evaluation)

### Network Requirements

- Outbound HTTPS to cloud provider APIs (AWS, Azure, GCP, etc.)
- Outbound to EDR, SIEM, and IAM provider APIs
- Internal TCP 5432 (PostgreSQL)
- Internal TCP 6379 (Redis)
- Internal TCP 8181 (OPA server)
- Inbound TCP 8000 (API, configurable)

### Credentials & Secrets

Before deployment, gather:
- Database credentials (username, password, URL)
- Redis URL (for queue backend)
- JWT secret (min 32 chars, generated if not provided)
- Cloud provider credentials (AWS IAM, Azure, GCP service accounts)
- Connector credentials (Okta, CrowdStrike, etc. as needed)
- (Optional) AI provider API key (Anthropic, OpenAI, Gemini, local ollama)

---

## 1. Installation from Source

### Clone Repository

```bash
git clone https://github.com/grcwarlock/warlock.git
cd warlock
```

### Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate    # On Windows: .venv\Scripts\activate
```

### Install Dependencies

For **production with AWS connectors + AI reasoning:**

```bash
pip install -e ".[aws,ai]"
```

For **all optional connectors** (not recommended for production; use extras as needed):

```bash
pip install -e ".[all]"
```

For **minimal installation** (core framework only):

```bash
pip install -e .
```

Available extras:
- `aws` — Amazon Web Services connectors
- `azure` — Microsoft Azure connectors
- `gcp` — Google Cloud Platform connectors
- `ai` — AI reasoning (Anthropic, OpenAI, Gemini, ollama)
- `dev` — Development tools (pytest, ruff, black)
- `all` — All connectors and AI

---

## 2. PostgreSQL Setup

### Create Database and User

```sql
-- Connect to PostgreSQL as superuser
psql -U postgres

-- Create user
CREATE USER warlock WITH PASSWORD 'STRONG_PASSWORD_HERE';

-- Create database owned by warlock user
CREATE DATABASE warlock OWNER warlock;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE warlock TO warlock;

-- Connect to warlock database
\c warlock

-- Grant schema privileges (for migrations)
GRANT ALL ON SCHEMA public TO warlock;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO warlock;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO warlock;
```

### Run Migrations

```bash
export WLK_DATABASE_URL="postgresql://warlock:PASSWORD@localhost:5432/warlock"
.venv/bin/alembic upgrade head
```

Verify migration completed:

```bash
psql postgresql://warlock:PASSWORD@localhost:5432/warlock -c "SELECT version FROM alembic_version;"
```

---

## 3. Redis Setup

### Option A: Docker (Recommended for Dev/Staging)

```bash
docker run -d \
  --name warlock-redis \
  -p 6379:6379 \
  redis:7-alpine
```

Verify:

```bash
redis-cli ping    # Should return PONG
```

### Option B: Native Installation

**macOS (Homebrew):**

```bash
brew install redis
brew services start redis
```

**Ubuntu/Debian:**

```bash
apt-get update && apt-get install -y redis-server
systemctl start redis-server
```

**Production Deployment:**

```bash
# Amazon ElastiCache
# Azure Cache for Redis
# Or managed Redis service from your cloud provider
```

### Configure Queue Backend

Set environment variables:

```bash
export WLK_QUEUE_BACKEND=redis
export WLK_QUEUE_URL=redis://localhost:6379
export WLK_QUEUE_PREFIX=warlock        # stream prefix
export WLK_QUEUE_CONSUMER_GROUP=warlock-pipeline
export WLK_QUEUE_MAX_RETRIES=3         # retry failed events
export WLK_QUEUE_BATCH_SIZE=100        # process 100 events per batch
```

---

## 4. OPA Server Setup

Open Policy Agent enforces compliance policy gates and evaluates Rego policies.

### Install OPA

**macOS:**

```bash
brew install opa
```

**Linux:**

```bash
wget https://openpolicyagent.org/downloads/latest/opa_linux_x86_64
chmod +x opa_linux_x86_64
sudo mv opa_linux_x86_64 /usr/local/bin/opa
```

**Docker:**

```bash
docker run -d \
  --name warlock-opa \
  -p 8181:8181 \
  -v /path/to/warlock/policies:/policies \
  openpolicyagent/opa:latest \
  run --server --bundle /policies
```

### Start OPA Server (CLI)

```bash
cd /path/to/warlock
opa run --server --bundle policies/
```

Expected output:

```
Listening on :8181
```

### Configure OPA in Warlock

```bash
# API gateway policy enforcement (fail-closed for security)
export WLK_OPA_URL=http://localhost:8181/v1/data/api/authz

# Compliance evaluation engine (optional, skips if OPA down)
export WLK_OPA_COMPLIANCE_ENABLED=true
export WLK_OPA_COMPLIANCE_URL=http://localhost:8181/v1/data
export WLK_OPA_COMPLIANCE_TIMEOUT=30.0
export WLK_OPA_COMPLIANCE_FAIL_MODE=open   # skip if OPA unavailable
export WLK_OPA_FAIL_MODE=closed            # SECURITY: deny if OPA unavailable
```

Verify OPA is working:

```bash
curl -X POST http://localhost:8181/v1/data/api/authz \
  -H "Content-Type: application/json" \
  -d '{"input": {"user": "admin", "action": "read"}}'
```

---

## 5. Environment Variables Reference

Create `.env` file in project root or source before starting services:

```bash
# Database (PostgreSQL for production, SQLite for dev)
WLK_DATABASE_URL=postgresql://warlock:PASSWORD@db.example.com:5432/warlock

# API Server
WLK_API_HOST=0.0.0.0
WLK_API_PORT=8000
WLK_API_RELOAD=false              # hot-reload on file changes (dev only)

# JWT Authentication
WLK_JWT_SECRET=your-32+-char-secret-key-here
WLK_JWT_EXPIRE_MINUTES=60

# Queue Backend (memory, redis, kafka, sqs)
WLK_QUEUE_BACKEND=redis
WLK_QUEUE_URL=redis://redis:6379
WLK_QUEUE_PREFIX=warlock
WLK_QUEUE_CONSUMER_GROUP=warlock-pipeline
WLK_QUEUE_MAX_RETRIES=3
WLK_QUEUE_BATCH_SIZE=100

# Scheduler (pipeline collection and snapshots)
WLK_SCHEDULER_INTERVAL_MINUTES=60          # data collection interval
WLK_SNAPSHOT_INTERVAL_MINUTES=1440         # posture snapshot (daily)
WLK_CADENCE_CHECK_INTERVAL_MINUTES=60      # control assessment schedule check

# Pipeline
WLK_PIPELINE_BATCH_SIZE=500                # findings per batch
WLK_PIPELINE_TIMEOUT_SECONDS=300           # timeout per batch

# OPA Policy Enforcement
WLK_OPA_URL=http://localhost:8181/v1/data/api/authz
WLK_OPA_FAIL_MODE=closed                   # SECURITY: deny if OPA unavailable

# OPA Compliance Evaluation (optional)
WLK_OPA_COMPLIANCE_ENABLED=true
WLK_OPA_COMPLIANCE_URL=http://localhost:8181/v1/data
WLK_OPA_COMPLIANCE_TIMEOUT=30.0
WLK_OPA_COMPLIANCE_FAIL_MODE=open          # skip evaluation if OPA unavailable
WLK_OPA_BUNDLE_PATH=policies/

# AI Reasoning (optional)
WLK_AI_PROVIDER=anthropic                  # "anthropic", "openai", "gemini", "ollama"
WLK_AI_API_KEY=sk-ant-...                  # API key for chosen provider
WLK_AI_MODEL=claude-3-5-sonnet-20241022    # model identifier
WLK_AI_BASE_URL=                           # for ollama: http://localhost:11434/v1
WLK_AI_CONFIDENCE_FLOOR=0.7                # min confidence to accept AI assessment
WLK_AI_TEMPERATURE=0.0                     # 0.0 for reproducibility

# Field Encryption (optional, for sensitive fields)
WLK_ENCRYPTION_KEY=                        # 32-char key for field encryption

# CORS (if exposing API to external clients)
WLK_CORS_ORIGINS=["https://app.example.com"]

# Environment & Logging
WLK_ENV=production                         # "development", "staging", "production"
WLK_LOG_LEVEL=INFO                         # "DEBUG", "INFO", "WARNING", "ERROR"
WLK_LOG_FORMAT=json                        # "text" or "json" for structured logging

# Data Retention
WLK_CHANGE_EVENT_RETENTION_DAYS=90         # auto-purge change events older than this

# Cloud Providers (enable only those you use)
WLK_AWS_ENABLED=true
WLK_AWS_REGIONS=["us-east-1", "us-west-2"]
WLK_AWS_ASSUME_ROLE_ARN=arn:aws:iam::...

WLK_AZURE_ENABLED=true
WLK_AZURE_SUBSCRIPTION_ID=...
WLK_AZURE_TENANT_ID=...

WLK_GCP_ENABLED=true
WLK_GCP_PROJECT_ID=...

# EDR Providers
WLK_CROWDSTRIKE_ENABLED=true
WLK_CROWDSTRIKE_CLIENT_ID=...
WLK_CROWDSTRIKE_CLIENT_SECRET=...

WLK_DEFENDER_ENABLED=true
WLK_DEFENDER_TENANT_ID=...
WLK_DEFENDER_CLIENT_ID=...
WLK_DEFENDER_CLIENT_SECRET=...

# IAM Providers
WLK_OKTA_ENABLED=true
WLK_OKTA_DOMAIN=acme.okta.com
WLK_OKTA_API_TOKEN=...

# SIEM Providers
WLK_SPLUNK_ENABLED=true
WLK_SPLUNK_BASE_URL=https://splunk.example.com:8089
WLK_ELASTIC_ENABLED=true
WLK_ELASTIC_BASE_URL=https://elastic.example.com:9200

# (See warlock/config.py for complete list of 40+ connectors)
```

### Generate JWT Secret

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Output is a 64-character hex string suitable for `WLK_JWT_SECRET`.

---

## 6. Running the API Server

### With Uvicorn (Development & Testing)

```bash
.venv/bin/uvicorn warlock.api.app:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload              # auto-reload on code changes (dev only)
```

### With Gunicorn (Production)

```bash
.venv/bin/pip install gunicorn

.venv/bin/gunicorn \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --timeout 120 \
  --access-logfile - \
  warlock.api.app:app
```

**Worker Count Formula:**
- `(2 × CPU_CORES) + 1`
- For 4 CPU: `(2 × 4) + 1 = 9 workers`
- For 8 CPU: `(2 × 8) + 1 = 17 workers`

### Via CLI Command

```bash
warlock-api          # Uses config from environment variables
```

Verify API is running:

```bash
curl http://localhost:8000/api/v1/health
```

Expected response:

```json
{
  "status": "ok",
  "version": "2.0.0",
  "timestamp": "2026-03-19T14:30:45Z"
}
```

### Interactive API Documentation

Once running, visit:
- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

---

## 7. Running the Pipeline Scheduler

The scheduler runs data collection and control assessment on a schedule.

### Start Scheduler

```bash
.venv/bin/warlock scheduler start
```

Expected output:

```
[2026-03-19 14:30:45] Scheduler started
[2026-03-19 14:30:45] Job: collect (every 60 minutes)
[2026-03-19 14:30:45] Job: snapshot (every 1440 minutes = 24 hours)
[2026-03-19 14:30:45] Waiting for next run...
```

### Check Scheduler Status

```bash
.venv/bin/warlock scheduler status
```

### Graceful Shutdown

```bash
# Scheduler captures SIGTERM and completes current batch before exiting
kill -TERM <scheduler_pid>
```

### Run Pipeline Manually

```bash
# Full pipeline: collect → normalize → map → assess
.venv/bin/warlock collect

# Limit to specific source
.venv/bin/warlock collect -s aws

# Check control assessment cadence
.venv/bin/warlock cadence
```

---

## 8. Docker Deployment

### Using docker-compose (Development)

```bash
docker-compose up
```

This starts:
- PostgreSQL (port 5432)
- Redis (port 6379)
- Warlock API (port 8000)

Expected output:

```
db_1   | LOG: starting services
redis_1 | Ready to accept connections
api_1  | Uvicorn running on http://0.0.0.0:8000
```

### Multi-Stage Dockerfile (Production)

The included Dockerfile uses multi-stage builds:

1. **Builder stage** — Install dependencies, compile extensions
2. **Runtime stage** — Minimal image with only runtime dependencies

Build image:

```bash
docker build -t warlock:latest .

# With optional connectors
docker build --build-arg EXTRAS="aws,ai" -t warlock:latest .
```

Run container:

```bash
docker run -d \
  --name warlock \
  -p 8000:8000 \
  -e WLK_DATABASE_URL=postgresql://warlock:pwd@db:5432/warlock \
  -e WLK_QUEUE_BACKEND=redis \
  -e WLK_QUEUE_URL=redis://redis:6379 \
  -e WLK_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
  warlock:latest
```

### Kubernetes Deployment

Example manifest for Kubernetes (requires Helm):

```yaml
apiVersion: v1
kind: Deployment
metadata:
  name: warlock-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: warlock
  template:
    metadata:
      labels:
        app: warlock
    spec:
      containers:
      - name: api
        image: warlock:latest
        ports:
        - containerPort: 8000
        env:
        - name: WLK_DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: warlock-secrets
              key: database-url
        - name: WLK_QUEUE_URL
          value: redis://warlock-redis:6379
        livenessProbe:
          httpGet:
            path: /api/v1/health/live
            port: 8000
          initialDelaySeconds: 15
          periodSeconds: 20
        readinessProbe:
          httpGet:
            path: /api/v1/health/ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
```

For full Helm chart, see `./helm/` directory.

---

## 9. Monitoring

### Health Endpoints

```bash
# Basic health
curl http://localhost:8000/api/v1/health

# Liveness probe (is service running?)
curl http://localhost:8000/api/v1/health/live

# Readiness probe (is service ready for traffic? checks DB + scheduler)
curl http://localhost:8000/api/v1/health/ready
```

### Prometheus Metrics (when available)

```bash
curl http://localhost:8000/metrics
```

Metrics exported:
- `warlock_pipeline_runs_total` — total pipeline executions
- `warlock_pipeline_duration_seconds` — collection latency
- `warlock_findings_total` — total findings collected
- `warlock_control_results_total` — total control assessments
- `warlock_assertions_passed_total` — assertion pass rate
- `warlock_api_requests_total` — API request counts

### Log Aggregation

Structured logging (JSON format):

```bash
export WLK_LOG_FORMAT=json
.venv/bin/warlock-api 2>&1 | jq .
```

Logs include:
- Request/response metadata
- Pipeline stage timing
- Assertion results
- Policy decisions
- Error traces

Send to:
- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Splunk**
- **CloudWatch** (AWS)
- **Application Insights** (Azure)

---

## 10. Backup and Recovery

### Database Backups

**PostgreSQL pg_dump:**

```bash
# Full backup
pg_dump postgresql://warlock:PASSWORD@db.example.com:5432/warlock > warlock_backup.sql

# With compression
pg_dump -Fc postgresql://warlock:PASSWORD@db.example.com:5432/warlock > warlock_backup.dump

# Scheduled backups (daily, 2 AM)
0 2 * * * pg_dump -Fc postgresql://warlock:PASSWORD@db:5432/warlock > /backups/warlock_$(date +\%Y\%m\%d).dump
```

**Cloud Provider Backups:**
- AWS RDS: automated snapshots, point-in-time recovery
- Azure Database for PostgreSQL: geo-redundant backups, restore to different regions
- Google Cloud SQL: automated backups with retention policies

### Restore from Backup

```bash
# From SQL backup
psql postgresql://warlock:PASSWORD@db.example.com:5432/warlock < warlock_backup.sql

# From compressed dump
pg_restore -d warlock warlock_backup.dump
```

### Legal Hold

Controls are marked for legal hold when active litigation or audit is in progress. Retained records:

```bash
# Mark control for legal hold
.venv/bin/warlock legal-hold --control AC-2 --reason "SOX audit 2026"

# Verify legal holds
.venv/bin/warlock legal-hold --list

# Override hold (requires management approval)
.venv/bin/warlock legal-hold --control AC-2 --release
```

Legal holds prevent automatic purging (see `WLK_CHANGE_EVENT_RETENTION_DAYS`).

---

## 11. Upgrading

### Backup First

```bash
# Database backup
pg_dump -Fc postgresql://warlock:PASSWORD@db:5432/warlock > warlock_backup.dump

# OPA policies backup
cp -r policies/ policies.backup/
```

### Pull Latest Code

```bash
git pull origin main
```

### Update Dependencies

```bash
pip install -e ".[aws,ai]" --upgrade
```

### Run Migrations

```bash
.venv/bin/alembic upgrade head
```

### Verify Migrations Completed

```bash
.venv/bin/alembic current
```

### Downgrade (if needed)

```bash
# Rollback one migration
.venv/bin/alembic downgrade -1

# Rollback to specific version
.venv/bin/alembic downgrade ae1027a6acf
```

See `alembic/versions/` for migration history.

### Restart Services

```bash
# Stop API server (CTRL+C)
# Stop scheduler (CTRL+C)

# Start API
.venv/bin/warlock-api

# Start scheduler
.venv/bin/warlock scheduler start
```

### Verify Upgrade

```bash
# Check version
curl http://localhost:8000/api/v1/health | jq .version

# Run quick pipeline test
.venv/bin/warlock collect --source aws --limit 10

# Verify controls still assessed
.venv/bin/warlock coverage
```

---

## 12. Security Hardening Checklist

Before production deployment, verify:

### API Security

- [ ] **JWT Secret:** 32+ character random string
  ```bash
  WLK_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  ```
- [ ] **HTTPS/TLS:** API behind reverse proxy with valid certificate (nginx, ALB, etc.)
- [ ] **CORS:** Restricted to known origins (never use `*`)
  ```bash
  WLK_CORS_ORIGINS=["https://app.example.com", "https://admin.example.com"]
  ```
- [ ] **Rate Limiting:** Enabled at reverse proxy or API gateway (10 req/sec per IP)
- [ ] **Request Timeout:** 120 seconds (via gunicorn `--timeout`)

### Policy Enforcement

- [ ] **OPA Fail Mode:** `closed` (deny if policy engine unavailable)
  ```bash
  WLK_OPA_FAIL_MODE=closed
  ```
- [ ] **Policy Tests:** All 631+ tests pass
  ```bash
  opa test policies/
  ```
- [ ] **Scope Filters:** Verified ABAC prevents privilege escalation
  ```bash
  grep -r "apply_framework_scope\|apply_source_scope" warlock/api/
  ```

### Database Security

- [ ] **Network Isolation:** PostgreSQL not exposed to internet
- [ ] **Strong Credentials:** Password 20+ chars, auto-generated via secrets manager
- [ ] **SSL/TLS:** Database connections encrypted
  ```bash
  WLK_DATABASE_URL=postgresql://...?sslmode=require
  ```
- [ ] **User Permissions:** Minimal privileges granted
- [ ] **Backup Encryption:** Backups encrypted at rest

### Credential Management

- [ ] **No Hardcoded Secrets:** All credentials in environment variables or secrets manager
- [ ] **Secrets Rotation:** Keys rotated every 90 days
- [ ] **Audit Logging:** All credential access logged and monitored
- [ ] **Field Encryption:** Sensitive fields encrypted with `WLK_ENCRYPTION_KEY`

### Deployment Security

- [ ] **Image Scanning:** Docker image scanned for vulnerabilities
  ```bash
  docker scan warlock:latest
  ```
- [ ] **Minimal Base Image:** `python:3.12-slim` (no unnecessary packages)
- [ ] **Non-Root User:** Container runs as `warlock:warlock` (UID 1001)
- [ ] **Read-Only Filesystem:** Root filesystem read-only where possible
- [ ] **Network Policies:** Kubernetes NetworkPolicies restrict traffic

### Audit & Compliance

- [ ] **Audit Trail:** Immutable hash-chained audit log in database
- [ ] **Access Logs:** JSON structured logs shipped to centralized logging
- [ ] **Configuration Audit:** Environment variables logged on startup
- [ ] **Change Tracking:** Schema versions and migrations tracked

---

## 13. Troubleshooting

### Issue: API Won't Start

**Error: "database connection refused"**

```bash
# Verify PostgreSQL is running
pg_isready -h localhost -p 5432

# Check connection string
echo $WLK_DATABASE_URL

# Verify user/password
psql $WLK_DATABASE_URL -c "SELECT 1"
```

**Error: "alembic version table not found"**

```bash
# Run migrations
.venv/bin/alembic upgrade head
```

### Issue: Scheduler Not Running

**Error: "scheduler crashed"**

```bash
# Check logs for errors
.venv/bin/warlock scheduler start 2>&1 | head -20

# Verify database is accessible
.venv/bin/warlock coverage

# Verify queue backend is running
redis-cli ping   # Should return PONG
```

### Issue: Pipeline Fails to Collect

**Error: "OPA unavailable" or "OPA policy deny"**

```bash
# Verify OPA is running
curl http://localhost:8181/v1/data/api/authz

# Check OPA policies have no errors
opa check policies/

# If OPA is unavailable, set fail mode to open (not recommended)
export WLK_OPA_FAIL_MODE=open
```

**Error: "connector timeout"**

```bash
# Increase timeout
export WLK_PIPELINE_TIMEOUT_SECONDS=600

# Check cloud provider API status
# Review connector logs for rate limiting
```

### Issue: High Memory Usage

**Pipeline consuming too much memory:**

```bash
# Reduce batch size
export WLK_PIPELINE_BATCH_SIZE=100    # from 500

# Reduce queue batch size
export WLK_QUEUE_BATCH_SIZE=50        # from 100

# Monitor memory usage
ps aux | grep warlock
```

### Issue: Slow Assessment

**Controls taking too long to assess:**

```bash
# Check AI reasoning is not enabled unnecessarily
export WLK_AI_PROVIDER=""

# Verify assertion cache is warm
.venv/bin/warlock coverage --refresh

# Profile the pipeline
.venv/bin/python -m cProfile -s cumtime warlock.cli:main collect | head -20
```

### Clear Database (Development Only)

**WARNING: This deletes all data.**

```bash
# Drop all tables
.venv/bin/alembic downgrade base

# Re-create schema
.venv/bin/alembic upgrade head

# Reseed with demo data
python scripts/demo_seed.py
```

---

## Support

- **Documentation:** [README.md](../README.md), [CONTRIBUTING.md](../CONTRIBUTING.md), [CLAUDE.md](../CLAUDE.md)
- **Issues:** GitHub issue tracker with logs and reproduction steps
- **Security:** security@grcwarlock.io for vulnerabilities (not public issues)

Happy deploying!
