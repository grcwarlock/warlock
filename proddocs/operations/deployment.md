# Warlock Deployment Guide

This guide covers deploying Warlock in Docker (recommended), local development, and production configuration.

## Quick Start -- Docker Demo

The fastest way to run the complete platform:

```bash
docker compose up demo
```

This starts the full stack (Postgres 16, Redis 7, OPA 0.62, Warlock API), runs database migrations, seeds demo data, and starts the API server on port 8000.

**After startup:**

| Service | URL |
|---------|-----|
| API Health | http://localhost:8000/api/v1/health |
| Swagger Docs | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |
| Trust Portal | http://localhost:8000/trust/status |

**Demo credentials:** `admin@acme.com` / `WarlockAdmin2026!`

**Stop and reset:**

```bash
docker compose down          # stop all services
docker compose down -v       # stop and delete all data (volumes)
```

---

## Docker Architecture

The `docker-compose.yml` defines five services:

### Services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `db` | postgres:16-alpine | 5432 (localhost only) | Primary database |
| `redis` | redis:7-alpine | 6379 (localhost only) | Queue backend and shared cache |
| `opa` | openpolicyagent/opa:0.62.1-static | 8181 (localhost only) | Policy evaluation engine |
| `api` | warlock (built) | 8000 | API server only (no demo data) |
| `demo` | warlock (built) | 8000 | API server with migration + seed |

### Which service to use

- **`demo`** -- Full demo with sample data. For evaluation, demos, local development.
- **`api`** -- Clean API server. For production-like deployments where you control data.

The `api` and `demo` services both depend on `db`, `redis`, and `opa` being healthy before starting.

### Volumes

| Volume | Mount | Purpose |
|--------|-------|---------|
| `pgdata` | PostgreSQL data directory | Persistent database storage |
| `lake` | `/app/lake` (demo only) | Data lake Parquet files |

---

## Docker Build

The Dockerfile uses a multi-stage build:

1. **Builder stage** -- Installs Python dependencies with pip caching.
2. **Runtime stage** -- Copies installed packages and application source. Runs as non-root user `warlock` (UID 1001).

Build with optional extras:

```bash
# Standard build
docker build -t warlock .

# With AI, lake, and monitoring support
docker build --build-arg EXTRAS="ai,lake,monitoring" -t warlock .
```

The image includes a health check that hits `/api/v1/health` every 30 seconds.

---

## Environment Variables

All Warlock configuration is driven by environment variables prefixed with `WLK_`. Set them in your `.env` file, docker-compose.yml, or shell.

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `WLK_DATABASE_URL` | `sqlite:///warlock.db` | Database connection string. Use `postgresql://` in production. |
| `WLK_DATABASE_READ_URL` | (empty) | Read replica URL. Falls back to `WLK_DATABASE_URL`. |
| `WLK_PGBOUNCER_MODE` | `false` | When true: pool_size=1, max_overflow=0, no prepared statements. |
| `WLK_JWT_SECRET` | (empty) | JWT signing secret. **Required in production, minimum 32 characters.** |
| `WLK_JWT_EXPIRE_MINUTES` | `60` | JWT token lifetime. |
| `WLK_ENCRYPTION_KEY` | (empty) | Fernet key for field-level encryption. **Required in production.** |
| `WLK_ENV` | `development` | Environment mode: development, staging, production. |
| `WLK_LOG_LEVEL` | `INFO` | Logging level: DEBUG, INFO, WARNING, ERROR. |
| `WLK_LOG_FORMAT` | `text` | Log format: text or json (structured logging). |

### API Server

| Variable | Default | Description |
|----------|---------|-------------|
| `WLK_API_HOST` | `0.0.0.0` | API server bind address. |
| `WLK_API_PORT` | `8000` | API server port. |
| `WLK_API_RELOAD` | `false` | Enable hot reload (development only). |
| `WLK_CORS_ORIGINS` | `[]` | Allowed CORS origins. Never use `*`. |

### Queue and Cache

| Variable | Default | Description |
|----------|---------|-------------|
| `WLK_QUEUE_BACKEND` | `memory` | Queue backend: memory, redis, kafka, sqs. |
| `WLK_QUEUE_URL` | (empty) | Queue connection URL (e.g., `redis://localhost:6379`). |
| `WLK_QUEUE_PREFIX` | `warlock` | Stream/topic prefix. |
| `WLK_QUEUE_CONSUMER_GROUP` | `warlock-pipeline` | Consumer group name. |
| `WLK_QUEUE_MAX_RETRIES` | `3` | Maximum retry count for failed queue messages. |
| `WLK_CACHE_URL` | (empty) | Shared cache URL. Empty = in-memory (single worker only). Set to Redis URL for multi-worker. |

### Pipeline

| Variable | Default | Description |
|----------|---------|-------------|
| `WLK_PIPELINE_BATCH_SIZE` | `500` | Batch size for pipeline processing. |
| `WLK_PIPELINE_TIMEOUT_SECONDS` | `300` | Pipeline run timeout. |
| `WLK_SCHEDULER_INTERVAL_MINUTES` | `60` | Pipeline collection interval. |
| `WLK_SNAPSHOT_INTERVAL_MINUTES` | `1440` | Posture snapshot interval (daily). |

### OPA Policy Engine

| Variable | Default | Description |
|----------|---------|-------------|
| `WLK_OPA_URL` | (empty) | OPA decision endpoint for API gate. |
| `WLK_OPA_FAIL_MODE` | `closed` | API gate fail mode: closed (deny if OPA down) or open. **Do not change to open.** |
| `WLK_OPA_COMPLIANCE_ENABLED` | `false` | Enable OPA compliance evaluation. |
| `WLK_OPA_COMPLIANCE_URL` | (empty) | OPA compliance endpoint (e.g., `http://localhost:8181/v1/data`). |
| `WLK_OPA_COMPLIANCE_FAIL_MODE` | `open` | Compliance evaluation fail mode. Open by design (evaluation is optional). |
| `WLK_OPA_BUNDLE_PATH` | `policies/` | Path to OPA policy bundle. |

### AI Reasoning (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `WLK_AI_ENABLED` | `false` | Master switch for AI features. |
| `WLK_AI_PROVIDER` | (empty) | AI provider: anthropic, openai, gemini, ollama. |
| `WLK_AI_API_KEY` | (empty) | API key for the AI provider. |
| `WLK_AI_MODEL` | (empty) | Model to use (e.g., claude-sonnet-4-20250514, gpt-4o). |
| `WLK_AI_BASE_URL` | (empty) | Base URL for Ollama/vLLM. |
| `WLK_AI_CONFIDENCE_FLOOR` | `0.7` | Minimum AI confidence to accept assessment. **Do not lower.** |
| `WLK_AI_TEMPERATURE` | `0.0` | LLM temperature. **Keep at 0.0 for reproducibility.** |
| `WLK_AI_MAX_TOKENS` | `1024` | Maximum tokens per AI response. |
| `WLK_AI_TIMEOUT` | `60.0` | AI request timeout in seconds. |

### Outbound Integrations

| Variable | Default | Description |
|----------|---------|-------------|
| `WLK_SLACK_WEBHOOK_URL` | (empty) | Slack incoming webhook URL. |
| `WLK_SLACK_MIN_SEVERITY` | `medium` | Minimum severity to trigger Slack alerts. |
| `WLK_PAGERDUTY_ROUTING_KEY` | (empty) | PagerDuty routing key. |
| `WLK_PAGERDUTY_MIN_SEVERITY` | `high` | Minimum severity to trigger PagerDuty. |
| `WLK_JIRA_BASE_URL` | (empty) | Jira instance URL. |
| `WLK_JIRA_EMAIL` | (empty) | Jira service account email. |
| `WLK_JIRA_API_TOKEN` | (empty) | Jira API token. |
| `WLK_JIRA_PROJECT_KEY` | `GRC` | Jira project key. |
| `WLK_SERVICENOW_OUTBOUND_INSTANCE` | (empty) | ServiceNow instance name. |

### Data Lake (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `WLK_LAKE_ENABLED` | `false` | Enable data lake. |
| `WLK_LAKE_PATH` | `lake` | Lake root directory. |
| `WLK_LAKE_CATALOG_TYPE` | `sqlite` | Catalog type: sqlite (dev) or rest (cloud). |
| `WLK_LAKE_STORAGE_BACKEND` | `local` | Storage backend: local, s3, azure. |
| `WLK_LAKE_READS` | `false` | Enable lake reads (requires lake_enabled). |

### Trust Portal

| Variable | Default | Description |
|----------|---------|-------------|
| `WLK_TRUST_PORTAL_SECRET` | (empty) | HMAC secret for download token signing. **Required in production.** |

### Data Retention

| Variable | Default | Description |
|----------|---------|-------------|
| `WLK_CHANGE_EVENT_RETENTION_DAYS` | `90` | Auto-purge change events older than this. |

---

## Production Configuration

### Required Settings

These must be set for production (`WLK_ENV=production`):

```bash
WLK_JWT_SECRET=<random-string-at-least-32-chars>
WLK_ENCRYPTION_KEY=<fernet-key>
WLK_DATABASE_URL=postgresql://user:password@host:5432/warlock
WLK_TRUST_PORTAL_SECRET=<random-string>
WLK_ENV=production
```

Generate a Fernet key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Security Defaults (Do Not Change)

| Setting | Default | Why |
|---------|---------|-----|
| `WLK_OPA_FAIL_MODE` | `closed` | Changing to `open` bypasses all API policy enforcement. |
| `WLK_AI_CONFIDENCE_FLOOR` | `0.7` | Lowering accepts unreliable AI compliance assessments. |
| `WLK_AI_TEMPERATURE` | `0.0` | Raising makes compliance results non-deterministic. |
| `WLK_CORS_ORIGINS` | `[]` | Never add `*` wildcard. |

### Recommended Production Stack

```yaml
# docker-compose.prod.yml
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: warlock
      POSTGRES_USER: warlock
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}

  opa:
    image: openpolicyagent/opa:0.62.1-static
    command: ["run", "--server", "--addr", ":8181", "--bundle", "/policies"]
    volumes:
      - ./policies:/policies:ro

  api:
    build:
      context: .
      args:
        EXTRAS: "ai,lake,monitoring"
    environment:
      WLK_DATABASE_URL: postgresql://warlock:${DB_PASSWORD}@db:5432/warlock
      WLK_QUEUE_BACKEND: redis
      WLK_QUEUE_URL: redis://:${REDIS_PASSWORD}@redis:6379
      WLK_CACHE_URL: redis://:${REDIS_PASSWORD}@redis:6379
      WLK_JWT_SECRET: ${JWT_SECRET}
      WLK_ENCRYPTION_KEY: ${ENCRYPTION_KEY}
      WLK_TRUST_PORTAL_SECRET: ${TRUST_SECRET}
      WLK_ENV: production
      WLK_LOG_FORMAT: json
      WLK_OPA_COMPLIANCE_ENABLED: "true"
      WLK_OPA_COMPLIANCE_URL: http://opa:8181/v1/data
    depends_on:
      db: { condition: service_healthy }
      redis: { condition: service_healthy }
      opa: { condition: service_healthy }
```

---

## Local Development

### One-Command Demo

```bash
./scripts/demo.sh
```

This script:
1. Creates a virtual environment if needed
2. Installs dependencies
3. Starts OPA server (if installed)
4. Creates a fresh database and seeds demo data
5. Optionally configures AI (interactive prompt)
6. Starts the API server on port 8000

### Manual Setup

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev,ai]"

# Initialize database
alembic upgrade head

# Seed demo data
python scripts/demo_seed.py

# Start API server
warlock-api
```

### Make Targets

```bash
make install     # Install dependencies
make test        # Run pytest
make lint        # Run ruff linter
make qa          # Full QA gate
make qa-quick    # Quick QA (lint + test only)
make dev         # Start docker compose + migrate
make seed        # Run demo seed
make demo        # Full one-command demo
make clean       # Stop docker, remove DB
```

---

## Database Migrations

Warlock manages database schema via `Base.metadata.create_all()` in `init_db()`. No Alembic versions directory exists; `alembic/env.py` is present for future migration support.

### Run Migrations

```bash
# Apply all pending migrations
alembic upgrade head

# Check current version
alembic current

# View migration history
alembic history
```

### Docker Migrations

The demo service runs `Base.metadata.create_all()` for fresh Postgres databases. For upgrades to existing databases, exec into the container:

```bash
docker compose exec api alembic upgrade head
```

### SQLite vs PostgreSQL

- **Development:** SQLite (default, `sqlite:///warlock.db`)
- **Production:** PostgreSQL 16+ (recommended)

SQLite works for single-process development. PostgreSQL is required for:
- Multi-worker deployments
- Concurrent pipeline runs
- Data lake integration
- Read replicas

---

## Health Checks

Three health endpoints are available for load balancers and container orchestrators:

| Endpoint | Purpose | Auth | Check |
|----------|---------|------|-------|
| `GET /api/v1/health` | Basic health | No | Process alive, returns version |
| `GET /api/v1/health/live` | Liveness probe | No | Process alive |
| `GET /api/v1/health/ready` | Readiness probe | No | Database connectivity + scheduler state |

The Docker health check uses `/api/v1/health` with a 30-second interval and 15-second startup grace period.

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /api/v1/health/live
    port: 8000
  initialDelaySeconds: 15
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /api/v1/health/ready
    port: 8000
  initialDelaySeconds: 15
  periodSeconds: 10
```

---

## Prometheus Metrics

When `prometheus_client` is installed, a `/metrics` endpoint is automatically mounted. This exposes standard Python and FastAPI metrics.

Install monitoring extras:

```bash
pip install -e ".[monitoring]"
```

Or build the Docker image with monitoring:

```bash
docker build --build-arg EXTRAS="monitoring" -t warlock .
```

---

## Connector Configuration

Warlock supports 165 source connectors. Each connector is enabled via an `_enabled` flag and configured with provider-specific credentials. All are opt-in and disabled by default.

Example connector configuration:

```bash
# AWS
WLK_AWS_ENABLED=true
WLK_AWS_REGIONS='["us-east-1","us-west-2"]'
WLK_AWS_ASSUME_ROLE_ARN=arn:aws:iam::123456789:role/warlock-readonly

# CrowdStrike
WLK_CROWDSTRIKE_ENABLED=true
WLK_CROWDSTRIKE_CLIENT_ID=abc123
WLK_CROWDSTRIKE_CLIENT_SECRET=xyz789

# Okta
WLK_OKTA_ENABLED=true
WLK_OKTA_DOMAIN=acme.okta.com
WLK_OKTA_API_TOKEN=00abc...
```

For the full list of connector variables, see `warlock/config.py` or run:

```bash
python -c "from warlock.config import Settings; print([f for f in Settings.model_fields if f.endswith('_enabled')])"
```
