# Docker Setup

Run the complete Warlock platform with a single command. Docker Compose orchestrates PostgreSQL, Redis, OPA, and the Warlock API server.

## Prerequisites

- Docker Engine 24+ ([install](https://docs.docker.com/engine/install/))
- Docker Compose v2+ (bundled with Docker Desktop)
- 4 GB RAM available for containers

Verify your installation:

```bash
docker --version       # Docker Engine 24+
docker compose version # Docker Compose v2+
```

## Quick Start

```bash
git clone https://github.com/grcwarlock/warlock.git && cd warlock
docker compose up demo
```

This starts everything: Postgres 16, Redis 7, OPA 0.62, database schema creation, demo seed data (165 connectors, ~5,475 findings, 373,852 control mappings), and the API server on port 8000.

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

**Full reset (rebuild + fresh data):**

```bash
docker compose down -v && docker compose up demo
```

---

## What the Demo Does

The `demo` service runs `scripts/docker-demo.sh` as its entrypoint. It executes four steps:

1. **Wait for database** -- Polls Postgres for up to 30 seconds until it accepts connections.
2. **Create schema** -- Runs `Base.metadata.create_all()` to build all 42 tables.
3. **Seed demo data** -- Executes `demo_seed.py`, which simulates 165 connectors collecting data across 14 compliance frameworks.
4. **Start API server** -- Launches `warlock-api` (Uvicorn on port 8000).

Expected seed output:

```
Connectors succeeded:   165
Connectors failed:      0
Raw events collected:   589
Findings normalized:    ~5,475
Controls mapped:        373,852
```

---

## Services

The `docker-compose.yml` defines five services:

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `db` | postgres:16-alpine | 5432 (localhost only) | Primary database |
| `redis` | redis:7-alpine | 6379 (localhost only) | Queue backend (Redis Streams) |
| `opa` | openpolicyagent/opa:0.62.1-static | 8181 (localhost only) | Policy evaluation engine |
| `api` | warlock (built) | 8000 | API server only (no demo data) |
| `demo` | warlock (built) | 8000 | API server with schema creation + seed |

### Which Service to Use

- **`demo`** -- Full demo with sample data. Use for evaluation, demos, and local development.
- **`api`** -- Clean API server without seed data. Use for production-like deployments where you control data.

Both `api` and `demo` depend on `db`, `redis`, and `opa` being healthy before starting.

### Volumes

| Volume | Mount | Purpose |
|--------|-------|---------|
| `pgdata` | PostgreSQL data directory | Persistent database storage |
| `lake` | `/app/lake` (demo only) | Data lake Parquet files |

---

## Environment Variables

The `demo` and `api` services set these variables in `docker-compose.yml`:

| Variable | Value in docker-compose | Description |
|----------|------------------------|-------------|
| `WLK_DATABASE_URL` | `postgresql://warlock:warlock_dev@db:5432/warlock` | Postgres connection string |
| `WLK_QUEUE_BACKEND` | `redis` | Queue backend type |
| `WLK_QUEUE_URL` | `redis://redis:6379` | Redis connection string |
| `WLK_JWT_SECRET` | `dev-only-change-in-production-min-32-chars` | JWT signing secret (change in production) |
| `WLK_ENV` | `development` | Environment mode |
| `WLK_LOG_LEVEL` | `INFO` | Logging level |
| `WLK_OPA_COMPLIANCE_ENABLED` | `true` | Enable OPA policy evaluation |
| `WLK_OPA_COMPLIANCE_URL` | `http://opa:8181/v1/data` | OPA server URL |
| `WLK_LAKE_ENABLED` | `true` (demo only) | Enable data lake writes |
| `WLK_LAKE_PATH` | `/app/lake` (demo only) | Lake storage path |

For the full variable reference, see [Deployment Guide](deployment.md) or `.env.example`.

---

## Building from Source

The Dockerfile uses a multi-stage build:

1. **Builder stage** -- Installs Python dependencies with pip caching.
2. **Runtime stage** -- Copies installed packages and application source. Runs as non-root user `warlock` (UID 1001).

```bash
# Standard build
docker build -t warlock .

# With optional extras (AI reasoning, data lake, Prometheus metrics)
docker build --build-arg EXTRAS="ai,lake,monitoring" -t warlock .

# Rebuild within docker compose
docker compose build
```

Available extras: `ai`, `lake`, `monitoring`, `aws`, `azure`, `gcp`.

The `docker-compose.yml` builds with `EXTRAS="ai,lake,monitoring"` by default.

---

## Health Check Endpoints

Three health endpoints are available for load balancers and container orchestrators:

| Endpoint | Purpose | Auth Required | Checks |
|----------|---------|---------------|--------|
| `GET /api/v1/health` | Basic health | No | Process alive, returns version |
| `GET /api/v1/health/live` | Liveness probe | No | Process alive |
| `GET /api/v1/health/ready` | Readiness probe | No | Database connectivity + scheduler state |

The Docker health check hits `/api/v1/health` every 30 seconds with a 15-second startup grace period.

**Example responses:**

```bash
# Basic health
curl http://localhost:8000/api/v1/health
# {"status":"ok","version":"2.0.0a1","timestamp":"2026-03-23T12:00:00+00:00"}

# Readiness (returns 503 if database or scheduler is down)
curl http://localhost:8000/api/v1/health/ready
# {"status":"ok","checks":{"database":"ok","scheduler":"running"},"timestamp":"..."}
```

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

## Production Deployment Notes

### Use PostgreSQL, Not SQLite

SQLite is for development only. PostgreSQL is required for:

- Multi-worker deployments
- Concurrent pipeline runs
- Data lake integration
- Read replicas

### Required Production Settings

```bash
WLK_DATABASE_URL=postgresql://user:password@host:5432/warlock
WLK_JWT_SECRET=<random-string-at-least-32-chars>       # REQUIRED
WLK_ENCRYPTION_KEY=<fernet-key>                         # REQUIRED
WLK_TRUST_PORTAL_SECRET=<random-string>                 # REQUIRED
WLK_ENV=production
```

Generate a Fernet encryption key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Security Defaults (Do Not Change)

| Setting | Default | Why |
|---------|---------|-----|
| `WLK_OPA_FAIL_MODE` | `closed` | Changing to `open` bypasses all API policy enforcement |
| `WLK_AI_CONFIDENCE_FLOOR` | `0.7` | Lowering accepts unreliable AI compliance assessments |
| `WLK_AI_TEMPERATURE` | `0.0` | Raising makes compliance results non-deterministic |
| `WLK_CORS_ORIGINS` | `[]` | Never add `*` wildcard |

### Production Compose Example

See the [Deployment Guide](deployment.md) for a full `docker-compose.prod.yml` example with Redis authentication, external secrets, and JSON structured logging.

---

## Troubleshooting

### Container fails to start

**Symptom:** `demo` service exits immediately.

**Check logs:**

```bash
docker compose logs demo
```

**Common causes:**

- Postgres not ready yet. The demo script waits up to 30 seconds, but slow disks may need more time. Check `docker compose logs db`.
- Port 8000 already in use. Stop any local process on that port: `lsof -ti:8000 | xargs kill -9`.

### "Database not available after 30s"

The demo script waits for Postgres connectivity. If this fails:

1. Check Postgres logs: `docker compose logs db`
2. Verify Postgres is healthy: `docker compose ps`
3. Restart from scratch: `docker compose down -v && docker compose up demo`

### Seed shows connector failures

Expected: 165 succeeded, 0 failed. If connectors fail:

1. Check the full seed output in logs: `docker compose logs demo | grep -A5 "Connectors"`
2. Ensure the image was built with the latest source: `docker compose build demo`

### OPA policy evaluation not working

Verify OPA is running:

```bash
curl http://localhost:8181/v1/data
```

Check OPA logs:

```bash
docker compose logs opa
```

The `policies/` directory must exist and contain valid Rego files. OPA mounts it read-only.

### Out of disk space

The `pgdata` volume grows with pipeline data. To reclaim space:

```bash
docker compose down -v   # deletes all volumes (destroys data)
docker system prune -f    # remove unused images and build cache
```

### Rebuilding after code changes

```bash
docker compose build demo    # rebuild the image
docker compose down -v       # remove old data
docker compose up demo       # start fresh
```
