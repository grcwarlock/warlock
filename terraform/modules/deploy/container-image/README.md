# Warlock Container Image

Production container deployment for the Warlock GRC platform.

## Quick Start

From the repository root:

```bash
cd terraform/modules/deploy/container-image
docker compose up --build
```

Services will be available at:
- **Warlock API**: http://localhost:8000
- **Nginx proxy**: http://localhost:80
- **OPA**: http://localhost:8181

## Architecture

| Service | Description |
|---|---|
| warlock-api | FastAPI application server (Gunicorn + Uvicorn workers) |
| warlock-worker | Background pipeline scheduler |
| postgres | PostgreSQL 15 database |
| redis | Redis 7 cache and queue backend |
| opa | Open Policy Agent for policy enforcement |
| nginx | Reverse proxy with security headers |

## Environment Variables

Override these in production:

| Variable | Default | Notes |
|---|---|---|
| `WLK_DATABASE_URL` | `postgresql://warlock:warlock@postgres:5432/warlock` | Use a managed database in production |
| `WLK_JWT_SECRET` | `dev-secret-change-in-production-32chars` | Must be 32+ characters, cryptographically random |
| `WLK_AI_ENABLED` | `false` | Set to `true` and configure `WLK_GEMINI_API_KEY` for AI assessments |
| `WLK_OPA_URL` | `http://opa:8181` | OPA endpoint for policy evaluation |
| `WLK_REDIS_URL` | `redis://redis:6379/0` | Redis connection string |
| `WLK_ENCRYPTION_KEY` | (empty) | Required in production for field-level encryption |
| `WLK_GDPR_HMAC_SECRET` | (empty) | Required for GDPR erasure/export, must be 32+ chars |

## Production Considerations

- Replace the `WLK_JWT_SECRET` with a cryptographically random 32+ character string.
- Set `WLK_ENCRYPTION_KEY` and `WLK_GDPR_HMAC_SECRET` for field-level encryption and GDPR compliance.
- Use a managed PostgreSQL instance instead of the containerized one.
- Add TLS certificates to the nginx service for HTTPS.
- Pin all image tags to specific versions or digests for reproducible builds.
- Configure external log aggregation (the containers log to stdout/stderr).
- Set resource limits (CPU, memory) on each service for stability.

## Building the Image Standalone

```bash
# From repository root
DOCKER_BUILDKIT=1 docker build \
    -f terraform/modules/deploy/container-image/Dockerfile \
    -t warlock:latest \
    .
```
