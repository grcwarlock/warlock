# Warlock Deployment Guide

> **This document has been superseded.** The canonical deployment reference is
> [`proddocs/operations/deployment.md`](../proddocs/operations/deployment.md)
> (environment variables, quick start, production configuration).
>
> For developer setup, see [`CONTRIBUTING.md`](../CONTRIBUTING.md).

This file is kept as an extended step-by-step supplement for first-time
bare-metal deployments. For the authoritative configuration reference and
environment variable tables, always consult `proddocs/operations/deployment.md`.

---

## Prerequisites

- **Python:** 3.12+
- **PostgreSQL:** 15+ (production; SQLite for dev)
- **Redis:** 7+ (distributed queue backend)
- **OPA:** Latest stable (policy evaluation)

### Network

- Outbound HTTPS to cloud provider / EDR / SIEM / IAM APIs
- Internal TCP 5432 (PostgreSQL), 6379 (Redis), 8181 (OPA)
- Inbound TCP 8000 (API, configurable)

---

## 1. Installation

```bash
git clone https://github.com/grcwarlock/warlock.git && cd warlock
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[aws,ai]"        # production with AWS + AI
# pip install -e ".[all]"         # all connectors
# pip install -e .                # minimal
```

Extras: `aws`, `azure`, `gcp`, `ai`, `dev`, `all`.

## 2. PostgreSQL

```sql
CREATE USER warlock WITH PASSWORD 'STRONG_PASSWORD_HERE';
CREATE DATABASE warlock OWNER warlock;
GRANT ALL PRIVILEGES ON DATABASE warlock TO warlock;
\c warlock
GRANT ALL ON SCHEMA public TO warlock;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO warlock;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO warlock;
```

```bash
export WLK_DATABASE_URL="postgresql://warlock:PASSWORD@localhost:5432/warlock"
.venv/bin/alembic upgrade head
```

## 3. Redis

```bash
# macOS
brew install redis && brew services start redis
# Ubuntu
apt-get install -y redis-server && systemctl start redis-server
```

## 4. OPA

```bash
# macOS: brew install opa
# Linux: download from openpolicyagent.org
opa run --server --bundle policies/
```

## 5. Environment Variables

See [`proddocs/operations/deployment.md`](../proddocs/operations/deployment.md) for the
complete environment variable reference.

Generate a JWT secret: `python3 -c "import secrets; print(secrets.token_hex(32))"`

## 6. Start Services

```bash
# API (dev)
.venv/bin/uvicorn warlock.api.app:app --host 0.0.0.0 --port 8000

# API (production — use gunicorn)
.venv/bin/gunicorn --workers 4 --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 --timeout 120 warlock.api.app:app

# Scheduler
.venv/bin/warlock scheduler start
```

## 7. Verify

```bash
curl http://localhost:8000/api/v1/health
```

## 8. Security Hardening Checklist

- [ ] JWT secret 32+ chars (`WLK_JWT_SECRET`)
- [ ] HTTPS behind reverse proxy with valid cert
- [ ] CORS restricted (`WLK_CORS_ORIGINS` — never `*`)
- [ ] OPA fail mode closed (`WLK_OPA_FAIL_MODE=closed`)
- [ ] Database SSL (`?sslmode=require`)
- [ ] Field encryption key set (`WLK_ENCRYPTION_KEY`)
- [ ] `pip-audit` clean

## 9. Upgrading

```bash
pg_dump -Fc $WLK_DATABASE_URL > warlock_backup.dump
git pull origin main
pip install -e ".[aws,ai]" --upgrade
.venv/bin/alembic upgrade head
# Restart API + scheduler
```
