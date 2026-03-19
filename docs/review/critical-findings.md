# Critical Findings — Must Fix Before Production

Generated: 2026-03-19 from 14-agent parallel review

---

## C-1: JWT secret silently falls back to ephemeral value

- **Files:** `warlock/api/auth.py:33,135-148`
- **Agents:** security-auditor, security-engineer, penetration-tester, compliance-auditor
- **Issue:** No startup guard prevents running without `WLK_JWT_SECRET`. Multi-worker deployments get different secrets per process. Tokens forgeable with weak/empty values.
- **Fix:**
  - [ ] Add startup validation that refuses to start if `WLK_JWT_SECRET` is unset and `WLK_ENV=production`
  - [ ] Enforce minimum 32-character key length
  - [ ] Log at CRITICAL level in development mode when using ephemeral secret

---

## C-2: ABAC scoping never enforced at query time

- **Files:** `warlock/api/deps.py`, `warlock/api/app.py` (all list endpoints)
- **Agents:** security-auditor, penetration-tester
- **Issue:** `User.allowed_frameworks` and `allowed_sources` are stored but no endpoint filters results by them. An owner scoped to SOC 2 can read all NIST findings.
- **Fix:**
  - [ ] Create a reusable FastAPI dependency or query filter that applies `allowed_frameworks`/`allowed_sources` constraints
  - [ ] Apply the filter to every data-returning endpoint (findings, results, posture, cadence, sufficiency, drift, POA&Ms, issues)
  - [ ] Add integration test verifying scoped users cannot see out-of-scope data

---

## C-3: No account lockout or login brute-force protection

- **Files:** `warlock/api/auth.py:232`, `warlock/api/app.py:430`
- **Agents:** security-auditor, security-engineer, compliance-auditor
- **Issue:** 60 req/min shared rate limit means ~70 password guesses/min with no per-account tracking.
- **Fix:**
  - [ ] Add per-account failed login counter (DB column or Redis)
  - [ ] Lock accounts after 5 consecutive failures for 30 minutes
  - [ ] Log all failed authentication attempts to audit trail with source IP
  - [ ] Add stricter per-endpoint rate limit for `/auth/login` (5-10/min)

---

## C-4: SQLiteJSON dialect import prevents JSONB on PostgreSQL

- **Files:** `warlock/db/models.py:19`
- **Agents:** architect-reviewer
- **Issue:** `from sqlalchemy.dialects.sqlite import JSON as SQLiteJSON` used for 47 columns. On PostgreSQL these become TEXT, not queryable/indexable JSONB.
- **Fix:**
  - [ ] Change import to `from sqlalchemy import JSON` (the generic type)
  - [ ] Regenerate Alembic migrations or verify existing ones produce correct DDL
  - [ ] Test migration roundtrip on both SQLite and PostgreSQL

---

## C-5: No CI/CD pipeline, no Dockerfile, no deployment artifacts

- **Files:** Project root
- **Agents:** devops-engineer, cloud-architect, docker-expert
- **Issue:** Zero automation between commit and production. No container, no compose, no K8s manifests, no GitHub Actions.
- **Fix:**
  - [ ] Create `Dockerfile` (multi-stage: builder + runtime, non-root user, HEALTHCHECK)
  - [ ] Create `.dockerignore`
  - [ ] Create `docker-compose.yml` (postgres + redis + api for local dev)
  - [ ] Create `.github/workflows/ci.yml` (lint + test + build)
  - [ ] Create `Makefile` with install, test, lint, migrate, dev targets
  - [ ] Create `.env.example` from config.py

---

## C-6: No backup or disaster recovery strategy

- **Files:** `warlock/db/engine.py`
- **Agents:** cloud-architect
- **Issue:** SQLite file on disk with no backup. Compliance evidence loss = repeat the entire audit period.
- **Fix:**
  - [ ] Document requirement for managed PostgreSQL with automated backups (35-day retention minimum)
  - [ ] Add export artifact archival to versioned object storage (S3 with versioning)
  - [ ] Define RTO/RPO targets (recommended: RPO 1hr, RTO 4hr)
  - [ ] Wire `_execute_retention` to `RetentionManager.purge_expired()` with legal hold checks

---

## C-7: No GDPR data subject rights implementation

- **Files:** `warlock/db/models.py` (Personnel, User, TrustAccessRequest)
- **Agents:** compliance-auditor
- **Issue:** Platform stores PII with no erasure, access, or portability endpoints for its own data.
- **Fix:**
  - [ ] Implement `DELETE /api/v1/personnel/{id}/gdpr-erase` that anonymizes PII fields
  - [ ] Implement `GET /api/v1/personnel/{id}/data-export` for subject access requests
  - [ ] Document lawful basis for processing personnel data
  - [ ] Add data processing records (GDPR Article 30)
