# Medium Findings — Improve When Possible

Generated: 2026-03-19 from 14-agent parallel review

---

## M-1: No FK enforcement on SQLite

- **Files:** `warlock/db/engine.py`
- **Agents:** database-optimizer
- **Issue:** `PRAGMA foreign_keys=ON` never emitted. All FK constraints silently unenforced on SQLite.
- **Fix:**
  - [ ] Add SQLAlchemy event listener on engine connect: `cursor.execute("PRAGMA foreign_keys=ON")`
  - [ ] Gate behind `settings.database_url.startswith("sqlite")`

---

## M-2: Audit trail race condition on SQLite

- **Files:** `warlock/db/audit.py:31-36`, `warlock/db/models.py` (AuditEntry)
- **Agents:** security-auditor, compliance-auditor, database-optimizer
- **Issue:** `with_for_update()` is a no-op on SQLite. `sequence` column lacks UNIQUE constraint. Concurrent writes can produce duplicate sequences and break the hash chain.
- **Fix:**
  - [ ] Add `unique=True` to `AuditEntry.sequence` index
  - [ ] For SQLite: serialize audit writes through an application-level lock or queue
  - [ ] Add periodic chain verification to the scheduler

---

## M-3: No structured JSON logging

- **Files:** Multiple
- **Agents:** sre-engineer, cloud-architect, docker-expert
- **Issue:** Plain text key=value logs unparseable by Datadog, Loki, CloudWatch. No correlation ID threading across pipeline stages.
- **Fix:**
  - [ ] Add `python-json-logger` or `structlog` with JSON output behind `WLK_LOG_FORMAT=json`
  - [ ] Add request/correlation ID middleware that threads through all log lines
  - [ ] Apply `WLK_LOG_LEVEL` from config to the Python logging root handler at startup

---

## M-4: OSCAL import-ap and import-ssp are unresolvable # refs

- **Files:** `warlock/export/oscal.py:206`
- **Agents:** grc-engineer
- **Issue:** OSCAL validators and FedRAMP automated tooling (FART) will flag `"import-ap": {"href": "#"}`.
- **Fix:**
  - [ ] Generate Assessment Plan document alongside Assessment Results, link via UUID
  - [ ] For SSP-POA&M linkage, emit SSP UUID into POA&M's `import-ssp.href`
  - [ ] Add `back-matter` with `resources` for any `#` references

---

## M-5: func.julianday() is SQLite-specific — breaks on PostgreSQL

- **Files:** `warlock/assessors/drift.py:194-197`
- **Agents:** code-reviewer, database-optimizer
- **Issue:** `func.julianday()` in drift correlation will error on PostgreSQL.
- **Fix:**
  - [ ] Replace with Python-side sorting: `events.sort(key=lambda e: abs((e.occurred_at - detected_at).total_seconds()))`
  - [ ] Remove the `func.julianday` ORDER BY from the query

---

## M-6: No PostgreSQL connection pool configuration

- **Files:** `warlock/db/engine.py`
- **Agents:** cloud-architect, database-optimizer
- **Issue:** Default pool_size=5 insufficient. Missing `pool_recycle` causes stale connections on managed databases.
- **Fix:**
  - [ ] Add production pool config: `pool_size=20, max_overflow=30, pool_recycle=1800, pool_timeout=30`
  - [ ] Gate behind non-SQLite database URL detection

---

## M-7: Attestation workflow has no separation-of-duties enforcement

- **Files:** `warlock/api/app.py:2300-2359`
- **Agents:** penetration-tester, compliance-auditor
- **Issue:** Same user can prepare, submit, review, and approve their own attestation.
- **Fix:**
  - [ ] Enforce `reviewed_by != prepared_by`, `approved_by != reviewed_by`, `approved_by != prepared_by`
  - [ ] Require admin or auditor role for approval
  - [ ] Log SoD violation attempts to audit trail

---

## M-8: No dependency lock file

- **Files:** Project root
- **Agents:** devops-engineer, dependency-manager
- **Issue:** Non-deterministic installs. Different versions resolved on each `pip install`.
- **Fix:**
  - [ ] Run `uv lock` and commit `uv.lock` (or use `pip-compile` for `requirements.txt`)
  - [ ] Add lock file check to CI pipeline

---

## M-9: Scheduler skips first execution of non-collect schedules

- **Files:** `warlock/pipeline/scheduler.py:119-124`
- **Agents:** feature-dev:code-reviewer, sre-engineer
- **Issue:** `posture_snapshot` won't run for 24h after startup. `cadence_check` skipped for first hour.
- **Fix:**
  - [ ] Run all enabled schedules on startup (not just `pipeline_collect`)
  - [ ] Or initialize `last_run` to epoch so interval is immediately exceeded

---

## M-10: Missing FK cascade rules — orphan rows accumulate

- **Files:** `warlock/db/models.py`
- **Agents:** database-optimizer
- **Issue:** Deleting a ConnectorRun leaves orphaned RawEvents, Findings, ControlMappings, ControlResults.
- **Fix:**
  - [ ] Add `ondelete="CASCADE"` to pipeline chain FKs: connector_run_id, raw_event_id, finding_id
  - [ ] Add `ondelete="SET NULL"` to optional FKs: poam_id, engagement_id, system_profile_id
  - [ ] Generate Alembic migration for the FK changes

---

## M-11: No CORS configuration

- **Files:** `warlock/api/app.py`
- **Agents:** security-engineer, compliance-auditor
- **Issue:** Secure by default but high risk of `allow_origins=["*"]` when frontend is added.
- **Fix:**
  - [ ] Add explicit `CORSMiddleware` with `allow_origins` from `WLK_CORS_ORIGINS` env var
  - [ ] Default to empty (no cross-origin) if unset
  - [ ] Document CORS configuration in `.env.example`
