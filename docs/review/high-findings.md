# High Findings — Fix Soon, Real Risk

Generated: 2026-03-19 from 14-agent parallel review

---

## H-1: Legacy SHA-256 password hashes accepted without forced re-hash

- **Files:** `warlock/api/auth.py:79-98`
- **Agents:** security-auditor, feature-dev:code-reviewer, compliance-auditor
- **Issue:** `verify_password` accepts legacy SHA-256 hashes. Logs a warning but never re-hashes on successful login. Users on weak hashes stay vulnerable indefinitely.
- **Fix:**
  - [ ] In `authenticate_user`, after successful legacy verification, call `hash_password(password)` and update the DB row
  - [ ] Extract PBKDF2 iteration count to a shared constant (`_PBKDF2_ITERATIONS = 600_000`)
  - [ ] Add CLI command to identify users still on legacy hashes
  - [ ] Set a deadline after which legacy hashes are rejected

---

## H-2: No JWT token revocation mechanism

- **Files:** `warlock/api/auth.py`, `warlock/api/deps.py`
- **Agents:** security-auditor, security-engineer, compliance-auditor
- **Issue:** Once issued, JWT valid for 60 minutes with no blocklist. Compromised/deactivated user tokens remain valid.
- **Fix:**
  - [ ] Add `jti` (JWT ID) claim to tokens
  - [ ] Implement token revocation store (Redis-backed blocklist or per-user `token_valid_after` timestamp)
  - [ ] Check revocation on every `decode_access_token` call
  - [ ] Add `POST /api/v1/auth/logout` endpoint
  - [ ] Consider reducing token TTL to 15 minutes with refresh token flow

---

## H-3: API key with empty scopes=[] grants full role permissions

- **Files:** `warlock/api/deps.py:55-58`
- **Agents:** feature-dev:code-reviewer, penetration-tester
- **Issue:** `if api_key.scopes` is falsy for empty list, so `effective = role_perms` (full permissions). Empty scopes should mean zero permissions.
- **Fix:**
  - [ ] Change condition: `if api_key and api_key.scopes is not None` with `effective = role_perms & set(api_key.scopes) if api_key.scopes else set()`
  - [ ] Validate scopes at API key creation: reject scopes not in `PERMISSIONS[current_user.role]`
  - [ ] Add test for empty scopes behavior

---

## H-4: N+1 queries in posture aggregation — 880+ queries per snapshot

- **Files:** `warlock/assessors/posture.py:257-260`, `warlock/assessors/cadence.py:112-118`
- **Agents:** code-reviewer, database-optimizer
- **Issue:** `aggregate_framework` loops per-control with 2-3 queries each. `take_snapshot` compounds with `score_control`. 880+ queries for two frameworks.
- **Fix:**
  - [ ] Rewrite `aggregate_framework` to batch-fetch all ControlResult rows for framework in one query, group in Python
  - [ ] Batch-fetch provider diversity via single `GROUP BY` query
  - [ ] Rewrite `check_framework` in `cadence.py` to use single `GROUP BY control_id` query for `MAX(assessed_at)`
  - [ ] Rewrite `DriftDetector.detect` to fetch all recent snapshots in one query

---

## H-5: Pipeline run tracking uses in-memory global — unsafe in multi-worker

- **Files:** `warlock/api/app.py:363-579`
- **Agents:** code-reviewer, feature-dev:code-reviewer
- **Issue:** `_pipeline_running` flag is per-process. Concurrent workers spawn duplicate pipeline runs.
- **Fix:**
  - [ ] Move pipeline run state to database: check for `ConnectorRun` with `status='running'` before starting
  - [ ] Remove in-memory `_pipeline_running` and `_pipeline_lock` globals

---

## H-6: No MFA for platform users

- **Files:** `warlock/db/models.py` (User model)
- **Agents:** compliance-auditor
- **Issue:** Platform assesses MFA on other systems but doesn't enforce it on its own admin accounts.
- **Fix:**
  - [ ] Add `mfa_required` (Boolean) and `mfa_secret` (encrypted String) columns to User model
  - [ ] Implement TOTP verification (pyotp) in login flow
  - [ ] Make MFA mandatory for admin and auditor roles
  - [ ] Store TOTP secrets encrypted via existing `FieldEncryptor`

---

## H-7: OPA policy gate defaults to fail-open

- **Files:** `warlock/api/policy_gate.py:34`
- **Agents:** security-auditor, security-engineer, compliance-auditor
- **Issue:** `fail_mode = "open"` means OPA outage silently bypasses all policy enforcement.
- **Fix:**
  - [ ] Change default to `"closed"` for production (gate by `WLK_ENV`)
  - [ ] Log every fail-open decision at WARNING level
  - [ ] Add OPA availability to the health check readiness probe

---

## H-8: In-memory rate limiter ineffective in multi-worker deployments

- **Files:** `warlock/api/middleware.py:27-100`
- **Agents:** security-engineer, cloud-architect, sre-engineer
- **Issue:** Per-process dict. N workers = Nx effective rate limit. Acknowledged in code comments.
- **Fix:**
  - [ ] Implement Redis-backed sliding window rate limiter
  - [ ] Add startup warning if worker count > 1 and rate limiter backend is in-memory
  - [ ] Add differentiated limits: `/auth/login` at 5-10/min, health excluded

---

## H-9: api/app.py is 3,973 lines — monolith endpoint file

- **Files:** `warlock/api/app.py`
- **Agents:** architect-reviewer
- **Issue:** Every endpoint in one file. Merge conflicts, impossible navigation, no separation of concerns.
- **Fix:**
  - [ ] Split into FastAPI `APIRouter` modules: `routers/pipeline.py`, `routers/findings.py`, `routers/audit.py`, `routers/admin.py`, `routers/poams.py`, `routers/trust.py`
  - [ ] Move Pydantic response models to `api/schemas.py`
  - [ ] Keep `app.py` as the composition root (~50 lines)

---

## H-10: AI assessments not reproducible for audit

- **Files:** `warlock/assessors/ai_reasoning.py`
- **Agents:** grc-engineer
- **Issue:** No `temperature: 0`, no prompt hash stored, no confidence floor. AI at confidence 0.1 written same as 0.95 in DB.
- **Fix:**
  - [ ] Set `temperature: 0` on all provider API calls
  - [ ] Store `prompt_hash` (SHA256 of system_prompt + user_prompt) on ControlResult or in audit trail
  - [ ] Add configurable confidence floor (default 0.7); below that, status remains `not_assessed`
  - [ ] Increase raw_data truncation limit from 20 items or switch to size-based truncation

---

## H-11: Health endpoint returns static "ok" regardless of system state

- **Files:** `warlock/api/app.py:416-422`
- **Agents:** sre-engineer, cloud-architect, docker-expert
- **Issue:** Load balancer never routes away from a broken instance. DB down, scheduler crashed — still reports "ok".
- **Fix:**
  - [ ] Split into `/api/v1/health/live` (process alive) and `/api/v1/health/ready` (DB reachable + scheduler running)
  - [ ] Ready probe: execute `SELECT 1` via engine, check scheduler state
  - [ ] Return HTTP 503 with failing check details when not ready

---

## H-12: Missing Azure/GCP packages in optional dependency groups

- **Files:** `pyproject.toml`, `warlock/connectors/azure.py`, `warlock/connectors/gcp.py`
- **Agents:** dependency-manager
- **Issue:** Azure connector imports 9 packages but only 2 declared. GCP imports 4 but only 2 declared. `pip install warlock[azure]` fails at runtime.
- **Fix:**
  - [ ] Add missing Azure packages: `azure-mgmt-policyinsights`, `azure-mgmt-security`, `azure-mgmt-network`, `azure-mgmt-keyvault`, `azure-mgmt-storage`, `azure-mgmt-monitor`, `azure-mgmt-alertsmanagement`
  - [ ] Add missing GCP packages: `google-cloud-resource-manager`, `google-cloud-compute`
  - [ ] Remove redundant `api` optional group (fastapi/uvicorn already in core deps)
  - [ ] Add version upper bounds to all dependencies
  - [ ] Generate and commit a lock file (`uv.lock` or `requirements.txt`)
